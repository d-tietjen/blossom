//! Embeddable Global Blossom node runtime.
//!
//! [`NodeRuntime`] owns one consensus group, its committed epoch chain, pending
//! blocks, service registry, recovery state, and optional durable stores.
//! [`MultiGroupRuntime`] routes independent group IDs to independent runtimes.
//! Applications select verified or trusted consensus with [`TrustMode`], while
//! [`RuntimeMode::Overlay`] disables consensus entry points and retains only
//! topology-aware fan-out.
//!
//! The implementation is divided by responsibility:
//!
//! - `core` constructs runtimes and exposes status and telemetry.
//! - `application` handles opaque application state and filtered availability.
//! - `consensus` drives local production and consensus-stage transitions.
//! - `messages` validates and dispatches inbound protocol messages.
//! - `recovery` owns snapshots, certified catch-up, and repair.
//! - `snapshot` validates the versioned persisted runtime envelope.
//! - `multi_group` provides group routing without shared consensus state.
//!
//! Child modules contain focused `impl` blocks; this parent file owns shared
//! types and invariants so internal visibility does not leak into the public
//! API.

#![warn(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use borsh::{BorshDeserialize, BorshSerialize};
use indextreemap::IndexTreeMap;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::address_book::{
    AddressBook, Service, ServiceKind, SignedServiceRecord,
    unix_time_millis as service_unix_time_millis,
};
use crate::admission::{NodeAdmission, ReconnectVote};
use crate::algorithm::{
    ConsensusParameters, QuorumSize, byzantine_fault_bound, select_prefill_recipients_with_size,
    select_quorums_with_size, supermajority_count,
};
#[cfg(feature = "availability-gossip")]
use crate::availability::{
    AvailabilityEntry, AvailabilityGossip, AvailabilityGossipBody, AvailabilityReceipt,
    AvailabilityStore, FilteredPayloadBatchDelivery, FilteredPayloadBatchDeliveryBody,
    FilteredPayloadBatchFetch, FilteredPayloadBatchFetchBody, FilteredPayloadDelivery,
    FilteredPayloadFetch, FilteredPayloadRequest,
};
use crate::block::{Block, BlockApplicationState};
use crate::block_store::DurableBlockStore;
use crate::blossom::{
    BlossomBody, BlossomMessage, Commit, CommitBody, Dispatch, DispatchBody, EchoReDispatch,
    EchoRequest, EchoResponse, EpochStarted, Header, Proposal, ProposalBody, ReconcileAppraisal,
    ReconcileCommit, ReconcileRequest, ReconcileResponse, RoundSkipCertificateMessage,
    RoundSkipVoteBody, RoundSkipVoteMessage, SignatureTree, TrustedAcknowledgement, Verification,
    VerificationBody,
};
use crate::crypto::{PubKey, SecretSigner, Signature};
use crate::encounter::{EncounterOutcome, EncounterPhase, EncounterRecord, EncounterRecordBody};
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::hash::{DoHash, HashType};
use crate::latency_topology::{
    ClosestPeer, LatencyEstimate, LatencyTopology, LatencyTopologyMetadataV1, unix_time_millis,
};
use crate::local_block::LocalBlock;
use crate::membership::{
    CommittedMemberOperation, ConsensusNodeRemovalPolicy, MAX_MEMBERSHIP_LEASE_MILLIS,
    MemberOperation, MembershipLeaseCertificate, MembershipLeaseChallenge, MembershipLeaseRequest,
    MembershipLeaseStatement, MembershipLeaseVote, RelaySet, VerifiedMembershipView,
};
use crate::messages::{MSGKey, Msg};
use crate::node::NodeIdentity;
use crate::nonce::Nonce;
use crate::overlay::{
    BroadcastReport, FanOutStrategy, add_self_consensus_service, broadcast_wire_request_pooled,
    select_fanout_targets_with_size,
};
use crate::round_skip::{
    DataDisseminationManifest, FutureRoundAssistDecision, FutureRoundAssistInput,
    FutureRoundAssistKind, RoundSkipVote,
};
use crate::service_client::TcpServiceClient;
use crate::state::{
    CERTIFIED_EPOCH_SUFFIX_VERSION, CertifiedEpochSuffix, Epoch, EpochBody, EpochChain, LocalState,
    MAX_CERTIFIED_EPOCH_SUFFIX, PendingDispatch, RoundSkipKey, TempQuorum,
    configured_max_pending_raw_dispatch_bytes,
    configured_max_pending_raw_dispatch_bytes_per_sender, validate_certified_extension,
    validate_genesis_anchor,
};
use crate::telemetry::{TelemetryEvent, TelemetryHandle};
use crate::trusted_log::{
    TrustedEpochLog, TrustedFailureAssessment, TrustedLogHead, TrustedRoundId, TrustedRoundLock,
    TrustedServiceDirective, assess_trusted_durability_failure, validate_trusted_extension,
};
use crate::wire::{HotDispatch, NodePing, NodePong, WireRequest, WireResponse};

const RUNTIME_BROADCAST_MAX_CONNECTIONS: usize = 4;

mod application;
mod consensus;
mod core;
mod messages;
mod multi_group;
mod recovery;
mod snapshot;

pub use multi_group::MultiGroupRuntime;

#[derive(Debug, Clone)]
/// Configuration used to construct one [`NodeRuntime`].
///
/// Consensus parameters are committed by genesis. A restored runtime rejects
/// any local quorum override that differs from the committed value.
pub struct RuntimeConfig {
    /// Consensus group owned by the runtime.
    pub group_id: ConsensusGroupId,
    /// Local public identity and optional in-memory signing material.
    pub self_node: NodeIdentity,
    /// Optional genesis epoch; generated from `self_node` when absent.
    pub genesis: Option<Epoch>,
    /// Optional previously committed epoch chain.
    pub epochchain: Option<EpochChain>,
    /// Initial node-local service registry.
    pub address_book: AddressBook,
    /// Maximum number of queued local blocks.
    pub block_cap: usize,
    /// Deterministic quorum branching factor.
    pub quorum_size: QuorumSize,
    /// Verified or trusted Global Blossom execution profile.
    pub trust_mode: TrustMode,
    /// Consensus-owning or topology-only runtime mode.
    pub mode: RuntimeMode,
    /// Policy for deriving committed validator removals.
    pub consensus_node_removal_policy: ConsensusNodeRemovalPolicy,
    /// Destination for structured runtime events.
    pub telemetry: TelemetryHandle,
    /// Optional path for atomic runtime snapshots.
    pub snapshot_path: Option<PathBuf>,
    /// Optional path for durable verified block storage.
    pub block_store_path: Option<PathBuf>,
    /// Append-only trusted confirmation/epoch log. This is intentionally separate
    /// from verified snapshots so enabling trusted durability cannot alter the
    /// trustless protocol.
    pub trusted_epoch_log_path: Option<PathBuf>,
    membership_lease_watermarks: BTreeMap<MembershipLeaseChallenge, MembershipLeaseWatermark>,
}

impl RuntimeConfig {
    /// Creates a root-group verified consensus configuration.
    pub fn new(self_node: NodeIdentity) -> Self {
        Self {
            group_id: ConsensusGroupId::root(),
            self_node,
            genesis: None,
            epochchain: None,
            address_book: AddressBook::new(),
            block_cap: 100,
            quorum_size: QuorumSize::DEFAULT,
            trust_mode: TrustMode::Verified,
            mode: RuntimeMode::Consensus,
            consensus_node_removal_policy: ConsensusNodeRemovalPolicy::disabled(),
            telemetry: TelemetryHandle::default(),
            snapshot_path: None,
            block_store_path: None,
            trusted_epoch_log_path: None,
            membership_lease_watermarks: BTreeMap::new(),
        }
    }

    /// Creates a topology-only configuration with consensus APIs disabled.
    pub fn overlay(self_node: NodeIdentity) -> Self {
        let mut config = Self::new(self_node);
        config.mode = RuntimeMode::Overlay;
        config
    }

    /// Creates a verified consensus configuration for an explicit group.
    pub fn for_group(self_node: NodeIdentity, group_id: ConsensusGroupId) -> Self {
        let mut config = Self::new(self_node);
        config.group_id = group_id;
        config
    }

    /// Reconstructs configuration from a validated snapshot.
    pub fn from_snapshot(snapshot: RuntimeSnapshotV1, self_node: NodeIdentity) -> Result<Self> {
        Self::from_snapshot_with_quorum_override(snapshot, self_node, None)
    }

    /// Reconstructs configuration while checking an optional operator quorum.
    ///
    /// A supplied value must equal the parameters committed in the snapshot.
    pub fn from_snapshot_with_quorum_override(
        snapshot: RuntimeSnapshotV1,
        self_node: NodeIdentity,
        configured_quorum_size: Option<QuorumSize>,
    ) -> Result<Self> {
        snapshot.validate_for_node(&self_node)?;
        if let Some(configured) = configured_quorum_size
            && configured != snapshot.consensus_parameters.quorum_size
        {
            return Err(BlossomError::ConsensusParametersMismatch {
                configured: configured.get(),
                committed: snapshot.consensus_parameters.quorum_size.get(),
            });
        }
        let genesis = snapshot
            .epochchain
            .epochchain
            .first()
            .cloned()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let latest_members = snapshot
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?
            .body
            .members
            .clone();
        let mut address_book = AddressBook::from_services(snapshot.address_book);
        let now = service_unix_time_millis();
        for record in snapshot.signed_service_records {
            if record.body.expires_at_unix_millis > now {
                address_book.apply_signed_record(
                    record,
                    snapshot.group_id,
                    &latest_members,
                    now,
                )?;
            }
        }
        let fallback_watermark_expiry = now.saturating_add(MAX_MEMBERSHIP_LEASE_MILLIS);
        let mut watermark_expiries = snapshot
            .membership_lease_watermark_expiries
            .into_iter()
            .collect::<BTreeMap<_, _>>();
        let membership_lease_watermarks = snapshot
            .membership_lease_watermarks
            .into_iter()
            .map(|(challenge, statement_hash)| {
                let expires_at_unix_millis = watermark_expiries
                    .remove(&challenge)
                    .unwrap_or(fallback_watermark_expiry);
                (
                    challenge,
                    MembershipLeaseWatermark {
                        statement_hash,
                        expires_at_unix_millis,
                    },
                )
            })
            .filter(|(_, watermark)| watermark.expires_at_unix_millis > now)
            .collect();
        Ok(Self {
            group_id: snapshot.group_id,
            self_node,
            genesis: Some(genesis),
            epochchain: Some(snapshot.epochchain),
            address_book,
            block_cap: snapshot.block_cap,
            quorum_size: snapshot.consensus_parameters.quorum_size,
            trust_mode: snapshot.trust_mode,
            mode: snapshot.mode,
            consensus_node_removal_policy: snapshot.consensus_node_removal_policy,
            telemetry: TelemetryHandle::default(),
            snapshot_path: None,
            block_store_path: None,
            trusted_epoch_log_path: None,
            membership_lease_watermarks,
        })
    }

    /// Enables runtime snapshot persistence at `path`.
    pub fn with_snapshot_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.snapshot_path = Some(path.into());
        self
    }

    /// Enables durable verified block storage at `path`.
    pub fn with_block_store_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.block_store_path = Some(path.into());
        self
    }

    /// Enables crash-safe trusted confirmation and epoch storage at `path`.
    pub fn with_trusted_epoch_log_path(mut self, path: impl Into<PathBuf>) -> Self {
        self.trusted_epoch_log_path = Some(path.into());
        self
    }

    /// Selects the quorum branching factor committed by a new genesis.
    pub fn with_quorum_size(mut self, quorum_size: QuorumSize) -> Self {
        self.quorum_size = quorum_size;
        self
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
/// Runtime responsibility within a process.
pub enum RuntimeMode {
    /// Own epoch state and accept consensus operations.
    Consensus,
    /// Retain only service discovery and topology fan-out.
    Overlay,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
/// Consensus authentication and fault model.
pub enum TrustMode {
    /// Verify signed blocks, messages, and Byzantine-safe evidence.
    Verified,
    /// Use the known-member trusted Global Blossom protocol.
    Trusted,
    /// Marker for the separate small-cluster HA runtime.
    ///
    /// [`NodeRuntime`] rejects this mode; use the HA runtime instead.
    HighAvailability,
}

impl TrustMode {
    /// Returns whether this selects trusted Global Blossom.
    pub fn is_trusted(self) -> bool {
        self == Self::Trusted
    }

    /// Returns whether this is the separate HA marker.
    pub fn is_high_availability(self) -> bool {
        self == Self::HighAvailability
    }
}

#[derive(Clone)]
/// Thread-safe runtime for one Global Blossom consensus group.
///
/// Clones share state. Signing material remains in memory, while snapshots and
/// durable stores contain public identities only.
pub struct NodeRuntime {
    inner: Arc<RuntimeInner>,
}

struct RuntimeInner {
    group_id: ConsensusGroupId,
    state: RwLock<LocalState>,
    future_round_messages: RwLock<BTreeMap<FutureRoundMessageKey, Vec<Msg>>>,
    epoch_started_hints: RwLock<BTreeMap<PubKey, EpochTarget>>,
    epoch_started_retry: RwLock<Option<EpochStartedRetry>>,
    prefill_dispatch_retry: RwLock<Option<PrefillDispatchRetry>>,
    local_blocks: RwLock<LocalBlock>,
    accepted_local_blocks: RwLock<BTreeMap<Nonce, HashType>>,
    #[cfg(feature = "availability-gossip")]
    availability: RwLock<AvailabilityStore>,
    address_book: RwLock<AddressBook>,
    network_client: TcpServiceClient,
    latency_topology: RwLock<LatencyTopology>,
    signer: Option<SecretSigner>,
    trust_mode: TrustMode,
    mode: RuntimeMode,
    block_cap: usize,
    consensus_parameters: ConsensusParameters,
    consensus_node_removal_policy: ConsensusNodeRemovalPolicy,
    snapshot_path: Option<PathBuf>,
    durable_block_store: Option<DurableBlockStore>,
    trusted_epoch_log: Option<TrustedEpochLog>,
    trusted_transition_lock: Mutex<()>,
    dispatch_production_lock: Mutex<()>,
    telemetry: TelemetryHandle,
    next_telemetry_span_id: AtomicU64,
    epoch_commit_tx: watch::Sender<Nonce>,
    verified_membership_tx: watch::Sender<Arc<VerifiedMembershipView>>,
    membership_lease_watermarks:
        Mutex<BTreeMap<MembershipLeaseChallenge, MembershipLeaseWatermark>>,
}

#[derive(Debug, Clone, Copy)]
struct MembershipLeaseWatermark {
    statement_hash: HashType,
    expires_at_unix_millis: u64,
}

#[derive(Debug, Clone)]
struct EpochStartedRetry {
    message: EpochStarted,
    pending_validators: BTreeSet<PubKey>,
    last_failures: BTreeMap<PubKey, String>,
}

#[derive(Debug, Clone)]
struct PrefillDispatchRetry {
    dispatch: Dispatch,
    pending_recipients: BTreeSet<PubKey>,
    last_failures: BTreeMap<PubKey, String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct FutureRoundMessageKey {
    last_epoch: HashType,
    nonce: Nonce,
    round: u8,
    kind: MSGKey,
    body_hash: HashType,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Version-1 public runtime snapshot.
///
/// The envelope excludes secret signing keys and is validated against the
/// restoring node identity before use.
pub struct RuntimeSnapshotV1 {
    /// Snapshot format version.
    pub version: u16,
    /// Consensus group captured by the snapshot.
    pub group_id: ConsensusGroupId,
    /// Public key of the node that produced the snapshot.
    pub self_public_key: PubKey,
    /// Complete committed epoch chain.
    pub epochchain: EpochChain,
    /// Public service records known at snapshot time.
    pub address_book: Vec<Service>,
    #[serde(default)]
    /// Signed relay-service records known at snapshot time.
    pub signed_service_records: Vec<SignedServiceRecord>,
    /// Configured local block queue capacity.
    pub block_cap: usize,
    #[serde(default)]
    /// Consensus parameters committed by genesis.
    pub consensus_parameters: ConsensusParameters,
    /// Verified or trusted execution profile.
    pub trust_mode: TrustMode,
    /// Consensus or overlay responsibility.
    pub mode: RuntimeMode,
    /// Committed validator-removal policy.
    pub consensus_node_removal_policy: ConsensusNodeRemovalPolicy,
    #[serde(default)]
    /// Anti-equivocation watermarks for membership lease challenges.
    pub membership_lease_watermarks: Vec<(MembershipLeaseChallenge, HashType)>,
    #[serde(default)]
    /// Absolute expiry for each membership-lease anti-equivocation watermark.
    ///
    /// Older version-1 snapshots may omit this additive field. Restoring one
    /// conservatively retains its watermarks for a complete maximum lease
    /// lifetime before allowing them to expire.
    pub membership_lease_watermark_expiries: Vec<(MembershipLeaseChallenge, u64)>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Evidence supplied when deciding whether a reconnecting node may rejoin.
pub struct ReconnectAdmissionEvidence {
    /// Signed admission statement for the candidate.
    pub admission: NodeAdmission,
    /// Current-validator votes over the admission and recovery point.
    pub votes: Vec<ReconnectVote>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Result of validating reconnect admission evidence.
pub struct ReconnectAdmissionDecision {
    /// Whether the evidence authorizes reconnect admission.
    pub accepted: bool,
    /// Stable operator-facing decision explanation.
    pub reason: String,
    /// Number of distinct valid current-validator votes.
    pub distinct_votes: usize,
    /// Number of votes required by the committed membership.
    pub required_votes: usize,
    /// Public key whose admission was evaluated.
    pub candidate: PubKey,
}

#[derive(Debug, Clone)]
struct RuntimeTelemetryMeta {
    stage: &'static str,
    event: &'static str,
    last_epoch: Option<HashType>,
    nonce: Option<Nonce>,
    round: Option<u8>,
    peer: Option<PubKey>,
    message_kind: Option<&'static str>,
}

#[derive(Debug, Clone)]
struct RuntimeTelemetrySpan {
    span_id: u64,
    meta: RuntimeTelemetryMeta,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Exact consensus coordinate for the next epoch under one group.
pub struct EpochTarget {
    /// Consensus group containing the epoch.
    pub group_id: ConsensusGroupId,
    /// Hash of the immediately preceding committed epoch.
    pub last_epoch: HashType,
    /// Nonce assigned to the target epoch.
    pub nonce: Nonce,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone)]
/// Public status snapshot for one runtime.
pub struct NodeStatus {
    /// Consensus group served by the runtime.
    pub group_id: ConsensusGroupId,
    /// Public-only local node identity.
    pub node: NodeIdentity,
    /// Hash of the committed head epoch.
    pub last_epoch: HashType,
    /// Nonce of the committed head epoch.
    pub last_epoch_nonce: Nonce,
    /// Nonce expected for the next epoch.
    pub next_nonce: Nonce,
    /// Closed local blocks plus an open block containing submitted transactions.
    pub pending_blocks: usize,
    /// Operator-configured quorum branching factor.
    pub configured_quorum_size: usize,
    /// Quorum size after capping by current membership.
    pub effective_quorum_size: usize,
    /// Hash of consensus parameters committed by the network.
    pub consensus_parameters_hash: HashType,
    /// Public services currently registered for the node.
    pub services: Vec<Service>,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, Copy, PartialEq, Eq,
)]
/// Service-facing readiness classification for a trusted runtime.
pub enum TrustedServiceHealth {
    /// Durable trusted writes may proceed normally.
    Ready,
    /// Progress is possible but one or more operational signals are impaired.
    Degraded,
    /// Trusted writes must stop.
    Unavailable,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Machine-readable readiness of a trusted Global Blossom runtime.
pub struct TrustedOperationalStatus {
    /// Aggregate service health.
    pub health: TrustedServiceHealth,
    /// Whether a trusted durable epoch log is configured.
    pub durable: bool,
    /// Nonce of the durable trusted head.
    pub head_nonce: Nonce,
    /// Hash of the durable trusted head.
    pub head_hash: HashType,
    /// Number of epochs retained by the trusted log.
    pub durable_epoch_count: u64,
    /// Whether an uncommitted confirmation lock is durable.
    pub pending_round_lock: bool,
    /// Members expected in the current trusted round.
    pub expected_round_members: usize,
    /// Distinct members whose dispatches are observed.
    pub observed_dispatch_members: usize,
    /// Matching acknowledgements required to confirm.
    pub required_acknowledgements: usize,
    /// Matching acknowledgements currently observed.
    pub observed_matching_acknowledgements: usize,
    /// Matching confirmations required to finalize.
    pub required_confirmations: usize,
    /// Matching confirmations currently observed.
    pub observed_matching_confirmations: usize,
    /// Whether the runtime may currently accept trusted writes.
    pub accepts_writes: bool,
    /// Required service-control actions.
    pub directives: Vec<TrustedServiceDirective>,
}

/// Read-only diagnostic snapshot of one node's current consensus round.
///
/// This deliberately exposes counts and hashes, not mutable protocol state. It
/// is primarily used by deterministic simulations and benchmark fault traces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusRoundStatus {
    /// Epoch coordinate being diagnosed.
    pub target: EpochTarget,
    /// Hierarchical consensus round number.
    pub round: u8,
    /// Members selected for this round's quorum.
    pub expected_quorum_members: usize,
    /// Local dispatch matrix result, when known.
    pub dispatch_status: Option<bool>,
    /// Valid dispatches received for the round.
    pub received_dispatches: usize,
    /// Dispatches buffered pending missing evidence.
    pub pending_dispatches: usize,
    /// Locally verified block count.
    pub verified_blocks: usize,
    /// Distinct verification senders.
    pub verification_senders: usize,
    /// Verification votes grouped by block-set hash.
    pub verification_counts: BTreeMap<HashType, u8>,
    /// Block-set hash that reached verification consensus.
    pub verification_consensus_hash: Option<HashType>,
    /// Distinct proposal senders.
    pub proposal_senders: usize,
    /// Proposal votes grouped by proposal hash.
    pub proposal_counts: BTreeMap<HashType, u32>,
    /// Proposal decision after threshold evaluation.
    pub proposal_consensus: Option<bool>,
    /// Proposals buffered pending local block verification.
    pub pending_proposals: usize,
    /// Commits buffered pending proposal evidence.
    pub pending_commits: usize,
    /// Distinct commit senders.
    pub commit_senders: usize,
    /// Distinct affirmative commit senders.
    pub commit_true_senders: usize,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Receipt returned after a local block is durably accepted.
pub struct AcceptedBlock {
    /// Consensus group that accepted the block.
    pub group_id: ConsensusGroupId,
    /// Canonical block hash.
    pub hash: HashType,
    /// Epoch nonce targeted by the block.
    pub nonce: Nonce,
    /// Number of opaque application-state bytes committed by the block.
    pub application_state_bytes: usize,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Bounded acknowledgement of an inbound protocol message.
pub struct MessageReceipt {
    /// Stable wire/protocol message kind.
    pub kind: String,
    /// Whether the message passed validation and was incorporated.
    pub accepted: bool,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Opaque application state observed in one verified peer block.
pub struct PeerApplicationState {
    /// Consensus group containing the block.
    pub group_id: ConsensusGroupId,
    /// Public key of the block producer.
    pub peer: PubKey,
    /// Canonical block hash.
    pub block_hash: HashType,
    /// Previous epoch hash committed by the block.
    pub last_epoch: HashType,
    /// Epoch nonce targeted by the block.
    pub nonce: Nonce,
    /// Application-owned state bytes.
    pub application_state: BlockApplicationState,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Deterministic prefill recipients and their reachable services.
pub struct PrefillDispatchPlan {
    /// Epoch coordinate targeted by the prefill.
    pub target: EpochTarget,
    /// Public key producing the prefill dispatch.
    pub source: PubKey,
    /// Deterministically selected recipient keys.
    pub recipients: Vec<PubKey>,
    /// Resolved services for reachable recipients.
    pub services: Vec<Service>,
    /// Selected recipients without a registered consensus service.
    pub missing_services: Vec<PubKey>,
}

impl PrefillDispatchPlan {
    /// Returns the total deterministic recipient count.
    pub fn recipient_count(&self) -> usize {
        self.recipients.len()
    }

    /// Returns the number of recipients with a resolved service.
    pub fn reachable_count(&self) -> usize {
        self.services.len()
    }

    /// Returns whether every selected recipient has a service.
    pub fn is_fully_reachable(&self) -> bool {
        self.missing_services.is_empty()
    }
}

#[derive(Debug, Clone)]
/// Result of constructing and broadcasting one prefill dispatch.
pub struct PrefillDispatchBroadcastReport {
    /// Deterministic recipient plan used for the broadcast.
    pub plan: PrefillDispatchPlan,
    /// Signed dispatch sent to the selected recipients.
    pub dispatch: Dispatch,
    /// Per-peer network results.
    pub broadcast: BroadcastReport,
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Read-only diagnostic snapshot of the verified prefill barrier.
///
/// The barrier is ready only after every sender routed to this validator has
/// supplied its exact signed round-zero dispatch. Outbound recipients remain
/// pending until they acknowledge that immutable dispatch.
pub struct PrefillStageStatus {
    /// Epoch coordinate being prefetched.
    pub target: EpochTarget,
    /// Validator whose local barrier is described.
    pub self_key: PubKey,
    /// Current hierarchical consensus round.
    pub current_round: u8,
    /// Validators whose prefill dispatch is required locally.
    pub expected_senders: BTreeSet<PubKey>,
    /// Validators whose prefill dispatch is durably represented in memory.
    pub recorded_senders: BTreeSet<PubKey>,
    /// Required local senders that have not arrived.
    pub missing_senders: BTreeSet<PubKey>,
    /// Routed recipients that have not acknowledged this node's dispatch.
    pub pending_recipients: BTreeSet<PubKey>,
    /// Most recent rejection or transport failure for each pending recipient.
    pub last_failures: BTreeMap<PubKey, String>,
}

impl PrefillStageStatus {
    /// Returns whether the local activation barrier is satisfied.
    pub fn ready(&self) -> bool {
        self.missing_senders.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
/// Read-only diagnostic snapshot of certified epoch dissemination.
pub struct EpochDisseminationStatus {
    /// Epoch coordinate this node is currently attempting.
    pub local_target: EpochTarget,
    /// Authenticated validators that announced a newer certified head.
    pub catch_up_hints: BTreeMap<PubKey, EpochTarget>,
    /// Validators that have not acknowledged this node's latest announcement.
    pub pending_validators: BTreeSet<PubKey>,
    /// Most recent rejection or transport failure for each pending validator.
    pub last_failures: BTreeMap<PubKey, String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
/// Decision and optional local vote produced by round-skip assistance.
pub struct RoundSkipAssistOutcome {
    /// Validated assistance decision.
    pub decision: FutureRoundAssistDecision,
    /// Signed local vote when this node has new evidence to contribute.
    pub message: Option<RoundSkipVoteMessage>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Requests required to repair blocks committed by a dissemination manifest.
pub struct ManifestRepairPlan {
    /// Hash identifying the validated manifest.
    pub manifest_hash: HashType,
    /// Block hashes absent from local durable or verified storage.
    pub missing_blocks: BTreeSet<HashType>,
    /// Missing hashes grouped by eligible replica holder.
    pub requests_by_holder: BTreeMap<PubKey, Vec<HashType>>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
/// Result of validating and installing manifest repair blocks.
pub struct ManifestRepairReceipt {
    /// Hash identifying the repaired manifest.
    pub manifest_hash: HashType,
    /// Number of newly inserted verified blocks.
    pub inserted_blocks: usize,
    /// Manifest blocks still unavailable after this repair attempt.
    pub missing_blocks: BTreeSet<HashType>,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
/// Readiness of recovery evidence for a consensus round.
pub enum RecoveryEvidenceStatus {
    /// Enough valid evidence is present to continue.
    Healthy,
    /// Additional valid member evidence may still satisfy the threshold.
    DelayedOrMissing,
    /// Existing evidence makes safe recovery impossible.
    Unrecoverable,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
/// Threshold assessment for buffered recovery evidence.
pub struct RecoveryWaitAssessment {
    /// Consensus round being assessed.
    pub round: u8,
    /// Aggregate evidence readiness.
    pub status: RecoveryEvidenceStatus,
    /// Nodes whose evidence currently passes.
    pub passed_nodes: usize,
    /// Nodes whose evidence remains pending.
    pub pending_nodes: usize,
    /// Distinct nodes required to continue.
    pub required_nodes: usize,
}

#[derive(Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone, PartialEq, Eq)]
/// Encounter evidence extracted from one verified peer block.
pub struct ObservedEncounterRecord {
    /// Consensus group containing the evidence.
    pub group_id: ConsensusGroupId,
    /// Hash of the block that carried the record.
    pub block_hash: HashType,
    /// Validator that produced the carrying block.
    pub block_validator: PubKey,
    /// Signed encounter record.
    pub record: EncounterRecord,
}

fn apply_telemetry_meta(mut event: TelemetryEvent, meta: &RuntimeTelemetryMeta) -> TelemetryEvent {
    event = match (meta.last_epoch, meta.nonce) {
        (Some(last_epoch), Some(nonce)) => event.with_target(last_epoch, nonce),
        _ => event,
    };
    event = match meta.round {
        Some(round) => event.with_round(round),
        None => event,
    };
    event = match meta.peer {
        Some(peer) => event.with_peer(peer),
        None => event,
    };
    event = match meta.message_kind {
        Some(message_kind) => event.with_message_kind(message_kind),
        None => event,
    };
    event
}

fn message_telemetry_meta(message: &Msg) -> RuntimeTelemetryMeta {
    match message {
        Msg::Dispatch(message) => header_telemetry_meta(
            "dispatch",
            "dispatch_received",
            &message.header,
            Some("Dispatch"),
        ),
        Msg::EchoResponse(message) => header_telemetry_meta(
            "echo",
            "echo_response_received",
            &message.header,
            Some("EchoResponse"),
        ),
        Msg::Verification(message) => header_telemetry_meta(
            "verification",
            "verification_received",
            &message.header,
            Some("Verification"),
        ),
        Msg::TrustedAcknowledgement(message) => header_telemetry_meta(
            "trusted_acknowledgement",
            "trusted_acknowledgement_received",
            &message.header,
            Some("TrustedAcknowledgement"),
        ),
        Msg::Proposal(message) => header_telemetry_meta(
            "proposal",
            "proposal_received",
            &message.header,
            Some("Proposal"),
        ),
        Msg::Commit(message) => {
            header_telemetry_meta("commit", "commit_received", &message.header, Some("Commit"))
        }
        Msg::EpochStarted(message) => header_telemetry_meta(
            "epoch_finality",
            "epoch_started_received",
            &message.header,
            Some("EpochStarted"),
        ),
        Msg::EchoRequest(message) => header_telemetry_meta(
            "echo",
            "echo_request_received",
            &message.header,
            Some("EchoRequest"),
        ),
        Msg::EchoReDispatch(message) => header_telemetry_meta(
            "echo",
            "echo_redispatch_received",
            &message.header,
            Some("EchoReDispatch"),
        ),
        Msg::RoundSkipVote(message) => header_telemetry_meta(
            "round_skip",
            "round_skip_vote_received",
            &message.header,
            Some("RoundSkipVote"),
        ),
        Msg::RoundSkipCertificate(message) => header_telemetry_meta(
            "round_skip",
            "round_skip_certificate_received",
            &message.header,
            Some("RoundSkipCertificate"),
        ),
        Msg::ReconcileAppraisal(message) => header_telemetry_meta(
            "reconcile",
            "reconcile_appraisal_received",
            &message.header,
            Some("ReconcileAppraisal"),
        ),
        Msg::ReconcileRequest(message) => header_telemetry_meta(
            "reconcile",
            "reconcile_request_received",
            &message.header,
            Some("ReconcileRequest"),
        ),
        Msg::ReconcileResponse(message) => header_telemetry_meta(
            "reconcile",
            "reconcile_response_received",
            &message.header,
            Some("ReconcileResponse"),
        ),
        Msg::ReconcileCommit(message) => header_telemetry_meta(
            "reconcile",
            "reconcile_commit_received",
            &message.header,
            Some("ReconcileCommit"),
        ),
        Msg::Ok => RuntimeTelemetryMeta {
            stage: "runtime",
            event: "ok_received",
            last_epoch: None,
            nonce: None,
            round: None,
            peer: None,
            message_kind: Some("Ok"),
        },
        Msg::Fail => RuntimeTelemetryMeta {
            stage: "runtime",
            event: "fail_received",
            last_epoch: None,
            nonce: None,
            round: None,
            peer: None,
            message_kind: Some("Fail"),
        },
    }
}

fn message_header_kind_hash(message: &Msg) -> Option<(&Header, MSGKey, HashType)> {
    match message {
        Msg::Dispatch(message) => Some((&message.header, MSGKey::Dispatch, message.body_hash())),
        Msg::EchoResponse(message) => {
            Some((&message.header, MSGKey::EchoResponse, message.body_hash()))
        }
        Msg::EchoRequest(message) => {
            Some((&message.header, MSGKey::EchoRequest, message.body_hash()))
        }
        Msg::EchoReDispatch(message) => {
            Some((&message.header, MSGKey::EchoReDispatch, message.body_hash()))
        }
        Msg::Verification(message) => {
            Some((&message.header, MSGKey::Verification, message.body_hash()))
        }
        Msg::TrustedAcknowledgement(message) => Some((
            &message.header,
            MSGKey::TrustedAcknowledgement,
            message.body_hash(),
        )),
        Msg::Proposal(message) => Some((&message.header, MSGKey::Proposal, message.body_hash())),
        Msg::Commit(message) => Some((&message.header, MSGKey::Commit, message.body_hash())),
        Msg::EpochStarted(message) => {
            Some((&message.header, MSGKey::EpochStarted, message.body_hash()))
        }
        Msg::RoundSkipVote(message) => {
            Some((&message.header, MSGKey::RoundSkipVote, message.body_hash()))
        }
        Msg::RoundSkipCertificate(message) => Some((
            &message.header,
            MSGKey::RoundSkipCertificate,
            message.body_hash(),
        )),
        Msg::ReconcileAppraisal(message) => Some((
            &message.header,
            MSGKey::ReconcileAppraisal,
            message.body_hash(),
        )),
        Msg::ReconcileRequest(message) => Some((
            &message.header,
            MSGKey::ReconcileRequest,
            message.body_hash(),
        )),
        Msg::ReconcileResponse(message) => Some((
            &message.header,
            MSGKey::ReconcileResponse,
            message.body_hash(),
        )),
        Msg::ReconcileCommit(message) => Some((
            &message.header,
            MSGKey::ReconcileCommit,
            message.body_hash(),
        )),
        Msg::Ok | Msg::Fail => None,
    }
}

fn header_telemetry_meta(
    stage: &'static str,
    event: &'static str,
    header: &Header,
    message_kind: Option<&'static str>,
) -> RuntimeTelemetryMeta {
    RuntimeTelemetryMeta {
        stage,
        event,
        last_epoch: Some(header.last_epoch),
        nonce: Some(header.nonce),
        round: Some(header.round),
        peer: Some(header.sender),
        message_kind,
    }
}

fn record_peer_application_state(
    peer_states: &mut BTreeMap<PubKey, PeerApplicationState>,
    group_id: ConsensusGroupId,
    block_hash: HashType,
    block: &Block,
    last_epoch: HashType,
    nonce: Nonce,
) {
    let peer = block.body.validator;
    let candidate = PeerApplicationState {
        group_id,
        peer,
        block_hash,
        last_epoch,
        nonce,
        application_state: block.body.application_state.clone(),
    };

    match peer_states.get(&peer) {
        Some(existing) if existing.nonce.value() > nonce.value() => {}
        _ => {
            peer_states.insert(peer, candidate);
        }
    }
}

fn record_observed_encounters(
    records: &mut Vec<ObservedEncounterRecord>,
    group_id: ConsensusGroupId,
    block_hash: HashType,
    block: &Block,
) {
    records.extend(block.body.encounter_records.iter().cloned().map(|record| {
        ObservedEncounterRecord {
            group_id,
            block_hash,
            block_validator: block.body.validator,
            record,
        }
    }));
}

fn quorum_has_signature_from(quorum: &TempQuorum, subject: PubKey, phase: EncounterPhase) -> bool {
    match phase {
        EncounterPhase::Dispatch => quorum.received_dispatches.contains(&subject),
        EncounterPhase::Verification => quorum.verifications.verifications.contains_key(&subject),
        EncounterPhase::Proposal => quorum.proposals.proposals.contains_key(&subject),
        EncounterPhase::Commit => quorum.commit_senders.contains(&subject),
        EncounterPhase::EpochStarted => quorum.epoch_started_senders.contains(&subject),
        EncounterPhase::CatchUp => false,
    }
}

fn record_verified_dispatch_blocks(quorum: &mut TempQuorum, blocks: BTreeMap<HashType, Block>) {
    for (hash, block) in blocks {
        quorum.record_verified_block(hash, block);
    }
    quorum.verified_blocks_hash = Some(quorum.verified_blocks_hash());
}

fn record_commit_vote(quorum: &mut TempQuorum, message: Commit, required_signatures: usize) {
    let sender = message.header.sender;
    quorum.pending_commits.remove(&sender);
    quorum.commit_senders.insert(sender);
    if message.body.consensus {
        quorum.commit_true_senders.insert(sender);
        if let Some(signature) = message.body.epoch_signature {
            quorum.epoch_signatures.insert(sender, signature);
        }
    } else {
        quorum.commit_true_senders.remove(&sender);
        quorum.epoch_signatures.remove(&sender);
    }
    quorum.commit_sent = quorum.commit_true_senders.len() >= required_signatures;
}

fn commit_sender_and_threshold(state: &mut LocalState, header: &Header) -> Result<(bool, usize)> {
    let previous = state
        .epochchain
        .epochchain
        .last()
        .ok_or(BlossomError::EmptyEpochChain)?;
    if previous.hash != header.last_epoch || previous.body.nonce.new_next() != header.nonce {
        return Err(BlossomError::InvalidEpochNonce);
    }
    let sender_is_validator = previous.body.verifiers.contains_key(&header.sender);
    let validator_count = previous.body.verifiers.len();
    let consensus = state.get_mut_consensus(&header.last_epoch, header.nonce);
    let final_round = consensus.peers.len().checked_sub(1) == Some(usize::from(header.round));
    if final_round {
        Ok((sender_is_validator, supermajority_count(validator_count)))
    } else {
        let round_peers = consensus.peers_with_us(header.round);
        let sender_is_round_peer = round_peers.contains(&header.sender);
        let threshold = supermajority_count(round_peers.len());
        Ok((sender_is_round_peer, threshold))
    }
}

fn validate_commit_epoch_share(state: &LocalState, message: &Commit) -> Result<()> {
    if !message.body.consensus {
        if message.body.epoch_hash.is_some() || message.body.epoch_signature.is_some() {
            return Err(BlossomError::WireProtocol(
                "false commit cannot carry an epoch certificate share".to_string(),
            ));
        }
        return Ok(());
    }
    match state.prepare_verified_epoch(
        &message.header.last_epoch,
        message.header.nonce,
        message.header.round,
    )? {
        None => {
            if message.body.epoch_hash.is_some() || message.body.epoch_signature.is_some() {
                return Err(BlossomError::WireProtocol(
                    "non-final commit cannot carry an epoch certificate share".to_string(),
                ));
            }
        }
        Some(epoch) => {
            if message.body.epoch_hash != Some(epoch.hash) {
                return Err(BlossomError::InvalidBlockHash);
            }
            message
                .body
                .epoch_signature
                .ok_or(BlossomError::FailedConsensus)?
                .verify(epoch.hash.as_ref(), &message.header.sender)?;
        }
    }
    Ok(())
}

fn proposal_matches_verified_blocks(message: &Proposal, quorum: &TempQuorum) -> bool {
    message.body.approved_blocks.as_ref() == Some(&quorum.verified_blocks())
        && message.body.approved_hash == quorum.verified_blocks_hash
}

fn activate_pending_proposals(quorum: &mut TempQuorum) {
    let matching_senders = quorum
        .pending_proposals
        .iter()
        .filter_map(|(sender, proposal)| {
            proposal_matches_verified_blocks(proposal, quorum).then_some(*sender)
        })
        .collect::<Vec<_>>();
    for sender in matching_senders {
        if let Some(proposal) = quorum.pending_proposals.remove(&sender) {
            quorum.proposals.record(proposal);
        }
    }
}

fn activate_pending_true_commits(quorum: &mut TempQuorum, required_signatures: usize) {
    if quorum.proposals.consensus() != Some(true) {
        return;
    }
    let pending = std::mem::take(&mut quorum.pending_commits);
    for message in pending.into_values() {
        record_commit_vote(quorum, message, required_signatures);
    }
}

impl MessageReceipt {
    fn accepted(kind: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            accepted: true,
        }
    }
}

/// Creates a root-group genesis epoch from public node identities.
pub fn genesis_epoch(nodes: impl IntoIterator<Item = NodeIdentity>) -> Epoch {
    genesis_epoch_for_group_with_parameters(
        ConsensusGroupId::root(),
        nodes,
        ConsensusParameters::default(),
    )
}

/// Creates a genesis epoch for an explicit consensus group.
pub fn genesis_epoch_for_group(
    group_id: ConsensusGroupId,
    nodes: impl IntoIterator<Item = NodeIdentity>,
) -> Epoch {
    genesis_epoch_for_group_with_parameters(group_id, nodes, ConsensusParameters::default())
}

/// Creates a genesis epoch with explicit committed consensus parameters.
pub fn genesis_epoch_for_group_with_parameters(
    group_id: ConsensusGroupId,
    nodes: impl IntoIterator<Item = NodeIdentity>,
    consensus_parameters: ConsensusParameters,
) -> Epoch {
    let mut verifiers = IndexTreeMap::new();
    for node in nodes {
        verifiers.insert(node.public_key(), node.public_only());
    }

    let mut epoch = Epoch {
        body: EpochBody {
            group_id,
            members: crate::membership::MemberSet::from_verifiers(&verifiers),
            verifiers,
            nonce: Nonce::new(0),
            consensus_parameters: Some(consensus_parameters),
            ..Default::default()
        },
        ..Default::default()
    };
    epoch.set_hash();
    epoch
}

#[cfg(test)]
mod tests;
