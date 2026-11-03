//! Blossom v2 consensus protocol.
//!
//! This crate contains the protocol messages, quorum selection, block
//! commitment, membership reducers, runtime service registry, TCP wire surface,
//! telemetry events, and block-intake primitives needed to build and test
//! Blossom nodes.
//!
//! Blossom is application-agnostic: transaction payload bytes and block-carried
//! application state are committed by the protocol but interpreted by the
//! application layer. Ledger, cache, database, and workflow integrations should
//! live above this crate.
//!
//! Start with [`NodeRuntime`] for consensus participation, [`OverlayRuntime`]
//! for topology-aware fan-out without epoch state, [`WireRequest`] for TCP
//! integration, and [`Transaction`] plus [`Block`] for application bytes.

#[cfg(feature = "active-active")]
/// Durable application-owned commands with globally certified ordering.
pub mod active_active;
#[cfg(feature = "high-availability")]
/// Crash-safe coordination between accepted lifecycle and global ordering.
pub mod active_active_coordinator;
#[cfg(feature = "high-availability")]
/// Recovery and contract-cutover orchestration for active-active HA groups.
pub mod active_active_ha;
#[cfg(feature = "active-passive")]
/// Native OpenRaft active-passive replication and durable log adapters.
pub mod active_passive;
/// Service records and the node-local address book.
pub mod address_book;
/// Signed node admission and reconnect evidence.
pub mod admission;
/// Quorum thresholds, deterministic selection, and topology calculations.
pub mod algorithm;
#[cfg(feature = "availability-gossip")]
/// Certified availability metadata and filtered-payload transfer.
pub mod availability;
/// Blocks, opaque transactions, commitments, and fair ordering.
pub mod block;
/// Durable block indexing by nonce and hash.
pub mod block_store;
/// Consensus protocol messages and their validation rules.
pub mod blossom;
/// Public keys, signing keys, signatures, and verification helpers.
pub mod crypto;
/// Signed peer-encounter evidence.
pub mod encounter;
/// Crate-wide errors and the [`Result`] alias.
pub mod error;
/// Consensus group identifiers.
pub mod group;
/// In-process test and benchmark harnesses.
pub mod harness;
/// Protocol hashes, domains, and feature registry.
pub mod hash;
#[cfg(feature = "high-availability")]
/// Trusted fixed-membership HA consensus for two through seven nodes.
pub mod high_availability;
/// Latency relationships and topology-aware peer selection.
pub mod latency_topology;
/// Node-local block construction and bounded pending queues.
pub mod local_block;
/// Transactional embedded persistence backed by ShardLog.
pub mod log_store;
/// Validator membership, service capabilities, and freshness certificates.
pub mod membership;
/// Authenticated membership-lease RPCs carried by the existing TCP listener.
pub mod membership_transport;
/// The top-level consensus message enum and stable message keys.
pub mod messages;
/// Public node identity and node-role types.
pub mod node;
/// Monotonic epoch nonces.
pub mod nonce;
/// Topology fan-out without consensus epoch ownership.
pub mod overlay;
#[cfg(feature = "parallel-networks")]
/// Coordination records for independent HA and Global Blossom networks.
pub mod parallel_networks;
#[cfg(any(
    feature = "propagation-adaptive",
    feature = "propagation-inventory",
    feature = "propagation-push"
))]
/// Feature-gated latency, bandwidth, and adaptive data-plane policies.
pub mod propagation;
/// Per-round message matrices and quorum queues.
pub mod register;
/// Certified round skipping and future-round assistance.
pub mod round_skip;
/// The embeddable verified and trusted node runtime.
pub mod runtime;
/// Site-aware committee layout and safety manifests.
pub mod safety;
/// Typed TCP service-client operations.
pub mod service_client;
/// Epoch chains and in-progress consensus state.
pub mod state;
#[cfg(feature = "availability-gossip")]
/// Subset-gossip and prefill propagation models.
pub mod subset_gossip;
/// TCP nodes, drivers, and connection helpers.
pub mod tcp;
/// Structured protocol telemetry and optional exporters.
pub mod telemetry;
#[cfg(feature = "trusted-checkpoint-dag")]
/// Append-only dissemination beneath trusted sequential checkpoints.
pub mod trusted_dag;
/// Crash-safe trusted epoch and confirmation storage.
pub mod trusted_log;
/// Bounded Borsh wire frames and optimized hot-path codecs.
pub mod wire;

#[cfg(feature = "active-active")]
pub use active_active::{
    ActiveActiveCommand, ActiveActiveConsistencyMode, ActiveActiveDurabilityMetrics,
    AdmissionBatchReceipt, AdmissionBatchReceiptBody, AdmissionReceipt, AdmissionReceiptBody,
    AdmittedCommand, ApplicationCommand, ApplicationCommandEnvelope, ApplicationContractActivation,
    ApplicationResult, AppliedBy, AppliedByTracker, AppliedCompletion, ApplyProgress,
    AuthenticatedAvailabilityReceipt, AvailabilityCertificate, AvailabilityReceiptBody,
    AvailabilityTrust, BatchReference, BatchReferenceMetadata, CertifiedReadBarrier, ClientEpoch,
    ClientId, CommandBatch, CommandIdentity, CommandSpecVersion, CommitteeTransitionActivation,
    CommitteeTransitionCertificate, CommitteeTransitionStatement, CommitteeTransitionVote,
    DurableAdmissionStore, GlobalOrderedEngine, HolderMembership, LocalAdmissionBatchCertificate,
    LocalAdmissionCertificate, LocalAdmissionPolicy, MAX_ACTIVE_ACTIVE_SHARD_ID_BYTES,
    MAX_APPLICATION_COMMAND_BYTES, MAX_APPLICATION_RESULT_BYTES,
    MAX_PIPELINED_AVAILABILITY_WINDOWS, MAX_REFERENCES_PER_ORDERING_WINDOW, MAX_WAIT_FOR_TIMEOUT,
    MembershipCutoverDisposition, Milestone, MilestoneEvent, OrderCertificate, OrderStatement,
    OrderVote, OrderedApplication, OrderedBatch, ReadBarrierCertificate, ReadBarrierChallenge,
    ReadBarrierRequest, ReadBarrierStatement, ReadBarrierVote, ReadConsistency, ReferenceStatus,
    ReplicaMembershipEpoch, RetentionEvidence, RouteGeneration, StoreGeneration,
    ValidatorGeneration, VerifiedLocalAdmissionBatch, WaitForOutcome, Watermark, WriteMode,
    ordered_batch_references, ordered_batch_references_trusted, required_cutover_disposition,
};
#[cfg(feature = "high-availability")]
pub use active_active_coordinator::{
    ActiveActiveCoordinatorDurability, ActiveActiveGlobalCoordinator,
};
#[cfg(feature = "high-availability")]
pub use active_active_ha::{
    ACTIVE_ACTIVE_HA_CUTOVER_MANIFEST_VERSION, ACTIVE_ACTIVE_HA_RECOVERY_MANIFEST_VERSION,
    AcceptedWriteDisposition, AcceptedWriteRecord, AcceptedWriteResolution, ActiveActiveCutover,
    ActiveActiveHaCutoverManifest, ActiveActiveHaEngine, ActiveActiveHaLifecycleDurabilityMetrics,
    ActiveActiveHaRecoveryManifest, ActiveActiveHaRecoveryStatus, LearnerCatchUp,
    MAX_ACCEPTED_WRITE_ABORT_REASON_BYTES, MAX_ACTIVE_ACTIVE_HA_ACCEPTED_COMMAND_BYTES,
    MAX_ACTIVE_ACTIVE_HA_ACCEPTED_WRITES, MAX_ACTIVE_ACTIVE_HA_SHARD_LANES,
    PreparedActiveActiveHaShardBatch,
};
#[cfg(feature = "active-passive")]
pub use active_passive::{
    ActivePassiveClientWriteRaftError, ActivePassiveClientWriteResponse, ActivePassiveCommand,
    ActivePassiveContract, ActivePassiveContractChange, ActivePassiveInitializeError,
    ActivePassiveInitializeRaftError, ActivePassiveLinearizableReadError,
    ActivePassiveMembershipError, ActivePassiveNode, ActivePassiveNodeId,
    ActivePassiveOperationalStatus, ActivePassiveRaft, ActivePassiveRaftConfig,
    ActivePassiveRequest, ActivePassiveResponse, ActivePassiveRuntime, ActivePassiveStartError,
    ActivePassiveWriteError, MemoryRaftLogStore, RaftLogStoreIdentity, ShardStreamRaftLogStore,
};
pub use address_book::{
    AddressBook, MAX_SERVICE_HOST_BYTES, MAX_SERVICE_PROTOCOL_BYTES,
    MAX_SERVICE_RECORD_LIFETIME_MILLIS, Service, ServiceKind, ServiceRecordBody,
    SignedServiceRecord,
};
pub use admission::{
    NODE_ADMISSION_DOMAIN, NodeAdmission, NodeAdmissionBody, RECONNECT_VOTE_DOMAIN, ReconnectVote,
    ReconnectVoteBody,
};
pub use algorithm::{
    BLOSSOM_QUORUM_SIZE_ENV, CONSENSUS_PARAMETERS_VERSION, ConsensusParameters, QUORUM_SIZE,
    QuorumSize, SUPERMAJORITY, byzantine_fault_bound, distinct_current_validator_count,
    find_round_number_with_size, has_distinct_supermajority, has_supermajority,
    max_liveness_omissions, min_supermajority_intersection, select_prefill_recipients,
    select_prefill_recipients_with_size, select_quorums, select_quorums_from_index_tree_with_size,
    select_quorums_with_size, supermajority_count, supermajority_has_honest_overlap,
    supermajority_order_statistic,
};
#[cfg(feature = "availability-gossip")]
pub use availability::{
    AvailabilityEntry, AvailabilityGossip, AvailabilityGossipBody, AvailabilityReceipt,
    AvailabilityStore, FILTERED_PAYLOAD_MAX_BYTES, FilteredPayloadBatchDelivery,
    FilteredPayloadBatchDeliveryBody, FilteredPayloadBatchFetch, FilteredPayloadBatchFetchBody,
    FilteredPayloadDelivery, FilteredPayloadDeliveryBody, FilteredPayloadDeliveryItem,
    FilteredPayloadFetch, FilteredPayloadFetchBody, FilteredPayloadMissing, FilteredPayloadRequest,
    LocalFilteredPayload, ideal_push_gossip_delay_ms, ideal_push_gossip_rounds,
    validate_filtered_payload,
};
pub use block::{
    BLOCK_APPLICATION_STATE_MAX_BYTES, BLOCK_APPLICATION_STATE_SOFT_LIMIT_BYTES, Block,
    BlockApplicationState, BlockBody, Transaction, TransactionPayload,
};
#[cfg(feature = "filtered-transactions")]
pub use block::{FilteredDeliveryPolicy, FilteredPayloadView, FilteredTransactionSlot};
#[cfg(feature = "fair-block-ordering")]
pub use block::{
    fair_block_order_key, fair_block_order_seed, fair_order_transaction_count,
    fair_ordered_block_commitments, fair_ordered_blocks,
};
pub use block_store::{BlockHandle, BlockIndex, BlockRecord, DurableBlockStore};
pub use blossom::*;
pub use crypto::{Keypair, PubKey, SecKey, SecretSigner, Signature, verify_batch};
pub use encounter::{
    ENCOUNTER_RECORD_DOMAIN, ENCOUNTER_RECORD_ENCODED_LEN, EncounterOutcome, EncounterPhase,
    EncounterRecord, EncounterRecordBody,
};
pub use error::{BlossomError, Result};
pub use group::ConsensusGroupId;
pub use harness::{MockBlockService, SimulatedCluster, SimulatedNode, signed_block};
pub use hash::{
    DoHash, FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE, FAIR_BLOCK_ORDERING_PROTOCOL_FEATURE_CODE,
    HIGH_AVAILABILITY_PROTOCOL_FEATURE, HIGH_AVAILABILITY_PROTOCOL_FEATURE_CODE, HashType,
    PROTOCOL_FEATURE_CODE_VERSION, PROTOCOL_FEATURE_CODES, PROTOCOL_FEATURE_REGISTRY,
    ProtocolConsensusSurface, ProtocolFeatureCode, ProtocolFeatureRegistryEntry,
    RESERVED_PROTOCOL_FEATURE_CODE, SHA256_PROTOCOL_HASH_ALGORITHM, XXH3_PROTOCOL_HASH_ALGORITHM,
    protocol_feature_code_bytes, protocol_feature_registry_entry, protocol_hash_algorithm,
    protocol_hash_algorithm_is_compatible, validate_protocol_feature_codes,
    validate_protocol_feature_registry,
};
#[cfg(feature = "high-availability")]
pub use high_availability::*;
pub use indextreemap::{IndexTreeMap, SharedIndexTreeMap};
pub use latency_topology::{
    ClosestPeer, LatencyEstimate, LatencyEstimateMethod, LatencyRelationship, LatencyTopology,
    LatencyTopologyConfig, LatencyTopologyMetadataV1, unix_time_millis,
};
pub use local_block::LocalBlock;
pub use log_store::{
    BLOSSOM_LOG_STORE_FORMAT_VERSION, BlossomLogCheckpointReceipt, BlossomLogCommitReceipt,
    BlossomLogDurabilityMetrics, BlossomLogEntry, BlossomLogSnapshot, BlossomLogStore,
    BlossomLogStoreConfig, BlossomLogStoreIdentity, BlossomLogTransaction,
};
pub use membership::{
    CommittedMemberOperation, ConsensusNodeAdmissionPlan, ConsensusNodeRemovalDecision,
    ConsensusNodeRemovalPlan, ConsensusNodeRemovalPolicy, MAX_MEMBERSHIP_LEASE_MILLIS,
    MemberCapability, MemberOperation, MemberRecord, MemberSet, MemberStatus,
    MembershipLeaseCertificate, MembershipLeaseChallenge, MembershipLeaseRequest,
    MembershipLeaseStatement, MembershipLeaseVote, RelaySet, VerifiedMembershipView,
    apply_committed_member_operations, apply_consensus_node_admission_plan,
    apply_consensus_node_removal_plan, apply_epoch_member_registry_transition,
    apply_epoch_membership_transition, derive_consensus_node_admission_plan,
    derive_consensus_node_removal_plan,
};
pub use membership_transport::{
    MEMBERSHIP_LEASE_RPC_KIND, MEMBERSHIP_LEASE_RPC_MAX_PAYLOAD_BYTES,
    MembershipLeaseInstallRequest, MembershipLeaseRpc, MembershipLeaseRpcResponse,
    MembershipLeaseRpcService, MembershipLeaseVoteRequest,
};
pub use messages::{MSGKey, Msg};
pub use node::{NodeIdentity, NodeType};
pub use nonce::Nonce;
pub use overlay::{BroadcastReceipt, BroadcastReport, FanOutStrategy, OverlayRuntime};
#[cfg(feature = "parallel-networks")]
pub use parallel_networks::{
    HA_GROUP_STATE_REFERENCE_VERSION, HaGroupRegistration, HaGroupStateReference,
    HaGroupStateReferenceBody, PARALLEL_NETWORK_SNAPSHOT_VERSION, ParallelNetworkCoordinator,
    ParallelNetworkEvent, ParallelNetworkSnapshot, ParallelNetworkStatus,
};
pub use register::{MessageMatrix, QuorumQueue, Status};
pub use round_skip::{
    DataDisseminationManifest, DataDisseminationManifestValidation, FutureRoundAssistDecision,
    FutureRoundAssistInput, FutureRoundAssistKind, RoundSkipCertificate,
    RoundSkipCertificateValidation, RoundSkipVote, future_round_assist_decision,
    skipped_round_assist_decision,
};
pub use runtime::{
    AcceptedBlock, ConsensusRoundStatus, EpochDisseminationStatus, EpochTarget, MessageReceipt,
    MultiGroupRuntime, NodeRuntime, NodeStatus, ObservedEncounterRecord, PeerApplicationState,
    PrefillDispatchBroadcastReport, PrefillDispatchPlan, PrefillStageStatus,
    ReconnectAdmissionDecision, ReconnectAdmissionEvidence, RuntimeConfig, RuntimeMode,
    RuntimeSnapshotV1, TrustMode, TrustedOperationalStatus, TrustedServiceHealth, genesis_epoch,
    genesis_epoch_for_group, genesis_epoch_for_group_with_parameters,
};
pub use safety::{
    CommitteeLayout, CommitteeParticipant, SafetyManifest, SiteId, generate_safety_manifest,
    select_site_balanced_committee,
};
pub use service_client::{TcpServiceClient, TimedNodePong};
pub use state::{
    CERTIFIED_EPOCH_SUFFIX_VERSION, CertifiedEpochSuffix, DEFAULT_MAX_PENDING_RAW_DISPATCH_BYTES,
    DEFAULT_MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER, Epoch, EpochBody, EpochChain, EpochNonce,
    LocalState, MAX_CERTIFIED_EPOCH_SUFFIX, MAX_PENDING_RAW_DISPATCH_BYTES_ENV,
    MAX_PENDING_RAW_DISPATCH_BYTES_PER_SENDER_ENV, PendingDispatch, PrefillDispatchRecord,
    TempConsensus, TempQuorum, TrustedOrderedTransaction,
    configured_max_pending_raw_dispatch_bytes,
    configured_max_pending_raw_dispatch_bytes_per_sender,
};
#[cfg(feature = "availability-gossip")]
pub use subset_gossip::{
    SubsetGossipConfig, SubsetGossipEpochRow, SubsetGossipProtocolVersion, SubsetGossipReport,
    SubsetLatencyDistribution, SubsetLatencyProfile, SubsetPrefillMode, run_subset_gossip,
    run_subset_gossip_v1, run_subset_gossip_v2,
};
pub use tcp::{
    ApplicationHandler, ApplicationHandlerFuture, ConsensusDriverConfig, ConsensusDriverTick,
    DEFAULT_TCP_REQUEST_TIMEOUT, MultiGroupApplicationHandler, TcpConnection, TcpMultiGroupNode,
    TcpNode, TcpNodeMetrics, TcpNodeMetricsSnapshot, send_wire_frame, send_wire_request,
    send_wire_request_raw_response,
};
#[cfg(feature = "eden-logger")]
pub use telemetry::EdenLoggerTelemetrySink;
#[cfg(feature = "telemetry")]
pub use telemetry::{
    BlossomTelemetryMetrics, BlossomTelemetryMetricsSnapshot, FastTelemetryRegistration,
    FastTelemetrySink,
};
pub use telemetry::{
    FanoutTelemetrySink, InMemoryTelemetrySink, JsonlTcpTelemetrySink, JsonlTcpTelemetrySinkConfig,
    NoopTelemetrySink, TELEMETRY_SCHEMA_VERSION, TelemetryEvent, TelemetryEventKind,
    TelemetryHandle, TelemetrySeverity, TelemetrySink,
};
#[cfg(feature = "trusted-checkpoint-dag")]
pub use trusted_dag::{
    MIN_GLOBAL_BLOSSOM_PARTICIPANTS, SequentialQuorumDagReport, TrustedCheckpointDag,
    TrustedDagCandidate, TrustedDagCandidateBody, TrustedDagCheckpoint, TrustedDagCheckpointBody,
    TrustedDagFrontierEntry, TrustedDagIngestOutcome, TrustedDagRoundCompletion,
    TrustedDagRoundLock, TrustedDagVertex, TrustedDagVertexBody,
    run_sequential_quorum_dag_experiment,
};
pub use trusted_log::{
    TrustedFailureAssessment, TrustedFailureClass, TrustedLogHead, TrustedRoundId,
    TrustedServiceDirective, assess_trusted_durability_failure,
};
pub use wire::{
    AddressBookUpdate, ApplicationRequest, ApplicationResponse, EncodedFrame, FRAME_PREFIX_BYTES,
    FRAME_WRITE_CHUNK_BYTES_ENV, HOT_WIRE_CODEC_ENV, HotDispatch, NodeHealth, NodePing, NodePong,
    ServiceRegistration, WireRequest, WireRequestFrame, WireResponse,
    configured_frame_write_chunk_bytes, configured_max_frame_size, decode_wire_request_frame,
    decode_wire_request_payload, decode_wire_response_payload, encoded_len, framed_len,
    hot_dispatch_response_into_request_frame, hot_dispatch_response_to_request_frame,
    hot_wire_codec_enabled, hot_wire_request_framed_len, hot_wire_response_framed_len,
    read_encoded_frame, read_frame, read_wire_request, read_wire_request_frame,
    read_wire_request_frame_optional, read_wire_response, wire_request_framed_len,
    wire_response_framed_len, write_encoded_frame, write_frame, write_wire_request,
    write_wire_response,
};
