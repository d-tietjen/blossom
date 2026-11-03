# Changelog

All notable changes to Blossom are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Blossom uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html) for its
public Rust APIs and separately versions consensus and durable wire formats.

## [Unreleased]

### Added

- Authenticated membership-lease vote and install RPCs can share the existing
  group-routed TCP listener. Requests bind the requester, group, epoch,
  challenge, and absolute expiry, with bounded payloads and independent
  per-group requester rate limits.
- Globally ordered active-active engines can install holder and validator
  replacements certified by an old-validator supermajority. Transition votes
  are durably non-equivocating, activation is restricted to a quiescent
  globally-applied boundary, and the full certificate history is replayed on
  restart before historical order certificates are accepted.

### Fixed

- Overlay Client and Relay runtime snapshots now recover against their active
  committed member identity without requiring validator membership. Consensus
  snapshots retain validator ownership checks; inactive or absent Overlay keys
  remain rejected, and recovery does not restore a fresh membership lease.

- TCP service requests now have a bounded total deadline. Interrupted framed
  exchanges close their socket instead of returning a partial or late reply
  to the pool, and cancelled consensus/overlay broadcasts retain ownership of
  every pending request rather than detaching transport tasks.

- Membership-lease anti-equivocation and RPC rate-limit state now expires and
  is reclaimed instead of growing for the lifetime of the process. Snapshot
  restoration remains backward compatible and conservatively ages legacy
  watermarks for one maximum lease lifetime.
- Topology-only runtimes now reject the generic application-transaction
  submission entry point consistently with the other consensus APIs.
- The HA isolation gate recognizes that the `high-availability` feature
  intentionally enables the feature-gated active-active API.

## [2.0.0] - 2026-07-28

### Added

- Durable active-active accepted-write and cutover lifecycle storage backed by
  the shared ShardLog implementation.
- Sharded lifecycle group admission, complete-batch holder receipts,
  membership-bound admission certificates, accepted-hash lookup, and grouped
  application completion.
- `ActiveActiveGlobalCoordinator` for crash-safe lifecycle/order cutovers and
  `GlobalApplied` cleanup only after durable application.
- Production durability inspection for lifecycle, HA runtime, admission, and
  ordered completion stores.
- Native global-ordered, trusted active-active, and OpenRaft active-passive
  profiles behind explicit feature and runtime boundaries.
- Opaque application commands and results, bounded `status` and `wait_for`,
  terminal `Applied` completion, and the optional `GlobalApplied` write mode.
- Consensus-certified fresh read barriers for partition-safe linearizable
  reads.
- Certified epoch suffix catch-up with genesis, chain, block, Merkle-root,
  membership-transition, and previous-verifier validation.
- A committed member registry separating `client`, `relay`, and `validator`
  capabilities, with add, revoke, suspend, and key-rotation operations.
- Signed, expiring, generation-monotonic relay records and fail-closed verified
  membership leases with efficient membership subscriptions.
- Active-active learner catch-up, contract-aware cutover, activation,
  accepted-write recertification or abort, recovery status, and signed
  manifests.
- Active-passive learners, joint-consensus membership changes, snapshots,
  linearizable reads, and application-defined state-machine integration.
- Public transactional `BlossomLogStore` storage, backed by the standalone
  `shardlog` crate, for active-active, trusted epochs, HA, OpenRaft, and
  application state.
- Certified HA history compaction and checkpoint-bound reactivation evidence.
- Configurable network deadlines, connection limits, request bounds, signed
  watermarks, and crash-safe durable recovery.
- A multi-core OpenRaft production campaign runner with stable, message-aware
  request/response fault IDs and explicit fault-coverage admission.
- Regression coverage for ordinary append catch-up after partition healing,
  snapshot installation, leader transitions, certified epoch dissemination,
  and large TCP driver clusters.

### Changed

- The crates.io package is named `blossom-consensus`; its Rust library name
  remains `blossom`.
- Active-active application ordering and propagation policies are
  feature-gated modules within the single public `blossom-consensus` package.
  Observer and benchmark packages are non-publishable repository tooling.
- Rust 1.93 is the minimum supported Rust version for every profile.
- `BatchReference` format and codec version 2 commit the route generation and
  application command-spec version.
- Secret signing material is memory-only and excluded from durable identities,
  snapshots, logs, wire messages, and unrestricted formatting.
- Active-passive and active-active durability now share the embedded ShardLog
  backend. Earlier development redb files are an explicit reset or certified
  recovery boundary and are never overwritten.
- Final-round commit shares are collected by a deterministic bounded committee
  into a certificate signed by a supermajority of the complete validator set.

### Fixed

- HA production validation rejects empty test filters, exercises the modular
  durability and transport tests by their complete paths, and serializes the
  linker-heavy Hegel target on shared runners. The release gate reclaims
  obsolete package-profile artifacts before HA qualification to stay within
  hosted-runner disk limits.
- Parallel durability fault tests use collision-free temporary store IDs.
- OpenRaft 0.9.25 handles a transient empty log-range read during leadership
  changes without panicking a replication worker.
- Verified 24-node and 36-node epochs are published to a validator
  supermajority through authenticated epoch hints and certified suffix
  catch-up. Prefill runs before ordinary dispatch and retains its exact signed
  message until every routed recipient acknowledges it, preventing accepted
  writer blocks from being replaced by empty prefill blocks. Exact dispatch
  replay is idempotent, conflicting replay is rejected, and final-certificate
  shares remain retryable after incomplete broadcasts. Consensus driver ticks
  are bound to the epoch target on which they began, so an in-flight tick
  cannot resume after finalization and seal an empty dispatch for the next
  epoch. Late application admission after a local dispatch is sealed now fails
  closed. The native validation adapter rechecks every activation barrier
  after a complete cluster-wide prefill wave, preventing a validator whose
  last required dispatch arrived late in that wave from remaining in round
  zero. Verified verification and proposal broadcasts retry their exact signed
  messages after incomplete delivery. Verified finality validation now applies
  its timeout to inactivity, refreshing the deadline when signed round
  progress is observed, as the trusted validator already did. Each epoch hint
  is retried only to validators that have not acknowledged it, and hints for an
  unknown newer head no longer fail the current-target envelope check.
- Healed OpenRaft replicas now resume ordinary append replication even when
  the first post-heal heartbeat discovers a newer term.
- Active-passive client writes retry the same idempotent command across
  transient leader transitions, including `ForwardToLeader(None)`.
- Idle consensus-driver recovery assessment now materializes the deterministic
  round instead of failing with `UnknownSender`.
- Test driver failures are reported to their parent test, large TCP cases are
  serialized, and benchmark Raft nodes shut down as one cluster operation.
- Membership lease certificates commit an absolute issuance time and expiry,
  so reinstalling cached evidence cannot renew an isolated node. Published
  relay expiry also clamps the verified view's forwarding deadline.
- Normal member-registry add and key-rotation operations can no longer grant
  validator authority; new validator keys require certified supermajority
  `NodeAdmission` evidence.
- Secret-key seeds zeroize on drop, and both individual and batch Ed25519
  verification reject weak public keys.
- HA production validation scopes filtered unit and soak runs to the library
  target, avoiding redundant late-stage linker pressure without dropping the
  dedicated HA integration suite.

### Removed

- The closed `BlindWrite`/`Append`/`CompareAndSwap` command model and the
  duplicate internal application state machine.
- `EpochChainRange`; `CertifiedEpochSuffix` is the stronger catch-up contract.
- The global-ordered profile's non-terminal `Sealed`/`Converged` completion
  model.
- Direct Blossom dependencies on `shard-stream-core`,
  `shard-stream-storage`, and redb.

[Unreleased]: https://github.com/d-tietjen/blossom/compare/v2.0.0...HEAD
[2.0.0]: https://github.com/d-tietjen/blossom/releases/tag/v2.0.0
