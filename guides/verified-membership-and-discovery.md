# Verified Membership and Discovery

This is the production contract for services such as Eden that use Blossom
membership without making every network participant a consensus validator.

## Identity and certified history

`SecKey` is signing material, not protocol state. It is non-`Copy`, has only
redacted `Debug`, and implements neither `Display` nor Serde/Borsh
serialization, and zeroizes its seed bytes on drop. Individual and batch
signature verification reject weak Ed25519 public keys. `NodeRuntime` extracts
a `SecretSigner` during construction and immediately converts its stored
`NodeIdentity` to public-only form. Epochs, snapshots, HA recovery manifests,
logs, wire messages, and status/debug output therefore contain only public
identity. Deployments still keep key loading and rotation in their secret
manager.

Verified catch-up uses `CertifiedEpochSuffix`, identified by an exact
`(anchor_hash, anchor_nonce)` pair. Use
`NodeRuntime::certified_epoch_suffix` to export a bounded suffix and
`NodeRuntime::catch_up_certified_suffix` to install it. Installation requires
the anchor to equal the local finalized tip and verifies, for every epoch:

- exact hash and nonce linkage;
- every block hash, signature, target, and previous-validator writer;
- the block Merkle root;
- the deterministic committed membership transition; and
- an exact-epoch-hash quorum certificate from the previous verifier set.

The genesis anchor is checked separately. Verified full-chain and uncertified
range replacement are rejected; trusted mode retains its application-managed
trusted recovery path.

## Network members and validators

`MemberSet` is hash-committed in every epoch and contains `MemberRecord` values
with `client`, `relay`, and `validator` capabilities plus an active, suspended,
or revoked status. `MemberOperation` provides explicit add, suspend, revoke,
and public-key rotation transitions. A validator stages one with
`NodeRuntime::stage_member_operation`; the operation becomes visible only
after the containing epoch is certified.

Only active records with the `validator` capability enter the consensus
verifier set. Registry add and key-rotation operations cannot grant
`validator`; new validator keys must pass the distinct-validator
supermajority `NodeAdmission` path. NAT-hidden clients and relays therefore do
not increase or bypass the consensus quorum.

Runtime snapshots bind the exact local public key and responsibility. Consensus
snapshots require the key in the current verifier set. Overlay snapshots require
an active committed Client, Relay or Validator capability; suspended, revoked,
absent or roleless records cannot own a recovered Overlay runtime. The existing
genesis, group, chain and certificate checks apply in both modes. Changing an
Overlay snapshot to Consensus does not turn a Client/Relay into a validator.
Retained snapshots preserve membership history, not a live forwarding lease:
after restart, install a newly verified quorum lease before admitting traffic.

## Signed service records

Remote discovery accepts `SignedServiceRecord`, not an unauthenticated
`Service`. Its signed body commits:

```text
group ID, owner public key, service kind, protocol/host/port,
generation, expiry, tombstone
```

`NodeRuntime::register_signed_service` verifies owner signature, group,
membership status, capability, lifetime, and monotonic generation before
mutating the address book. A relay endpoint requires the active `relay`
capability; a consensus endpoint requires `validator`. Removal uses a signed
tombstone with a higher generation. Records expire after their committed
deadline and may not request a lifetime longer than 24 hours.

The plain `register_service` API remains local configuration only. It is not a
remote admission or discovery protocol and never grants membership.

## Freshness and fail-closed forwarding

A certified epoch proves membership at a point in history, not that an
isolated relay still has the newest epoch. Relays must subscribe with:

```rust
let membership = runtime.watch_verified_membership();
```

The receiver carries `Arc<VerifiedMembershipView>`, including the group,
certified epoch hash and nonce, member and relay sets, and a monotonic
`valid_until`. A new epoch publishes an already-expired view. Validators sign
one fresh `MembershipLeaseStatement` per random challenge, including an
absolute signed issuance time and expiry; after the caller collects a
supermajority, `install_membership_lease` publishes the renewed view. Reusing
the same cached certificate cannot move `valid_until` forward, including
after reinstall. Signed service updates are published only while that exact
epoch lease is fresh and never extend the lease. If a published relay record
expires sooner, its signed deadline clamps `valid_until` so forwarding stops
promptly.

`MembershipLeaseRpcService` exposes lease vote and install operations through
an `ApplicationRequest` on the existing `TcpMultiGroupNode` listener; it does
not require another port. The signed request binds the requester identity,
routed group, exact epoch, challenge, and absolute expiry. The handler admits
only active members in that exact committed epoch, enforces the wire payload
bound, and keeps an independent per-group requester rate window. Expired rate
windows and anti-equivocation watermarks are reclaimed. Runtime snapshots
persist watermark expiries; older version-1 snapshots without the additive
expiry field retain their existing watermarks conservatively for one maximum
lease lifetime after restoration.

Every forwarding decision must call `VerifiedMembershipView::require_fresh`
and then check the required `client` or `relay` capability. Once
`valid_until` passes without quorum contact, forwarding stops. Do not cache a
positive authorization beyond the view lease.

## Deployment boundary

The verified membership APIs do not replace transport security. Public
deployments must use key-bound peer authentication (mTLS or Noise/QUIC),
connection and concurrency limits, connect/read/write deadlines,
request-specific payload limits, rate limiting, crash-safe persistence, and
anti-equivocation signing watermarks. Blossom bounds wire payloads, fsyncs its
file-backed snapshots and parent directory, and persists membership-lease
watermarks in runtime snapshots. The isolated HA transport additionally
provides configurable deadlines and connection limits.

The HA shared-HMAC profile remains a trusted crash-fault protocol: any member
with the cluster key is inside that trust boundary, and payloads are not
encrypted. A private mTLS sidecar may supply confidentiality, per-node
authentication, and rate limiting, but it is a required part of the production
deployment boundary when those properties are not implemented by the
embedding service.
