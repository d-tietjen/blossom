# Operations

## Runtime Persistence

`blossom-node` supports committed runtime snapshots and durable verified block
storage:

- `BLOSSOM_STATE_SNAPSHOT`
- `BLOSSOM_BLOCK_STORE`
- `BLOSSOM_BOOTSTRAP_SERVICES`

The node can sync bootstrap address-book metadata, but reachability metadata
does not change validator membership.

## TCP Wire Surface

The TCP server accepts sequential length-prefixed request frames on a persistent
connection, with one in-flight exchange per connection:

```text
u32 big-endian payload length
Borsh-encoded WireRequest
```

Responses use the same frame shape with `WireResponse`.

`TcpServiceClient` and the one-shot TCP helpers bound a whole request to thirty
seconds by default, including connection and response I/O. A pooled client's
`with_request_timeout` accepts an explicit nonzero total budget, including
waiting for a pool slot and identical-frame reconnect retries. Choose this
budget below the embedding application's lease/deadline. A timeout means the
remote result is unknown: preserve the operation identifier and reconcile
committed state before retrying a mutation.

An in-flight `TcpConnection` exchange owns its socket. Cancellation or an I/O
error closes the socket; the pool reconnects before reusing that destination.
Consensus and overlay broadcasts own their concurrent futures, so cancelling
a broadcast closes its in-flight exchanges without leaving detached requests.
Manual users of `TcpConnection::connect` still supply their own enclosing
deadline; that low-level constructor does not install a request policy.

Pool admission is part of the request budget. The generic six-connection pool
does not guarantee quorum progress for a wider validator set: six stalled peers
can occupy every slot before later healthy destinations are contacted. Size
`with_max_connections` for the admitted validator set and concurrent rounds,
and check the deployment's aggregate descriptor/memory limits. Deadlines bound
resource use; they do not reserve enough capacity for quorum by themselves.

`NodeRuntime::try_new` uses a separate four-slot internal broadcast/prefill
pool. `NodeRuntime::try_new_with_network_client` lets an embedding application
provide its own bounded pool and timeout before starting work. Configuring only
`TcpNode` does not change that internal pool. The generic thirty-second default
supports slower verified multi-round workloads; lease-based services must
select an explicit shorter budget for both clients rather than inherit it.

Important requests include `Health`, `Ping`, `State`, `EpochChain`,
`CertifiedEpochSuffix`, `AddressBook`, `RegisterService`, `Group`, `NextNonce`,
`SubmitBlock`, `Dispatch`, `PrefillDispatch`, `Message`, `SendNonce`,
`BlockNonce`, `GetBlock`, and `SendBlock`. Verified catch-up uses only the
anchor-bound, certificate-validated `CertifiedEpochSuffix`; the weaker
`EpochChainRange` protocol is not retained.

## Telemetry

`TelemetrySink` implementations emit stage progress, spans, dropped-node events,
reconnect events, block-flow metrics, and errors. `blossom-observer` collects
JSONL telemetry and analyzes distributed health across nodes.

Production services can enable the `observability` feature to fan the same
events into bounded `fast-telemetry` metrics/spans and structured
`eden-logger` records. The service owns exporter and global logger
initialization. See [Observability](observability.md) for setup and signal
coverage.

## Production Notes

Before public trustless deployment, operators should add deployment-specific key
management, monitoring, alerting, public-join abuse controls, and multi-host
soak testing.
