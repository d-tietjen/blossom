//! Native single-proposer progress with independently owned grouped listeners.

use std::time::Duration;

use blossom::{
    ConsensusDriverConfig, ConsensusGroupId, MultiGroupRuntime, NodeIdentity, NodeRuntime, Nonce,
    RuntimeConfig, RuntimeSnapshotV1, Service, ServiceKind, TcpMultiGroupNode, TcpNode,
    TcpServiceClient, Transaction, genesis_epoch_for_group,
};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Abort all listeners/drivers on success or assertion failure.
struct Tasks(Vec<JoinHandle<()>>);

impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// A failed durable write retains the exact transaction and sealed candidate.
#[test]
fn block_store_failure_does_not_discard_pending_application_work() {
    let storage = tempfile::tempdir().expect("fixture");
    let directory = storage.path().join("blocks");
    let backup = storage.path().join("backup");
    let identity = NodeIdentity::generate("tcp", "127.0.0.1", 30001);
    let mut config = RuntimeConfig::new(identity);
    config.block_store_path = Some(directory.clone());
    let runtime = NodeRuntime::try_new(config).expect("runtime");
    let transaction = Transaction::new("retained through a real filesystem error");
    let hash = transaction.hash;
    runtime.submit_transaction(transaction).expect("submit");
    std::fs::rename(&directory, &backup).expect("fence block directory");
    std::fs::write(&directory, b"not a directory").expect("inject storage failure");
    assert!(runtime.dispatch_local_block(0).is_err());
    assert_eq!(runtime.status().expect("still pending").pending_blocks, 1);
    std::fs::remove_file(&directory).expect("remove fault");
    std::fs::rename(&backup, &directory).expect("restore store");
    let dispatch = runtime
        .dispatch_local_block(0)
        .expect("retry exact candidate");
    let transactions = dispatch
        .body
        .blocks
        .values()
        .flat_map(|block| &block.body.txs)
        .collect::<Vec<_>>();
    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].hash, hash);
    let block = dispatch.body.blocks.values().next().expect("block");
    assert_eq!(
        runtime
            .durable_block_by_nonce(Nonce(1))
            .expect("durable")
            .expect("stored")
            .hash,
        block.hash
    );
}

/// Later rounds cannot consume a request queued after round zero sealed.
#[test]
fn later_round_leaves_new_transactions_pending_for_the_next_epoch() {
    let identity = NodeIdentity::generate("tcp", "127.0.0.1", 30002);
    let runtime = NodeRuntime::try_new(RuntimeConfig::new(identity)).expect("runtime");
    runtime
        .submit_transaction(Transaction::new("epoch one"))
        .expect("first");
    runtime.dispatch_local_block(0).expect("seal first round");
    let next = Transaction::new("next epoch request");
    let next_hash = next.hash;
    runtime.submit_transaction(next).expect("late request");
    let later = runtime.dispatch_local_block(1).expect("later round");
    assert!(
        !later
            .body
            .blocks
            .values()
            .flat_map(|block| &block.body.txs)
            .any(|tx| tx.hash == next_hash)
    );
    assert_eq!(
        runtime
            .status()
            .expect("pending next request")
            .pending_blocks,
        1
    );
}

/// A request-driven five-node group must commit real work without idle churn.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_proposer_commits_without_peer_dummy_transactions_or_idle_epochs() {
    let storage = tempfile::tempdir().expect("private fixture");
    let mut listeners = Vec::new();
    let mut identities = Vec::new();
    for _ in 0..5 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        identities.push(NodeIdentity::generate(
            "tcp",
            "127.0.0.1",
            listener.local_addr().expect("address").port(),
        ));
        listeners.push(listener);
    }
    let group = ConsensusGroupId::named("request-driven-single-proposer-regression");
    let genesis = genesis_epoch_for_group(group, identities.iter().cloned());
    let mut runtimes = Vec::new();
    let mut tasks = Tasks(Vec::new());
    for (index, (identity, listener)) in identities.iter().cloned().zip(listeners).enumerate() {
        let mut config = RuntimeConfig::for_group(identity, group);
        config.genesis = Some(genesis.clone());
        config.snapshot_path = Some(storage.path().join(format!("member-{index}.json")));
        config.block_store_path = Some(storage.path().join(format!("blocks-{index}")));
        config
            .address_book
            .extend_services(identities.iter().map(|peer| {
                Service::new(
                    ServiceKind::Consensus,
                    peer.public_key(),
                    "tcp",
                    peer.host.clone(),
                    peer.port,
                )
            }));
        let client = || {
            TcpServiceClient::new()
                .with_request_timeout(Duration::from_secs(2))
                .expect("bounded requests")
                .for_group(group)
        };
        let runtime = NodeRuntime::try_new_with_network_client(config, client()).expect("runtime");
        let listener_node = TcpMultiGroupNode::new(MultiGroupRuntime::new(runtime.clone()));
        tasks.0.push(tokio::spawn(async move {
            listener_node.serve(listener).await.expect("serve");
        }));
        let driver = TcpNode::with_services(runtime.clone(), client());
        tasks.0.push(tokio::spawn(async move {
            driver
                .run_consensus_driver(ConsensusDriverConfig {
                    event_driven: true,
                    require_local_pending_block: true,
                    continue_after_error: true,
                    ..Default::default()
                })
                .await
                .expect("driver");
        }));
        runtimes.push(runtime);
    }
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert!(
        runtimes
            .iter()
            .all(|runtime| runtime.status().expect("idle").last_epoch_nonce == Nonce(0))
    );
    for nonce in 1..=2 {
        // Only ordinal zero submits application work. Other nodes contribute
        // the protocol's normal signed empty blocks, never dummy transactions.
        let transaction = Transaction::new(format!("single real request {nonce}"));
        let hash = transaction.hash;
        runtimes[0]
            .submit_transaction(transaction)
            .expect("one submission");
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if runtimes.iter().all(|runtime| {
                    runtime.status().expect("progress").last_epoch_nonce >= Nonce(nonce)
                }) && (0..5).all(|index| {
                    RuntimeSnapshotV1::read_json(
                        storage.path().join(format!("member-{index}.json")),
                    )
                    .ok()
                    .and_then(|snapshot| {
                        snapshot
                            .epochchain
                            .epochchain
                            .last()
                            .map(|epoch| epoch.body.nonce)
                    }) == Some(Nonce(nonce))
                }) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("all five validators commit the one request");
        let mut heads = Vec::new();
        for (index, runtime) in runtimes.iter().enumerate() {
            let chain = runtime.epochchain();
            let epoch = chain.epochchain.last().expect("committed head");
            assert_eq!(epoch.body.nonce, Nonce(nonce));
            let transactions = epoch
                .body
                .blocks
                .values()
                .flat_map(|block| &block.body.txs)
                .collect::<Vec<_>>();
            assert_eq!(transactions.len(), 1);
            assert_eq!(transactions[0].hash, hash);
            heads.push(epoch.hash);
            let snapshot =
                RuntimeSnapshotV1::read_json(storage.path().join(format!("member-{index}.json")))
                    .expect("durable snapshot");
            assert_eq!(
                snapshot
                    .epochchain
                    .epochchain
                    .last()
                    .expect("durable head")
                    .hash,
                epoch.hash
            );
        }
        assert!(heads.iter().all(|head| *head == heads[0]));
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert!(runtimes.iter().all(|runtime| {
            runtime
                .status()
                .expect("idle after commit")
                .last_epoch_nonce
                == Nonce(nonce)
        }));
    }
}
