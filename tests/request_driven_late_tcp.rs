//! Late application requests remain intact across a real two-round epoch.

use blossom::{
    ConsensusDriverConfig, ConsensusGroupId, ConsensusParameters, MultiGroupRuntime, NodeIdentity,
    NodeRuntime, Nonce, QuorumSize, RuntimeConfig, Service, ServiceKind, TcpMultiGroupNode,
    TcpNode, TcpServiceClient, Transaction, genesis_epoch_for_group_with_parameters,
};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

/// Own listeners and drivers even if an assertion unwinds.
struct Tasks(Vec<JoinHandle<()>>);
impl Drop for Tasks {
    fn drop(&mut self) {
        for task in &self.0 {
            task.abort();
        }
    }
}

/// Start the actual request-driven transport with the required two rounds.
fn drive(node: TcpNode) -> JoinHandle<()> {
    tokio::spawn(async move {
        node.run_consensus_driver(ConsensusDriverConfig {
            max_round: 1,
            event_driven: true,
            require_local_pending_block: true,
            continue_after_error: true,
            ..Default::default()
        })
        .await
        .expect("driver");
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn late_request_is_committed_once_in_the_next_multi_round_epoch() {
    let mut listeners = Vec::new();
    let mut identities = Vec::new();
    for _ in 0..9 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        identities.push(NodeIdentity::generate(
            "tcp",
            "127.0.0.1",
            listener.local_addr().expect("address").port(),
        ));
        listeners.push(listener);
    }
    let group = ConsensusGroupId::named("late-request-two-round-regression");
    let quorum = QuorumSize::new(3).expect("supported branching factor");
    let genesis = genesis_epoch_for_group_with_parameters(
        group,
        identities.iter().cloned(),
        ConsensusParameters::new(quorum),
    );
    let mut runtimes = Vec::new();
    let mut drivers = Vec::new();
    let mut tasks = Tasks(Vec::new());
    for (identity, listener) in identities.iter().cloned().zip(listeners) {
        let mut config = RuntimeConfig::for_group(identity, group);
        config.genesis = Some(genesis.clone());
        config.quorum_size = quorum;
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
                .expect("timeout")
                .for_group(group)
        };
        let runtime = NodeRuntime::try_new_with_network_client(config, client()).expect("runtime");
        let listener_node = TcpMultiGroupNode::new(MultiGroupRuntime::new(runtime.clone()));
        tasks.0.push(tokio::spawn(async move {
            listener_node.serve(listener).await.expect("serve");
        }));
        drivers.push(TcpNode::with_services(runtime.clone(), client()));
        runtimes.push(runtime);
    }
    assert_eq!(runtimes[0].quorum_round_count().expect("round count"), 2);
    let proposer = drivers.remove(0);
    tasks.0.push(drive(proposer));
    let first = Transaction::new("first epoch application request");
    let first_hash = first.hash;
    runtimes[0]
        .submit_transaction(first)
        .expect("first request");
    tokio::time::timeout(Duration::from_secs(5), async {
        while !runtimes[0]
            .has_local_prefill_dispatch()
            .expect("prefill status")
        {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("first block sealed before peer drivers start");
    assert_eq!(
        runtimes[0].status().expect("head").last_epoch_nonce,
        Nonce(0)
    );
    let late = Transaction::new("late request for the next epoch");
    let late_hash = late.hash;
    runtimes[0].submit_transaction(late).expect("late request");
    for driver in drivers {
        tasks.0.push(drive(driver));
    }
    let progress = tokio::time::timeout(Duration::from_secs(15), async {
        while !runtimes
            .iter()
            .all(|runtime| runtime.status().expect("progress").last_epoch_nonce >= Nonce(2))
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await;
    if progress.is_err() {
        for (index, runtime) in runtimes.iter().enumerate() {
            let status = runtime.status().expect("status");
            let prefill = runtime.prefill_stage_status().expect("prefill");
            eprintln!(
                "member {index}: head={:?}, pending={}, round={}, prefill recorded={}, missing={}, outbound={}",
                status.last_epoch_nonce,
                status.pending_blocks,
                prefill.current_round,
                prefill.recorded_senders.len(),
                prefill.missing_senders.len(),
                prefill.pending_recipients.len()
            );
            for round in 0..=1 {
                let state = runtime.consensus_round_status(round).expect("round");
                eprintln!(
                    "round {round}: expected={}, received={}, pending={}, verification={}, proposal={}, commit={}",
                    state.expected_quorum_members,
                    state.received_dispatches,
                    state.pending_dispatches,
                    state.verification_senders,
                    state.proposal_senders,
                    state.commit_senders
                );
            }
        }
    }
    progress.expect("both real requests reach all nine validators");
    let mut heads = Vec::new();
    for runtime in &runtimes {
        let chain = runtime.epochchain();
        for (nonce, expected) in [(1, first_hash), (2, late_hash)] {
            let epoch = chain
                .epochchain
                .iter()
                .find(|epoch| epoch.body.nonce == Nonce(nonce))
                .expect("epoch");
            let hashes = epoch
                .body
                .blocks
                .values()
                .flat_map(|block| &block.body.txs)
                .map(|tx| tx.hash)
                .collect::<Vec<_>>();
            assert_eq!(hashes, vec![expected]);
        }
        heads.push(chain.epochchain.last().expect("head").hash);
    }
    assert!(heads.iter().all(|head| *head == heads[0]));
    tokio::time::sleep(Duration::from_millis(250)).await;
    assert!(
        runtimes
            .iter()
            .all(|runtime| runtime.status().expect("idle").last_epoch_nonce == Nonce(2))
    );
}
