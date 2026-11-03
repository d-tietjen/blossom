//! TCP service, request routing, and runtime integration tests.

mod deadlines;

use super::*;
use crate::block::{Block, Transaction};
use crate::blossom::{BlossomBody, EchoRequest, Header};
use crate::crypto::Keypair;
use crate::group::ConsensusGroupId;
use crate::harness::SimulatedCluster;
use crate::messages::MSGKey;
use crate::node::NodeIdentity;
use crate::overlay::FanOutStrategy;
use crate::runtime::{
    MultiGroupRuntime, RuntimeConfig, TrustMode, genesis_epoch, genesis_epoch_for_group,
};

fn tcp_node() -> (TcpNode, Keypair) {
    let keypair = Keypair::generate();
    let identity = NodeIdentity::new(
        keypair.public,
        Some(keypair.secret.clone()),
        "tcp",
        "127.0.0.1",
        8080,
        false,
    );
    (
        TcpNode::new(crate::NodeRuntime::new(RuntimeConfig::new(identity))),
        keypair,
    )
}

fn signed_test_header<T: BlossomBody>(
    signer: &Keypair,
    target: &crate::EpochTarget,
    round: u8,
    kind: MSGKey,
    body: &T,
) -> Header {
    let signature_hash = Header::signature_hash_for_body(
        &signer.public,
        &target.last_epoch,
        target.nonce,
        round,
        kind,
        body,
    );
    Header {
        sender: signer.public,
        last_epoch: target.last_epoch,
        nonce: target.nonce,
        round,
        signature: signer.signer().sign(signature_hash.as_ref()),
    }
}

fn six_node_tcp_runtime() -> (TcpNode, Vec<Keypair>) {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let identities = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                (index == 0).then_some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                8700 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let genesis = genesis_epoch(identities.clone());
    let mut config = RuntimeConfig::new(identities[0].clone());
    config.genesis = Some(genesis);
    (TcpNode::new(crate::NodeRuntime::new(config)), keypairs)
}

#[tokio::test]
async fn handle_request_returns_health_and_errors() {
    let (node, keypair) = tcp_node();

    match node.handle_request(WireRequest::Health).await.unwrap() {
        WireResponse::Health(health) => {
            assert_eq!(health.public_key, keypair.public);
            assert!(health.protocol_hash_compatible());
        }
        response => panic!("expected health, got {}", response.kind()),
    }

    match node
        .handle_request(WireRequest::GetBlock(crate::Nonce::new(1)))
        .await
        .unwrap_err()
    {
        BlossomError::WireProtocol(message) => assert!(message.contains("does not have")),
        error => panic!("unexpected error: {error}"),
    }
}

#[tokio::test]
async fn application_handler_round_trips_over_node_request_path() {
    let (base_node, keypair) = tcp_node();
    let node = TcpNode::with_application_handler(base_node.runtime, |request| {
        Box::pin(async move {
            assert_eq!(request.kind, "test/echo");
            Ok(ApplicationResponse::new("test/echo", request.payload))
        })
    });

    match node
        .handle_request(WireRequest::Application(ApplicationRequest::new(
            "test/echo",
            b"payload",
        )))
        .await
        .unwrap()
    {
        WireResponse::Application(response) => {
            assert_eq!(response.kind, "test/echo");
            assert_eq!(response.payload, b"payload");
        }
        response => panic!(
            "expected application response from {}, got {}",
            keypair.public,
            response.kind()
        ),
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let server = tokio::spawn(node.clone().serve(listener));
    let service = Service::new(
        ServiceKind::Engine,
        keypair.public,
        "tcp",
        "127.0.0.1",
        port,
    );
    let response = TcpServiceClient::new()
        .application(&service, ApplicationRequest::new("test/echo", b"network"))
        .await
        .unwrap();
    assert_eq!(response.kind, "test/echo");
    assert_eq!(response.payload, b"network");
    server.abort();
}

#[tokio::test]
async fn handle_request_serves_durable_blocks_by_nonce() {
    let keypair = Keypair::generate();
    let identity = NodeIdentity::new(
        keypair.public,
        Some(keypair.secret.clone()),
        "tcp",
        "127.0.0.1",
        8080,
        false,
    );
    let root = std::env::temp_dir().join(format!(
        "blossom-tcp-block-store-{}-{}",
        std::process::id(),
        keypair.public
    ));
    let mut config = RuntimeConfig::new(identity);
    config.block_store_path = Some(root.clone());
    let node = TcpNode::new(crate::NodeRuntime::new(config));
    let target = node.runtime.next_epoch_target().unwrap();
    let mut block = Block::default();
    block.body.last_epoch = target.last_epoch;
    block.body.nonce = target.nonce;
    block.sign(&keypair.secret);
    let hash = block.hash;

    node.handle_request(WireRequest::SendBlock(block))
        .await
        .unwrap();

    match node
        .handle_request(WireRequest::GetBlock(target.nonce))
        .await
        .unwrap()
    {
        WireResponse::Block(block) => assert_eq!(block.hash, hash),
        response => panic!("expected block, got {}", response.kind()),
    }
    std::fs::remove_dir_all(root).ok();
}

#[tokio::test]
async fn handle_request_returns_direct_pong_without_consensus() {
    let (node, keypair) = tcp_node();
    let ping = crate::NodePing::with_payload(42, b"hello-peer");

    match node.handle_request(WireRequest::Ping(ping)).await.unwrap() {
        WireResponse::Pong(pong) => {
            assert_eq!(pong.group_id, ConsensusGroupId::root());
            assert_eq!(pong.public_key, keypair.public);
            assert!(pong.protocol_hash_compatible());
            assert_eq!(pong.nonce, 42);
            assert_eq!(pong.payload, b"hello-peer");
        }
        response => panic!("expected pong, got {}", response.kind()),
    }
}

#[tokio::test]
async fn handle_request_serves_durable_blocks_by_hash() {
    let keypair = Keypair::generate();
    let identity = NodeIdentity::new(
        keypair.public,
        Some(keypair.secret.clone()),
        "tcp",
        "127.0.0.1",
        8610,
        false,
    );
    let root = std::env::temp_dir().join(format!(
        "blossom-tcp-block-store-hash-{}-{}",
        std::process::id(),
        keypair.public
    ));
    let mut config = RuntimeConfig::new(identity);
    config.block_store_path = Some(root.clone());
    let runtime = NodeRuntime::new(config);
    let target = runtime.next_epoch_target().unwrap();
    let mut block = Block::default();
    block.body.last_epoch = target.last_epoch;
    block.body.nonce = target.nonce;
    block.body.txs.push(Transaction::new("tcp-hash-repair"));
    block.sign(&keypair.secret);
    runtime.submit_block(block.clone()).unwrap();
    let node = TcpNode::new(runtime);

    match node
        .handle_request(WireRequest::GetBlocksByHash {
            hashes: vec![block.hash, HashType([9; 32])],
        })
        .await
        .unwrap()
    {
        WireResponse::BlocksByHash(blocks) => {
            assert_eq!(blocks.len(), 1);
            assert_eq!(blocks.get(&block.hash).unwrap().hash, block.hash);
        }
        response => panic!("expected blocks_by_hash, got {}", response.kind()),
    }

    std::fs::remove_dir_all(root).ok();
}

#[tokio::test]
async fn echo_request_returns_targeted_redispatch_response() {
    let (node, keypairs) = six_node_tcp_runtime();
    let target = node.runtime.next_epoch_target().unwrap();
    let mut block = Block::default();
    block.body.last_epoch = target.last_epoch;
    block.body.nonce = target.nonce;
    block.body.txs.push(Transaction::new("tcp-echo-redispatch"));
    block.sign(&keypairs[0].secret);
    node.runtime.submit_block(block).unwrap();
    let dispatch = node.runtime.dispatch_local_block(0).unwrap();
    let block_hash = *dispatch.body.blocks.keys().next().unwrap();
    let requested_blocks = [(block_hash, ())].into_iter().collect();
    let request = EchoRequest {
        header: signed_test_header(
            &keypairs[1],
            &target,
            0,
            MSGKey::EchoRequest,
            &requested_blocks,
        ),
        requested_blocks,
    };

    match node
        .handle_request(WireRequest::Message(Msg::EchoRequest(request)))
        .await
        .unwrap()
    {
        WireResponse::EchoReDispatch(Some(redispatch)) => {
            assert_eq!(redispatch.header.sender, keypairs[0].public);
            assert!(redispatch.redispatched_blocks.contains_key(&block_hash));
        }
        response => panic!("expected echo_redispatch response, got {}", response.kind()),
    }
}

#[tokio::test]
async fn prefill_retry_reuses_the_exact_signed_message() {
    let keypairs = (0..36).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let identities = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                (index == 0).then_some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                8600 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let genesis = genesis_epoch(identities.clone());
    let mut config = RuntimeConfig::new(identities[0].clone());
    config.genesis = Some(genesis);
    let runtime = NodeRuntime::new(config);
    let target = runtime.next_epoch_target().unwrap();
    let mut block = Block::default();
    block.body.last_epoch = target.last_epoch;
    block.body.nonce = target.nonce;
    block.body.txs.push(Transaction::new("tcp-driver-prefill"));
    block.sign(&keypairs[0].secret);
    runtime.submit_block(block).unwrap();

    let first = runtime
        .try_broadcast_prefill_dispatch()
        .await
        .unwrap()
        .expect("the first prefill should be produced");
    let second = runtime
        .try_broadcast_prefill_dispatch()
        .await
        .unwrap()
        .expect("unreachable recipients should keep prefill retryable");

    assert_eq!(
        borsh::to_vec(&first.dispatch).unwrap(),
        borsh::to_vec(&second.dispatch).unwrap()
    );
    assert!(!first.plan.missing_services.is_empty());
    assert_eq!(first.plan.missing_services, second.plan.missing_services);
    assert!(runtime.has_local_prefill_dispatch().unwrap());
}

#[tokio::test]
async fn runtime_broadcast_reuses_one_pooled_tcp_connection() {
    let cluster = SimulatedCluster::spawn_manual_with_trust_mode_and_quorum(
        2,
        TrustMode::Verified,
        crate::QuorumSize::DEFAULT,
    )
    .await
    .unwrap();
    let target = cluster.node(1).identity.public_key();

    for _ in 0..64 {
        let report = cluster
            .node(0)
            .runtime
            .broadcast_request(WireRequest::State, FanOutStrategy::Direct(vec![target]))
            .await
            .unwrap();
        assert_eq!(report.attempted(), 1);
        assert_eq!(report.accepted(), 1);
    }

    assert_eq!(cluster.node_metrics()[1].connections, 1);
}

#[tokio::test]
async fn runtime_broadcast_eviction_bounds_a_wider_fanout() {
    let cluster = SimulatedCluster::spawn_manual_with_trust_mode_and_quorum(
        6,
        TrustMode::Verified,
        crate::QuorumSize::DEFAULT,
    )
    .await
    .unwrap();

    let report = cluster
        .node(0)
        .runtime
        .broadcast_request(WireRequest::State, FanOutStrategy::All)
        .await
        .unwrap();

    assert_eq!(report.attempted(), 5);
    assert_eq!(report.accepted(), 5);
    assert_eq!(report.failed(), 0);
}

#[tokio::test]
async fn service_client_retries_an_initially_refused_connection() {
    let reservation = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reservation.local_addr().unwrap();
    drop(reservation);

    let (node, keypair) = tcp_node();
    let server = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(5)).await;
        let listener = TcpListener::bind(address).await.unwrap();
        node.serve(listener).await
    });
    let service = Service::new(
        ServiceKind::Consensus,
        keypair.public,
        "tcp",
        "127.0.0.1",
        address.port(),
    );

    let response = TcpServiceClient::new()
        .request(&service, &WireRequest::Health)
        .await
        .unwrap();
    assert!(matches!(response, WireResponse::Health(_)));
    server.abort();
}

#[tokio::test]
async fn multi_group_node_routes_grouped_requests_to_subnets() {
    let keypairs = (0..6).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let identities = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                (index == 0).then_some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                8000 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();

    let root_genesis = genesis_epoch(identities.clone());
    let subnet_id = ConsensusGroupId::named("cache-hotset-a");
    let subnet_genesis = genesis_epoch_for_group(subnet_id, identities[..3].to_vec());

    let mut root_config = RuntimeConfig::new(identities[0].clone());
    root_config.genesis = Some(root_genesis.clone());
    let root_runtime = NodeRuntime::new(root_config);

    let mut subnet_config = RuntimeConfig::new(identities[0].clone());
    subnet_config.group_id = subnet_id;
    subnet_config.genesis = Some(subnet_genesis.clone());
    let subnet_runtime = NodeRuntime::new(subnet_config);
    subnet_runtime
        .set_application_state(b"subnet-only")
        .unwrap();

    let root_target = root_runtime.next_epoch_target().unwrap();
    let subnet_target = subnet_runtime.next_epoch_target().unwrap();
    let node = TcpMultiGroupNode::new(MultiGroupRuntime::with_groups(
        root_runtime,
        [subnet_runtime],
    ));

    match node.handle_request(WireRequest::NextNonce).await.unwrap() {
        WireResponse::NextNonce(target) => {
            assert_eq!(target.last_epoch, root_target.last_epoch)
        }
        response => panic!("expected root next nonce, got {}", response.kind()),
    }

    let grouped_next = WireRequest::Group {
        group_id: subnet_id,
        request: Box::new(WireRequest::NextNonce),
    };
    match node.handle_request(grouped_next).await.unwrap() {
        WireResponse::NextNonce(target) => {
            assert_eq!(target.last_epoch, subnet_target.last_epoch);
            assert_eq!(target.nonce, subnet_target.nonce);
        }
        response => panic!("expected subnet next nonce, got {}", response.kind()),
    }

    let grouped_ping = WireRequest::Group {
        group_id: subnet_id,
        request: Box::new(WireRequest::Ping(crate::NodePing::new(7))),
    };
    match node.handle_request(grouped_ping).await.unwrap() {
        WireResponse::Pong(pong) => {
            assert_eq!(pong.group_id, subnet_id);
            assert_eq!(pong.public_key, keypairs[0].public);
            assert_eq!(pong.nonce, 7);
            assert!(pong.payload.is_empty());
        }
        response => panic!("expected subnet pong, got {}", response.kind()),
    }

    let grouped_dispatch = WireRequest::Group {
        group_id: subnet_id,
        request: Box::new(WireRequest::Dispatch { round: 0 }),
    };
    match node.handle_request(grouped_dispatch).await.unwrap() {
        WireResponse::Dispatch(dispatch) => {
            assert_eq!(dispatch.header.last_epoch, subnet_target.last_epoch);
            let block = dispatch.body.blocks.values().next().unwrap();
            assert_eq!(block.application_state(), b"subnet-only");
        }
        response => panic!("expected subnet dispatch, got {}", response.kind()),
    }

    let unknown_group = WireRequest::Group {
        group_id: ConsensusGroupId::named("not-hosted"),
        request: Box::new(WireRequest::NextNonce),
    };
    assert!(matches!(
        node.handle_request(unknown_group).await,
        Err(BlossomError::WireProtocol(message)) if message.contains("unknown consensus group")
    ));
}

#[tokio::test]
async fn group_scoped_service_client_uses_one_multi_group_listener() {
    let keypairs = (0..4).map(|_| Keypair::generate()).collect::<Vec<_>>();
    let identities = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                Some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                19_000 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let root_genesis = genesis_epoch(identities.clone());
    let subnet_id = ConsensusGroupId::named("scoped-client-subnet");
    let subnet_genesis = genesis_epoch_for_group(subnet_id, identities.clone());
    let mut root_config = RuntimeConfig::new(identities[0].clone());
    root_config.genesis = Some(root_genesis);
    let mut subnet_config = RuntimeConfig::for_group(identities[0].clone(), subnet_id);
    subnet_config.genesis = Some(subnet_genesis);
    let node = TcpMultiGroupNode::new(MultiGroupRuntime::with_groups(
        NodeRuntime::new(root_config),
        [NodeRuntime::new(subnet_config)],
    ));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(node.serve(listener));
    let service = Service::new(
        ServiceKind::Consensus,
        keypairs[0].public,
        "tcp",
        address.ip().to_string(),
        address.port(),
    );
    let pong = TcpServiceClient::new()
        .for_group(subnet_id)
        .ping(&service, crate::NodePing::new(91))
        .await
        .unwrap();
    assert_eq!(pong.group_id, subnet_id);
    assert_eq!(pong.nonce, 91);
    server.abort();
}
