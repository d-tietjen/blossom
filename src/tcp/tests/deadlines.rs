//! Real socket regressions for deadline, cancellation and fanout ownership.

use super::*;
use std::num::NonZeroUsize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;

async fn listener() -> (TcpListener, Service) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let service = Service::new(
        ServiceKind::Consensus,
        Keypair::generate().public,
        "tcp",
        "127.0.0.1",
        listener.local_addr().expect("address").port(),
    );
    (listener, service)
}

async fn require_closed(stream: &mut TcpStream) {
    let mut byte = [0_u8; 1];
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), stream.read(&mut byte))
            .await
            .expect("socket closed promptly")
            .expect("EOF"),
        0
    );
}

#[test]
fn timeout_policy_is_explicit_and_nonzero() {
    assert_eq!(
        TcpServiceClient::new().request_timeout(),
        DEFAULT_TCP_REQUEST_TIMEOUT
    );
    assert!(
        TcpServiceClient::new()
            .with_request_timeout(Duration::ZERO)
            .is_err()
    );
}

#[tokio::test]
async fn partial_reply_timeout_closes_pool_socket_and_next_rpc_reconnects() {
    let (listener, service) = listener().await;
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.expect("first connection");
        crate::wire::read_wire_request(&mut first)
            .await
            .expect("first request");
        first
            .write_all(&[0, 0])
            .await
            .expect("partial response prefix");
        require_closed(&mut first).await;
        let _ = crate::wire::write_wire_response(
            &mut first,
            &WireResponse::Application(ApplicationResponse::new("test", b"late-first")),
        )
        .await;
        let (mut second, _) = listener.accept().await.expect("fresh connection");
        crate::wire::read_wire_request(&mut second)
            .await
            .expect("second request");
        crate::wire::write_wire_response(
            &mut second,
            &WireResponse::Application(ApplicationResponse::new("test", b"second-only")),
        )
        .await
        .expect("second response");
    });
    let client = TcpServiceClient::new()
        .with_request_timeout(Duration::from_millis(200))
        .expect("budget");
    assert!(
        client
            .application(&service, ApplicationRequest::new("test", b"first"))
            .await
            .is_err()
    );
    let second = client
        .application(&service, ApplicationRequest::new("test", b"second"))
        .await
        .expect("reconnect");
    assert_eq!(second.payload, b"second-only");
    server.await.expect("server");
}

#[tokio::test]
async fn externally_cancelled_raw_exchange_cannot_reuse_its_socket() {
    for raw in [false, true] {
        let (listener, service) = listener().await;
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("connection");
            crate::wire::read_wire_request(&mut stream)
                .await
                .expect("request");
            require_closed(&mut stream).await;
        });
        let mut connection = TcpConnection::connect(service.socket_addr())
            .await
            .expect("connect");
        let exchange = async {
            if raw {
                connection
                    .request_raw_response(&WireRequest::Health)
                    .await
                    .map(|_| ())
            } else {
                connection.request(&WireRequest::Health).await.map(|_| ())
            }
        };
        assert!(
            tokio::time::timeout(Duration::from_millis(200), exchange)
                .await
                .is_err()
        );
        assert!(connection.stream.is_none());
        assert!(connection.request(&WireRequest::Health).await.is_err());
        server.await.expect("server");
    }
}

#[tokio::test]
async fn cancelled_backpressured_write_closes_the_incomplete_exchange() {
    let (listener, service) = listener().await;
    let (release, wait) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("connection");
        wait.await.expect("writer cancelled");
        let mut received = Vec::new();
        tokio::time::timeout(Duration::from_secs(1), stream.read_to_end(&mut received))
            .await
            .expect("EOF after write cancellation")
            .expect("read");
        assert!(!received.is_empty());
        assert!(
            received.len() < 4 * 1024 * 1024,
            "whole request must not have reached the peer"
        );
    });
    let mut connection = TcpConnection::connect(service.socket_addr())
        .await
        .expect("connect");
    socket2::SockRef::from(connection.stream.as_ref().expect("connected"))
        .set_send_buffer_size(4096)
        .expect("bounded send queue");
    let request = WireRequest::Application(ApplicationRequest::new(
        "test/write-pressure",
        vec![7_u8; 4 * 1024 * 1024],
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(200), connection.request(&request))
            .await
            .is_err()
    );
    assert!(connection.stream.is_none());
    release.send(()).expect("release reader");
    server.await.expect("server");
}

#[tokio::test]
async fn pool_slot_wait_is_inside_the_request_deadline() {
    let (first_listener, first_service) = listener().await;
    let (second_listener, second_service) = listener().await;
    let (received, ready) = oneshot::channel();
    let server = tokio::spawn(async move {
        let (mut stream, _) = first_listener.accept().await.expect("connection");
        crate::wire::read_wire_request(&mut stream)
            .await
            .expect("request");
        received.send(()).expect("request signal");
        require_closed(&mut stream).await;
    });
    let client = TcpServiceClient::with_max_connections(NonZeroUsize::MIN)
        .with_request_timeout(Duration::from_secs(30))
        .expect("budget");
    let active = client.clone();
    let request =
        tokio::spawn(async move { active.request(&first_service, &WireRequest::Health).await });
    ready.await.expect("active request");
    let waiting = client
        .with_request_timeout(Duration::from_millis(100))
        .expect("short budget");
    assert!(
        tokio::time::timeout(
            Duration::from_secs(1),
            waiting.request(&second_service, &WireRequest::Health)
        )
        .await
        .expect("bounded pool wait")
        .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(50), second_listener.accept())
            .await
            .is_err()
    );
    request.abort();
    assert!(request.await.expect_err("cancelled").is_cancelled());
    server.await.expect("server");
}

#[tokio::test]
async fn transport_retry_preserves_the_exact_request_frame() {
    let (listener, service) = listener().await;
    let server = tokio::spawn(async move {
        let (mut first, _) = listener.accept().await.expect("first connection");
        let first_request = crate::wire::read_wire_request(&mut first)
            .await
            .expect("first frame");
        drop(first);
        let (mut second, _) = listener.accept().await.expect("retry connection");
        let retry = crate::wire::read_wire_request(&mut second)
            .await
            .expect("retry frame");
        assert_eq!(
            borsh::to_vec(&first_request).expect("first bytes"),
            borsh::to_vec(&retry).expect("retry bytes")
        );
        crate::wire::write_wire_response(&mut second, &WireResponse::Ok)
            .await
            .expect("response");
    });
    assert!(matches!(
        TcpServiceClient::new()
            .request(
                &service,
                &WireRequest::Application(ApplicationRequest::new("operation", b"stable-identity"))
            )
            .await
            .expect("retry"),
        WireResponse::Ok
    ));
    server.await.expect("server");
}

#[tokio::test]
async fn concurrent_broadcast_keeps_healthy_receipts_with_stalled_peers() {
    for healthy in [3, 4] {
        let mut services = Vec::new();
        let mut servers = Vec::new();
        for index in 0..5 {
            let (listener, service) = listener().await;
            services.push(service);
            servers.push(tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("connection");
                crate::wire::read_wire_request(&mut stream)
                    .await
                    .expect("request");
                if index < healthy {
                    crate::wire::write_wire_response(&mut stream, &WireResponse::Ok)
                        .await
                        .expect("reply");
                } else {
                    require_closed(&mut stream).await;
                }
            }));
        }
        let expected_order = services
            .iter()
            .map(|service| service.public_key)
            .collect::<Vec<_>>();
        let (mut node, _) = tcp_node();
        node.services = TcpServiceClient::new()
            .with_request_timeout(Duration::from_millis(200))
            .expect("budget");
        let report = tokio::time::timeout(
            Duration::from_secs(1),
            node.broadcast_message_to(services, Msg::Ok),
        )
        .await
        .expect("bounded fanout")
        .expect("report");
        assert_eq!(report.attempted(), 5);
        assert_eq!(report.accepted(), healthy);
        assert_eq!(
            report
                .receipts
                .iter()
                .map(|receipt| receipt.target)
                .collect::<Vec<_>>(),
            expected_order
        );
        for server in servers {
            server.await.expect("server");
        }
    }
}

#[tokio::test]
async fn runtime_internal_broadcast_uses_the_supplied_short_deadline() {
    let mut services = Vec::new();
    let mut servers = Vec::new();
    for index in 0..5 {
        let (listener, service) = listener().await;
        services.push(service);
        servers.push(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("connection");
            crate::wire::read_wire_request(&mut stream)
                .await
                .expect("request");
            if index == 0 {
                require_closed(&mut stream).await;
            } else {
                crate::wire::write_wire_response(&mut stream, &WireResponse::Ok)
                    .await
                    .expect("healthy response");
            }
        }));
    }
    let client =
        TcpServiceClient::with_max_connections(NonZeroUsize::new(5).expect("admitted peers"))
            .with_request_timeout(Duration::from_millis(300))
            .expect("short lease budget");
    let identity = NodeIdentity::generate("tcp", "127.0.0.1", 8080);
    let mut config = RuntimeConfig::new(identity);
    config.address_book.extend_services(services);
    let runtime =
        NodeRuntime::try_new_with_network_client(config, client).expect("configured runtime");
    let report = tokio::time::timeout(
        Duration::from_secs(1),
        runtime.broadcast_request(WireRequest::Health, FanOutStrategy::All),
    )
    .await
    .expect("explicit short budget, not generic thirty-second default")
    .expect("report");
    assert_eq!(report.attempted(), 5);
    assert_eq!(report.accepted(), 4);
    for server in servers {
        server.await.expect("server");
    }
}

#[tokio::test]
async fn admitted_wide_fanout_reaches_healthy_peers_after_six_blackholes() {
    let mut services = Vec::new();
    let mut servers = Vec::new();
    for index in 0..24 {
        let (listener, service) = listener().await;
        services.push(service);
        servers.push(tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("connection");
            crate::wire::read_wire_request(&mut stream)
                .await
                .expect("request");
            if index < 6 {
                require_closed(&mut stream).await;
            } else {
                crate::wire::write_wire_response(&mut stream, &WireResponse::Ok)
                    .await
                    .expect("healthy response");
            }
        }));
    }
    // The embedding application admits enough simultaneous connections for its
    // validator set; the generic six-slot default is not a quorum guarantee.
    let client = TcpServiceClient::with_max_connections(
        NonZeroUsize::new(24).expect("admitted validator count"),
    )
    .with_request_timeout(Duration::from_millis(300))
    .expect("budget");
    let report =
        crate::overlay::broadcast_wire_request_pooled(WireRequest::Health, services, &client)
            .await
            .expect("bounded fanout");
    assert_eq!(report.attempted(), 24);
    assert_eq!(report.accepted(), 18);
    assert!(
        report.receipts[..6]
            .iter()
            .all(|receipt| receipt.response.is_err())
    );
    assert!(
        report.receipts[6..]
            .iter()
            .all(|receipt| receipt.response.is_ok())
    );
    for server in servers {
        server.await.expect("server");
    }
}

#[tokio::test]
async fn cancelling_broadcast_closes_every_inflight_socket_without_detached_tasks() {
    for mode in ["node", "overlay", "pooled-overlay"] {
        let mut services = Vec::new();
        let mut servers = Vec::new();
        let mut received = Vec::new();
        for _ in 0..3 {
            let (listener, service) = listener().await;
            services.push(service);
            let (sent, ready) = oneshot::channel();
            received.push(ready);
            servers.push(tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("connection");
                crate::wire::read_wire_request(&mut stream)
                    .await
                    .expect("request");
                sent.send(()).expect("request signal");
                require_closed(&mut stream).await;
            }));
        }
        let (mut node, _) = tcp_node();
        node.services = TcpServiceClient::new()
            .with_request_timeout(Duration::from_secs(30))
            .expect("long internal budget");
        let broadcast = tokio::spawn(async move {
            match mode {
                "node" => node.broadcast_message_to(services, Msg::Ok).await,
                "overlay" => {
                    crate::overlay::broadcast_wire_request(WireRequest::Health, services).await
                }
                _ => {
                    crate::overlay::broadcast_wire_request_pooled(
                        WireRequest::Health,
                        services,
                        &node.services,
                    )
                    .await
                }
            }
        });
        for signal in received {
            signal.await.expect("all requests reached peers");
        }
        broadcast.abort();
        assert!(broadcast.await.expect_err("cancelled").is_cancelled());
        for server in servers {
            server.await.expect("closed before internal timeout");
        }
    }
}
