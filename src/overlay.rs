//! Topology-aware message fan-out without consensus epoch ownership.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, RwLock};

use crate::address_book::{AddressBook, Service, ServiceKind};
use crate::algorithm::{QuorumSize, select_quorums_with_size};
use crate::crypto::PubKey;
use crate::error::{BlossomError, Result};
use crate::hash::HashType;
use crate::messages::Msg;
use crate::node::NodeIdentity;
use crate::runtime::{RuntimeConfig, RuntimeMode};
use crate::service_client::TcpServiceClient;
use crate::tcp::send_wire_frame;
use crate::wire::{EncodedFrame, WireRequest, WireResponse};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FanOutStrategy {
    All,
    Direct(Vec<PubKey>),
    Topology {
        seed: HashType,
        round: Option<usize>,
        shuffle: bool,
    },
}

impl FanOutStrategy {
    pub fn all() -> Self {
        Self::All
    }

    pub fn direct(targets: impl IntoIterator<Item = PubKey>) -> Self {
        Self::Direct(targets.into_iter().collect())
    }

    pub fn topology(seed: HashType) -> Self {
        Self::Topology {
            seed,
            round: None,
            shuffle: true,
        }
    }

    pub fn topology_round(seed: HashType, round: usize) -> Self {
        Self::Topology {
            seed,
            round: Some(round),
            shuffle: true,
        }
    }

    pub fn unshuffled_topology(seed: HashType) -> Self {
        Self::Topology {
            seed,
            round: None,
            shuffle: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct BroadcastReport {
    pub receipts: Vec<BroadcastReceipt>,
}

impl BroadcastReport {
    pub fn attempted(&self) -> usize {
        self.receipts.len()
    }

    pub fn accepted(&self) -> usize {
        self.receipts
            .iter()
            .filter(|receipt| receipt.accepted())
            .count()
    }

    pub fn failed(&self) -> usize {
        self.receipts
            .iter()
            .filter(|receipt| !receipt.accepted())
            .count()
    }
}

#[derive(Debug, Clone)]
pub struct BroadcastReceipt {
    pub target: PubKey,
    pub service: Service,
    pub response: Result<WireResponse>,
}

impl BroadcastReceipt {
    pub fn accepted(&self) -> bool {
        match &self.response {
            Ok(WireResponse::MessageReceipt(receipt)) => receipt.accepted,
            Ok(WireResponse::Error(_)) | Err(_) => false,
            Ok(_) => true,
        }
    }
}

#[derive(Clone)]
pub struct OverlayRuntime {
    inner: Arc<OverlayInner>,
}

struct OverlayInner {
    self_node: NodeIdentity,
    address_book: RwLock<AddressBook>,
    quorum_size: QuorumSize,
}

impl OverlayRuntime {
    pub fn new(self_node: NodeIdentity) -> Self {
        Self::from_config(RuntimeConfig::overlay(self_node))
    }

    pub fn from_config(mut config: RuntimeConfig) -> Self {
        config.mode = RuntimeMode::Overlay;
        add_self_consensus_service(&mut config.address_book, &config.self_node);

        Self {
            inner: Arc::new(OverlayInner {
                self_node: config.self_node,
                address_book: RwLock::new(config.address_book),
                quorum_size: config.quorum_size,
            }),
        }
    }

    pub fn self_node(&self) -> NodeIdentity {
        self.inner.self_node.clone()
    }

    pub fn address_book(&self) -> Vec<Service> {
        self.inner
            .address_book
            .read()
            .expect("address book lock poisoned")
            .clone()
            .into_services()
    }

    /// Registers or replaces a local service endpoint for overlay fan-out.
    ///
    /// Overlay registration does not create consensus state or verifier
    /// membership; it only makes the endpoint selectable by fan-out strategy.
    pub fn register_service(&self, service: Service) -> Option<Service> {
        self.inner
            .address_book
            .write()
            .expect("address book lock poisoned")
            .add(service)
    }

    pub fn fanout_targets(&self, strategy: &FanOutStrategy) -> Vec<Service> {
        let address_book = self
            .inner
            .address_book
            .read()
            .expect("address book lock poisoned");
        select_fanout_targets_with_size(
            &self.inner.self_node,
            &address_book,
            strategy,
            self.inner.quorum_size,
        )
    }

    pub async fn broadcast(&self, msg: Msg, strategy: FanOutStrategy) -> Result<BroadcastReport> {
        self.broadcast_request(WireRequest::Message(msg), strategy)
            .await
    }

    pub async fn broadcast_request(
        &self,
        request: WireRequest,
        strategy: FanOutStrategy,
    ) -> Result<BroadcastReport> {
        let targets = self.fanout_targets(&strategy);
        broadcast_wire_request(request, targets).await
    }
}

pub(crate) fn add_self_consensus_service(address_book: &mut AddressBook, self_node: &NodeIdentity) {
    address_book.add(Service::new(
        ServiceKind::Consensus,
        self_node.public_key(),
        self_node.protocol.clone(),
        self_node.host.clone(),
        self_node.port,
    ));
}

#[allow(dead_code)]
pub(crate) fn select_fanout_targets(
    self_node: &NodeIdentity,
    address_book: &AddressBook,
    strategy: &FanOutStrategy,
) -> Vec<Service> {
    select_fanout_targets_with_size(self_node, address_book, strategy, QuorumSize::DEFAULT)
}

pub(crate) fn select_fanout_targets_with_size(
    self_node: &NodeIdentity,
    address_book: &AddressBook,
    strategy: &FanOutStrategy,
    quorum_size: QuorumSize,
) -> Vec<Service> {
    let self_key = self_node.public_key();
    let services = address_book
        .services_for_kind(ServiceKind::Consensus)
        .cloned()
        .map(|service| (service.public_key, service))
        .collect::<BTreeMap<_, _>>();

    let selected = match strategy {
        FanOutStrategy::All => services.keys().copied().collect::<BTreeSet<_>>(),
        FanOutStrategy::Direct(targets) => targets.iter().copied().collect::<BTreeSet<_>>(),
        FanOutStrategy::Topology {
            seed,
            round,
            shuffle,
        } => {
            let mut keys = services.keys().copied().collect::<BTreeSet<_>>();
            keys.insert(self_key);
            let quorums = select_quorums_with_size(keys, &self_key, *seed, *shuffle, quorum_size);
            match round {
                Some(round) => quorums
                    .get(*round)
                    .into_iter()
                    .flatten()
                    .copied()
                    .collect::<BTreeSet<_>>(),
                None => quorums.into_iter().flatten().collect::<BTreeSet<_>>(),
            }
        }
    };

    selected
        .into_iter()
        .filter(|target| *target != self_key)
        .filter_map(|target| services.get(&target).cloned())
        .collect()
}

pub(crate) async fn broadcast_wire_request(
    request: WireRequest,
    targets: Vec<Service>,
) -> Result<BroadcastReport> {
    const TRANSPORT_ATTEMPTS: usize = 3;

    let frame = EncodedFrame::encode_wire_request(&request)?;
    let requests = targets.into_iter().map(|service| {
        let frame = frame.clone();
        async move {
            let response = async {
                let mut last_error = BlossomError::Io("transport attempts exhausted".to_owned());
                for attempt in 0..TRANSPORT_ATTEMPTS {
                    match send_wire_frame(service.socket_addr(), &frame).await {
                        Ok(response) => return Ok(response),
                        Err(error) => {
                            last_error = error;
                            if attempt + 1 < TRANSPORT_ATTEMPTS {
                                tokio::task::yield_now().await;
                            }
                        }
                    }
                }
                Err(last_error)
            }
            .await;
            BroadcastReceipt {
                target: service.public_key,
                service,
                response,
            }
        }
    });
    // Own every exchange; cancellation leaves no detached transport tasks.
    let receipts = futures_util::future::join_all(requests).await;

    Ok(BroadcastReport { receipts })
}

pub(crate) async fn broadcast_wire_request_pooled(
    request: WireRequest,
    targets: Vec<Service>,
    client: &TcpServiceClient,
) -> Result<BroadcastReport> {
    let frame = EncodedFrame::encode_wire_request(&request)?;
    let requests = targets.into_iter().map(|service| {
        let client = client.clone();
        let frame = frame.clone();
        async move {
            let response = client.request_frame(&service, &frame).await;
            BroadcastReceipt {
                target: service.public_key,
                service,
                response,
            }
        }
    });
    let receipts = futures_util::future::join_all(requests).await;
    Ok(BroadcastReport { receipts })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::Keypair;

    fn identity(index: u8, port: u16) -> NodeIdentity {
        NodeIdentity::new(PubKey([index; 32]), None, "tcp", "127.0.0.1", port, false)
    }

    #[test]
    fn overlay_runtime_selects_topology_fanout_without_epoch_state() {
        let self_node = identity(0, 8000);
        let overlay = OverlayRuntime::new(self_node);
        for index in 1..6 {
            overlay.register_service(Service::new(
                ServiceKind::Consensus,
                PubKey([index; 32]),
                "tcp",
                "127.0.0.1",
                8000 + index as u16,
            ));
        }

        let targets =
            overlay.fanout_targets(&FanOutStrategy::unshuffled_topology(HashType::default()));

        assert_eq!(targets.len(), 5);
        assert!(
            targets
                .iter()
                .all(|service| service.public_key != PubKey([0; 32]))
        );
    }

    #[test]
    fn direct_fanout_ignores_unknown_targets_and_self() {
        let keypair = Keypair::generate();
        let self_node = NodeIdentity::new(
            keypair.public,
            Some(keypair.secret.clone()),
            "tcp",
            "127.0.0.1",
            8000,
            false,
        );
        let peer = PubKey([7; 32]);
        let overlay = OverlayRuntime::new(self_node.clone());
        overlay.register_service(Service::new(
            ServiceKind::Consensus,
            peer,
            "tcp",
            "127.0.0.1",
            8001,
        ));

        let targets = overlay.fanout_targets(&FanOutStrategy::direct([
            self_node.public_key(),
            PubKey([9; 32]),
            peer,
        ]));

        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].public_key, peer);
    }
}
