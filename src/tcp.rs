//! Bounded TCP node service, request routing, and consensus drivers.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use fast_telemetry::Counter;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;

use crate::address_book::{Service, ServiceKind};
#[cfg(feature = "availability-gossip")]
use crate::availability::FilteredPayloadMissing;
use crate::error::{BlossomError, Result};
use crate::group::ConsensusGroupId;
use crate::hash::HashType;
use crate::messages::Msg;
use crate::overlay::{BroadcastReceipt, BroadcastReport};
use crate::runtime::{MultiGroupRuntime, NodeRuntime};
use crate::service_client::TcpServiceClient;
use crate::wire::{
    AddressBookUpdate, ApplicationRequest, ApplicationResponse, EncodedFrame, NodeHealth, NodePong,
    WireRequest, WireRequestFrame, WireResponse, read_encoded_frame,
    read_wire_request_frame_optional, read_wire_response, write_encoded_frame, write_wire_request,
    write_wire_response,
};

pub type ApplicationHandler =
    Arc<dyn Fn(ApplicationRequest) -> ApplicationHandlerFuture + Send + Sync>;
pub type ApplicationHandlerFuture =
    Pin<Box<dyn Future<Output = Result<ApplicationResponse>> + Send>>;
pub type MultiGroupApplicationHandler =
    Arc<dyn Fn(ConsensusGroupId, ApplicationRequest) -> ApplicationHandlerFuture + Send + Sync>;

#[derive(Clone)]
pub struct TcpNode {
    pub runtime: NodeRuntime,
    pub services: TcpServiceClient,
    metrics: Option<TcpNodeMetrics>,
    application_handler: Option<ApplicationHandler>,
    driver_notify: Arc<Notify>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsensusDriverConfig {
    pub interval: Duration,
    /// Wake the driver immediately when a state-changing protocol message is
    /// received. Request-driven deployments should combine this with
    /// `require_local_pending_block` so notifications cannot create idle
    /// epochs.
    pub event_driven: bool,
    pub max_round: u8,
    /// Enables proactive block prefill before hierarchical consensus rounds.
    ///
    /// Verified consensus with more than one round always enables prefill,
    /// even when this compatibility flag is `false`, because every validator
    /// must derive the same epoch hash before issuing a global certificate
    /// share. Trusted consensus may still opt out.
    pub drive_prefill: bool,
    pub drive_dispatch: bool,
    /// Do not initiate an epoch until this node has a locally submitted block.
    ///
    /// This is useful for request-driven deployments and benchmarks that must
    /// not create empty epochs while idle. The compatibility default remains
    /// `false`.
    pub require_local_pending_block: bool,
    /// Keep serving and retry the next driver tick after a transient error.
    ///
    /// Production callers retain fail-fast behavior by default. Controlled
    /// benchmark clusters enable retries so one connection race cannot tear
    /// down the node's TCP listener.
    pub continue_after_error: bool,
}

impl Default for ConsensusDriverConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_millis(25),
            event_driven: false,
            max_round: 0,
            drive_prefill: false,
            drive_dispatch: true,
            require_local_pending_block: false,
            continue_after_error: false,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct ConsensusDriverTick {
    pub prefill_broadcasts: usize,
    pub dispatch_broadcasts: usize,
    pub trusted_acknowledgement_broadcasts: usize,
    pub verification_broadcasts: usize,
    pub proposal_broadcasts: usize,
    pub commit_broadcasts: usize,
    pub epoch_started_broadcasts: usize,
    pub echo_redispatch_responses: usize,
    pub manifest_repair_fetches: usize,
    pub catch_up_updates: usize,
}

impl ConsensusDriverTick {
    pub fn broadcasts(&self) -> usize {
        self.prefill_broadcasts
            + self.dispatch_broadcasts
            + self.trusted_acknowledgement_broadcasts
            + self.verification_broadcasts
            + self.proposal_broadcasts
            + self.commit_broadcasts
            + self.epoch_started_broadcasts
            + self.echo_redispatch_responses
    }
}

impl TcpNode {
    pub fn new(runtime: NodeRuntime) -> Self {
        Self {
            runtime,
            services: TcpServiceClient::new(),
            metrics: None,
            application_handler: None,
            driver_notify: Arc::new(Notify::new()),
        }
    }

    pub fn with_services(runtime: NodeRuntime, services: TcpServiceClient) -> Self {
        Self {
            runtime,
            services,
            metrics: None,
            application_handler: None,
            driver_notify: Arc::new(Notify::new()),
        }
    }

    pub fn with_metrics(runtime: NodeRuntime, metrics: TcpNodeMetrics) -> Self {
        Self {
            runtime,
            services: TcpServiceClient::new(),
            metrics: Some(metrics),
            application_handler: None,
            driver_notify: Arc::new(Notify::new()),
        }
    }

    pub fn with_application_handler(
        runtime: NodeRuntime,
        handler: impl Fn(ApplicationRequest) -> ApplicationHandlerFuture + Send + Sync + 'static,
    ) -> Self {
        Self {
            runtime,
            services: TcpServiceClient::new(),
            metrics: None,
            application_handler: Some(Arc::new(handler)),
            driver_notify: Arc::new(Notify::new()),
        }
    }

    pub fn metrics(&self) -> Option<TcpNodeMetricsSnapshot> {
        self.metrics.as_ref().map(TcpNodeMetrics::snapshot)
    }

    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|err| BlossomError::Io(err.to_string()))?;
            let node = self.clone();
            if let Some(metrics) = &node.metrics {
                metrics.record_connection();
            }
            tokio::spawn(async move {
                if let Err(err) = node.handle_connection(stream).await {
                    node.runtime.emit_telemetry_failure(
                        "transport",
                        "connection_failed",
                        &err,
                        None,
                    );
                    log::error!("connection failed: {err}");
                }
            });
        }
    }

    pub async fn serve_with_consensus_driver(
        self,
        listener: TcpListener,
        config: ConsensusDriverConfig,
    ) -> Result<()> {
        let serving = self.clone().serve(listener);
        let driving = self.run_consensus_driver(config);
        tokio::pin!(serving);
        tokio::pin!(driving);

        tokio::select! {
            result = &mut serving => result,
            result = &mut driving => result,
        }
    }

    pub async fn run_consensus_driver(self, config: ConsensusDriverConfig) -> Result<()> {
        let mut interval = tokio::time::interval(config.interval);
        let mut active_nonce = None;
        interval.tick().await;
        loop {
            if config.event_driven {
                tokio::select! {
                    _ = interval.tick() => {}
                    _ = self.driver_notify.notified() => {}
                }
            } else {
                interval.tick().await;
            }
            if config.require_local_pending_block {
                let status = self.runtime.status()?;
                if active_nonce.is_some_and(|nonce| nonce != status.next_nonce) {
                    active_nonce = None;
                }
                if active_nonce.is_none() {
                    if status.pending_blocks == 0 {
                        continue;
                    }
                    active_nonce = Some(status.next_nonce);
                }
            }
            if let Err(error) = self.drive_consensus_once(&config).await {
                if config.continue_after_error {
                    self.runtime.emit_telemetry_failure(
                        "service",
                        "consensus_driver_retry",
                        &error,
                        None,
                    );
                    log::warn!("consensus driver tick failed and will be retried: {error}");
                } else {
                    return Err(error);
                }
            }
        }
    }

    pub async fn drive_consensus_once(
        &self,
        config: &ConsensusDriverConfig,
    ) -> Result<ConsensusDriverTick> {
        let mut tick = ConsensusDriverTick::default();
        let drive_target = self.runtime.next_epoch_target()?;
        let catch_up_peers = self.runtime.epoch_started_catch_up_services()?;
        if !catch_up_peers.is_empty() {
            tick.catch_up_updates = self
                .catch_up_from_epoch_started_peers(&catch_up_peers)
                .await?;
            if tick.catch_up_updates != 0 {
                return Ok(tick);
            }
        }
        if !self.runtime.trust_mode().is_trusted()
            && let Some(epoch_started) = self.runtime.try_produce_epoch_started()?
        {
            let report = self.broadcast_epoch_started(epoch_started.clone()).await?;
            self.runtime.complete_epoch_started_broadcast(
                &epoch_started,
                report
                    .receipts
                    .iter()
                    .filter(|receipt| receipt.accepted())
                    .map(|receipt| receipt.target),
            );
            self.runtime.record_epoch_started_broadcast_failures(
                &epoch_started,
                report.receipts.iter().filter_map(epoch_started_failure),
            );
            tick.epoch_started_broadcasts += 1;
        }
        if self.runtime.next_epoch_target()? != drive_target {
            return Ok(tick);
        }
        let drive_prefill = config.drive_prefill
            || (!self.runtime.trust_mode().is_trusted() && config.max_round > 0);
        if drive_prefill
            && config.max_round > 0
            && self
                .runtime
                .try_broadcast_prefill_dispatch()
                .await?
                .is_some()
        {
            tick.prefill_broadcasts += 1;
        }

        if drive_prefill && config.max_round > 0 && !self.runtime.try_activate_prefill_round()? {
            return Ok(tick);
        }
        if self.runtime.next_epoch_target()? != drive_target {
            return Ok(tick);
        }

        let round = self.runtime.current_consensus_round()?;
        if round > config.max_round {
            return Err(crate::BlossomError::WireProtocol(format!(
                "consensus advanced to round {round}, beyond configured maximum {}",
                config.max_round
            )));
        }
        for message in self.runtime.drain_buffered_current_round_messages()? {
            self.runtime.receive_message(message)?;
        }
        if config.drive_dispatch
            && let Some(dispatch) = self
                .runtime
                .try_produce_dispatch_for_target(round, Some(&drive_target))?
        {
            let blocks_hash = dispatch.body.blocks_hash;
            let report = self
                .broadcast_round_message(round, Msg::Dispatch(dispatch))
                .await?;
            if report.failed() != 0 {
                self.runtime.schedule_dispatch_retry(round, blocks_hash)?;
                tick.dispatch_broadcasts += 1;
                return Ok(tick);
            }
            tick.dispatch_broadcasts += 1;
        }
        if self.runtime.next_epoch_target()? != drive_target {
            return Ok(tick);
        }
        if self.runtime.trust_mode().is_trusted()
            && let Some(acknowledgement) =
                self.runtime.try_produce_trusted_acknowledgement(round)?
        {
            let blocks_hash = acknowledgement.body.blocks_hash;
            let report = self
                .broadcast_round_message(round, Msg::TrustedAcknowledgement(acknowledgement))
                .await?;
            if report.failed() != 0 {
                self.runtime
                    .schedule_trusted_acknowledgement_retry(round, blocks_hash)?;
            }
            tick.trusted_acknowledgement_broadcasts += 1;
        }
        if self.runtime.next_epoch_target()? != drive_target {
            return Ok(tick);
        }
        if let Some(verification) = self.runtime.try_produce_verification(round)? {
            let blocks_hash = verification.body.blocks_hash;
            let report = self
                .broadcast_round_message(round, Msg::Verification(verification))
                .await?;
            if report.failed() != 0 {
                if self.runtime.trust_mode().is_trusted() {
                    self.runtime
                        .schedule_trusted_confirmation_retry(round, blocks_hash)?;
                } else {
                    self.runtime
                        .schedule_verification_retry(round, blocks_hash)?;
                }
            }
            tick.verification_broadcasts += 1;
            if self.runtime.trust_mode().is_trusted() {
                self.runtime
                    .complete_trusted_verification(round, blocks_hash)?;
            }
        }
        if self.runtime.next_epoch_target()? != drive_target {
            return Ok(tick);
        }
        if self.runtime.trust_mode().is_trusted() {
            self.runtime.try_complete_trusted_verification(round)?;
            if let Some(epoch_started) = self.runtime.try_produce_epoch_started()? {
                let report = self.broadcast_epoch_started(epoch_started.clone()).await?;
                self.runtime.complete_epoch_started_broadcast(
                    &epoch_started,
                    report
                        .receipts
                        .iter()
                        .filter(|receipt| receipt.accepted())
                        .map(|receipt| receipt.target),
                );
                self.runtime.record_epoch_started_broadcast_failures(
                    &epoch_started,
                    report.receipts.iter().filter_map(epoch_started_failure),
                );
                tick.epoch_started_broadcasts += 1;
            }
            return Ok(tick);
        }
        if let Some(proposal) = self.runtime.try_produce_proposal(round)? {
            let signature = proposal.header.signature;
            let report = self
                .broadcast_round_message(round, Msg::Proposal(proposal))
                .await?;
            if report.failed() != 0 {
                self.runtime.schedule_proposal_retry(round, signature)?;
            }
            tick.proposal_broadcasts += 1;
        }
        if self.runtime.next_epoch_target()? != drive_target {
            return Ok(tick);
        }
        if let Some(proposal) = self.runtime.try_produce_false_proposal(round)? {
            let signature = proposal.header.signature;
            let report = self
                .broadcast_round_message(round, Msg::Proposal(proposal))
                .await?;
            if report.failed() != 0 {
                self.runtime.schedule_proposal_retry(round, signature)?;
            }
            tick.proposal_broadcasts += 1;
        }
        if self.runtime.next_epoch_target()? != drive_target {
            return Ok(tick);
        }
        let finality_collectors = if self.runtime.is_final_consensus_round(round)? {
            Some(self.runtime.finality_collector_services()?)
        } else {
            None
        };
        let commit = match self.runtime.try_produce_commit(round)? {
            Some(commit) => Some(commit),
            None if finality_collectors.is_some() => self.runtime.retry_final_commit(round)?,
            None => None,
        };
        if let Some(commit) = commit {
            if let Some(collectors) = finality_collectors {
                self.broadcast_message_to(collectors, Msg::Commit(commit))
                    .await?;
            } else {
                self.broadcast_round_message(round, Msg::Commit(commit))
                    .await?;
            }
            tick.commit_broadcasts += 1;
        }
        Ok(tick)
    }

    /// Drives only certified epoch announcement and catch-up work.
    ///
    /// Manual protocol harnesses use this after a node has finalized their
    /// requested epoch so it can disseminate the certificate without starting
    /// another epoch.
    pub async fn drive_epoch_dissemination_once(&self) -> Result<ConsensusDriverTick> {
        let mut tick = ConsensusDriverTick::default();
        let catch_up_peers = self.runtime.epoch_started_catch_up_services()?;
        if !catch_up_peers.is_empty() {
            tick.catch_up_updates = self
                .catch_up_from_epoch_started_peers(&catch_up_peers)
                .await?;
            if tick.catch_up_updates != 0 {
                return Ok(tick);
            }
        }
        if !self.runtime.trust_mode().is_trusted()
            && let Some(epoch_started) = self.runtime.try_produce_epoch_started()?
        {
            let report = self.broadcast_epoch_started(epoch_started.clone()).await?;
            self.runtime.complete_epoch_started_broadcast(
                &epoch_started,
                report
                    .receipts
                    .iter()
                    .filter(|receipt| receipt.accepted())
                    .map(|receipt| receipt.target),
            );
            self.runtime.record_epoch_started_broadcast_failures(
                &epoch_started,
                report.receipts.iter().filter_map(epoch_started_failure),
            );
            tick.epoch_started_broadcasts += 1;
        }
        Ok(tick)
    }

    /// Drives only verified v2 prefill and its activation barrier.
    ///
    /// Manual protocol harnesses use this before ordinary round dispatch so a
    /// writer's queued block cannot be consumed twice.
    pub async fn drive_prefill_stage_once(&self, max_round: u8) -> Result<ConsensusDriverTick> {
        let mut tick = ConsensusDriverTick::default();
        if self.runtime.trust_mode().is_trusted() || max_round == 0 {
            return Ok(tick);
        }
        let drive_target = self.runtime.next_epoch_target()?;
        if self
            .runtime
            .try_broadcast_prefill_dispatch()
            .await?
            .is_some()
        {
            tick.prefill_broadcasts = 1;
        }
        if self.runtime.next_epoch_target()? != drive_target {
            return Ok(tick);
        }
        self.runtime.try_activate_prefill_round()?;
        Ok(tick)
    }

    /// Drives only the Dispatch stage for the current round.
    ///
    /// Deterministic protocol harnesses use this to establish an all-writer
    /// admission barrier before allowing acknowledgement or confirmation
    /// production. Normal autonomous operation continues to use
    /// [`Self::drive_consensus_once`].
    pub async fn drive_dispatch_stage_once(&self, max_round: u8) -> Result<ConsensusDriverTick> {
        let drive_target = self.runtime.next_epoch_target()?;
        let round = self.runtime.current_consensus_round()?;
        if round > max_round {
            return Err(crate::BlossomError::WireProtocol(format!(
                "consensus advanced to round {round}, beyond configured maximum {max_round}"
            )));
        }
        for message in self.runtime.drain_buffered_current_round_messages()? {
            self.runtime.receive_message(message)?;
        }
        let mut tick = ConsensusDriverTick::default();
        if self.runtime.next_epoch_target()? != drive_target {
            return Ok(tick);
        }
        if let Some(dispatch) = self
            .runtime
            .try_produce_dispatch_for_target(round, Some(&drive_target))?
        {
            let blocks_hash = dispatch.body.blocks_hash;
            let report = self
                .broadcast_round_message(round, Msg::Dispatch(dispatch))
                .await?;
            if report.failed() != 0 {
                self.runtime.schedule_dispatch_retry(round, blocks_hash)?;
            }
            tick.dispatch_broadcasts = 1;
        }
        Ok(tick)
    }

    pub async fn repair_manifest_from_holders(
        &self,
        manifest: &crate::round_skip::DataDisseminationManifest,
    ) -> Result<usize> {
        let plan = self.runtime.manifest_repair_plan(manifest)?;
        if plan.missing_blocks.is_empty() {
            return Ok(0);
        }
        let services = self.runtime.address_book();
        let mut fetched = std::collections::BTreeMap::new();
        for (holder, hashes) in plan.requests_by_holder {
            let Some(service) = services.iter().find(|service| {
                service.kind == ServiceKind::Consensus && service.public_key == holder
            }) else {
                continue;
            };
            match self
                .services
                .request(service, &WireRequest::GetBlocksByHash { hashes })
                .await?
            {
                WireResponse::BlocksByHash(blocks) => {
                    fetched.extend(blocks);
                }
                WireResponse::Error(message) => {
                    return Err(BlossomError::ExternalService(message));
                }
                response => {
                    return Err(BlossomError::WireProtocol(format!(
                        "expected blocks_by_hash response from manifest holder, got {}",
                        response.kind()
                    )));
                }
            }
        }
        let receipt = self.runtime.repair_manifest_blocks(manifest, fetched)?;
        if !receipt.missing_blocks.is_empty() {
            return Err(BlossomError::WireProtocol(format!(
                "manifest repair still missing {} carried blocks",
                receipt.missing_blocks.len()
            )));
        }
        Ok(receipt.inserted_blocks)
    }

    pub async fn catch_up_from_epoch_started_peers(&self, peers: &[Service]) -> Result<usize> {
        let mut updates = 0usize;
        let mut successful_responses = 0usize;
        let mut last_error = None;
        for service in peers {
            let local_tip = self
                .runtime
                .epochchain()
                .epochchain
                .last()
                .cloned()
                .ok_or(BlossomError::EmptyEpochChain)?;
            let request = if self.runtime.trust_mode().is_trusted() {
                WireRequest::EpochChain
            } else {
                WireRequest::CertifiedEpochSuffix {
                    anchor_hash: local_tip.hash,
                    anchor_nonce: local_tip.body.nonce,
                    max_epochs: 4096,
                }
            };
            match self.services.request(service, &request).await {
                Ok(WireResponse::CertifiedEpochSuffix(suffix)) => {
                    successful_responses += 1;
                    if self.runtime.catch_up_certified_suffix(suffix)? {
                        updates += 1;
                        break;
                    }
                }
                Ok(WireResponse::EpochChain(chain)) => {
                    successful_responses += 1;
                    if self.runtime.catch_up_from_epoch_started(chain)? {
                        updates += 1;
                        break;
                    }
                }
                Ok(WireResponse::Error(message)) => {
                    last_error = Some(BlossomError::ExternalService(message));
                }
                Ok(response) => {
                    last_error = Some(BlossomError::WireProtocol(format!(
                        "expected epoch_chain response during catch-up, got {}",
                        response.kind()
                    )));
                }
                Err(error) => {
                    last_error = Some(error);
                }
            }
        }
        if successful_responses == 0
            && let Some(error) = last_error
        {
            return Err(error);
        }
        Ok(updates)
    }

    async fn broadcast_round_message(&self, round: u8, msg: Msg) -> Result<BroadcastReport> {
        let targets = self.runtime.round_consensus_services(round)?;
        self.broadcast_message_to(targets, msg).await
    }

    async fn broadcast_epoch_started(
        &self,
        message: crate::EpochStarted,
    ) -> Result<BroadcastReport> {
        let targets = self.runtime.epoch_started_retry_services(&message);
        self.broadcast_message_to(targets, Msg::EpochStarted(message))
            .await
    }

    async fn broadcast_message_to(
        &self,
        targets: Vec<Service>,
        msg: Msg,
    ) -> Result<BroadcastReport> {
        let frame = EncodedFrame::encode_wire_request(&WireRequest::Message(msg))?;
        let requests = targets.into_iter().map(|service| {
            let client = self.services.clone();
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
        // Own every future in this call. Cancellation closes in-flight sockets
        // instead of detaching spawned requests; input receipt order is stable.
        let receipts = futures_util::future::join_all(requests).await;
        Ok(BroadcastReport { receipts })
    }

    pub async fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        configure_tcp_stream(&stream)?;
        while let Some(request) = read_wire_request_frame_optional(&mut stream).await? {
            let started = Instant::now();
            let result = self.handle_request_frame(request).await;
            if let Some(metrics) = &self.metrics {
                metrics.record_request(started.elapsed().as_nanos(), result.is_ok());
            }
            let response = match result {
                Ok(response) => response,
                Err(err) => WireResponse::Error(err.to_string()),
            };
            write_wire_response(&mut stream, &response).await?;
        }
        Ok(())
    }

    pub async fn handle_request_frame(&self, request: WireRequestFrame) -> Result<WireResponse> {
        match request {
            WireRequestFrame::Request(request) => {
                let drives_consensus = request_drives_consensus(&request);
                let response = self.handle_request(request).await;
                if drives_consensus && response.is_ok() {
                    self.driver_notify.notify_one();
                }
                response
            }
            WireRequestFrame::HotDispatch(dispatch) => {
                let response =
                    WireResponse::MessageReceipt(self.runtime.receive_hot_dispatch(dispatch)?);
                self.driver_notify.notify_one();
                Ok(response)
            }
        }
    }

    pub async fn handle_request(&self, request: WireRequest) -> Result<WireResponse> {
        match request {
            WireRequest::Application(request) => {
                let handler = self.application_handler.as_ref().ok_or_else(|| {
                    BlossomError::WireProtocol(
                        "application requests are not configured on this node".to_string(),
                    )
                })?;
                Ok(WireResponse::Application(handler(request).await?))
            }
            WireRequest::Group { group_id, request } => {
                if group_id != self.runtime.group_id() {
                    return Err(unknown_group(group_id));
                }
                handle_runtime_request(&self.runtime, &self.services, *request).await
            }
            request => handle_runtime_request(&self.runtime, &self.services, request).await,
        }
    }
}

fn epoch_started_failure(receipt: &BroadcastReceipt) -> Option<(crate::PubKey, String)> {
    if receipt.accepted() {
        return None;
    }
    let error = match &receipt.response {
        Ok(WireResponse::Error(message)) => message.clone(),
        Ok(response) => format!("unexpected {} response", response.kind()),
        Err(error) => error.to_string(),
    };
    Some((receipt.target, error))
}

fn request_drives_consensus(request: &WireRequest) -> bool {
    match request {
        WireRequest::Group { request, .. } => request_drives_consensus(request),
        WireRequest::RegisterService(_)
        | WireRequest::SubmitBlock(_)
        | WireRequest::PrefillDispatch(_)
        | WireRequest::Message(_)
        | WireRequest::SendNonce(_)
        | WireRequest::BlockNonce(_)
        | WireRequest::SendBlock(_) => true,
        _ => false,
    }
}

#[derive(Clone, Default)]
pub struct TcpNodeMetrics {
    inner: Arc<TcpNodeMetricsInner>,
}

struct TcpNodeMetricsInner {
    connections: Counter,
    requests: Counter,
    responses: Counter,
    errors: Counter,
    handler_nanos: Counter,
}

impl Default for TcpNodeMetricsInner {
    fn default() -> Self {
        Self {
            connections: Counter::new(64),
            requests: Counter::new(64),
            responses: Counter::new(64),
            errors: Counter::new(64),
            handler_nanos: Counter::new(64),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TcpNodeMetricsSnapshot {
    pub connections: u64,
    pub requests: u64,
    pub responses: u64,
    pub errors: u64,
    pub handler_nanos: u64,
}

impl TcpNodeMetrics {
    pub fn snapshot(&self) -> TcpNodeMetricsSnapshot {
        TcpNodeMetricsSnapshot {
            connections: counter_sum_u64(&self.inner.connections),
            requests: counter_sum_u64(&self.inner.requests),
            responses: counter_sum_u64(&self.inner.responses),
            errors: counter_sum_u64(&self.inner.errors),
            handler_nanos: counter_sum_u64(&self.inner.handler_nanos),
        }
    }

    fn record_connection(&self) {
        self.inner.connections.inc();
    }

    fn record_request(&self, nanos: u128, success: bool) {
        self.inner.requests.inc();
        match success {
            true => self.inner.responses.inc(),
            false => self.inner.errors.inc(),
        };
        counter_add_u128(&self.inner.handler_nanos, nanos);
    }
}

fn counter_sum_u64(counter: &Counter) -> u64 {
    u64::try_from(counter.sum()).unwrap_or_default()
}

fn counter_add_u128(counter: &Counter, value: u128) {
    counter.add(isize::try_from(value).unwrap_or(isize::MAX));
}

#[derive(Clone)]
pub struct TcpMultiGroupNode {
    pub runtime: MultiGroupRuntime,
    pub services: TcpServiceClient,
    application_handler: Option<MultiGroupApplicationHandler>,
}

impl TcpMultiGroupNode {
    pub fn new(runtime: MultiGroupRuntime) -> Self {
        Self {
            runtime,
            services: TcpServiceClient::new(),
            application_handler: None,
        }
    }

    pub fn with_services(runtime: MultiGroupRuntime, services: TcpServiceClient) -> Self {
        Self {
            runtime,
            services,
            application_handler: None,
        }
    }

    pub fn with_application_handler(
        runtime: MultiGroupRuntime,
        handler: impl Fn(ConsensusGroupId, ApplicationRequest) -> ApplicationHandlerFuture
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            runtime,
            services: TcpServiceClient::new(),
            application_handler: Some(Arc::new(handler)),
        }
    }

    pub fn with_services_and_application_handler(
        runtime: MultiGroupRuntime,
        services: TcpServiceClient,
        handler: impl Fn(ConsensusGroupId, ApplicationRequest) -> ApplicationHandlerFuture
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            runtime,
            services,
            application_handler: Some(Arc::new(handler)),
        }
    }

    pub async fn serve(self, listener: TcpListener) -> Result<()> {
        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|err| BlossomError::Io(err.to_string()))?;
            let node = self.clone();
            tokio::spawn(async move {
                if let Err(err) = node.handle_connection(stream).await {
                    node.runtime.root_runtime().emit_telemetry_failure(
                        "transport",
                        "multi_group_connection_failed",
                        &err,
                        None,
                    );
                    log::error!("connection failed: {err}");
                }
            });
        }
    }

    pub async fn handle_connection(&self, mut stream: TcpStream) -> Result<()> {
        configure_tcp_stream(&stream)?;
        while let Some(request) = read_wire_request_frame_optional(&mut stream).await? {
            let response = match self.handle_request_frame(request).await {
                Ok(response) => response,
                Err(err) => WireResponse::Error(err.to_string()),
            };
            write_wire_response(&mut stream, &response).await?;
        }
        Ok(())
    }

    pub async fn handle_request_frame(&self, request: WireRequestFrame) -> Result<WireResponse> {
        match request {
            WireRequestFrame::Request(request) => self.handle_request(request).await,
            WireRequestFrame::HotDispatch(dispatch) => {
                let runtime = self
                    .runtime
                    .group_for_epoch(&dispatch.header.last_epoch)
                    .ok_or_else(|| unknown_epoch_group(dispatch.header.last_epoch))?;
                Ok(WireResponse::MessageReceipt(
                    runtime.receive_hot_dispatch(dispatch)?,
                ))
            }
        }
    }

    pub async fn handle_request(&self, request: WireRequest) -> Result<WireResponse> {
        match request {
            WireRequest::Group { group_id, request } => {
                let runtime = self
                    .runtime
                    .group(&group_id)
                    .ok_or_else(|| unknown_group(group_id))?;
                match *request {
                    WireRequest::Application(request) => {
                        let handler = self.application_handler.as_ref().ok_or_else(|| {
                            BlossomError::WireProtocol(
                                "application requests are not configured on this multi-group node"
                                    .to_string(),
                            )
                        })?;
                        Ok(WireResponse::Application(handler(group_id, request).await?))
                    }
                    request => handle_runtime_request(&runtime, &self.services, request).await,
                }
            }
            WireRequest::Application(request) => {
                let group_id = self.runtime.root_group();
                let handler = self.application_handler.as_ref().ok_or_else(|| {
                    BlossomError::WireProtocol(
                        "application requests are not configured on this multi-group node"
                            .to_string(),
                    )
                })?;
                Ok(WireResponse::Application(handler(group_id, request).await?))
            }
            request => {
                let runtime = self.runtime.root_runtime();
                handle_runtime_request(&runtime, &self.services, request).await
            }
        }
    }
}

async fn handle_runtime_request(
    runtime: &NodeRuntime,
    services: &TcpServiceClient,
    request: WireRequest,
) -> Result<WireResponse> {
    match request {
        WireRequest::Health => Ok(WireResponse::Health(NodeHealth::new(
            "ok",
            runtime.self_node().public_key(),
        ))),
        WireRequest::Ping(ping) => Ok(WireResponse::Pong(NodePong::new_with_consensus_parameters(
            runtime.group_id(),
            runtime.self_node().public_key(),
            runtime.consensus_parameters(),
            ping.nonce,
            ping.payload,
        ))),
        WireRequest::Application(_) => Err(BlossomError::WireProtocol(
            "application requests require an application handler".to_string(),
        )),
        #[cfg(feature = "availability-gossip")]
        WireRequest::AvailabilityGossip(gossip) => Ok(WireResponse::AvailabilityReceipt(
            runtime.receive_availability_gossip(gossip)?,
        )),
        #[cfg(feature = "availability-gossip")]
        WireRequest::GetFilteredPayload(fetch) => {
            let missing = FilteredPayloadMissing {
                scope: fetch.body.scope,
                holder: runtime.self_node().public_key(),
                slot_hash: fetch.body.slot_hash,
                payload_commitment: fetch.body.payload_commitment,
            };
            match runtime.serve_filtered_payload_fetch(fetch)? {
                Some(delivery) => Ok(WireResponse::FilteredPayload(delivery)),
                None => Ok(WireResponse::FilteredPayloadMissing(missing)),
            }
        }
        #[cfg(feature = "availability-gossip")]
        WireRequest::GetFilteredPayloadBatch(fetch) => Ok(WireResponse::FilteredPayloadBatch(
            runtime.serve_filtered_payload_batch_fetch(fetch)?,
        )),
        #[cfg(feature = "availability-gossip")]
        WireRequest::StoreFilteredPayload(delivery) => Ok(WireResponse::AvailabilityReceipt(
            runtime.receive_filtered_payload(delivery)?,
        )),
        #[cfg(feature = "availability-gossip")]
        WireRequest::StoreFilteredPayloadBatch(delivery) => Ok(WireResponse::AvailabilityReceipt(
            runtime.receive_filtered_payload_batch(delivery)?,
        )),
        WireRequest::State => Ok(WireResponse::State(runtime.status()?)),
        WireRequest::EpochChain => Ok(WireResponse::EpochChain(runtime.epochchain())),
        WireRequest::CertifiedEpochSuffix {
            anchor_hash,
            anchor_nonce,
            max_epochs,
        } => Ok(WireResponse::CertifiedEpochSuffix(
            runtime.certified_epoch_suffix(anchor_hash, anchor_nonce, max_epochs as usize)?,
        )),
        WireRequest::AddressBook => Ok(WireResponse::AddressBook(runtime.address_book())),
        WireRequest::RegisterService(registration) => {
            let (service, admission, signed_record) = registration.into_parts();
            let previous = match signed_record {
                Some(record) => runtime.register_signed_service(record)?,
                None => {
                    let admission = admission.as_ref().ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "service registration has no authentication evidence".to_string(),
                        )
                    })?;
                    admission.verify()?;
                    runtime.register_service(service.clone())
                }
            };
            let admitted_node = match admission {
                Some(admission) => runtime.stage_node_admission(admission)?,
                None => None,
            };
            let nonce_announced = if service.kind == ServiceKind::Block {
                let target = runtime.next_epoch_target()?;
                services.send_nonce(&service, target.nonce).await?;
                Some(target.nonce)
            } else {
                None
            };
            Ok(WireResponse::AddressBookUpdated(AddressBookUpdate {
                service,
                previous,
                nonce_announced,
                admitted_node,
            }))
        }
        WireRequest::NextNonce => Ok(WireResponse::NextNonce(runtime.next_epoch_target()?)),
        WireRequest::SubmitBlock(block) => {
            Ok(WireResponse::BlockAccepted(runtime.submit_block(block)?))
        }
        WireRequest::Dispatch { round } => {
            Ok(WireResponse::Dispatch(runtime.dispatch_local_block(round)?))
        }
        WireRequest::PrefillDispatch(dispatch) => Ok(WireResponse::MessageReceipt(
            runtime.receive_prefill_dispatch(dispatch)?,
        )),
        WireRequest::Message(message) => match message {
            Msg::EchoRequest(request) => {
                let redispatch = runtime.respond_to_echo_request(&request)?;
                runtime.receive_message(Msg::EchoRequest(request))?;
                Ok(WireResponse::EchoReDispatch(redispatch))
            }
            message => Ok(WireResponse::MessageReceipt(
                runtime.receive_message(message)?,
            )),
        },
        WireRequest::SendNonce(_) | WireRequest::BlockNonce(_) => Ok(WireResponse::Ok),
        WireRequest::GetBlock(nonce) => match runtime.durable_block_by_nonce(nonce)? {
            Some(block) => Ok(WireResponse::Block(block)),
            None => Err(BlossomError::WireProtocol(
                "this node does not have a durable block for the requested nonce".to_string(),
            )),
        },
        WireRequest::GetBlocksByHash { hashes } => Ok(WireResponse::BlocksByHash(
            runtime.durable_blocks_by_hash(hashes)?,
        )),
        WireRequest::SendBlock(block) => {
            runtime.submit_block(block)?;
            Ok(WireResponse::Ok)
        }
        WireRequest::Group { group_id, .. } => Err(BlossomError::WireProtocol(format!(
            "nested grouped request for group {group_id} is not allowed"
        ))),
    }
}

fn unknown_group(group_id: ConsensusGroupId) -> BlossomError {
    BlossomError::WireProtocol(format!("unknown consensus group {group_id}"))
}

fn unknown_epoch_group(last_epoch: HashType) -> BlossomError {
    BlossomError::WireProtocol(format!("no consensus group is tracking epoch {last_epoch}"))
}

/// Default whole-request budget for service clients and one-shot TCP helpers.
pub const DEFAULT_TCP_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// A framed TCP connection whose in-flight exchange owns the socket.
/// Cancellation or a transport error permanently closes that socket; a caller
/// must reconnect rather than reuse a partial or late response.
pub struct TcpConnection {
    /// Present only between successful, fully framed request/response exchanges.
    stream: Option<TcpStream>,
}

impl TcpConnection {
    pub async fn connect(addr: impl AsRef<str>) -> Result<Self> {
        let stream = TcpStream::connect(addr.as_ref())
            .await
            .map_err(|err| BlossomError::Io(err.to_string()))?;
        configure_tcp_stream(&stream)?;
        Ok(Self {
            stream: Some(stream),
        })
    }

    pub async fn request(&mut self, request: &WireRequest) -> Result<WireResponse> {
        let frame = EncodedFrame::encode_wire_request(request)?;
        self.request_frame(&frame).await
    }

    pub async fn request_frame(&mut self, frame: &EncodedFrame) -> Result<WireResponse> {
        let mut stream = self.take_stream()?;
        let result = async {
            write_encoded_frame(&mut stream, frame).await?;
            read_wire_response(&mut stream).await
        }
        .await;
        if result.is_ok() {
            self.stream = Some(stream);
        }
        result
    }

    pub async fn request_raw_response(&mut self, request: &WireRequest) -> Result<EncodedFrame> {
        let mut stream = self.take_stream()?;
        let result = async {
            write_wire_request(&mut stream, request).await?;
            read_encoded_frame(&mut stream).await
        }
        .await;
        if result.is_ok() {
            self.stream = Some(stream);
        }
        result
    }

    /// Move ownership into the request future so dropping it closes the socket.
    fn take_stream(&mut self) -> Result<TcpStream> {
        self.stream.take().ok_or_else(|| {
            BlossomError::Io(
                "TCP connection closed after an interrupted exchange; reconnect required".into(),
            )
        })
    }
}

fn configure_tcp_stream(stream: &TcpStream) -> Result<()> {
    stream
        .set_nodelay(true)
        .map_err(|err| BlossomError::Io(err.to_string()))
}

pub async fn send_wire_request(
    addr: impl AsRef<str>,
    request: WireRequest,
) -> Result<WireResponse> {
    tokio::time::timeout(DEFAULT_TCP_REQUEST_TIMEOUT, async {
        let mut connection = TcpConnection::connect(addr).await?;
        connection.request(&request).await
    })
    .await
    .map_err(|_| {
        BlossomError::Io("TCP request deadline elapsed; remote outcome may be unknown".into())
    })?
}

pub async fn send_wire_frame(addr: impl AsRef<str>, frame: &EncodedFrame) -> Result<WireResponse> {
    tokio::time::timeout(DEFAULT_TCP_REQUEST_TIMEOUT, async {
        let mut connection = TcpConnection::connect(addr).await?;
        connection.request_frame(frame).await
    })
    .await
    .map_err(|_| {
        BlossomError::Io("TCP frame deadline elapsed; remote outcome may be unknown".into())
    })?
}

pub async fn send_wire_request_raw_response(
    addr: impl AsRef<str>,
    request: WireRequest,
) -> Result<EncodedFrame> {
    tokio::time::timeout(DEFAULT_TCP_REQUEST_TIMEOUT, async {
        let mut connection = TcpConnection::connect(addr).await?;
        connection.request_raw_response(&request).await
    })
    .await
    .map_err(|_| {
        BlossomError::Io("TCP raw-response deadline elapsed; remote outcome may be unknown".into())
    })?
}

#[cfg(test)]
mod tests;
