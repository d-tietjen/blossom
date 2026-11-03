//! Runtime construction, shared accessors, status, and telemetry plumbing.

use super::*;

impl NodeRuntime {
    /// Creates a runtime and panics when the configuration is invalid.
    pub fn new(config: RuntimeConfig) -> Self {
        Self::try_new(config).expect("invalid Blossom runtime configuration")
    }

    /// Returns the runtime's verified or trusted execution policy.
    pub fn trust_mode(&self) -> TrustMode {
        self.inner.trust_mode
    }

    /// Validates configuration and constructs a runtime.
    pub fn try_new(config: RuntimeConfig) -> Result<Self> {
        Self::try_new_with_network_client(
            config,
            TcpServiceClient::with_max_connections(
                NonZeroUsize::new(RUNTIME_BROADCAST_MAX_CONNECTIONS)
                    .expect("runtime broadcast pool size is non-zero"),
            ),
        )
    }

    /// Construct with an application-owned transport admission/deadline policy.
    ///
    /// The internal broadcast/prefill client is independent of `TcpNode`'s
    /// service client. Supply both explicitly when short leases or a wider
    /// admitted validator set require different bounds. No protocol state or
    /// durable snapshot changes; clones retain this same runtime-owned pool.
    pub fn try_new_with_network_client(
        mut config: RuntimeConfig,
        network_client: TcpServiceClient,
    ) -> Result<Self> {
        if config.trust_mode.is_high_availability() {
            return Err(BlossomError::InvalidConfiguration(
                "high-availability mode uses HighAvailabilityRuntime, not NodeRuntime".to_string(),
            ));
        }
        let signer = config.self_node.signer().ok();
        config.self_node = config.self_node.public_only();
        let requested_group_id = config.group_id;
        let configured_parameters = ConsensusParameters::new(config.quorum_size);
        configured_parameters.validate()?;
        let genesis = config.genesis.take().unwrap_or_else(|| {
            genesis_epoch_for_group_with_parameters(
                config.group_id,
                [config.self_node.clone()],
                configured_parameters,
            )
        });
        if requested_group_id != ConsensusGroupId::root()
            && requested_group_id != genesis.body.group_id
        {
            return Err(BlossomError::InvalidConfiguration(
                "runtime config group id does not match genesis group id".to_string(),
            ));
        }
        let committed_parameters = genesis.body.effective_consensus_parameters();
        committed_parameters.validate()?;
        if configured_parameters != committed_parameters {
            return Err(BlossomError::ConsensusParametersMismatch {
                configured: configured_parameters.quorum_size.get(),
                committed: committed_parameters.quorum_size.get(),
            });
        }
        let group_id = genesis.body.group_id;
        add_self_consensus_service(&mut config.address_book, &config.self_node);
        let mut state = LocalState::new_with_consensus_node_removal_policy(
            config.self_node,
            genesis,
            config.consensus_node_removal_policy,
        );
        if let Some(epochchain) = config.epochchain.take() {
            for epoch in &epochchain.epochchain {
                let epoch_parameters = epoch.body.effective_consensus_parameters();
                if epoch_parameters != committed_parameters {
                    return Err(BlossomError::ConsensusParametersMismatch {
                        configured: committed_parameters.quorum_size.get(),
                        committed: epoch_parameters.quorum_size.get(),
                    });
                }
            }
            state.epochchain = epochchain;
        }
        if config.trusted_epoch_log_path.is_some() && !config.trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted epoch log is only applicable to TrustMode::Trusted".to_string(),
            ));
        }
        let trusted_epoch_log = match config.trusted_epoch_log_path.as_ref() {
            Some(path) => {
                let (store, recovered) = TrustedEpochLog::open(
                    path,
                    state.self_node.public_key(),
                    &state.epochchain,
                    state.consensus_node_removal_policy,
                )?;
                state.epochchain = recovered;
                let round_locks = store.round_locks()?;
                for (expected_round, round_lock) in round_locks.iter().enumerate() {
                    let head = state
                        .epochchain
                        .epochchain
                        .last()
                        .ok_or(BlossomError::EmptyEpochChain)?;
                    let head_hash = head.hash;
                    let head_nonce = head.body.nonce;
                    let head_verifiers = head.body.verifiers.clone();
                    if round_lock.round_id.group_id != group_id
                        || round_lock.round_id.previous_epoch_hash != head_hash
                        || round_lock.round_id.previous_epoch_nonce != head_nonce
                        || round_lock.round_id.nonce != head_nonce.new_next()
                        || usize::from(round_lock.round_id.round) != expected_round
                    {
                        return Err(BlossomError::InvalidConfiguration(
                            "trusted epoch log contains non-contiguous locks outside the current epoch"
                                .to_string(),
                        ));
                    }
                    let available_rounds = state
                        .get_mut_consensus(
                            &round_lock.round_id.previous_epoch_hash,
                            round_lock.round_id.nonce,
                        )
                        .peers
                        .len();
                    if expected_round >= available_rounds {
                        return Err(BlossomError::InvalidConfiguration(
                            "trusted epoch log contains a lock beyond the committed topology"
                                .to_string(),
                        ));
                    }
                    for block in round_lock.blocks.values() {
                        if !head_verifiers.contains_key(&block.body.validator) {
                            return Err(BlossomError::UnknownSender);
                        }
                    }
                    let quorum = state.get_mut_quorum(
                        &round_lock.round_id.previous_epoch_hash,
                        round_lock.round_id.nonce,
                        round_lock.round_id.round,
                    );
                    for (hash, block) in &round_lock.blocks {
                        quorum.record_verified_block(*hash, block.clone());
                    }
                    quorum.verified_blocks_hash = Some(quorum.verified_blocks_hash());
                    quorum
                        .trusted_confirmations
                        .record(round_lock.verification.clone())?;
                    quorum.verification_sent = true;
                }
                if let Some(highest) = round_locks.last() {
                    let consensus = state.get_mut_consensus(
                        &highest.round_id.previous_epoch_hash,
                        highest.round_id.nonce,
                    );
                    consensus.round = highest.round_id.round;
                    if let Some(quorum) = consensus.quorum.get_mut(&highest.round_id.round) {
                        quorum.verification_sent = false;
                    }
                }
                Some(store)
            }
            None => None,
        };
        let durable_block_store = config
            .block_store_path
            .map(DurableBlockStore::open)
            .transpose()?;
        let mut local_blocks = LocalBlock::new(config.block_cap);
        if let Some(block) = trusted_epoch_log
            .as_ref()
            .map(TrustedEpochLog::pending_local_block)
            .transpose()?
            .flatten()
        {
            local_blocks.enqueue_preverified_block(block)?;
        }
        let committed_nonce = state
            .epochchain
            .epochchain
            .last()
            .map(|epoch| epoch.body.nonce)
            .unwrap_or_default();
        let (epoch_commit_tx, _) = watch::channel(committed_nonce);
        let committed_epoch = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let initial_membership = Arc::new(VerifiedMembershipView {
            group_id,
            epoch_hash: committed_epoch.hash,
            epoch_nonce: committed_epoch.body.nonce.0,
            lease_expires_at_unix_millis: 0,
            valid_until: std::time::Instant::now(),
            members: Arc::new(committed_epoch.body.members.clone()),
            relays: Arc::new(RelaySet::new()),
        });
        let (verified_membership_tx, _) = watch::channel(initial_membership);

        Ok(Self {
            inner: Arc::new(RuntimeInner {
                group_id,
                state: RwLock::new(state),
                future_round_messages: RwLock::new(BTreeMap::new()),
                epoch_started_hints: RwLock::new(BTreeMap::new()),
                epoch_started_retry: RwLock::new(None),
                prefill_dispatch_retry: RwLock::new(None),
                local_blocks: RwLock::new(local_blocks),
                accepted_local_blocks: RwLock::new(BTreeMap::new()),
                #[cfg(feature = "availability-gossip")]
                availability: RwLock::new(AvailabilityStore::default()),
                address_book: RwLock::new(config.address_book),
                network_client,
                latency_topology: RwLock::new(LatencyTopology::default()),
                signer,
                trust_mode: config.trust_mode,
                mode: config.mode,
                block_cap: config.block_cap,
                consensus_parameters: committed_parameters,
                consensus_node_removal_policy: config.consensus_node_removal_policy,
                snapshot_path: config.snapshot_path,
                durable_block_store,
                trusted_epoch_log,
                trusted_transition_lock: Mutex::new(()),
                dispatch_production_lock: Mutex::new(()),
                telemetry: config.telemetry,
                next_telemetry_span_id: AtomicU64::new(1),
                epoch_commit_tx,
                verified_membership_tx,
                membership_lease_watermarks: Mutex::new(config.membership_lease_watermarks),
            }),
        })
    }

    /// Returns the local node's public identity.
    pub fn self_node(&self) -> NodeIdentity {
        self.inner
            .state
            .read()
            .expect("state lock poisoned")
            .self_node
            .clone()
    }

    /// Returns the runtime execution mode.
    pub fn mode(&self) -> RuntimeMode {
        self.inner.mode
    }

    /// Returns the consensus group served by this runtime.
    pub fn group_id(&self) -> ConsensusGroupId {
        self.inner.group_id
    }

    /// Returns the consensus parameters committed by the runtime.
    pub fn consensus_parameters(&self) -> ConsensusParameters {
        self.inner.consensus_parameters
    }

    /// Subscribes to durable local epoch-chain advancement.
    pub fn subscribe_epoch_commits(&self) -> watch::Receiver<Nonce> {
        self.inner.epoch_commit_tx.subscribe()
    }

    /// Watches the current certified member/relay view.
    ///
    /// Receivers must call [`VerifiedMembershipView::require_fresh`] before
    /// forwarding. A newly installed epoch is published expired until a quorum
    /// membership lease for that exact epoch is installed.
    pub fn watch_verified_membership(&self) -> watch::Receiver<Arc<VerifiedMembershipView>> {
        self.inner.verified_membership_tx.subscribe()
    }

    /// Builds the exact membership lease statement this node can vote for.
    pub fn membership_lease_statement(
        &self,
        request: MembershipLeaseRequest,
    ) -> Result<MembershipLeaseStatement> {
        if request.valid_for_millis == 0
            || request.valid_for_millis > crate::membership::MAX_MEMBERSHIP_LEASE_MILLIS
        {
            return Err(BlossomError::InvalidConfiguration(
                "membership lease duration is outside the supported bound".to_string(),
            ));
        }
        let state = self.inner.state.read().expect("state lock poisoned");
        let head = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let statement = MembershipLeaseStatement {
            group_id: self.inner.group_id,
            epoch_hash: head.hash,
            epoch_nonce: head.body.nonce,
            member_set_hash: head.body.members.hash()?,
            challenge: request.challenge,
            issued_at_unix_millis: request.issued_at_unix_millis,
            valid_for_millis: request.valid_for_millis,
        };
        statement.remaining_validity_at(service_unix_time_millis())?;
        Ok(statement)
    }

    /// Signs a membership lease statement after validating the local view.
    pub fn vote_membership_lease(
        &self,
        request: MembershipLeaseRequest,
    ) -> Result<MembershipLeaseVote> {
        let statement = self.membership_lease_statement(request)?;
        let signer = self
            .inner
            .signer
            .as_ref()
            .ok_or(BlossomError::MissingSecretKey)?;
        let state = self.inner.state.read().expect("state lock poisoned");
        let head = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        if !head.body.verifiers.contains_key(&signer.public_key()) {
            return Err(BlossomError::UnknownSender);
        }
        drop(state);
        let statement_hash = HashType::hash(&borsh::to_vec(&statement).map_err(|error| {
            BlossomError::WireProtocol(format!("encode membership lease watermark: {error}"))
        })?);
        let expires_at_unix_millis = statement.expires_at_unix_millis()?;
        let now_unix_millis = service_unix_time_millis();
        let mut watermarks = self
            .inner
            .membership_lease_watermarks
            .lock()
            .expect("membership lease watermark lock poisoned");
        watermarks.retain(|_, watermark| watermark.expires_at_unix_millis > now_unix_millis);
        match watermarks.get(&statement.challenge) {
            Some(previous) if previous.statement_hash != statement_hash => {
                return Err(BlossomError::InvalidConfiguration(
                    "membership lease challenge was already signed for a different statement"
                        .to_string(),
                ));
            }
            Some(_) => {}
            None => {
                watermarks.insert(
                    statement.challenge,
                    MembershipLeaseWatermark {
                        statement_hash,
                        expires_at_unix_millis,
                    },
                );
            }
        }
        MembershipLeaseVote::signed(statement, signer)
    }

    /// Validates and installs a quorum-certified membership lease.
    pub fn install_membership_lease(
        &self,
        certificate: MembershipLeaseCertificate,
    ) -> Result<Arc<VerifiedMembershipView>> {
        let (epoch_hash, epoch_nonce, members, validators) = {
            let state = self.inner.state.read().expect("state lock poisoned");
            let head = state
                .epochchain
                .epochchain
                .last()
                .ok_or(BlossomError::EmptyEpochChain)?;
            (
                head.hash,
                head.body.nonce,
                head.body.members.clone(),
                head.body.verifiers.clone(),
            )
        };
        let now_unix_millis = service_unix_time_millis();
        certificate.verify(&validators)?;
        if certificate.statement.group_id != self.inner.group_id
            || certificate.statement.epoch_hash != epoch_hash
            || certificate.statement.epoch_nonce != epoch_nonce
            || certificate.statement.member_set_hash != members.hash()?
        {
            return Err(BlossomError::InvalidEpochNonce);
        }
        let lease_expires_at_unix_millis = certificate.statement.expires_at_unix_millis()?;
        let remaining_millis = certificate
            .statement
            .remaining_validity_at(now_unix_millis)?;
        let now = std::time::Instant::now();
        let mut valid_until = now + std::time::Duration::from_millis(remaining_millis);
        let (relays, earliest_relay_expiry) = self.verified_relay_set(&members, now_unix_millis);
        if let Some(relay_expiry) = earliest_relay_expiry {
            valid_until = valid_until.min(
                now + std::time::Duration::from_millis(
                    relay_expiry.saturating_sub(now_unix_millis),
                ),
            );
        }
        let current = self.inner.verified_membership_tx.borrow().clone();
        if current.epoch_hash == epoch_hash
            && lease_expires_at_unix_millis <= current.lease_expires_at_unix_millis
        {
            valid_until = valid_until.min(current.valid_until);
        }
        let view = Arc::new(VerifiedMembershipView {
            group_id: self.inner.group_id,
            epoch_hash,
            epoch_nonce: epoch_nonce.0,
            lease_expires_at_unix_millis,
            valid_until,
            members: Arc::new(members),
            relays: Arc::new(relays),
        });
        self.inner.verified_membership_tx.send_replace(view.clone());
        Ok(view)
    }

    /// Waits for one epoch to appear in this node's committed chain.
    pub async fn wait_for_committed_epoch(
        &self,
        nonce: Nonce,
        timeout: std::time::Duration,
    ) -> Result<Epoch> {
        if timeout.is_zero() {
            return Err(BlossomError::InvalidConfiguration(
                "epoch commit wait timeout must be non-zero".to_string(),
            ));
        }
        let mut commits = self.subscribe_epoch_commits();
        let wait = async {
            loop {
                if let Some(epoch) = self
                    .epochchain()
                    .epochchain
                    .into_iter()
                    .find(|epoch| epoch.body.nonce == nonce)
                {
                    return Ok(epoch);
                }
                commits.changed().await.map_err(|_| {
                    BlossomError::ExternalService(
                        "local epoch commit notification channel closed".to_string(),
                    )
                })?;
            }
        };
        tokio::time::timeout(timeout, wait).await.map_err(|_| {
            BlossomError::ExternalService(format!(
                "timed out waiting for local epoch {nonce} commit"
            ))
        })?
    }

    pub(super) fn publish_epoch_commit(&self) -> Result<()> {
        let (nonce, hash, members) = {
            let state = self.inner.state.read().expect("state lock poisoned");
            let head = state
                .epochchain
                .epochchain
                .last()
                .ok_or(BlossomError::EmptyEpochChain)?;
            (head.body.nonce, head.hash, head.body.members.clone())
        };
        self.inner.epoch_commit_tx.send_replace(nonce);
        self.inner
            .verified_membership_tx
            .send_replace(Arc::new(VerifiedMembershipView {
                group_id: self.inner.group_id,
                epoch_hash: hash,
                epoch_nonce: nonce.0,
                lease_expires_at_unix_millis: 0,
                valid_until: std::time::Instant::now(),
                members: Arc::new(members),
                relays: Arc::new(RelaySet::new()),
            }));
        Ok(())
    }

    /// Emits a structured runtime telemetry event through the configured sink.
    pub fn emit_telemetry_event(
        &self,
        stage: impl Into<String>,
        event: impl Into<String>,
        target: Option<&EpochTarget>,
    ) {
        if !self.inner.telemetry.is_enabled() {
            return;
        }
        let mut telemetry =
            TelemetryEvent::new(crate::telemetry::TelemetryEventKind::Event, stage, event)
                .with_node(self.self_node().public_key())
                .with_group_id(self.inner.group_id);
        telemetry = match target {
            Some(target) => telemetry.with_target(target.last_epoch, target.nonce),
            None => telemetry,
        };
        telemetry = self.with_quorum_telemetry(telemetry);
        self.inner.telemetry.record(telemetry);
    }

    /// Returns the configured event pipeline so embedding services can attach
    /// application events to the same metrics, spans, and structured logs.
    pub fn telemetry(&self) -> TelemetryHandle {
        self.inner.telemetry.clone()
    }

    /// Emits a structured failure without changing protocol behavior or
    /// applying a trusted-network recovery policy.
    pub fn emit_telemetry_failure(
        &self,
        stage: impl Into<String>,
        event: impl Into<String>,
        error: &BlossomError,
        target: Option<&EpochTarget>,
    ) {
        if !self.inner.telemetry.is_enabled() {
            return;
        }
        let mut telemetry =
            TelemetryEvent::new(crate::telemetry::TelemetryEventKind::Event, stage, event)
                .with_node(self.self_node().public_key())
                .with_group_id(self.inner.group_id)
                .with_outcome("error")
                .with_error(error.to_string());
        if let Some(target) = target {
            telemetry = telemetry.with_target(target.last_epoch, target.nonce);
        }
        self.inner
            .telemetry
            .record(self.with_quorum_telemetry(telemetry));
    }

    /// Returns a public snapshot of consensus and service state.
    pub fn status(&self) -> Result<NodeStatus> {
        let state = self.inner.state.read().expect("state lock poisoned");
        let epoch = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let pending_blocks = self
            .inner
            .local_blocks
            .read()
            .expect("block lock poisoned")
            .len();
        let services = self.address_book();

        let node = state.self_node.public_only();

        Ok(NodeStatus {
            group_id: self.inner.group_id,
            node,
            last_epoch: epoch.hash,
            last_epoch_nonce: epoch.body.nonce,
            next_nonce: epoch.body.nonce.new_next(),
            pending_blocks,
            configured_quorum_size: self.inner.consensus_parameters.quorum_size.get(),
            effective_quorum_size: self
                .inner
                .consensus_parameters
                .quorum_size
                .effective(epoch.body.verifiers.len()),
            consensus_parameters_hash: self.inner.consensus_parameters.hash(),
            services,
        })
    }

    /// Returns the durable trusted-log head, if trusted persistence is configured.
    pub fn trusted_epoch_log_head(&self) -> Result<Option<TrustedLogHead>> {
        if !self.inner.trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted epoch log status is only available in trusted mode".to_string(),
            ));
        }
        self.inner
            .trusted_epoch_log
            .as_ref()
            .map(TrustedEpochLog::head)
            .transpose()
    }

    /// Returns service-facing durability and quorum state for trusted active-
    /// active deployments.
    pub fn trusted_operational_status(&self) -> Result<TrustedOperationalStatus> {
        if !self.inner.trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted operational status is only available in trusted mode".to_string(),
            ));
        }
        let state = self.inner.state.read().expect("state lock poisoned");
        let head = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let target_nonce = head.body.nonce.new_next();
        let consensus = state.get_consensus(&head.hash, target_nonce);
        let quorum = consensus.and_then(|consensus| consensus.quorum.get(&consensus.round));
        let expected_round_members = quorum
            .map(|quorum| quorum.msg_matrix.quorum_nodes.len())
            .unwrap_or_default();
        let observed_dispatch_members = quorum.map_or(0, |quorum| {
            quorum.received_dispatches.len() + usize::from(quorum.dispatch_status == Some(true))
        });
        let required_confirmations = if expected_round_members == 0 {
            0
        } else {
            supermajority_count(expected_round_members)
        };
        let required_acknowledgements = required_confirmations;
        let observed_matching_acknowledgements = quorum
            .and_then(|quorum| {
                quorum
                    .trusted_acknowledgements
                    .count
                    .values()
                    .max()
                    .copied()
            })
            .and_then(|count| usize::try_from(count).ok())
            .unwrap_or_default();
        let observed_matching_confirmations = quorum
            .and_then(|quorum| quorum.trusted_confirmations.count.values().max().copied())
            .and_then(|count| usize::try_from(count).ok())
            .unwrap_or_default();
        let head_nonce = head.body.nonce;
        let head_hash = head.hash;
        drop(state);

        let durable_head = self.trusted_epoch_log_head()?;
        let durable = durable_head.is_some();
        let durable_matches_memory = durable_head
            .is_some_and(|durable| durable.nonce == head_nonce && durable.hash == head_hash);
        let pending_round_lock = durable_head.is_some_and(|durable| durable.pending_round_lock);
        let (health, directives) = if !durable || !durable_matches_memory {
            (
                TrustedServiceHealth::Unavailable,
                vec![
                    TrustedServiceDirective::NotifyOperators,
                    TrustedServiceDirective::NotifyUsers,
                    TrustedServiceDirective::DrainWrites,
                    TrustedServiceDirective::RestartOrRedeploy,
                ],
            )
        } else if pending_round_lock && observed_matching_confirmations < required_confirmations {
            (
                TrustedServiceHealth::Degraded,
                vec![
                    TrustedServiceDirective::NotifyOperators,
                    TrustedServiceDirective::AwaitConfirmationQuorum,
                ],
            )
        } else {
            (
                TrustedServiceHealth::Ready,
                vec![TrustedServiceDirective::Continue],
            )
        };
        let status = TrustedOperationalStatus {
            health,
            durable,
            head_nonce,
            head_hash,
            durable_epoch_count: durable_head.map_or(0, |durable| durable.epoch_count),
            pending_round_lock,
            expected_round_members,
            observed_dispatch_members,
            required_acknowledgements,
            observed_matching_acknowledgements,
            required_confirmations,
            observed_matching_confirmations,
            accepts_writes: durable_matches_memory && health != TrustedServiceHealth::Unavailable,
            directives,
        };
        self.inner.telemetry.record_trusted_operational_status(
            self.self_node().public_key(),
            self.inner.group_id,
            &status,
        );
        Ok(status)
    }

    /// Classifies a trusted-runtime failure into service health and directives.
    pub fn assess_trusted_failure(&self, error: &BlossomError) -> Result<TrustedFailureAssessment> {
        if !self.inner.trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted failure assessment is only available in trusted mode".to_string(),
            ));
        }
        let assessment = assess_trusted_durability_failure(error);
        self.inner.telemetry.record_trusted_failure(
            self.self_node().public_key(),
            self.inner.group_id,
            error,
            &assessment,
        );
        Ok(assessment)
    }

    /// Returns diagnostic state for one round of the current epoch.
    pub fn consensus_round_status(&self, round: u8) -> Result<ConsensusRoundStatus> {
        self.ensure_consensus_mode("inspect consensus round")?;
        let target = self.next_epoch_target()?;
        let state = self.inner.state.read().expect("state lock poisoned");
        let quorum = state.get_quorum(&target.last_epoch, target.nonce, round);
        Ok(match quorum {
            Some(quorum) => ConsensusRoundStatus {
                target,
                round,
                expected_quorum_members: quorum.msg_matrix.quorum_nodes.len(),
                dispatch_status: quorum.dispatch_status,
                received_dispatches: quorum.received_dispatches.len(),
                pending_dispatches: quorum.pending_dispatches.len(),
                verified_blocks: quorum.verified_blocks.len(),
                verification_senders: if self.inner.trust_mode.is_trusted() {
                    quorum.trusted_confirmations.confirmations.len()
                } else {
                    quorum.verifications.verifications.len()
                },
                verification_counts: if self.inner.trust_mode.is_trusted() {
                    quorum
                        .trusted_confirmations
                        .count
                        .iter()
                        .map(|(hash, count)| (*hash, u8::try_from(*count).unwrap_or(u8::MAX)))
                        .collect()
                } else {
                    quorum.verifications.count.clone()
                },
                verification_consensus_hash: if self.inner.trust_mode.is_trusted() {
                    quorum.trusted_confirmations.consensus_hash()
                } else {
                    quorum.verifications.consensus_hash()
                },
                proposal_senders: quorum.proposals.proposals.len(),
                proposal_counts: quorum.proposals.count.clone(),
                proposal_consensus: quorum.proposals.consensus(),
                pending_proposals: quorum.pending_proposals.len(),
                pending_commits: quorum.pending_commits.len(),
                commit_senders: quorum.commit_senders.len(),
                commit_true_senders: quorum.commit_true_senders.len(),
            },
            None => ConsensusRoundStatus {
                target,
                round,
                expected_quorum_members: 0,
                dispatch_status: None,
                received_dispatches: 0,
                pending_dispatches: 0,
                verified_blocks: 0,
                verification_senders: 0,
                verification_counts: BTreeMap::new(),
                verification_consensus_hash: None,
                proposal_senders: 0,
                proposal_counts: BTreeMap::new(),
                proposal_consensus: None,
                pending_proposals: 0,
                pending_commits: 0,
                commit_senders: 0,
                commit_true_senders: 0,
            },
        })
    }

    /// Returns all currently validated service records in the address book.
    pub fn address_book(&self) -> Vec<Service> {
        self.inner
            .address_book
            .read()
            .expect("address book lock poisoned")
            .clone()
            .into_services()
    }

    /// Records a direct RTT measurement owned by this node.
    pub fn observe_peer_latency(
        &self,
        peer: PubKey,
        rtt_micros: u64,
        observed_at_millis: u64,
    ) -> bool {
        let source = self.self_node().public_key();
        self.inner
            .latency_topology
            .write()
            .expect("latency topology lock poisoned")
            .observe(source, peer, rtt_micros, observed_at_millis)
    }

    /// Returns the fresh directly observed RTT to `peer`, if one exists.
    /// This lookup never performs topology reconstruction.
    pub fn direct_peer_latency_micros(&self, peer: PubKey) -> Option<u64> {
        let source = self.self_node().public_key();
        self.inner
            .latency_topology
            .read()
            .expect("latency topology lock poisoned")
            .direct_rtt_micros(source, peer, unix_time_millis())
    }

    /// Measures a live peer RTT and records it after checking endpoint identity.
    pub async fn ping_and_observe_latency(
        &self,
        client: &TcpServiceClient,
        service: &Service,
        ping: NodePing,
    ) -> Result<NodePong> {
        let timed = client.timed_ping(service, ping).await?;
        if timed.pong.public_key != service.public_key {
            return Err(BlossomError::KeyMismatch);
        }
        if !timed
            .pong
            .consensus_parameters_compatible(self.inner.consensus_parameters)
        {
            return Err(BlossomError::ConsensusParametersMismatch {
                configured: self.inner.consensus_parameters.quorum_size.get(),
                committed: timed.pong.quorum_size,
            });
        }
        self.observe_peer_latency(
            timed.pong.public_key,
            timed.rtt.as_micros().min(u128::from(u64::MAX)) as u64,
            unix_time_millis(),
        );
        Ok(timed.pong)
    }

    /// Exports bounded, reporter-owned topology metadata.
    pub fn latency_topology_metadata(&self) -> LatencyTopologyMetadataV1 {
        let reporter = self.self_node().public_key();
        self.inner
            .latency_topology
            .read()
            .expect("latency topology lock poisoned")
            .metadata(reporter, unix_time_millis())
    }

    /// Merges topology metadata after binding it to an authenticated peer key.
    pub fn merge_latency_topology_metadata(
        &self,
        authenticated_reporter: PubKey,
        metadata: &LatencyTopologyMetadataV1,
    ) -> Result<usize> {
        self.inner
            .latency_topology
            .write()
            .expect("latency topology lock poisoned")
            .merge_metadata(authenticated_reporter, metadata, unix_time_millis())
    }

    /// Returns a direct, trilaterated, or bounded RTT estimate.
    pub fn estimate_peer_latency(&self, source: PubKey, peer: PubKey) -> Option<LatencyEstimate> {
        self.inner
            .latency_topology
            .read()
            .expect("latency topology lock poisoned")
            .estimate(source, peer, unix_time_millis())
    }

    /// Selects the closest candidate according to the live geometric map.
    pub fn closest_peer(&self, peers: impl IntoIterator<Item = PubKey>) -> Option<ClosestPeer> {
        let source = self.self_node().public_key();
        self.inner
            .latency_topology
            .read()
            .expect("latency topology lock poisoned")
            .closest_peer(source, peers, unix_time_millis())
    }
}
