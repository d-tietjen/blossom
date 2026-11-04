//! Local consensus production, fan-out planning, and stage progression.

use super::*;

impl NodeRuntime {
    /// Resolves a fan-out strategy into validated destination services.
    pub fn fanout_targets(&self, strategy: &FanOutStrategy) -> Vec<Service> {
        let self_node = self.self_node();
        let address_book = self
            .inner
            .address_book
            .read()
            .expect("address book lock poisoned");
        select_fanout_targets_with_size(
            &self_node,
            &address_book,
            strategy,
            self.inner.consensus_parameters.quorum_size,
        )
    }

    /// Returns the deterministic peer set assigned to `round`.
    pub fn round_consensus_services(&self, round: u8) -> Result<Vec<Service>> {
        self.ensure_consensus_mode("select round consensus services")?;
        let target = self.next_epoch_target()?;
        let peers = {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            state
                .get_mut_consensus(&target.last_epoch, target.nonce)
                .peers(round)
        };
        let address_book = self
            .inner
            .address_book
            .read()
            .expect("address book lock poisoned");
        Ok(peers
            .into_iter()
            .filter_map(|peer| {
                address_book
                    .service_for(ServiceKind::Consensus, &peer)
                    .cloned()
            })
            .collect())
    }

    /// Returns the deterministic committee that gathers global final-round
    /// certificate shares for the current epoch.
    ///
    /// Every validator sends its final commit to this bounded committee.
    /// Committee members publish the resulting supermajority certificate, and
    /// the remaining validators install it through certified catch-up.
    pub fn finality_collector_services(&self) -> Result<Vec<Service>> {
        self.ensure_consensus_mode("select finality collectors")?;
        let target = self.next_epoch_target()?;
        let self_key = self.self_node().public_key();
        let mut ranked = {
            let state = self.inner.state.read().expect("state lock poisoned");
            let epoch = state
                .epochchain
                .epochchain
                .last()
                .ok_or(BlossomError::EmptyEpochChain)?;
            epoch
                .body
                .verifiers
                .keys()
                .copied()
                .map(|validator| {
                    let score = HashType::hash_slices([
                        b"blossom/finality-collector/v1".as_slice(),
                        target.last_epoch.as_ref(),
                        validator.as_ref(),
                    ]);
                    (score, validator)
                })
                .collect::<Vec<_>>()
        };
        ranked.sort_unstable();
        ranked.truncate(
            ranked
                .len()
                .min(self.inner.consensus_parameters.quorum_size.get()),
        );
        let collectors = ranked
            .into_iter()
            .map(|(_, validator)| validator)
            .filter(|validator| *validator != self_key)
            .collect::<Vec<_>>();
        let address_book = self
            .inner
            .address_book
            .read()
            .expect("address book lock poisoned");
        Ok(collectors
            .into_iter()
            .filter_map(|collector| {
                address_book
                    .service_for(ServiceKind::Consensus, &collector)
                    .cloned()
            })
            .collect())
    }

    /// Builds the prefill dispatch work required before the next round begins.
    pub fn prefill_dispatch_plan(&self) -> Result<PrefillDispatchPlan> {
        self.ensure_consensus_mode("plan v2 prefill dispatch")?;
        let self_node = self.self_node();
        let target = self.next_epoch_target()?;
        let state = self.inner.state.read().expect("state lock poisoned");
        let epoch = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        let recipients = select_prefill_recipients_with_size(
            epoch.body.verifiers.keys().copied(),
            &self_node.public_key(),
            target.last_epoch,
            self_node.shuffle,
            epoch.body.effective_consensus_parameters().quorum_size,
        );
        drop(state);

        let address_book = self
            .inner
            .address_book
            .read()
            .expect("address book lock poisoned");
        let mut services = Vec::new();
        let mut missing_services = Vec::new();
        for recipient in &recipients {
            match address_book.service_for(ServiceKind::Consensus, recipient) {
                Some(service) => services.push(service.clone()),
                None => missing_services.push(*recipient),
            }
        }

        Ok(PrefillDispatchPlan {
            target,
            source: self_node.public_key(),
            recipients,
            services,
            missing_services,
        })
    }

    /// Returns the number of rounds required to cover the effective quorum.
    pub fn quorum_round_count(&self) -> Result<usize> {
        self.ensure_consensus_mode("count quorum rounds")?;
        let self_node = self.self_node();
        let target = self.next_epoch_target()?;
        let state = self.inner.state.read().expect("state lock poisoned");
        let epoch = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        Ok(select_quorums_with_size(
            epoch.body.verifiers.keys().copied(),
            &self_node.public_key(),
            target.last_epoch,
            self_node.shuffle,
            epoch.body.effective_consensus_parameters().quorum_size,
        )
        .len())
    }

    /// Returns the round currently eligible to make consensus progress.
    pub fn current_consensus_round(&self) -> Result<u8> {
        self.ensure_consensus_mode("read current consensus round")?;
        let target = self.next_epoch_target()?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        Ok(state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .round)
    }

    /// Reports whether this node already seeded its prefill dispatch.
    pub fn has_local_prefill_dispatch(&self) -> Result<bool> {
        self.ensure_consensus_mode("check local prefill dispatch")?;
        let target = self.next_epoch_target()?;
        let self_key = self.self_node().public_key();
        let state = self.inner.state.read().expect("state lock poisoned");
        Ok(state
            .prefill_dispatches(&target.last_epoch, target.nonce)
            .is_some_and(|records| records.contains_key(&self_key)))
    }

    /// Broadcasts one protocol message according to `strategy`.
    pub async fn broadcast(&self, msg: Msg, strategy: FanOutStrategy) -> Result<BroadcastReport> {
        self.broadcast_request(WireRequest::Message(msg), strategy)
            .await
    }

    /// Broadcasts an arbitrary wire request according to `strategy`.
    pub async fn broadcast_request(
        &self,
        request: WireRequest,
        strategy: FanOutStrategy,
    ) -> Result<BroadcastReport> {
        let targets = self.fanout_targets(&strategy);
        broadcast_wire_request_pooled(request, targets, &self.inner.network_client).await
    }

    /// Builds and broadcasts this node's next prefill dispatch.
    pub async fn broadcast_prefill_dispatch(&self) -> Result<PrefillDispatchBroadcastReport> {
        let mut plan = self.prefill_dispatch_plan()?;
        let target = plan.target.clone();
        let (dispatch, pending_recipients) = {
            let retry = self
                .inner
                .prefill_dispatch_retry
                .read()
                .expect("prefill retry lock poisoned")
                .as_ref()
                .filter(|retry| {
                    retry.dispatch.header.last_epoch == target.last_epoch
                        && retry.dispatch.header.nonce == target.nonce
                })
                .cloned();
            match retry {
                Some(retry) => (retry.dispatch, retry.pending_recipients),
                None => {
                    let dispatch = self.dispatch_local_block(0)?;
                    {
                        let mut state = self.inner.state.write().expect("state lock poisoned");
                        state.record_prefill_dispatch(&dispatch)?;
                    }
                    let pending_recipients =
                        plan.recipients.iter().copied().collect::<BTreeSet<_>>();
                    *self
                        .inner
                        .prefill_dispatch_retry
                        .write()
                        .expect("prefill retry lock poisoned") = Some(PrefillDispatchRetry {
                        dispatch: dispatch.clone(),
                        pending_recipients: pending_recipients.clone(),
                        last_failures: BTreeMap::new(),
                    });
                    (dispatch, pending_recipients)
                }
            }
        };
        plan.recipients
            .retain(|recipient| pending_recipients.contains(recipient));
        plan.services
            .retain(|service| pending_recipients.contains(&service.public_key));
        plan.missing_services
            .retain(|recipient| pending_recipients.contains(recipient));
        let broadcast = broadcast_wire_request_pooled(
            WireRequest::PrefillDispatch(dispatch.clone()),
            plan.services.clone(),
            &self.inner.network_client,
        )
        .await?;
        {
            let mut retry = self
                .inner
                .prefill_dispatch_retry
                .write()
                .expect("prefill retry lock poisoned");
            if let Some(retry) = retry.as_mut()
                && retry.dispatch.header.last_epoch == target.last_epoch
                && retry.dispatch.header.nonce == target.nonce
            {
                for receipt in &broadcast.receipts {
                    if receipt.accepted() {
                        retry.pending_recipients.remove(&receipt.target);
                        retry.last_failures.remove(&receipt.target);
                    } else {
                        let failure = match &receipt.response {
                            Ok(WireResponse::Error(message)) => message.clone(),
                            Ok(response) => format!(
                                "unexpected {} response to prefill dispatch",
                                response.kind()
                            ),
                            Err(error) => error.to_string(),
                        };
                        retry.last_failures.insert(receipt.target, failure);
                    }
                }
            }
        }

        Ok(PrefillDispatchBroadcastReport {
            plan,
            dispatch,
            broadcast,
        })
    }

    /// Broadcasts prefill state only when the runtime has work to send.
    pub async fn try_broadcast_prefill_dispatch(
        &self,
    ) -> Result<Option<PrefillDispatchBroadcastReport>> {
        if self.quorum_round_count()? <= 1 {
            return Ok(None);
        }
        let target = self.next_epoch_target()?;
        let retry_complete = self
            .inner
            .prefill_dispatch_retry
            .read()
            .expect("prefill retry lock poisoned")
            .as_ref()
            .filter(|retry| {
                retry.dispatch.header.last_epoch == target.last_epoch
                    && retry.dispatch.header.nonce == target.nonce
            })
            .is_some_and(|retry| retry.pending_recipients.is_empty());
        if retry_complete {
            return Ok(None);
        }
        self.broadcast_prefill_dispatch().await.map(Some)
    }

    /// Seeds buffered prefill dispatches into the specified active round.
    pub fn seed_prefill_dispatches_for_round(&self, round: u8) -> Result<usize> {
        self.ensure_consensus_mode("seed prefill dispatches")?;
        let target = self.next_epoch_target()?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        Ok(state.seed_prefill_dispatches_into_quorum(&target.last_epoch, target.nonce, round))
    }

    /// Advances a prefill-enabled epoch to round one only after every routed
    /// prefill sender expected by this node has delivered its block set.
    ///
    /// Without this barrier a node can dispatch an incomplete aggregate into
    /// the final topology round, allowing different quorums to certify
    /// different epoch contents.
    pub fn try_activate_prefill_round(&self) -> Result<bool> {
        self.ensure_consensus_mode("activate prefill round")?;
        if self.quorum_round_count()? <= 1 {
            return Ok(true);
        }

        let status = self.prefill_stage_status()?;
        if !status.ready() {
            return Ok(false);
        }

        let mut state = self.inner.state.write().expect("state lock poisoned");
        let consensus = state.get_mut_consensus(&status.target.last_epoch, status.target.nonce);
        if consensus.peers.len() > 1 && consensus.round == 0 {
            consensus.round = 1;
        }
        Ok(true)
    }

    /// Returns the exact inbound and outbound state of the prefill barrier.
    pub fn prefill_stage_status(&self) -> Result<PrefillStageStatus> {
        self.ensure_consensus_mode("inspect prefill stage")?;
        let self_node = self.self_node();
        let target = self.next_epoch_target()?;
        let (verifiers, recorded_senders, current_round) = {
            let state = self.inner.state.read().expect("state lock poisoned");
            let epoch = state
                .epochchain
                .epochchain
                .last()
                .ok_or(BlossomError::EmptyEpochChain)?;
            let recorded = state
                .prefill_dispatches(&target.last_epoch, target.nonce)
                .map(|records| records.keys().copied().collect::<BTreeSet<_>>())
                .unwrap_or_default();
            (
                epoch.body.verifiers.values().cloned().collect::<Vec<_>>(),
                recorded,
                state
                    .get_consensus(&target.last_epoch, target.nonce)
                    .map(|consensus| consensus.round)
                    .unwrap_or_default(),
            )
        };
        let quorum_size = self.inner.consensus_parameters.quorum_size;
        let all_keys = verifiers
            .iter()
            .map(NodeIdentity::public_key)
            .collect::<Vec<_>>();
        let expected_senders = verifiers
            .iter()
            .filter_map(|sender| {
                let sender_key = sender.public_key();
                if sender_key == self_node.public_key() {
                    return Some(sender_key);
                }
                select_prefill_recipients_with_size(
                    all_keys.iter().copied(),
                    &sender_key,
                    target.last_epoch,
                    sender.shuffle,
                    quorum_size,
                )
                .contains(&self_node.public_key())
                .then_some(sender_key)
            })
            .collect::<BTreeSet<_>>();
        let missing_senders = expected_senders
            .difference(&recorded_senders)
            .copied()
            .collect();
        let (pending_recipients, last_failures) = self
            .inner
            .prefill_dispatch_retry
            .read()
            .expect("prefill retry lock poisoned")
            .as_ref()
            .filter(|retry| {
                retry.dispatch.header.last_epoch == target.last_epoch
                    && retry.dispatch.header.nonce == target.nonce
            })
            .map(|retry| {
                (
                    retry.pending_recipients.clone(),
                    retry.last_failures.clone(),
                )
            })
            .unwrap_or_default();
        Ok(PrefillStageStatus {
            target,
            self_key: self_node.public_key(),
            current_round,
            expected_senders,
            recorded_senders,
            missing_senders,
            pending_recipients,
            last_failures,
        })
    }

    /// Produces this node's dispatch when the requested round is ready.
    pub fn try_produce_dispatch(&self, round: u8) -> Result<Option<Dispatch>> {
        self.try_produce_dispatch_for_target(round, None)
    }

    pub(crate) fn try_produce_dispatch_for_target(
        &self,
        round: u8,
        required_target: Option<&EpochTarget>,
    ) -> Result<Option<Dispatch>> {
        self.ensure_consensus_mode("produce dispatch")?;
        let _production = self
            .inner
            .dispatch_production_lock
            .lock()
            .expect("dispatch production lock poisoned");
        let target = self.next_epoch_target()?;
        if required_target.is_some_and(|required| required != &target) {
            return Ok(None);
        }
        {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
            if quorum.dispatch_status == Some(true) {
                if quorum.dispatch_retry {
                    quorum.dispatch_retry = false;
                    return quorum.local_dispatch.clone().map(Some).ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "dispatch retry is missing its original message".to_string(),
                        )
                    });
                }
                return Ok(None);
            }
        }
        self.dispatch_local_block_locked(round, target).map(Some)
    }

    /// Schedules an exact replay of the locally signed dispatch.
    ///
    /// A peer may reject a valid dispatch until an earlier stage message has
    /// arrived, so both verified and trusted modes retry the immutable wire
    /// message after any incomplete broadcast.
    pub(crate) fn schedule_dispatch_retry(&self, round: u8, blocks_hash: HashType) -> Result<()> {
        let target = self.next_epoch_target()?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
        if quorum
            .local_dispatch
            .as_ref()
            .is_some_and(|dispatch| dispatch.body.blocks_hash == blocks_hash)
        {
            quorum.dispatch_retry = true;
        }
        Ok(())
    }

    /// Broadcasts the local node's monotonic trusted availability view.
    ///
    /// Acknowledgements may grow as delayed blocks arrive. They are not
    /// durable confirmation locks and are never produced in verified mode.
    pub fn try_produce_trusted_acknowledgement(
        &self,
        round: u8,
    ) -> Result<Option<TrustedAcknowledgement>> {
        self.ensure_consensus_mode("produce trusted acknowledgement")?;
        if !self.inner.trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted acknowledgements are unavailable in verified mode".to_string(),
            ));
        }
        let target = self.next_epoch_target()?;
        let self_node = self.self_node();
        let body = {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            state.seed_prefill_dispatches_into_quorum(&target.last_epoch, target.nonce, round);
            let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
            if !quorum.has_trusted_dispatch_quorum() {
                return Ok(None);
            }
            quorum.verify_trusted();
            quorum.activate_pending_trusted_messages()?;
            let blocks = quorum.verified_blocks();
            let blocks_hash = blocks.hash();
            if quorum.last_trusted_acknowledgement_hash == Some(blocks_hash)
                && quorum.trusted_acknowledgement_retry != Some(blocks_hash)
            {
                return Ok(None);
            }
            VerificationBody {
                blocks_hash,
                blocks,
            }
        };
        let acknowledgement = TrustedAcknowledgement {
            header: self.signed_header_for_body(
                &self_node,
                &target,
                round,
                MSGKey::TrustedAcknowledgement,
                &body,
            )?,
            body,
        };
        let mut state = self.inner.state.write().expect("state lock poisoned");
        let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
        if quorum.last_trusted_acknowledgement_hash == Some(acknowledgement.body.blocks_hash) {
            quorum.trusted_acknowledgement_retry = None;
            return Ok(Some(acknowledgement));
        }
        quorum
            .trusted_acknowledgements
            .record(acknowledgement.clone())?;
        quorum.last_trusted_acknowledgement_hash = Some(acknowledgement.body.blocks_hash);
        quorum.trusted_acknowledgement_retry = None;
        Ok(Some(acknowledgement))
    }

    pub(crate) fn schedule_trusted_acknowledgement_retry(
        &self,
        round: u8,
        blocks_hash: HashType,
    ) -> Result<()> {
        if !self.inner.trust_mode.is_trusted() {
            return Ok(());
        }
        let target = self.next_epoch_target()?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
        if quorum.last_trusted_acknowledgement_hash == Some(blocks_hash) {
            quorum.trusted_acknowledgement_retry = Some(blocks_hash);
        }
        Ok(())
    }

    /// Produces this node's verification when the requested round is ready.
    pub fn try_produce_verification(&self, round: u8) -> Result<Option<Verification>> {
        self.ensure_consensus_mode("produce verification")?;
        let _trusted_transition = self.inner.trusted_epoch_log.as_ref().map(|_| {
            self.inner
                .trusted_transition_lock
                .lock()
                .expect("trusted transition lock poisoned")
        });
        let target = self.next_epoch_target()?;
        let self_node = self.self_node();
        if !self.inner.trust_mode.is_trusted() {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
            if quorum.verification_retry {
                let verification = quorum
                    .verifications
                    .verifications
                    .get(&self_node.public_key())
                    .cloned()
                    .ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "verification retry is missing its immutable message".to_string(),
                        )
                    })?;
                quorum.verification_retry = false;
                return Ok(Some(verification));
            }
        }
        if self.inner.trust_mode.is_trusted() {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
            if let Some(retry_hash) = quorum.trusted_confirmation_retry {
                let confirmation = quorum
                    .trusted_confirmations
                    .confirmations
                    .get(&self_node.public_key())
                    .filter(|confirmation| confirmation.body.blocks_hash == retry_hash)
                    .cloned()
                    .ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "trusted confirmation retry is missing its immutable message"
                                .to_string(),
                        )
                    })?;
                quorum.trusted_confirmation_retry = None;
                return Ok(Some(confirmation));
            }
        }
        let trusted_round_id = if self.inner.trust_mode.is_trusted() {
            let previous_epoch_nonce = self
                .inner
                .state
                .read()
                .expect("state lock poisoned")
                .epochchain
                .epochchain
                .last()
                .ok_or(BlossomError::EmptyEpochChain)?
                .body
                .nonce;
            Some(TrustedRoundId {
                group_id: target.group_id,
                previous_epoch_hash: target.last_epoch,
                previous_epoch_nonce,
                nonce: target.nonce,
                round,
            })
        } else {
            None
        };
        let persisted_lock = match (
            self.inner.trusted_epoch_log.as_ref(),
            trusted_round_id.as_ref(),
        ) {
            (Some(store), Some(round_id)) => store.round_lock(round_id)?,
            _ => None,
        };
        let (body, trusted_blocks, trusted_round_id) = {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            state.seed_prefill_dispatches_into_quorum(&target.last_epoch, target.nonce, round);
            let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
            if quorum.verification_sent {
                return Ok(None);
            }
            if self.inner.trust_mode.is_trusted() {
                let round_id = trusted_round_id.expect("trusted round identity initialized above");
                if let Some(round_lock) = persisted_lock.as_ref() {
                    if round_lock.round_id != round_id {
                        return Err(BlossomError::InvalidConfiguration(
                            "durable trusted confirmation lock targets a different round"
                                .to_string(),
                        ));
                    }
                    for (hash, block) in &round_lock.blocks {
                        quorum.record_verified_block(*hash, block.clone());
                    }
                    quorum.verified_blocks_hash = Some(quorum.verified_blocks_hash());
                    (
                        round_lock.verification.body.clone(),
                        Some(round_lock.blocks.clone()),
                        Some(round_id),
                    )
                } else {
                    quorum.activate_pending_trusted_messages()?;
                    let Some(body) = quorum.trusted_acknowledgements.consensus_body().cloned()
                    else {
                        return Ok(None);
                    };
                    let blocks = quorum.trusted_candidate_blocks(&body).ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "trusted acknowledgement quorum references unavailable blocks"
                                .to_string(),
                        )
                    })?;
                    (body, Some(blocks), Some(round_id))
                }
            } else {
                if !quorum.has_complete_dispatch_set() {
                    return Ok(None);
                }
                quorum.verify();
                let blocks = quorum.verified_blocks();
                (
                    VerificationBody {
                        blocks_hash: blocks.hash(),
                        blocks,
                    },
                    None,
                    None,
                )
            }
        };
        let message = Verification {
            header: self.signed_header_for_body(
                &self_node,
                &target,
                round,
                MSGKey::Verification,
                &body,
            )?,
            body,
        };

        if let (Some(store), Some(blocks), Some(round_id)) = (
            self.inner.trusted_epoch_log.as_ref(),
            trusted_blocks.as_ref(),
            trusted_round_id,
        ) {
            store.lock_round(&TrustedRoundLock {
                round_id,
                verification: message.clone(),
                blocks: blocks.clone(),
            })?;
        }

        let mut state = self.inner.state.write().expect("state lock poisoned");
        let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
        if quorum.verification_sent {
            return Ok(None);
        }
        if self.inner.trust_mode.is_trusted() {
            if quorum.trusted_candidate_blocks(&message.body).is_none() {
                return Err(BlossomError::WireProtocol(
                    "trusted confirmation references unavailable local blocks".to_string(),
                ));
            }
            quorum.trusted_confirmations.record(message.clone())?;
        } else {
            if message.body.blocks != quorum.verified_blocks()
                || message.body.blocks_hash != quorum.verified_blocks_hash()
            {
                return Err(BlossomError::WireProtocol(
                    "local verified block set changed before verification could be recorded"
                        .to_string(),
                ));
            }
            quorum.verifications.record(message.clone());
        }
        quorum.verification_sent = true;
        Ok(Some(message))
    }

    pub(crate) fn schedule_verification_retry(
        &self,
        round: u8,
        blocks_hash: HashType,
    ) -> Result<()> {
        if self.inner.trust_mode.is_trusted() {
            return Ok(());
        }
        let target = self.next_epoch_target()?;
        let self_key = self.self_node().public_key();
        let mut state = self.inner.state.write().expect("state lock poisoned");
        let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
        if quorum
            .verifications
            .verifications
            .get(&self_key)
            .is_some_and(|verification| verification.body.blocks_hash == blocks_hash)
        {
            quorum.verification_retry = true;
        }
        Ok(())
    }

    pub(crate) fn schedule_trusted_confirmation_retry(
        &self,
        round: u8,
        blocks_hash: HashType,
    ) -> Result<()> {
        if !self.inner.trust_mode.is_trusted() {
            return Ok(());
        }
        let target = self.next_epoch_target()?;
        let self_key = self.self_node().public_key();
        let mut state = self.inner.state.write().expect("state lock poisoned");
        let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
        if quorum
            .trusted_confirmations
            .confirmations
            .get(&self_key)
            .is_some_and(|confirmation| confirmation.body.blocks_hash == blocks_hash)
        {
            quorum.trusted_confirmation_retry = Some(blocks_hash);
        }
        Ok(())
    }

    /// Completes one trusted dissemination round after a supermajority has
    /// confirmed the same immutable block set.
    pub fn complete_trusted_verification(
        &self,
        round: u8,
        expected_blocks_hash: HashType,
    ) -> Result<bool> {
        self.ensure_consensus_mode("complete trusted verification")?;
        if !self.inner.trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted verification completion requires trusted mode".to_string(),
            ));
        }
        let _trusted_transition = self.inner.trusted_epoch_log.as_ref().map(|_| {
            self.inner
                .trusted_transition_lock
                .lock()
                .expect("trusted transition lock poisoned")
        });
        let target = self.next_epoch_target()?;
        let self_key = self.self_node().public_key();
        let (confirmed_blocks, previous_epoch_nonce, final_round) = {
            let state = self.inner.state.read().expect("state lock poisoned");
            let consensus = state
                .get_consensus(&target.last_epoch, target.nonce)
                .ok_or(BlossomError::FailedConsensus)?;
            let quorum = state
                .get_quorum(&target.last_epoch, target.nonce, round)
                .ok_or(BlossomError::FailedConsensus)?;
            let local_confirmation_matches = quorum
                .trusted_confirmations
                .confirmations
                .get(&self_key)
                .is_some_and(|confirmation| confirmation.body.blocks_hash == expected_blocks_hash);
            if !quorum.verification_sent
                || !local_confirmation_matches
                || quorum.trusted_confirmations.consensus_hash() != Some(expected_blocks_hash)
            {
                return Ok(false);
            }
            let confirmed_blocks = quorum
                .trusted_confirmations
                .confirmations
                .get(&self_key)
                .expect("matching local trusted confirmation checked above")
                .body
                .blocks
                .clone();
            let previous_epoch_nonce = state
                .epochchain
                .epochchain
                .last()
                .ok_or(BlossomError::EmptyEpochChain)?
                .body
                .nonce;
            (
                confirmed_blocks,
                previous_epoch_nonce,
                consensus.peers.len() <= usize::from(round) + 1,
            )
        };
        if !final_round {
            return self
                .inner
                .state
                .write()
                .expect("state lock poisoned")
                .advance_trusted_round(&target.last_epoch, target.nonce, round, &confirmed_blocks);
        }
        let epoch = self
            .inner
            .state
            .read()
            .expect("state lock poisoned")
            .prepare_trusted_epoch(&target.last_epoch, target.nonce, round, &confirmed_blocks)?;
        let round_id = TrustedRoundId {
            group_id: target.group_id,
            previous_epoch_hash: target.last_epoch,
            previous_epoch_nonce,
            nonce: target.nonce,
            round,
        };
        if let Some(store) = self.inner.trusted_epoch_log.as_ref() {
            store.append_epoch(&epoch, Some(round_id))?;
            let pending = store.pending_local_block()?;
            self.inner
                .local_blocks
                .write()
                .expect("block lock poisoned")
                .reconcile_durable_pending_block(pending)?;
        }
        {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            let current = state
                .epochchain
                .epochchain
                .last()
                .ok_or(BlossomError::EmptyEpochChain)?;
            if current.hash == epoch.hash {
                return Ok(false);
            }
            state.install_trusted_epoch(epoch)?;
        }
        // Legacy snapshots remain an explicit compatibility artifact. A
        // configured append-only trusted log is already durable and avoids an
        // O(history) snapshot rewrite on the commit path.
        if self.inner.trusted_epoch_log.is_none() {
            self.persist_snapshot()?;
        }
        self.publish_epoch_commit()?;
        Ok(true)
    }

    /// Completes trusted verification when all required acknowledgements exist.
    pub fn try_complete_trusted_verification(&self, round: u8) -> Result<bool> {
        if !self.inner.trust_mode.is_trusted() {
            return Ok(false);
        }
        let target = self.next_epoch_target()?;
        let self_key = self.self_node().public_key();
        let expected = {
            let state = self.inner.state.read().expect("state lock poisoned");
            let Some(quorum) = state.get_quorum(&target.last_epoch, target.nonce, round) else {
                return Ok(false);
            };
            let Some(local) = quorum.trusted_confirmations.confirmations.get(&self_key) else {
                return Ok(false);
            };
            local.body.blocks_hash
        };
        self.complete_trusted_verification(round, expected)
    }

    /// Produces this node's proposal when the requested round is ready.
    pub fn try_produce_proposal(&self, round: u8) -> Result<Option<Proposal>> {
        self.ensure_consensus_mode("produce proposal")?;
        if self.inner.trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted mode uses confirmation quorum finality, not proposals".to_string(),
            ));
        }
        let target = self.next_epoch_target()?;
        let self_node = self.self_node();
        {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
            if quorum.proposal_retry {
                let proposal = quorum
                    .proposals
                    .proposals
                    .get(&self_node.public_key())
                    .cloned()
                    .ok_or_else(|| {
                        BlossomError::InvalidConfiguration(
                            "proposal retry is missing its immutable message".to_string(),
                        )
                    })?;
                quorum.proposal_retry = false;
                return Ok(Some(proposal));
            }
        }
        let body = {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            state.seed_prefill_dispatches_into_quorum(&target.last_epoch, target.nonce, round);
            let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
            activate_pending_proposals(quorum);
            if quorum.proposal_sent {
                return Ok(None);
            }
            let Some(approved_hash) = quorum.verifications.consensus_hash() else {
                return Ok(None);
            };
            let approved_blocks = quorum.verified_blocks();
            if approved_blocks.hash() != approved_hash {
                return Ok(None);
            }
            let verif = quorum
                .verifications
                .verifications
                .iter()
                .filter_map(|(sender, verification)| {
                    (verification.body.blocks_hash == approved_hash)
                        .then_some((*sender, verification.header.signature))
                })
                .take(quorum.verifications.supermajority as usize)
                .collect::<Vec<_>>();
            if verif.len() < quorum.verifications.supermajority as usize {
                return Ok(None);
            }
            ProposalBody {
                consensus: true,
                approved_blocks: Some(approved_blocks.clone()),
                approved_hash: Some(approved_hash),
                verif: Some(verif),
                signature_tree: Some(approved_blocks),
                signature_tree_hash: Some(approved_hash),
            }
        };
        body.validate()?;
        let message = Proposal {
            header: self.signed_header_for_body(
                &self_node,
                &target,
                round,
                MSGKey::Proposal,
                &body,
            )?,
            body,
        };

        let mut state = self.inner.state.write().expect("state lock poisoned");
        let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
        if quorum.proposal_sent {
            return Ok(None);
        }
        self.verify_proposal_proof(&message.header, &message.body, quorum)?;
        quorum.proposal_sent = true;
        quorum.proposals.record(message.clone());
        Ok(Some(message))
    }

    pub(crate) fn schedule_proposal_retry(&self, round: u8, signature: Signature) -> Result<()> {
        let target = self.next_epoch_target()?;
        let self_key = self.self_node().public_key();
        let mut state = self.inner.state.write().expect("state lock poisoned");
        let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
        if quorum
            .proposals
            .proposals
            .get(&self_key)
            .is_some_and(|proposal| proposal.header.signature == signature)
        {
            quorum.proposal_retry = true;
        }
        Ok(())
    }

    /// Produces this node's commit when the requested round is ready.
    pub fn try_produce_commit(&self, round: u8) -> Result<Option<Commit>> {
        self.ensure_consensus_mode("produce commit")?;
        if self.inner.trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted mode uses confirmation quorum finality, not commit votes".to_string(),
            ));
        }
        let target = self.next_epoch_target()?;
        let self_node = self.self_node();
        let body = {
            let state = self.inner.state.read().expect("state lock poisoned");
            let Some(quorum) = state.get_quorum(&target.last_epoch, target.nonce, round) else {
                return Ok(None);
            };
            if quorum.commit_senders.contains(&self_node.public_key()) {
                return Ok(None);
            }
            let Some(consensus) = quorum.proposals.consensus() else {
                return Ok(None);
            };
            let epoch_hash = if consensus {
                state
                    .prepare_verified_epoch(&target.last_epoch, target.nonce, round)?
                    .map(|epoch| epoch.hash)
            } else {
                None
            };
            let epoch_signature = epoch_hash
                .map(|hash| {
                    self.inner
                        .signer
                        .as_ref()
                        .map(|signer| signer.sign(hash.as_ref()))
                        .map_or_else(|| self_node.sign(hash.as_ref()), Ok)
                })
                .transpose()?;
            CommitBody {
                consensus,
                signature_tree_insert: None,
                epoch_hash,
                epoch_signature,
            }
        };
        let message = Commit {
            header: self.signed_header_for_body(
                &self_node,
                &target,
                round,
                MSGKey::Commit,
                &body,
            )?,
            body,
        };

        let mut chain_extended = false;
        {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            let (sender_is_authorized, required_signatures) =
                commit_sender_and_threshold(&mut state, &message.header)?;
            if !sender_is_authorized {
                return Err(BlossomError::UnknownSender);
            }
            if let Some(quorum) = state.get_quorum(&target.last_epoch, target.nonce, round) {
                if quorum.commit_senders.contains(&self_node.public_key()) {
                    return Ok(None);
                }
                if message.body.consensus && quorum.proposals.consensus() != Some(true) {
                    return Err(BlossomError::WireProtocol(
                        "true commit requires a local proposal supermajority".to_string(),
                    ));
                }
            }
            validate_commit_epoch_share(&state, &message)?;
            let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
            quorum.local_commit = Some(message.clone());
            record_commit_vote(quorum, message.clone(), required_signatures);
            if quorum.commit_sent {
                let before = state.epochchain.epochchain.len();
                state.advance_epoch(&target.last_epoch, target.nonce, round, true);
                chain_extended = state.epochchain.epochchain.len() > before;
            }
        }
        if chain_extended {
            self.persist_snapshot()?;
            self.publish_epoch_commit()?;
        }
        Ok(Some(message))
    }

    /// Returns the exact previously signed final-round commit for retry.
    ///
    /// Global certificate shares remain retryable until this node installs the
    /// certified epoch. Replays are idempotent because receivers index commit
    /// votes by validator public key.
    pub fn retry_final_commit(&self, round: u8) -> Result<Option<Commit>> {
        self.ensure_consensus_mode("retry final commit")?;
        if self.inner.trust_mode.is_trusted() {
            return Err(BlossomError::InvalidConfiguration(
                "trusted mode uses confirmation quorum finality, not commit votes".to_string(),
            ));
        }
        if !self.is_final_consensus_round(round)? {
            return Ok(None);
        }
        let target = self.next_epoch_target()?;
        let state = self.inner.state.read().expect("state lock poisoned");
        Ok(state
            .get_quorum(&target.last_epoch, target.nonce, round)
            .and_then(|quorum| quorum.local_commit.clone()))
    }

    /// Reports whether `round` is the global-certificate round for the current
    /// epoch target.
    pub fn is_final_consensus_round(&self, round: u8) -> Result<bool> {
        let target = self.next_epoch_target()?;
        let mut state = self.inner.state.write().expect("state lock poisoned");
        let consensus = state.get_mut_consensus(&target.last_epoch, target.nonce);
        Ok(consensus.peers.len().checked_sub(1) == Some(usize::from(round)))
    }

    /// Produces the epoch-start announcement after the local epoch commits.
    pub fn try_produce_epoch_started(&self) -> Result<Option<EpochStarted>> {
        self.ensure_consensus_mode("produce epoch-start announcement")?;
        let target = self.next_epoch_target()?;
        let self_node = self.self_node();
        let body = crate::blossom::EpochStartedBody::default();
        {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            let latest = state
                .epochchain
                .epochchain
                .last()
                .ok_or(BlossomError::EmptyEpochChain)?;
            if latest.body.nonce.value() == 0 {
                return Ok(None);
            }
            let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, 0);
            if quorum
                .epoch_started_senders
                .contains(&self_node.public_key())
            {
                let retry = self
                    .inner
                    .epoch_started_retry
                    .read()
                    .expect("epoch-start retry lock poisoned")
                    .as_ref()
                    .filter(|retry| {
                        retry.message.header.last_epoch == target.last_epoch
                            && retry.message.header.nonce == target.nonce
                            && !retry.pending_validators.is_empty()
                    })
                    .map(|retry| retry.message.clone());
                return Ok(retry);
            }
        }
        let message = EpochStarted {
            header: self.signed_header_for_body(
                &self_node,
                &target,
                0,
                MSGKey::EpochStarted,
                &body,
            )?,
            body,
        };
        let pending_validators = {
            let mut state = self.inner.state.write().expect("state lock poisoned");
            let pending_validators = state
                .epochchain
                .epochchain
                .last()
                .ok_or(BlossomError::EmptyEpochChain)?
                .body
                .verifiers
                .keys()
                .copied()
                .filter(|validator| *validator != self_node.public_key())
                .collect();
            state
                .get_mut_quorum(&target.last_epoch, target.nonce, 0)
                .epoch_started_senders
                .insert(self_node.public_key());
            pending_validators
        };
        *self
            .inner
            .epoch_started_retry
            .write()
            .expect("epoch-start retry lock poisoned") = Some(EpochStartedRetry {
            message: message.clone(),
            pending_validators,
            last_failures: BTreeMap::new(),
        });
        Ok(Some(message))
    }

    /// Returns registered consensus services that have not acknowledged the
    /// current epoch-start announcement.
    pub(crate) fn epoch_started_retry_services(&self, message: &EpochStarted) -> Vec<Service> {
        let pending_validators = self
            .inner
            .epoch_started_retry
            .read()
            .expect("epoch-start retry lock poisoned")
            .as_ref()
            .filter(|retry| {
                retry.message.header.last_epoch == message.header.last_epoch
                    && retry.message.header.nonce == message.header.nonce
            })
            .map(|retry| retry.pending_validators.clone())
            .unwrap_or_default();
        let address_book = self
            .inner
            .address_book
            .read()
            .expect("address book lock poisoned");
        pending_validators
            .into_iter()
            .filter_map(|validator| {
                address_book
                    .service_for(ServiceKind::Consensus, &validator)
                    .cloned()
            })
            .collect()
    }

    /// Retires acknowledged validators from epoch-start retry tracking.
    pub(crate) fn complete_epoch_started_broadcast(
        &self,
        message: &EpochStarted,
        acknowledged: impl IntoIterator<Item = PubKey>,
    ) {
        let mut retry = self
            .inner
            .epoch_started_retry
            .write()
            .expect("epoch-start retry lock poisoned");
        if let Some(retry) = retry.as_mut()
            && retry.message.header.last_epoch == message.header.last_epoch
            && retry.message.header.nonce == message.header.nonce
        {
            for validator in acknowledged {
                retry.pending_validators.remove(&validator);
                retry.last_failures.remove(&validator);
            }
        }
    }

    /// Records the most recent failed delivery for retry diagnostics.
    pub(crate) fn record_epoch_started_broadcast_failures(
        &self,
        message: &EpochStarted,
        failures: impl IntoIterator<Item = (PubKey, String)>,
    ) {
        let mut retry = self
            .inner
            .epoch_started_retry
            .write()
            .expect("epoch-start retry lock poisoned");
        if let Some(retry) = retry.as_mut()
            && retry.message.header.last_epoch == message.header.last_epoch
            && retry.message.header.nonce == message.header.nonce
        {
            for (validator, error) in failures {
                if retry.pending_validators.contains(&validator) {
                    retry.last_failures.insert(validator, error);
                }
            }
        }
    }

    #[cfg(feature = "availability-gossip")]
    /// Broadcasts this node's filtered-payload availability advertisement.
    pub async fn broadcast_availability_gossip(
        &self,
        strategy: FanOutStrategy,
    ) -> Result<BroadcastReport> {
        self.broadcast_request(
            WireRequest::AvailabilityGossip(self.availability_gossip()?),
            strategy,
        )
        .await
    }

    /// Returns the predecessor hash and nonce targeted by the next epoch.
    pub fn next_epoch_target(&self) -> Result<EpochTarget> {
        self.ensure_consensus_mode("select next epoch target")?;
        let state = self.inner.state.read().expect("state lock poisoned");
        let epoch = state
            .epochchain
            .epochchain
            .last()
            .ok_or(BlossomError::EmptyEpochChain)?;
        Ok(EpochTarget {
            group_id: self.inner.group_id,
            last_epoch: epoch.hash,
            nonce: epoch.body.nonce.new_next(),
        })
    }

    /// Reports whether the verified or durable chain contains `epoch_hash`.
    pub fn contains_epoch_hash(&self, epoch_hash: &HashType) -> bool {
        let state = self.inner.state.read().expect("state lock poisoned");
        state
            .epochchain
            .epochchain
            .iter()
            .any(|epoch| epoch.hash == *epoch_hash)
    }

    /// Validates and queues an application block for local dispatch.
    ///
    /// Admission fails with [`BlossomError::DuplicateBlock`] once this node has
    /// sealed its local dispatch for the target epoch.
    pub fn submit_block(&self, block: Block) -> Result<AcceptedBlock> {
        let _trusted_transition = self.inner.trusted_epoch_log.as_ref().map(|_| {
            self.inner
                .trusted_transition_lock
                .lock()
                .expect("trusted transition lock poisoned")
        });
        let _production = self
            .inner
            .dispatch_production_lock
            .lock()
            .expect("dispatch production lock poisoned");
        let target = self.next_epoch_target()?;
        let span = self.start_telemetry_span(self.target_telemetry_meta(
            "block_formation",
            "block_submitted",
            &target,
            None,
            Some(block.body.validator),
            None,
        ));
        let result = (|| {
            let local_dispatch_is_sealed = self
                .inner
                .state
                .read()
                .expect("state lock poisoned")
                .get_consensus(&target.last_epoch, target.nonce)
                .is_some_and(|consensus| {
                    consensus.quorum.values().any(|quorum| {
                        quorum.dispatch_status == Some(true) || quorum.local_dispatch.is_some()
                    })
                });
            if local_dispatch_is_sealed {
                return Err(BlossomError::DuplicateBlock);
            }
            if block.body.last_epoch != target.last_epoch {
                return Err(BlossomError::InvalidBlockLastEpoch);
            }
            if block.body.nonce != target.nonce {
                return Err(BlossomError::InvalidBlockNonce {
                    expected: target.nonce,
                    actual: block.body.nonce,
                });
            }

            self.verify_block_integrity(&block)?;
            self.validate_block_service(&block)?;
            #[cfg(feature = "availability-gossip")]
            self.store_filtered_payloads_from_block(&block)?;

            let application_state_bytes = block.application_state_len();
            let hash = if let Some(store) = self.inner.trusted_epoch_log.as_ref() {
                let mut local_blocks = self
                    .inner
                    .local_blocks
                    .write()
                    .expect("block lock poisoned");
                local_blocks.can_enqueue_preverified_block(&block)?;
                store.persist_local_block(&block)?;
                self.persist_block_if_configured(&block)?;
                local_blocks.enqueue_preverified_block(block.clone())?
            } else {
                let hash = self
                    .inner
                    .local_blocks
                    .write()
                    .expect("block lock poisoned")
                    .enqueue_preverified_block(block.clone())?;
                self.persist_block_if_configured(&block)?;
                hash
            };
            let mut accepted = self
                .inner
                .accepted_local_blocks
                .write()
                .expect("accepted local block lock poisoned");
            accepted.retain(|nonce, _| *nonce >= target.nonce);
            accepted.insert(target.nonce, hash);
            Ok(AcceptedBlock {
                group_id: self.inner.group_id,
                hash,
                nonce: target.nonce,
                application_state_bytes,
            })
        })();
        self.finish_telemetry_span(span, &result);
        result
    }

    /// Removes the next queued local block and wraps it in a round dispatch.
    ///
    /// Once sealed, repeated calls for the same epoch and round return the
    /// exact original dispatch and never consume another queued block.
    pub fn dispatch_local_block(&self, round: u8) -> Result<Dispatch> {
        let _production = self
            .inner
            .dispatch_production_lock
            .lock()
            .expect("dispatch production lock poisoned");
        let target = self.next_epoch_target()?;
        self.dispatch_local_block_locked(round, target)
    }

    fn dispatch_local_block_locked(&self, round: u8, target: EpochTarget) -> Result<Dispatch> {
        if let Some(dispatch) = self
            .inner
            .state
            .read()
            .expect("state lock poisoned")
            .get_quorum(&target.last_epoch, target.nonce, round)
            .and_then(|quorum| quorum.local_dispatch.clone())
        {
            return Ok(dispatch);
        }
        let span = self.start_telemetry_span(self.target_telemetry_meta(
            "dispatch",
            "dispatch_local_block",
            &target,
            Some(round),
            None,
            Some("Dispatch"),
        ));
        let result = (|| {
            let self_node = self.self_node();
            let block_service = self.block_service();
            let expected_accepted_hash = self
                .inner
                .accepted_local_blocks
                .read()
                .expect("accepted local block lock poisoned")
                .get(&target.nonce)
                .copied();

            let (maybe_block, application_state, encounter_records, node_admissions) = {
                let mut local_blocks = self
                    .inner
                    .local_blocks
                    .write()
                    .expect("block lock poisoned");
                // Prefill/round zero seals this epoch's own block exactly
                // once. Requests arriving during later rounds stay queued
                // for the next epoch rather than being discarded when the
                // original own block is already present in the aggregate.
                if round == 0
                    && local_blocks.is_empty()
                    && !local_blocks.build_block.body.txs.is_empty()
                {
                    local_blocks.close_block_with(target.last_epoch, target.nonce, |block| {
                        if self.inner.trust_mode.is_trusted() {
                            block.seal_unsigned(self_node.public_key());
                        } else {
                            block.sign_with(
                                self.inner
                                    .signer
                                    .as_ref()
                                    .ok_or(BlossomError::MissingSecretKey)?,
                            );
                        }
                        Ok(())
                    })?;
                }
                // Persist before removing a queued candidate. A transient
                // storage error must leave the exact sealed block available
                // for the request-driven retry, not replace it with emptiness.
                if let Some(block) = local_blocks.block_deque.front()
                    && block.body.nonce == target.nonce
                {
                    self.persist_block_if_configured(block)?;
                }
                let maybe_block = local_blocks.dequeue_block(
                    block_service.as_ref().map(|service| service.public_key),
                    target.last_epoch,
                    target.nonce,
                    round,
                )?;
                let encounter_records = if maybe_block.is_none() {
                    local_blocks.take_encounter_records()
                } else {
                    Vec::new()
                };
                let node_admissions = if maybe_block.is_none() {
                    local_blocks.take_node_admissions()
                } else {
                    Vec::new()
                };
                (
                    maybe_block,
                    local_blocks.application_state().clone(),
                    encounter_records,
                    node_admissions,
                )
            };
            match (expected_accepted_hash, maybe_block.as_ref()) {
                (Some(expected), Some(block)) if block.hash != expected => {
                    return Err(BlossomError::InvalidConfiguration(format!(
                        "queued local block {} does not match accepted block {expected} for nonce {}",
                        block.hash, target.nonce
                    )));
                }
                (Some(expected), None) => {
                    return Err(BlossomError::InvalidConfiguration(format!(
                        "accepted local block {expected} is missing for nonce {}",
                        target.nonce
                    )));
                }
                _ => {}
            }

            let was_queued = maybe_block.is_some();
            let block = match maybe_block {
                Some(block) => block,
                None => self.empty_block(
                    &self_node,
                    &target,
                    application_state,
                    encounter_records,
                    node_admissions,
                )?,
            };
            #[cfg(feature = "availability-gossip")]
            self.store_filtered_payloads_from_block(&block)?;
            if !was_queued {
                self.persist_block_if_configured(&block)?;
            }

            let mut blocks = if round > 0 {
                let mut state = self.inner.state.write().expect("state lock poisoned");
                state.seed_prefill_dispatches_into_quorum(&target.last_epoch, target.nonce, round);
                state
                    .get_mut_quorum(&target.last_epoch, target.nonce, round)
                    .canonical_verified_blocks()
            } else {
                BTreeMap::new()
            };
            if !blocks
                .values()
                .any(|carried| carried.body.validator == block.body.validator)
            {
                blocks.insert(block.hash, block);
            }
            let signature_tree = SignatureTree::default();
            let signature_tree_hash = signature_tree.hash();
            let body = DispatchBody {
                blocks_hash: blocks.hash(),
                blocks,
                signature_tree,
                signature_tree_hash,
            };
            let header = Header {
                sender: self_node.public_key(),
                last_epoch: target.last_epoch,
                nonce: target.nonce,
                round,
                signature: self.sign_body(
                    &self_node,
                    MSGKey::Dispatch,
                    target.last_epoch,
                    target.nonce,
                    round,
                    &body,
                )?,
            };

            let mut state = self.inner.state.write().expect("state lock poisoned");
            let quorum = state.get_mut_quorum(&target.last_epoch, target.nonce, round);
            quorum.dispatch_status = Some(true);
            record_verified_dispatch_blocks(quorum, body.blocks.clone());
            let dispatch = Dispatch { header, body };
            quorum.local_dispatch = Some(dispatch.clone());
            quorum.dispatch_retry = false;
            if expected_accepted_hash.is_some() {
                self.inner
                    .accepted_local_blocks
                    .write()
                    .expect("accepted local block lock poisoned")
                    .remove(&target.nonce);
            }
            Ok(dispatch)
        })();
        self.finish_telemetry_span(span, &result);
        result
    }
}
