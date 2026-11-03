//! Snapshot, certified catch-up, durable block, and repair tests.

use super::*;

#[test]
fn runtime_snapshot_round_trips_committed_state_without_secret_key() {
    let (runtime, keypair) = runtime();
    let path = std::env::temp_dir().join(format!(
        "blossom-runtime-snapshot-{}.json",
        std::process::id()
    ));

    runtime.write_snapshot(&path).unwrap();
    let snapshot = RuntimeSnapshotV1::read_json(&path).unwrap();
    std::fs::remove_file(&path).ok();

    assert_eq!(snapshot.version, RuntimeSnapshotV1::VERSION);
    assert_eq!(snapshot.self_public_key, keypair.public);
    assert_eq!(snapshot.epochchain.epochchain.len(), 1);

    let restored_node = NodeIdentity::new(
        keypair.public,
        Some(keypair.secret.clone()),
        "tcp",
        "127.0.0.1",
        8080,
        false,
    );
    let restored_config = RuntimeConfig::from_snapshot(snapshot, restored_node).unwrap();
    let restored = NodeRuntime::new(restored_config);

    assert_eq!(
        restored.status().unwrap().last_epoch,
        runtime.status().unwrap().last_epoch
    );
    assert!(!restored.status().unwrap().node.has_signing_material());
}

#[test]
fn verified_membership_watch_is_quorum_renewed_and_fail_closed() {
    let (runtime, keypairs, _) = runtime_with_peers();
    let receiver = runtime.watch_verified_membership();
    assert!(!receiver.borrow().is_fresh());

    let request = MembershipLeaseRequest::fresh(5_000).unwrap();
    let statement = runtime.membership_lease_statement(request).unwrap();
    let votes = keypairs[..4]
        .iter()
        .map(|keypair| MembershipLeaseVote::signed(statement.clone(), &keypair.signer()).unwrap())
        .collect::<Vec<_>>();
    let certificate = MembershipLeaseCertificate::from_votes(statement, votes).unwrap();
    let installed = runtime.install_membership_lease(certificate).unwrap();
    assert!(installed.is_fresh());
    assert!(receiver.borrow().is_fresh());

    let relay_owner = &keypairs[1];
    let record = SignedServiceRecord::signed(
        crate::address_book::ServiceRecordBody {
            group_id: runtime.group_id(),
            owner: relay_owner.public,
            service_kind: ServiceKind::Relay,
            protocol: "quic".to_string(),
            host: "relay.internal".to_string(),
            port: 7443,
            generation: 1,
            expires_at_unix_millis: service_unix_time_millis() + 500,
            tombstone: false,
        },
        &relay_owner.signer(),
    )
    .unwrap();
    runtime.register_signed_service(record).unwrap();
    assert!(receiver.borrow().relays.contains_key(&relay_owner.public));
    assert!(receiver.borrow().valid_until < installed.valid_until);

    runtime.publish_epoch_commit().unwrap();
    assert!(!receiver.borrow().is_fresh());
    assert!(receiver.borrow().require_fresh().is_err());
}

#[test]
fn membership_lease_signer_rejects_challenge_equivocation() {
    let (runtime, _, _) = runtime_with_peers();
    let request = MembershipLeaseRequest::fresh(1_000).unwrap();
    runtime.vote_membership_lease(request).unwrap();
    let conflicting = MembershipLeaseRequest {
        valid_for_millis: 2_000,
        ..request
    };
    assert!(runtime.vote_membership_lease(conflicting).is_err());
}

#[test]
fn membership_lease_watermarks_expire_and_are_reclaimed() {
    let (runtime, _, _) = runtime_with_peers();
    let request = MembershipLeaseRequest::fresh(1_000).unwrap();
    runtime.vote_membership_lease(request).unwrap();
    {
        let mut watermarks = runtime
            .inner
            .membership_lease_watermarks
            .lock()
            .expect("membership lease watermark lock is available");
        watermarks
            .get_mut(&request.challenge)
            .expect("signed challenge has a watermark")
            .expires_at_unix_millis = service_unix_time_millis().saturating_sub(1);
    }

    let replacement = MembershipLeaseRequest {
        issued_at_unix_millis: service_unix_time_millis(),
        valid_for_millis: 2_000,
        ..request
    };
    runtime.vote_membership_lease(replacement).unwrap();
    assert_eq!(
        runtime
            .inner
            .membership_lease_watermarks
            .lock()
            .expect("membership lease watermark lock is available")
            .len(),
        1
    );
}

#[test]
fn runtime_snapshot_preserves_membership_lease_watermark_expiry() {
    let (runtime, keypairs, _) = runtime_with_peers();
    let request = MembershipLeaseRequest::fresh(5_000).unwrap();
    runtime.vote_membership_lease(request).unwrap();
    let snapshot = runtime.snapshot().unwrap();
    assert_eq!(snapshot.membership_lease_watermarks.len(), 1);
    assert_eq!(snapshot.membership_lease_watermark_expiries.len(), 1);

    let restored_node = NodeIdentity::new(
        keypairs[0].public,
        Some(keypairs[0].secret.clone()),
        "tcp",
        "127.0.0.1",
        8000,
        false,
    );
    let restored = NodeRuntime::new(
        RuntimeConfig::from_snapshot(snapshot, restored_node).expect("valid restored runtime"),
    );
    let conflicting = MembershipLeaseRequest {
        valid_for_millis: 4_000,
        ..request
    };
    assert!(restored.vote_membership_lease(conflicting).is_err());
}

#[test]
fn legacy_runtime_snapshot_without_watermark_expiries_remains_compatible() {
    let (runtime, keypairs, _) = runtime_with_peers();
    let request = MembershipLeaseRequest::fresh(5_000).unwrap();
    runtime.vote_membership_lease(request).unwrap();
    let mut encoded = serde_json::to_value(runtime.snapshot().unwrap()).unwrap();
    encoded
        .as_object_mut()
        .expect("runtime snapshot serializes as an object")
        .remove("membership_lease_watermark_expiries");
    let legacy = serde_json::from_value::<RuntimeSnapshotV1>(encoded).unwrap();
    assert!(legacy.membership_lease_watermark_expiries.is_empty());

    let restored_node = NodeIdentity::new(
        keypairs[0].public,
        Some(keypairs[0].secret.clone()),
        "tcp",
        "127.0.0.1",
        8000,
        false,
    );
    let restored = NodeRuntime::new(
        RuntimeConfig::from_snapshot(legacy, restored_node).expect("valid legacy snapshot"),
    );
    assert_eq!(
        restored
            .snapshot()
            .unwrap()
            .membership_lease_watermarks
            .len(),
        1
    );
}

#[test]
fn reinstalling_cached_membership_certificate_cannot_extend_freshness() {
    let (runtime, keypairs, _) = runtime_with_peers();
    let request = MembershipLeaseRequest::fresh(1_000).unwrap();
    let statement = runtime.membership_lease_statement(request).unwrap();
    let votes = keypairs[..4]
        .iter()
        .map(|keypair| MembershipLeaseVote::signed(statement.clone(), &keypair.signer()).unwrap())
        .collect::<Vec<_>>();
    let certificate = MembershipLeaseCertificate::from_votes(statement, votes).unwrap();

    let first = runtime
        .install_membership_lease(certificate.clone())
        .unwrap();
    std::thread::sleep(std::time::Duration::from_millis(25));
    let reinstalled = runtime.install_membership_lease(certificate).unwrap();

    assert_eq!(
        reinstalled.lease_expires_at_unix_millis,
        first.lease_expires_at_unix_millis
    );
    assert!(reinstalled.valid_until <= first.valid_until);
}

#[test]
fn membership_lease_statement_rejects_an_expired_absolute_window() {
    let (runtime, _, _) = runtime_with_peers();
    let request = MembershipLeaseRequest {
        challenge: MembershipLeaseChallenge([9; 32]),
        issued_at_unix_millis: service_unix_time_millis().saturating_sub(1_000),
        valid_for_millis: 100,
    };

    assert_eq!(
        runtime.membership_lease_statement(request),
        Err(BlossomError::FailedConsensus)
    );
}

#[test]
fn runtime_snapshot_rejects_mismatched_node_key() {
    let (runtime, _) = runtime();
    let snapshot = runtime.snapshot().unwrap();
    let wrong = NodeIdentity::generate("tcp", "127.0.0.1", 8081);

    assert_eq!(
        RuntimeConfig::from_snapshot(snapshot, wrong).unwrap_err(),
        BlossomError::KeyMismatch
    );
}

#[test]
fn general_runtime_rejects_the_isolated_high_availability_mode() {
    let node = NodeIdentity::generate("tcp", "127.0.0.1", 8082);
    let mut config = RuntimeConfig::new(node);
    config.trust_mode = TrustMode::HighAvailability;
    assert!(matches!(
        NodeRuntime::try_new(config),
        Err(BlossomError::InvalidConfiguration(message))
            if message.contains("HighAvailabilityRuntime")
    ));
}

#[test]
fn runtime_uses_committed_configurable_quorum_size() {
    let keypair = Keypair::generate();
    let node = NodeIdentity::new(
        keypair.public,
        Some(keypair.secret.clone()),
        "tcp",
        "127.0.0.1",
        8082,
        false,
    );
    let quorum_size = QuorumSize::new(9).unwrap();
    let runtime =
        NodeRuntime::try_new(RuntimeConfig::new(node).with_quorum_size(quorum_size)).unwrap();
    let status = runtime.status().unwrap();

    assert_eq!(status.configured_quorum_size, 9);
    assert_eq!(status.effective_quorum_size, 1);
    assert_eq!(
        status.consensus_parameters_hash,
        ConsensusParameters::new(quorum_size).hash()
    );
    assert_eq!(
        runtime
            .epochchain()
            .epochchain
            .first()
            .unwrap()
            .body
            .effective_consensus_parameters()
            .quorum_size,
        quorum_size
    );
}

#[test]
fn restored_runtime_rejects_local_quorum_override_mismatch() {
    let (runtime, keypair) = runtime();
    let snapshot = runtime.snapshot().unwrap();
    let restored_node = NodeIdentity::new(
        keypair.public,
        Some(keypair.secret.clone()),
        "tcp",
        "127.0.0.1",
        8080,
        false,
    );

    assert_eq!(
        RuntimeConfig::from_snapshot_with_quorum_override(
            snapshot,
            restored_node,
            Some(QuorumSize::new(9).unwrap()),
        )
        .unwrap_err(),
        BlossomError::ConsensusParametersMismatch {
            configured: 9,
            committed: 6,
        }
    );
}

#[test]
fn legacy_snapshot_decodes_as_six_and_rewrites_explicit_parameters() {
    let (runtime, _) = runtime();
    let mut snapshot = runtime.snapshot().unwrap();
    for epoch in &mut snapshot.epochchain.epochchain {
        epoch.body.consensus_parameters = None;
        epoch.set_hash();
    }
    let mut json = serde_json::to_value(snapshot).unwrap();
    json.as_object_mut().unwrap().remove("consensus_parameters");
    let decoded: RuntimeSnapshotV1 = serde_json::from_value(json).unwrap();

    assert_eq!(decoded.consensus_parameters, ConsensusParameters::default());
    assert_eq!(
        decoded.epochchain.epochchain[0].body.consensus_parameters,
        None
    );
    decoded.validate().unwrap();

    let rewritten = serde_json::to_value(decoded).unwrap();
    assert_eq!(
        rewritten["consensus_parameters"]["quorum_size"],
        serde_json::json!(6)
    );
}

#[test]
fn catch_up_from_epoch_started_accepts_extending_chain_and_rejects_corruption() {
    let (leader, keypairs, target) = runtime_with_peers();
    let nodes = keypairs
        .iter()
        .enumerate()
        .map(|(index, keypair)| {
            NodeIdentity::new(
                keypair.public,
                (index == 1).then_some(keypair.secret.clone()),
                "tcp",
                "127.0.0.1",
                8400 + index as u16,
                false,
            )
        })
        .collect::<Vec<_>>();
    let genesis = leader.epochchain().epochchain[0].clone();
    let mut follower_config = RuntimeConfig::new(nodes[1].clone());
    follower_config.genesis = Some(genesis);
    let follower = NodeRuntime::new(follower_config);

    let block = signed_block_for_target(&keypairs[1], &target, b"catch-up");
    let block_keys = [(block.hash, ())].into_iter().collect::<BTreeMap<_, _>>();
    let response_body = ReconcileResponseBody {
        blocks_hash: block_keys.hash(),
        blocks: [(block.hash, block)].into_iter().collect(),
    };
    let signer = round_signer(&leader, &keypairs, &target, 0);
    leader
        .receive_message(Msg::ReconcileResponse(ReconcileResponse {
            header: signed_test_header(signer, &target, MSGKey::ReconcileResponse, &response_body),
            body: response_body,
        }))
        .unwrap();
    let verified_hash = {
        let state = leader.inner.state.read().expect("state lock poisoned");
        state
            .get_quorum(&target.last_epoch, target.nonce, 0)
            .unwrap()
            .verified_blocks_hash()
    };
    let epoch_hash = leader
        .inner
        .state
        .read()
        .expect("state lock poisoned")
        .prepare_verified_epoch(&target.last_epoch, target.nonce, 0)
        .unwrap()
        .unwrap()
        .hash;
    let commit_body = ReconcileCommitBody {
        blocks_hash: verified_hash,
        epoch_hash,
        signatures: keypairs
            .iter()
            .take(4)
            .map(|keypair| (keypair.public, keypair.signer().sign(epoch_hash.as_ref())))
            .collect(),
    };
    leader
        .try_reconcile_commit(ReconcileCommit {
            header: signed_test_header(signer, &target, MSGKey::ReconcileCommit, &commit_body),
            body: commit_body,
        })
        .unwrap();

    let anchor = follower.epochchain().epochchain.last().unwrap().clone();
    let suffix = leader
        .certified_epoch_suffix(anchor.hash, anchor.body.nonce, 4096)
        .unwrap();
    let mut corrupt = suffix.clone();
    corrupt.epochs.last_mut().unwrap().hash = HashType([3; 32]);
    assert!(follower.catch_up_certified_suffix(corrupt).is_err());

    let mut corrupt_nonce_link = suffix.clone();
    let latest = corrupt_nonce_link.epochs.last_mut().unwrap();
    latest.body.previous_nonce = Some(Nonce::new(99));
    latest.set_hash();
    assert!(
        follower
            .catch_up_certified_suffix(corrupt_nonce_link)
            .is_err()
    );

    assert!(follower.catch_up_certified_suffix(suffix).unwrap());
    assert_eq!(follower.epochchain().epochchain.len(), 2);
}

#[test]
fn durable_block_store_serves_submitted_blocks_by_nonce() {
    let keypair = Keypair::generate();
    let node = NodeIdentity::new(
        keypair.public,
        Some(keypair.secret.clone()),
        "tcp",
        "127.0.0.1",
        8080,
        false,
    );
    let root = std::env::temp_dir().join(format!(
        "blossom-runtime-block-store-{}-{}",
        std::process::id(),
        keypair.public
    ));
    let mut config = RuntimeConfig::new(node);
    config.block_store_path = Some(root.clone());
    let runtime = NodeRuntime::new(config);
    let target = runtime.next_epoch_target().unwrap();
    let block = signed_block_for_target(&keypair, &target, b"durable-block");

    runtime.submit_block(block.clone()).unwrap();

    assert_eq!(
        runtime
            .durable_block_by_nonce(target.nonce)
            .unwrap()
            .unwrap()
            .hash,
        block.hash
    );
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn durable_block_store_serves_submitted_blocks_by_hash() {
    let keypair = Keypair::generate();
    let node = NodeIdentity::new(
        keypair.public,
        Some(keypair.secret.clone()),
        "tcp",
        "127.0.0.1",
        8080,
        false,
    );
    let root = std::env::temp_dir().join(format!(
        "blossom-runtime-block-store-hash-{}-{}",
        std::process::id(),
        keypair.public
    ));
    let mut config = RuntimeConfig::new(node);
    config.block_store_path = Some(root.clone());
    let runtime = NodeRuntime::new(config);
    let target = runtime.next_epoch_target().unwrap();
    let block = signed_block_for_target(&keypair, &target, b"durable-block-by-hash");

    runtime.submit_block(block.clone()).unwrap();

    let blocks = runtime.durable_blocks_by_hash([block.hash]).unwrap();
    assert_eq!(blocks.get(&block.hash).unwrap().hash, block.hash);
    std::fs::remove_dir_all(root).ok();
}

#[test]
fn echo_redispatch_inserts_verified_missing_blocks() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = round_signer(&runtime, &keypairs, &target, 0);
    let block = signed_block_for_target(signer, &target, b"echo-redispatch");
    let mut redispatched_blocks = BTreeMap::new();
    redispatched_blocks.insert(block.hash, block.clone());
    let header = signed_test_header(
        signer,
        &target,
        MSGKey::EchoReDispatch,
        &redispatched_blocks,
    );

    let receipt = runtime
        .receive_message(Msg::EchoReDispatch(EchoReDispatch {
            header,
            redispatched_blocks,
        }))
        .unwrap();
    assert_eq!(receipt.kind, "echo_redispatch");

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 0)
        .unwrap();
    assert!(quorum.verified_blocks().contains_key(&block.hash));
}

#[test]
fn future_round_messages_buffer_until_round_becomes_current() {
    let (runtime, keypairs, target) = runtime_with_node_count(36);
    let signer = round_signer(&runtime, &keypairs, &target, 1);
    let body = VerificationBody::default();
    let message = Msg::Verification(Verification {
        header: signed_test_header_for_round(signer, &target, 1, MSGKey::Verification, &body),
        body,
    });

    let receipt = runtime.receive_message(message).unwrap();
    assert_eq!(receipt.kind, "future_round_buffered");
    assert!(
        runtime
            .drain_buffered_current_round_messages()
            .unwrap()
            .is_empty()
    );

    {
        let mut state = runtime.inner.state.write().expect("state lock poisoned");
        state
            .get_mut_consensus(&target.last_epoch, target.nonce)
            .round = 1;
    }
    let drained = runtime.drain_buffered_current_round_messages().unwrap();
    assert_eq!(drained.len(), 1);
}

#[test]
fn round_skip_certificate_advances_only_with_valid_manifest_and_supermajority() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = round_signer(&runtime, &keypairs, &target, 0);
    let current_validators = runtime
        .current_verifiers()
        .into_iter()
        .map(|node| node.public_key())
        .collect::<BTreeSet<_>>();
    let manifest = DataDisseminationManifest {
        last_epoch: target.last_epoch,
        nonce: target.nonce,
        first_fanout_round: 0,
        last_certified_round: Some(0),
        certified_blocks_hash: BTreeMap::<HashType, ()>::new().hash(),
        source_nodes: current_validators,
        ..Default::default()
    };
    let manifest_hash = manifest.hash();
    let votes = keypairs
        .iter()
        .take(4)
        .map(|keypair| {
            RoundSkipVote::sign(
                keypair.public,
                &keypair.secret,
                target.last_epoch,
                target.nonce,
                0,
                1,
                manifest_hash,
            )
        })
        .collect::<Vec<_>>();
    let certificate =
        RoundSkipCertificate::new(target.last_epoch, target.nonce, 0, 1, manifest_hash, votes);
    let body = RoundSkipCertificateBody {
        certificate,
        manifest,
    };
    let header = signed_test_header(signer, &target, MSGKey::RoundSkipCertificate, &body);

    let receipt = runtime
        .receive_message(Msg::RoundSkipCertificate(RoundSkipCertificateMessage {
            header,
            body,
        }))
        .unwrap();
    assert_eq!(receipt.kind, "round_skip_certificate");

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let consensus = state
        .get_consensus(&target.last_epoch, target.nonce)
        .unwrap();
    assert_eq!(consensus.round, 1);
}

#[test]
fn round_skip_certificate_rejects_duplicate_shortfall() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = round_signer(&runtime, &keypairs, &target, 0);
    let current_validators = runtime
        .current_verifiers()
        .into_iter()
        .map(|node| node.public_key())
        .collect::<BTreeSet<_>>();
    let manifest = DataDisseminationManifest {
        last_epoch: target.last_epoch,
        nonce: target.nonce,
        first_fanout_round: 0,
        last_certified_round: Some(0),
        certified_blocks_hash: BTreeMap::<HashType, ()>::new().hash(),
        source_nodes: current_validators,
        ..Default::default()
    };
    let manifest_hash = manifest.hash();
    let votes = (0..4)
        .map(|_| {
            RoundSkipVote::sign(
                keypairs[0].public,
                &keypairs[0].secret,
                target.last_epoch,
                target.nonce,
                0,
                1,
                manifest_hash,
            )
        })
        .collect::<Vec<_>>();
    let certificate =
        RoundSkipCertificate::new(target.last_epoch, target.nonce, 0, 1, manifest_hash, votes);
    let body = RoundSkipCertificateBody {
        certificate,
        manifest,
    };
    let header = signed_test_header(signer, &target, MSGKey::RoundSkipCertificate, &body);

    assert!(matches!(
        runtime.receive_message(Msg::RoundSkipCertificate(RoundSkipCertificateMessage {
            header,
            body
        })),
        Err(BlossomError::WireProtocol(_))
    ));
}

#[test]
fn reconcile_response_inserts_verified_blocks_and_commit_requires_supermajority() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let signer = round_signer(&runtime, &keypairs, &target, 0);
    let block = signed_block_for_target(signer, &target, b"reconcile-response");
    let mut blocks = BTreeMap::new();
    blocks.insert(block.hash, block.clone());
    let blocks_hash = blocks
        .keys()
        .map(|hash| (*hash, ()))
        .collect::<BTreeMap<_, _>>()
        .hash();
    let body = ReconcileResponseBody {
        blocks_hash,
        blocks,
    };
    let header = signed_test_header(signer, &target, MSGKey::ReconcileResponse, &body);

    runtime
        .receive_message(Msg::ReconcileResponse(ReconcileResponse { header, body }))
        .unwrap();

    let commit_body = ReconcileCommitBody {
        blocks_hash,
        epoch_hash: runtime
            .inner
            .state
            .read()
            .expect("state lock poisoned")
            .prepare_verified_epoch(&target.last_epoch, target.nonce, 0)
            .unwrap()
            .unwrap()
            .hash,
        signatures: keypairs
            .iter()
            .take(4)
            .map(|keypair| {
                let epoch_hash = runtime
                    .inner
                    .state
                    .read()
                    .expect("state lock poisoned")
                    .prepare_verified_epoch(&target.last_epoch, target.nonce, 0)
                    .unwrap()
                    .unwrap()
                    .hash;
                (keypair.public, keypair.signer().sign(epoch_hash.as_ref()))
            })
            .collect(),
    };
    let commit_header = signed_test_header(signer, &target, MSGKey::ReconcileCommit, &commit_body);
    let receipt = runtime
        .receive_message(Msg::ReconcileCommit(ReconcileCommit {
            header: commit_header,
            body: commit_body,
        }))
        .unwrap();
    assert_eq!(receipt.kind, "reconcile_commit");

    let state = runtime.inner.state.read().expect("state lock poisoned");
    let quorum = state
        .get_quorum(&target.last_epoch, target.nonce, 0)
        .unwrap();
    assert!(quorum.verified_blocks().contains_key(&block.hash));
}

#[test]
fn epoch_started_announcement_waits_for_post_genesis_finality() {
    let (runtime, _, _) = runtime_with_peers();

    assert!(runtime.try_produce_epoch_started().unwrap().is_none());
}

#[test]
fn reconnect_admission_requires_distinct_active_supermajority_votes() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let joiner = Keypair::generate();
    let admission = NodeAdmission::signed_for_consensus_service(
        Service::new(
            ServiceKind::Consensus,
            joiner.public,
            "tcp",
            "127.0.0.1",
            9100,
        ),
        target.last_epoch,
        target.nonce,
        &joiner.signer(),
    )
    .unwrap();
    let votes = keypairs
        .iter()
        .take(4)
        .map(|keypair| {
            ReconnectVote::signed_for_admission(
                &admission,
                target.last_epoch,
                Nonce::new(0),
                &keypair.signer(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();

    let decision = runtime
        .evaluate_reconnect_admission(&ReconnectAdmissionEvidence {
            admission: admission.clone(),
            votes,
        })
        .unwrap();

    assert!(decision.accepted);
    assert_eq!(decision.distinct_votes, 4);
    assert_eq!(decision.required_votes, 4);

    let staged = runtime
        .stage_reconnect_admission(ReconnectAdmissionEvidence {
            admission,
            votes: keypairs
                .iter()
                .take(4)
                .map(|keypair| {
                    ReconnectVote::signed_for_admission(
                        &NodeAdmission::signed_for_consensus_service(
                            Service::new(
                                ServiceKind::Consensus,
                                joiner.public,
                                "tcp",
                                "127.0.0.1",
                                9100,
                            ),
                            target.last_epoch,
                            target.nonce,
                            &joiner.signer(),
                        )
                        .unwrap(),
                        target.last_epoch,
                        Nonce::new(0),
                        &keypair.signer(),
                    )
                    .unwrap()
                })
                .collect(),
        })
        .unwrap();
    assert!(staged.accepted);
    assert_eq!(
        runtime
            .inner
            .local_blocks
            .read()
            .expect("block lock poisoned")
            .node_admissions()
            .len(),
        1
    );
}

#[test]
fn reconnect_admission_rejects_duplicates_stale_and_sybil_votes() {
    let (runtime, keypairs, target) = runtime_with_peers();
    let joiner = Keypair::generate();
    let sybil = Keypair::generate();
    let admission = NodeAdmission::signed_for_consensus_service(
        Service::new(
            ServiceKind::Consensus,
            joiner.public,
            "tcp",
            "127.0.0.1",
            9101,
        ),
        target.last_epoch,
        target.nonce,
        &joiner.signer(),
    )
    .unwrap();
    let duplicate_votes = (0..4)
        .map(|_| {
            ReconnectVote::signed_for_admission(
                &admission,
                target.last_epoch,
                Nonce::new(0),
                &keypairs[0].signer(),
            )
            .unwrap()
        })
        .collect::<Vec<_>>();
    let duplicate_decision = runtime
        .evaluate_reconnect_admission(&ReconnectAdmissionEvidence {
            admission: admission.clone(),
            votes: duplicate_votes,
        })
        .unwrap();
    assert!(!duplicate_decision.accepted);
    assert_eq!(duplicate_decision.distinct_votes, 1);

    let sybil_votes = keypairs
        .iter()
        .take(3)
        .map(|keypair| {
            ReconnectVote::signed_for_admission(
                &admission,
                target.last_epoch,
                Nonce::new(0),
                &keypair.signer(),
            )
            .unwrap()
        })
        .chain(std::iter::once(
            ReconnectVote::signed_for_admission(
                &admission,
                target.last_epoch,
                Nonce::new(0),
                &sybil.signer(),
            )
            .unwrap(),
        ))
        .collect::<Vec<_>>();
    let sybil_decision = runtime
        .evaluate_reconnect_admission(&ReconnectAdmissionEvidence {
            admission: admission.clone(),
            votes: sybil_votes,
        })
        .unwrap();
    assert!(!sybil_decision.accepted);
    assert_eq!(sybil_decision.distinct_votes, 3);

    let stale_admission = NodeAdmission::signed_for_consensus_service(
        Service::new(
            ServiceKind::Consensus,
            joiner.public,
            "tcp",
            "127.0.0.1",
            9101,
        ),
        HashType([1; 32]),
        target.nonce,
        &joiner.signer(),
    )
    .unwrap();
    let stale_decision = runtime
        .evaluate_reconnect_admission(&ReconnectAdmissionEvidence {
            admission: stale_admission,
            votes: Vec::new(),
        })
        .unwrap();
    assert!(!stale_decision.accepted);
    assert_eq!(stale_decision.reason, "stale admission target");
}

/// A registered Overlay member in a synthetic trusted genesis, with an
/// independent validator. No production membership admission is bypassed.
fn overlay_snapshot_runtime(capability: crate::MemberCapability) -> (NodeRuntime, NodeIdentity) {
    let group = ConsensusGroupId::root();
    let validator = NodeIdentity::generate("tcp", "127.0.0.1", 8080);
    let local = NodeIdentity::generate("tcp", "127.0.0.1", 8081);
    let mut genesis = genesis_epoch_for_group(group, [validator]);
    let operation = crate::CommittedMemberOperation {
        group_id: group,
        parent_epoch_hash: genesis.hash,
        operation: crate::MemberOperation::Add(
            crate::MemberRecord::new(local.public_only(), [capability], 1).expect("fixture member"),
        ),
    };
    let mut block = Block::default();
    block
        .body
        .txs
        .push(operation.to_transaction().expect("fixture operation"));
    genesis.body.members = crate::apply_committed_member_operations(
        &genesis.body.members,
        &BTreeMap::from([(HashType::hash(b"fixture-member"), block)]),
        group,
        genesis.hash,
    );
    genesis.set_hash();
    let mut config = RuntimeConfig::for_group(local.clone(), group);
    config.genesis = Some(genesis);
    config.mode = RuntimeMode::Overlay;
    (
        NodeRuntime::try_new(config).expect("fixture Overlay runtime"),
        local,
    )
}

#[test]
fn overlay_member_snapshot_recovers_client_and_relay_without_inheriting_a_lease() {
    for capability in [
        crate::MemberCapability::Client,
        crate::MemberCapability::Relay,
    ] {
        let (runtime, local) = overlay_snapshot_runtime(capability);
        let path = std::env::temp_dir().join(format!(
            "blossom-overlay-{}-{}.json",
            std::process::id(),
            local.public_key()
        ));
        runtime
            .write_snapshot(&path)
            .expect("write Overlay snapshot");
        let snapshot = RuntimeSnapshotV1::read_json(&path).expect("read Overlay snapshot");
        std::fs::remove_file(&path).expect("remove owned fixture snapshot");
        assert_eq!(snapshot.mode, RuntimeMode::Overlay);
        assert_eq!(snapshot.self_public_key, local.public_key());
        assert!(
            !snapshot
                .epochchain
                .epochchain
                .last()
                .expect("tip")
                .body
                .verifiers
                .contains_key(&local.public_key())
        );
        let recovered = NodeRuntime::try_new(
            RuntimeConfig::from_snapshot(snapshot.clone(), local.clone())
                .expect("restore identity"),
        )
        .expect("recover Overlay runtime");
        assert!(!recovered.watch_verified_membership().borrow().is_fresh());
        let mut changed_mode = snapshot.clone();
        changed_mode.mode = RuntimeMode::Consensus;
        assert!(
            changed_mode.validate().is_err(),
            "Client/Relay membership cannot substitute for a validator"
        );
        assert!(
            snapshot
                .validate_for_node(&NodeIdentity::generate("tcp", "127.0.0.1", 8082))
                .is_err()
        );
    }
}

#[test]
fn overlay_member_snapshot_refuses_absent_suspended_revoked_and_invalid_history() {
    for capability in [
        crate::MemberCapability::Client,
        crate::MemberCapability::Relay,
    ] {
        let (runtime, local) = overlay_snapshot_runtime(capability);
        let original = runtime.snapshot().expect("valid Overlay snapshot");
        for revoke in [true, false] {
            let mut snapshot = original.clone();
            let epoch = snapshot
                .epochchain
                .epochchain
                .last_mut()
                .expect("fixture tip");
            let operation = crate::CommittedMemberOperation {
                group_id: snapshot.group_id,
                parent_epoch_hash: epoch.hash,
                operation: if revoke {
                    crate::MemberOperation::Revoke {
                        public_key: local.public_key(),
                        generation: 2,
                    }
                } else {
                    crate::MemberOperation::Suspend {
                        public_key: local.public_key(),
                        generation: 2,
                    }
                },
            };
            let mut block = Block::default();
            block
                .body
                .txs
                .push(operation.to_transaction().expect("fixture status change"));
            epoch.body.members = crate::apply_committed_member_operations(
                &epoch.body.members,
                &BTreeMap::from([(HashType::hash(b"fixture-status"), block)]),
                snapshot.group_id,
                epoch.hash,
            );
            epoch.set_hash();
            assert!(
                snapshot.validate().is_err(),
                "inactive Overlay member cannot own a recovered runtime"
            );
        }
        let mut absent = original.clone();
        absent.self_public_key = Keypair::generate().public;
        assert!(absent.validate().is_err());
        let mut tampered = original;
        tampered
            .epochchain
            .epochchain
            .last_mut()
            .expect("fixture tip")
            .hash = HashType::hash(b"invalid snapshot hash");
        assert!(
            tampered.validate().is_err(),
            "Overlay recovery retains the existing hash and chain checks"
        );
    }
}
