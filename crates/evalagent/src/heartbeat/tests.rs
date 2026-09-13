use super::*;
use std::path::PathBuf;

fn args() -> RunArgs {
    RunArgs {
        controller_url: "http://unused.invalid".into(),
        run_id: "run".into(),
        key_file: PathBuf::new(),
        controller_pubkey: String::new(),
        incarnation: "inc".into(),
        vm2_template_digest: "template".into(),
        vm2_base_digest: "base".into(),
        lease_renew_interval_s: 5,
        boot_cmd: String::new(),
        seal_cmd: String::new(),
        destroy_cmd: String::new(),
        observe_cmd: String::new(),
        hostd_ip: None,
        vm2_ip: "10.99.0.2".parse().unwrap(),
        choke_wgip: None,
        model: "model".into(),
    }
}

fn challenge() -> Challenge {
    Challenge {
        v: PROTO_V,
        kind: "challenge".into(),
        run_id: "run".into(),
        aud: AUD_HOSTD.into(),
        incarnation: "inc".into(),
        epoch: 1,
        nonce: "ab".repeat(32),
        issued_at: 1_000,
        expires_in_s: CHALLENGE_TTL_S,
    }
}

#[test]
fn challenge_requests_are_signed_for_controller_and_unique_in_the_same_second() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let a = args();
    let first = challenge_request(&a, 1_000);
    let next = challenge_request(&a, 1_000);
    assert_ne!(first.request_id, next.request_id);
    for request in [first, next] {
        let signed = Signed::sign(&key, "hostd", &request);
        let decoded: ChallengeRequest = signed
            .verify(&key.verifying_key(), "challenge_request", AUD_CONTROLLER)
            .unwrap();
        assert_eq!(signed.signer, "hostd");
        assert_eq!(decoded.v, PROTO_V);
        assert_eq!(decoded.kind, "challenge_request");
        assert_eq!(
            (decoded.run_id, decoded.incarnation, decoded.issued_at),
            (a.run_id.clone(), a.incarnation.clone(), 1_000)
        );
        assert_eq!(decoded.request_id.len(), 64);
        assert!(decoded.request_id.bytes().all(|b| b.is_ascii_hexdigit()));
    }
}

#[test]
fn verified_nonce_and_host_observations_roundtrip_in_signed_evidence() {
    let controller = SigningKey::from_bytes(&[2; 32]);
    let host = SigningKey::from_bytes(&[1; 32]);
    let a = args();
    let ch = challenge();
    let verified = PendingChallenge::verify(
        &Signed::sign(&controller, "controller", &ch),
        &controller.verifying_key(),
        &a,
        1,
        Instant::now(),
        1_000,
    )
    .unwrap();
    let vm2 = Vm2Obs {
        instance: a.incarnation.clone(),
        template_digest: a.vm2_template_digest.clone(),
        base_image_digest: a.vm2_base_digest.clone(),
        running: Some(true),
        pid: Some(42),
        nested_virt: Some(true),
        port_forwards: Some(0),
        writable_mounts: Some(0),
        ..Default::default()
    };
    let gate = GateObs {
        state: GateState::Sealed,
        bypass_packets: None,
    };
    let watchdog = WatchdogObs {
        lease_token: 17,
        deadline_remaining_ms: 12_000,
    };
    let chokepoint = ChokepointObs {
        inference_requests: 9,
        denied: 3,
    };
    let ev = evidence(
        &a,
        verified.challenge.nonce,
        1_001,
        vm2.clone(),
        gate.clone(),
        watchdog.clone(),
        chokepoint.clone(),
    );
    let signed = Signed::sign(&host, "hostd", &ev);
    let decoded: HostEvidence = signed
        .verify(&host.verifying_key(), "host_evidence", AUD_CONTROLLER)
        .unwrap();
    assert_eq!(decoded, ev);
    assert_eq!(
        (
            decoded.run_id,
            decoded.incarnation,
            decoded.nonce,
            decoded.measured_at
        ),
        (a.run_id, a.incarnation, ch.nonce, 1_001)
    );
    assert_eq!(decoded.vm2, vm2);
    assert_eq!(decoded.gate, gate);
    assert_eq!(decoded.watchdog, watchdog);
    assert_eq!(decoded.chokepoint, chokepoint);
    assert_eq!(decoded.untrusted_vm2_report, None);
}

#[test]
fn foreign_forged_stale_or_malformed_challenges_are_rejected() {
    let controller = SigningKey::from_bytes(&[2; 32]);
    let wrong = SigningKey::from_bytes(&[3; 32]);
    for case in [
        "valid",
        "signature",
        "version",
        "type",
        "audience",
        "run",
        "incarnation",
        "epoch",
        "old",
        "future",
        "expired",
        "ttl",
        "nonce",
    ] {
        let mut ch = challenge();
        match case {
            "version" => ch.v += 1,
            "type" => ch.kind = "lease".into(),
            "audience" => ch.aud = AUD_CONTROLLER.into(),
            "run" => ch.run_id = "other".into(),
            "incarnation" => ch.incarnation = "other".into(),
            "epoch" => ch.epoch = 0,
            "old" => ch.issued_at -= CLOCK_SKEW_S + 1,
            "future" => ch.issued_at += CLOCK_SKEW_S + 1,
            "expired" => {
                ch.issued_at -= 2;
                ch.expires_in_s = 1;
            }
            "ttl" => ch.expires_in_s = CHALLENGE_TTL_S + 1,
            "nonce" => ch.nonce = "not-a-nonce".into(),
            _ => {}
        }
        let signer = if case == "signature" {
            &wrong
        } else {
            &controller
        };
        let result = PendingChallenge::verify(
            &Signed::sign(signer, "controller", &ch),
            &controller.verifying_key(),
            &args(),
            1,
            Instant::now(),
            1_000,
        );
        assert_eq!(result.is_ok(), case == "valid", "{case}");
    }
    let sent = Instant::now() - Duration::from_secs(CHALLENGE_TTL_S);
    assert!(
        PendingChallenge::verify(
            &Signed::sign(&controller, "controller", &challenge()),
            &controller.verifying_key(),
            &args(),
            1,
            sent,
            1_000
        )
        .is_err(),
        "a delayed response must not reset the nonce lifetime"
    );
}

#[test]
fn outstanding_challenges_wait_and_expiring_nonces_are_not_sent() {
    let now = Instant::now();
    let mut hb = Heartbeat::default();
    hb.defer_outstanding(now);
    assert!(hb.awaiting_challenge(now + OUTSTANDING_BACKOFF - Duration::from_millis(1)));
    assert!(!hb.awaiting_challenge(now + OUTSTANDING_BACKOFF));
    hb.pending = Some(PendingChallenge {
        challenge: challenge(),
        expires_at: now + Duration::from_secs(CHALLENGE_TTL_S),
    });
    assert!(
        !hb.awaiting_challenge(now),
        "a known nonce can be reused without polling /challenge"
    );
    assert!(!hb.discard_expiring(now));
    assert!(hb.discard_expiring(now + Duration::from_secs(CHALLENGE_TTL_S) - REQUEST_TIMEOUT));
    assert!(hb.pending.is_none());
    assert!(hb.awaiting_challenge(now + Duration::from_secs(CHALLENGE_TTL_S)));
}

#[test]
fn only_healthy_active_evidence_acknowledges_the_send_instant() {
    let sent_at = Instant::now() - Duration::from_secs(2);
    for (healthy, state) in [
        (true, "active"),
        (false, "active"),
        (false, "tripped"),
        (true, "tripped"),
        (true, "revoked"),
        (true, "terminated"),
        (true, "unknown"),
    ] {
        let response = serde_json::json!({"healthy": healthy, "state": state, "reason": null});
        match verdict(serde_json::from_value(response).unwrap(), sent_at) {
            Outcome::Healthy { sent_at: accepted } => {
                assert!(healthy && state == "active");
                assert_eq!(
                    accepted, sent_at,
                    "acknowledgement latency cannot extend health"
                );
            }
            Outcome::Rejected(_) => assert!(!healthy || state != "active"),
            Outcome::Deferred => panic!("a verdict is never a retry"),
        }
    }
    assert!(serde_json::from_str::<EvidenceResponse>(r#"{"state":"active"}"#).is_err());
}

#[test]
fn signed_destroy_orders_are_recognized_on_both_heartbeat_endpoints() {
    let controller = SigningKey::from_bytes(&[2; 32]);
    let order = Order {
        v: PROTO_V,
        kind: "order".into(),
        run_id: "run".into(),
        aud: AUD_HOSTD.into(),
        incarnation: "inc".into(),
        order: OrderKind::Destroy,
        fencing_token: 19,
        issued_at: 1_000,
        reason: "tripped".into(),
    };
    let signed = Signed::sign(&controller, "controller", &order);
    let reason = order_reason(&signed, &controller.verifying_key(), &args()).unwrap();
    assert!(reason.contains("Destroy") && reason.contains("tripped"));
    assert!(order_reason(
        &signed,
        &SigningKey::from_bytes(&[3; 32]).verifying_key(),
        &args()
    )
    .is_err());
    assert!(matches!(
        rejected_order(
            &signed,
            &SigningKey::from_bytes(&[3; 32]).verifying_key(),
            &args()
        ),
        Outcome::Rejected(_)
    ));
    assert!(matches!(
        serde_json::from_value::<Reply<EvidenceResponse>>(serde_json::to_value(&signed).unwrap())
            .unwrap(),
        Reply::Order(_)
    ));
    for wrapped in [
        serde_json::json!({"order": signed}),
        serde_json::json!({"state": "denied", "order": signed, "reason": "tripped"}),
    ] {
        assert!(matches!(
            serde_json::from_value::<Reply<EvidenceResponse>>(wrapped.clone()).unwrap(),
            Reply::Denied { .. }
        ));
        assert!(matches!(
            serde_json::from_value::<Reply<Signed>>(wrapped).unwrap(),
            Reply::Denied { .. }
        ));
    }
}

#[test]
fn cadence_leaves_a_local_stop_margin_before_controller_trip() {
    let trip = Duration::from_secs(CHALLENGE_TTL_S * MISSED_CHALLENGES_TO_TRIP as u64);
    assert_eq!(
        trip - MAX_EVIDENCE_AGE,
        Duration::from_secs(CHALLENGE_TTL_S)
    );
    assert!(Duration::from_secs(2 * 5) + 4 * REQUEST_TIMEOUT < MAX_EVIDENCE_AGE);
    assert!(validate_interval(5).is_ok());
    for seconds in [0, MAX_EVIDENCE_AGE.as_secs() / 2, trip.as_secs(), u64::MAX] {
        assert!(validate_interval(seconds).is_err());
    }
}
