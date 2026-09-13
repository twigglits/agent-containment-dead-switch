use super::*;
use crate::{Ctl, RequestReplay};
use axum::http::Request as HttpRequest;
use std::collections::HashMap;
use tower::ServiceExt;

struct Fixture {
    root: PathBuf,
    keys: BTreeMap<String, String>,
    scorer: SigningKey,
    second_scorer: SigningKey,
}

impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("ds-grading-controller-{}", random_hex(12)));
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(root.join("runs")).unwrap();
        std::fs::create_dir(root.join("evidence")).unwrap();
        let scorer = SigningKey::generate(&mut rand::rngs::OsRng);
        let second_scorer = SigningKey::generate(&mut rand::rngs::OsRng);
        let keys = BTreeMap::from([
            ("key1".into(), pubkey_hex(&scorer)),
            ("key2".into(), pubkey_hex(&second_scorer)),
        ]);
        Self {
            root,
            keys,
            scorer,
            second_scorer,
        }
    }

    fn init(&self, budget: u64) -> Arc<GradingService> {
        Arc::new(GradingService::open(&self.root, true, Some(budget), self.keys.clone()).unwrap())
    }

    fn reopen(&self) -> Arc<GradingService> {
        Arc::new(GradingService::open(&self.root, false, None, self.keys.clone()).unwrap())
    }

    fn app(&self, grading: Arc<GradingService>, runs: Vec<RunRecord>) -> Arc<App> {
        Arc::new(App {
            key: SigningKey::generate(&mut rand::rngs::OsRng),
            operator_token: "operator".into(),
            hostd_keys: vec![],
            state_dir: self.root.clone(),
            lease_ttl_s: 15,
            ctl: Mutex::new(Ctl {
                runs: runs.into_iter().map(|r| (r.run_id.clone(), r)).collect(),
                live: HashMap::new(),
                nonces: HashMap::new(),
            }),
            grading: Some(grading),
        })
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn run(id: &str) -> RunRecord {
    RunRecord {
        run_id: id.into(),
        state: RunState::Active,
        incarnation: Some(format!("inc-{id}")),
        hostd_pubkey: None,
        epoch: 1,
        fencing_token: 17,
        created_at: now_unix(),
        last_evidence_at: None,
        bypass_baseline: Some(0),
        expected_template_digest: Some("template".into()),
        expected_base_digest: Some("base".into()),
        reasons: vec![],
        defender_actions: vec![],
        request_replay: RequestReplay::default(),
        termination_confirmed_at: None,
    }
}

fn stopped(mut run: RunRecord) -> RunRecord {
    run.state = RunState::Revoked;
    run.termination_confirmed_at = Some(now_unix());
    run
}

fn request(campaign: &str, key: &str) -> AuthorizeBody {
    AuthorizeBody {
        campaign: campaign.into(),
        held_out_key_version: key.into(),
    }
}

fn store(service: &GradingService, run: &RunRecord, bytes: &[u8]) -> String {
    let now = now_unix();
    let grant = service.issue_upload(run, now).unwrap();
    service
        .reserve_upload(run, &grant.upload_token, now)
        .unwrap();
    service
        .store_upload(run, &grant.upload_token, bytes, now)
        .unwrap();
    grant.upload_token
}

fn result(job: &GradingJob, score: Score) -> GradingResult {
    GradingResult {
        v: PROTO_V,
        kind: RESULT_TYPE.into(),
        aud: AUD_GRADING_RESULTS.into(),
        job_id: job.job_id.clone(),
        run_id: job.run_id.clone(),
        incarnation: job.incarnation.clone(),
        fencing_token: job.fencing_token,
        issued_at: job.issued_at,
        expires_at: job.expires_at,
        submission_digest: job.submission_digest.clone(),
        task_id: job.task_id.clone(),
        input_version: job.input_version.clone(),
        scorer_version: job.scorer_version.clone(),
        sandbox_id: "c".repeat(32),
        launched_artifact_digest: job.submission_digest.clone(),
        captured_output_digest: sha256_hex(b"candidate"),
        score,
        status: GradingStatus::Completed,
        observations: LifecycleObservations {
            started: true,
            exited: true,
            timed_out: false,
            teardown_confirmed: true,
            started_at: job.issued_at,
            exited_at: job.issued_at,
            frozen_at: job.issued_at,
            teardown_confirmed_at: job.issued_at,
        },
    }
}

#[test]
fn durable_intake_pins_exact_bytes_and_claims_once_without_inspecting_code() {
    let f = Fixture::new();
    let service = f.init(1);
    let r = run("r1");
    let bytes = b"#!/bin/sh\n# untrusted bytes\nprintf 'PASS'\n\x00\xff";
    let token = store(&service, &r, bytes);
    let digest = sha256_hex(bytes);
    let broker: BrokerLedger = load_private(&service.dir.join("broker.json")).unwrap();
    assert_eq!(broker.submissions[&digest].size, bytes.len() as u64);
    assert_eq!(
        broker.authorizations["r1"].submission_digest.as_ref(),
        Some(&digest)
    );
    assert_eq!(
        service.read_object(&digest, bytes.len() as u64).unwrap(),
        bytes
    );
    assert_eq!(
        std::fs::metadata(service.dir.join("objects").join(&digest))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o400
    );
    assert!(service.reserve_upload(&r, &token, now_unix()).is_err());
    assert!(service
        .store_upload(&r, &token, b"replace", now_unix())
        .is_err());
    let duplicate = run("r2");
    let grant = service.issue_upload(&duplicate, now_unix()).unwrap();
    service
        .reserve_upload(&duplicate, &grant.upload_token, now_unix())
        .unwrap();
    assert!(service
        .store_upload(&duplicate, &grant.upload_token, bytes, now_unix())
        .is_err());
    assert_eq!(service.ledger.lock().unwrap().spent, 0);
    assert_eq!(service.broker.lock().unwrap().submissions.len(), 1);
}

#[test]
fn intake_rechecks_stop_after_capture_and_rejects_oversize_and_wrong_token() {
    let f = Fixture::new();
    let service = f.init(2);
    let r = run("r");
    let grant = service.issue_upload(&r, now_unix()).unwrap();
    assert!(service
        .reserve_upload(&r, &random_hex(32), now_unix())
        .is_err());
    service
        .reserve_upload(&r, &grant.upload_token, now_unix())
        .unwrap();
    assert!(service
        .store_upload(
            &stopped(r.clone()),
            &grant.upload_token,
            b"late",
            now_unix()
        )
        .is_err());
    assert!(service
        .store_upload(
            &r,
            &grant.upload_token,
            &vec![b'x'; MAX_SUBMISSION_BYTES + 1],
            now_unix()
        )
        .is_err());
    assert!(service
        .store_upload(&r, &grant.upload_token, b"", now_unix())
        .is_err());
    assert!(service.broker.lock().unwrap().submissions.is_empty());
}

#[test]
fn dispatch_requires_confirmed_terminal_eval_and_preserves_lease_fence() {
    let f = Fixture::new();
    let service = f.init(2);
    let r = run("r");
    store(&service, &r, b"submission");
    let request = request("campaign", "key1");
    assert!(service.claim(&r, &request, now_unix()).is_err());
    let mut terminal = r.clone();
    terminal.state = RunState::Tripped;
    assert!(service.claim(&terminal, &request, now_unix()).is_err());
    terminal = stopped(terminal);
    let dispatch = service.claim(&terminal, &request, now_unix()).unwrap();
    assert_eq!(dispatch.bytes, b"submission");
    assert_eq!(terminal.fencing_token, 17);
    assert_eq!(terminal.state, RunState::Revoked);
    let ledger: GradingLedger = load_private(&service.dir.join("ledger.json")).unwrap();
    assert_eq!(ledger.high_water, 1);
    assert_eq!(ledger.spent, 1);
    assert_eq!(
        ledger.claims[&dispatch.job.submission_digest].state,
        JobState::DispatchConsumed
    );
    assert!(service.claim(&terminal, &request, now_unix()).is_err());
}

#[tokio::test]
async fn separate_grading_authorization_cannot_resurrect_execution_lease() {
    let f = Fixture::new();
    let service = f.init(1);
    let mut r = run("r");
    let host = SigningKey::generate(&mut rand::rngs::OsRng);
    r.hostd_pubkey = Some(pubkey_hex(&host));
    store(&service, &r, b"submission");
    let r = stopped(r);
    service
        .claim(&r, &request("campaign", "key1"), now_unix())
        .unwrap();
    let app = f.app(service, vec![r]);
    let lease_request = LeaseRequest {
        v: PROTO_V,
        kind: "lease_request".into(),
        aud: AUD_CONTROLLER.into(),
        run_id: "r".into(),
        incarnation: "inc-r".into(),
        epoch: 1,
        issued_at: now_unix(),
        gate: GateState::Sealed,
    };
    let response = crate::lease(
        State(app.clone()),
        Json(Signed::sign(&host, "hostd", &lease_request)),
    )
    .await
    .unwrap();
    assert!(matches!(response.0, LeaseResponse::Denied { .. }));
    assert!(app.ctl.lock().unwrap().runs["r"].state.terminal());
}

#[test]
fn concurrent_claims_spend_and_launch_at_most_once() {
    let f = Fixture::new();
    let service = f.init(5);
    let r = run("r");
    store(&service, &r, b"submission");
    let r = stopped(r);
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let handles: Vec<_> = (0..8)
        .map(|_| {
            let service = service.clone();
            let r = r.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                barrier.wait();
                service
                    .claim(&r, &request("campaign", "key1"), now_unix())
                    .is_ok()
            })
        })
        .collect();
    let success = handles
        .into_iter()
        .filter_map(|thread| thread.join().ok())
        .filter(|ok| *ok)
        .count();
    assert_eq!(success, 1);
    let ledger: GradingLedger = load_private(&service.dir.join("ledger.json")).unwrap();
    assert_eq!(ledger.spent, 1);
    assert_eq!(ledger.claims.len(), 1);
}

#[test]
fn budget_counts_variants_campaigns_key_versions_and_restarts_globally() {
    let f = Fixture::new();
    let service = f.init(2);
    let first = run("first");
    store(&service, &first, b"variant A");
    let first = stopped(first);
    let d1 = service
        .claim(&first, &request("campaignA", "key1"), now_unix())
        .unwrap();
    service
        .commit_result(
            &first,
            &Signed::sign(&f.scorer, "scorer", &result(&d1.job, Score::Correct)),
            now_unix(),
        )
        .unwrap();
    let second = run("new-identity");
    store(&service, &second, b"variant B");
    let second = stopped(second);
    let d2 = service
        .claim(&second, &request("campaignB", "key2"), now_unix())
        .unwrap();
    service
        .commit_result(
            &second,
            &Signed::sign(
                &f.second_scorer,
                "scorer",
                &result(&d2.job, Score::Incorrect),
            ),
            now_unix(),
        )
        .unwrap();
    drop(service);
    let service = f.reopen();
    let third = run("reset-identity");
    // Intake still succeeds after grading exhaustion; no grader-dependent backpressure reaches it.
    store(&service, &third, b"variant C");
    assert!(service
        .claim(&stopped(third), &request("campaignC", "key1"), now_unix())
        .err()
        .unwrap()
        .to_string()
        .contains("budget exhausted"));
    assert_eq!(service.ledger.lock().unwrap().spent, 2);
    assert_eq!(service.anchor.max_jobs, 2);
}

#[test]
fn restart_ambiguous_dispatch_is_terminal_never_relaunched_or_released() {
    let f = Fixture::new();
    let service = f.init(4);
    let r = run("r");
    store(&service, &r, b"submission");
    let r = stopped(r);
    let job = service
        .claim(&r, &request("campaign", "key1"), now_unix())
        .unwrap()
        .job;
    drop(service);
    let service = f.reopen();
    assert_eq!(
        service.ledger.lock().unwrap().claims[&job.submission_digest].state,
        JobState::Abandoned
    );
    assert!(service
        .claim(&r, &request("retry", "key2"), now_unix())
        .is_err());
    assert!(service
        .commit_result(
            &r,
            &Signed::sign(&f.scorer, "scorer", &result(&job, Score::Correct)),
            now_unix()
        )
        .is_err());
    assert_eq!(service.ledger.lock().unwrap().spent, 1);
}

#[test]
fn timeout_uncertainty_retains_occupancy_and_never_grants_retry() {
    let f = Fixture::new();
    let service = f.init(4);
    let first = run("first");
    store(&service, &first, b"first");
    let first = stopped(first);
    let job = service
        .claim(&first, &request("campaign", "key1"), now_unix())
        .unwrap()
        .job;
    service.abandon(&job.job_id).unwrap();
    let second = run("second");
    store(&service, &second, b"second");
    let second = stopped(second);
    assert!(service
        .claim(&second, &request("campaign", "key1"), now_unix())
        .is_err());
    assert!(service
        .claim(&first, &request("campaign", "key1"), job.expires_at + 1)
        .is_err());
    let next = service
        .claim(&second, &request("campaign", "key1"), job.expires_at + 1)
        .unwrap();
    assert_eq!(next.job.fencing_token, 2);
    assert!(service
        .commit_result(
            &first,
            &Signed::sign(&f.scorer, "scorer", &result(&job, Score::Correct)),
            job.expires_at + 1
        )
        .is_err());
}

#[test]
fn append_checks_pinned_role_fencing_digest_expiry_and_teardown_before_commit() {
    let f = Fixture::new();
    let service = f.init(1);
    let r = run("r");
    store(&service, &r, b"submission");
    let r = stopped(r);
    let job = service
        .claim(&r, &request("campaign", "key1"), now_unix())
        .unwrap()
        .job;
    let good = result(&job, Score::Correct);
    assert!(service
        .commit_result(
            &r,
            &Signed::sign(&f.second_scorer, "scorer", &good),
            now_unix()
        )
        .is_err());
    assert!(service
        .commit_result(&r, &Signed::sign(&f.scorer, "hostd", &good), now_unix())
        .is_err());
    for changed in 0..6 {
        let mut bad = good.clone();
        match changed {
            0 => bad.fencing_token += 1,
            1 => bad.launched_artifact_digest = "e".repeat(64),
            2 => bad.observations.teardown_confirmed = false,
            3 => bad.task_id = "other-task".into(),
            4 => bad.observations.frozen_at = bad.issued_at + 1,
            _ => bad.incarnation = "wrong-incarnation".into(),
        }
        assert!(service
            .commit_result(&r, &Signed::sign(&f.scorer, "scorer", &bad), now_unix())
            .is_err());
    }
    assert!(service
        .commit_result(
            &r,
            &Signed::sign(&f.scorer, "scorer", &good),
            job.expires_at
        )
        .is_err());
    let signed = Signed::sign(&f.scorer, "scorer", &good);
    service.commit_result(&r, &signed, now_unix()).unwrap();
    service.commit_result(&r, &signed, now_unix()).unwrap();
    assert!(service
        .commit_result(
            &r,
            &Signed::sign(&f.scorer, "scorer", &result(&job, Score::Incorrect)),
            now_unix()
        )
        .is_err());
    let ledger: GradingLedger = load_private(&service.dir.join("ledger.json")).unwrap();
    assert_eq!(
        ledger.claims[&job.submission_digest].result.as_ref(),
        Some(&signed)
    );
    assert_eq!(ledger.spent, 1);
}

#[test]
fn controller_result_commit_honors_monotonic_expiry_even_if_wall_rolls_back() {
    let f = Fixture::new();
    let service = f.init(1);
    let r = run("r");
    store(&service, &r, b"submission");
    let r = stopped(r);
    let job = service
        .claim(&r, &request("campaign", "key1"), now_unix())
        .unwrap()
        .job;
    service
        .deadlines
        .lock()
        .unwrap()
        .get_mut(&job.job_id)
        .unwrap()
        .mono = Instant::now();
    assert!(service
        .commit_result(
            &r,
            &Signed::sign(&f.scorer, "scorer", &result(&job, Score::Correct)),
            job.issued_at
        )
        .is_err());
}

#[test]
fn result_authority_is_rechecked_after_slow_persistence_before_operator_visibility() {
    // Advance each authority boundary only AFTER the candidate is fsynced. This models a slow
    // fsync deterministically, without relying on filesystem latency or short real-time sleeps.
    for boundary in ["wall", "monotonic", "fencing"] {
        let f = Fixture::new();
        let service = f.init(1);
        let r = run("r");
        store(&service, &r, b"submission");
        let r = stopped(r);
        let job = service
            .claim(&r, &request("campaign", "key1"), now_unix())
            .unwrap()
            .job;
        let signed = Signed::sign(&f.scorer, "scorer", &result(&job, Score::Correct));
        let release_now = if boundary == "wall" {
            job.expires_at
        } else {
            now_unix()
        };
        let mut writes = 0;
        let committed = service.commit_result_with_persistence(
            &r,
            &signed,
            now_unix(),
            |next| {
                let barrier: PendingRelease =
                    load_private(&service.dir.join("pending-release.json"))?;
                assert_eq!(barrier.job_id, job.job_id);
                assert_eq!(barrier.submission_digest, job.submission_digest);
                service.save_ledger(next)?;
                writes += 1;
                if writes == 1 {
                    assert_eq!(
                        next.claims[&job.submission_digest].state,
                        JobState::ResultCommitted
                    );
                    let mut deadlines = service.deadlines.lock().unwrap();
                    let deadline = deadlines.get_mut(&job.job_id).unwrap();
                    match boundary {
                        "monotonic" => deadline.mono = Instant::now(),
                        "fencing" => deadline.fencing_token += 1,
                        _ => {}
                    }
                }
                Ok(())
            },
            || release_now,
        );
        assert!(committed.is_err(), "{boundary}");
        assert_eq!(writes, 2, "candidate then terminal tombstone");
        assert!(!service.dir.join("pending-release.json").exists());
        let disk: GradingLedger = load_private(&service.dir.join("ledger.json")).unwrap();
        for ledger in [&disk, &*service.ledger.lock().unwrap()] {
            assert_eq!(
                ledger.claims[&job.submission_digest].state,
                JobState::Abandoned
            );
            assert!(ledger.claims[&job.submission_digest].result.is_none());
            assert_eq!(ledger.spent, 1);
            assert_eq!(ledger.high_water, 1);
        }
        drop(service);
        let reopened = f.reopen();
        assert!(
            reopened.ledger.lock().unwrap().claims[&job.submission_digest]
                .result
                .is_none()
        );
        assert_eq!(reopened.ledger.lock().unwrap().spent, 1);
    }
}

#[test]
fn uncertain_late_result_tombstone_remains_withheld_after_restart() {
    let f = Fixture::new();
    let service = f.init(1);
    let r = run("r");
    store(&service, &r, b"submission");
    let r = stopped(r);
    let job = service
        .claim(&r, &request("campaign", "key1"), now_unix())
        .unwrap()
        .job;
    let signed = Signed::sign(&f.scorer, "scorer", &result(&job, Score::Correct));
    let mut writes = 0;
    assert!(service
        .commit_result_with_persistence(
            &r,
            &signed,
            now_unix(),
            |next| {
                writes += 1;
                if writes == 2 {
                    anyhow::bail!("simulated tombstone fsync failure");
                }
                service.save_ledger(next)
            },
            || job.expires_at,
        )
        .is_err());
    assert!(service.grading_poisoned.load(Ordering::SeqCst));
    assert!(
        service.ledger.lock().unwrap().claims[&job.submission_digest]
            .result
            .is_none()
    );
    let disk: GradingLedger = load_private(&service.dir.join("ledger.json")).unwrap();
    assert_eq!(
        disk.claims[&job.submission_digest].state,
        JobState::ResultCommitted
    );
    assert!(service.dir.join("pending-release.json").exists());
    drop(service);
    let reopened = f.reopen();
    let recovered: GradingLedger = load_private(&reopened.dir.join("ledger.json")).unwrap();
    assert_eq!(
        recovered.claims[&job.submission_digest].state,
        JobState::Abandoned
    );
    assert!(recovered.claims[&job.submission_digest].result.is_none());
    assert_eq!(recovered.spent, 1);
    assert_eq!(recovered.high_water, 1);
    assert!(!reopened.dir.join("pending-release.json").exists());
    assert!(reopened
        .claim(&r, &request("different-campaign", "key2"), now_unix())
        .is_err());
}

#[test]
fn normal_result_release_clears_barrier_and_preserves_exact_result_on_restart() {
    let f = Fixture::new();
    let service = f.init(1);
    let r = run("r");
    store(&service, &r, b"submission");
    let r = stopped(r);
    let job = service
        .claim(&r, &request("campaign", "key1"), now_unix())
        .unwrap()
        .job;
    let signed = Signed::sign(&f.scorer, "scorer", &result(&job, Score::Correct));
    service.commit_result(&r, &signed, now_unix()).unwrap();
    assert!(!service.dir.join("pending-release.json").exists());
    drop(service);
    let reopened = f.reopen();
    assert_eq!(
        reopened.ledger.lock().unwrap().claims[&job.submission_digest]
            .result
            .as_ref(),
        Some(&signed)
    );
    reopened.commit_result(&r, &signed, now_unix()).unwrap();
}

#[test]
fn cas_mutation_missing_state_corruption_and_reinitialization_fail_closed() {
    let f = Fixture::new();
    let service = f.init(2);
    let r = run("r");
    store(&service, &r, b"submission");
    let object = service.dir.join("objects").join(sha256_hex(b"submission"));
    std::fs::set_permissions(&object, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(&object, b"replacement").unwrap();
    assert!(service
        .claim(&stopped(r), &request("campaign", "key1"), now_unix())
        .is_err());
    assert_eq!(service.ledger.lock().unwrap().spent, 0);
    assert!(GradingService::open(&f.root, true, Some(2), f.keys.clone()).is_err());
    assert!(GradingService::open(&f.root, false, None, f.keys.clone()).is_err()); // exclusive process owner
    drop(service);
    let path = f.root.join("grading/ledger.json");
    let original = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    assert!(GradingService::open(&f.root, false, None, f.keys.clone()).is_err());
    assert!(GradingService::open(&f.root, true, Some(2), f.keys.clone()).is_err());
    create_private(&path, &serde_json::json!({"corrupt":true})).unwrap();
    assert!(GradingService::open(&f.root, false, None, f.keys.clone()).is_err());
    std::fs::write(&path, original).unwrap();
    let mut corrupt: GradingLedger = load_private(&path).unwrap();
    corrupt.spent = 1;
    persist_private(&path, &corrupt).unwrap();
    assert!(GradingService::open(&f.root, false, None, f.keys.clone()).is_err());
}

#[test]
fn signer_registry_cannot_replace_or_remove_pins_or_change_budget() {
    let f = Fixture::new();
    drop(f.init(2));
    assert!(GradingService::open(&f.root, false, Some(3), f.keys.clone()).is_err());
    let mut replaced = f.keys.clone();
    replaced.insert("key1".into(), pubkey_hex(&f.second_scorer));
    assert!(GradingService::open(&f.root, false, None, replaced).is_err());
    let mut removed = f.keys.clone();
    removed.remove("key2");
    assert!(GradingService::open(&f.root, false, None, removed).is_err());
    let mut appended = f.keys.clone();
    appended.insert(
        "key3".into(),
        pubkey_hex(&SigningKey::generate(&mut rand::rngs::OsRng)),
    );
    let service = GradingService::open(&f.root, false, None, appended).unwrap();
    assert_eq!(service.ledger.lock().unwrap().max_jobs, 2);
    assert_eq!(service.ledger.lock().unwrap().scorer_keys.len(), 3);
}

#[test]
fn persistence_failure_poisoning_is_plane_specific_and_does_not_reset_spend() {
    let f = Fixture::new();
    let service = f.init(3);
    let first = run("first");
    store(&service, &first, b"first");
    // Turn a protected ledger file into a directory to force a write failure before authority leaves.
    let ledger = service.dir.join("ledger.json");
    std::fs::remove_file(&ledger).unwrap();
    std::fs::create_dir(&ledger).unwrap();
    assert!(service
        .claim(&stopped(first), &request("campaign", "key1"), now_unix())
        .is_err());
    assert!(service.grading_poisoned.load(Ordering::SeqCst));
    assert!(!service.broker_poisoned.load(Ordering::SeqCst));
    // Grading errors never become broker backpressure or an admission status.
    store(&service, &run("second"), b"second");
    assert_eq!(service.broker.lock().unwrap().submissions.len(), 2);
}

#[test]
fn upload_rate_and_attempt_limits_survive_restart_and_wall_rollback() {
    let f = Fixture::new();
    let service = f.init(1);
    let r = run("r");
    let now = now_unix();
    let token = service.issue_upload(&r, now).unwrap().upload_token;
    for _ in 0..MAX_UPLOAD_ATTEMPTS {
        service.reserve_upload(&r, &token, now).unwrap();
    }
    assert!(service.reserve_upload(&r, &token, now).is_err());
    drop(service);
    let service = f.reopen();
    assert!(service.reserve_upload(&r, &token, now).is_err());
    assert!(service.issue_upload(&run("rollback"), now - 1).is_err());
    // A controller restart does not replenish the persisted per-minute admission budget.
    let mut broker = service.broker.lock().unwrap();
    broker.minute_attempts = MAX_UPLOADS_PER_MINUTE;
    service.save_broker(&broker).unwrap();
    drop(broker);
    let other = run("other");
    let token = service.issue_upload(&other, now).unwrap().upload_token;
    assert!(service.reserve_upload(&other, &token, now).is_err());
}

async fn call(
    router: Router,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, Vec<u8>) {
    let mut request = HttpRequest::builder().method(method).uri(path);
    if let Some(token) = bearer {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    let response = router
        .oneshot(request.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 65536)
        .await
        .unwrap()
        .to_vec();
    (status, bytes)
}

#[tokio::test]
async fn every_agent_receipt_is_identical_across_intake_grading_and_cross_run_states() {
    let f = Fixture::new();
    let service = f.init(1);
    let r = run("r");
    let dup = run("duplicate");
    let variant = run("variant");
    let later = run("later");
    let token = service.issue_upload(&r, now_unix()).unwrap().upload_token;
    let duplicate_token = service.issue_upload(&dup, now_unix()).unwrap().upload_token;
    let variant_token = service
        .issue_upload(&variant, now_unix())
        .unwrap()
        .upload_token;
    let later_token = service
        .issue_upload(&later, now_unix())
        .unwrap()
        .upload_token;
    let app = f.app(service.clone(), vec![r.clone(), dup, variant, later]);
    let router = upload_router().with_state(app.clone());
    let expected = (StatusCode::ACCEPTED, b"{\"status\":\"received\"}".to_vec());
    assert_eq!(
        call(
            router.clone(),
            "POST",
            "/submissions/%FF",
            Some(&token),
            vec![]
        )
        .await,
        expected
    );
    let response = router
        .clone()
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/submissions/%FF")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    assert_eq!(response.headers()[header::CONNECTION], "close");
    assert_eq!(
        call(
            router.clone(),
            "POST",
            "/submissions/r",
            Some(&token),
            b"code".to_vec()
        )
        .await,
        expected
    );
    assert_eq!(service.broker.lock().unwrap().submissions.len(), 1); // positive durability control
    assert_eq!(
        call(
            router.clone(),
            "POST",
            "/submissions/r",
            Some(&token),
            b"different".to_vec()
        )
        .await,
        expected
    );
    assert_eq!(
        call(
            router.clone(),
            "POST",
            "/submissions/duplicate",
            Some(&duplicate_token),
            b"code".to_vec()
        )
        .await,
        expected
    );
    assert_eq!(
        call(
            router.clone(),
            "POST",
            "/submissions/variant",
            Some(&variant_token),
            b"code-variant".to_vec()
        )
        .await,
        expected
    );
    assert_eq!(service.broker.lock().unwrap().submissions.len(), 2);
    assert_eq!(
        call(
            router.clone(),
            "POST",
            "/submissions/r",
            None,
            b"code".to_vec()
        )
        .await,
        expected
    );
    assert_eq!(
        call(
            router.clone(),
            "POST",
            "/submissions/later",
            Some(&later_token),
            vec![b'x'; MAX_SUBMISSION_BYTES + 1]
        )
        .await,
        expected
    );
    assert_eq!(
        call(router.clone(), "GET", "/grading/results", None, vec![]).await,
        expected
    );
    assert_eq!(
        call(
            router.clone(),
            "GET",
            "/submissions/r",
            Some(&token),
            vec![]
        )
        .await,
        expected
    );
    assert_eq!(
        call(
            router.clone(),
            "POST",
            "/fetch?url=http://10.20.0.4:7200",
            None,
            vec![]
        )
        .await,
        expected
    );
    let stopped = stopped(r);
    app.ctl
        .lock()
        .unwrap()
        .runs
        .insert("r".into(), stopped.clone());
    let job = service
        .claim(&stopped, &request("campaign", "key1"), now_unix())
        .unwrap()
        .job;
    service
        .commit_result(
            &stopped,
            &Signed::sign(&f.scorer, "scorer", &result(&job, Score::Correct)),
            now_unix(),
        )
        .unwrap();
    assert_eq!(
        call(
            router.clone(),
            "POST",
            "/submissions/r",
            Some(&token),
            b"late".to_vec()
        )
        .await,
        expected
    );
    // Budget exhausted and scorer plane failed, while independent broker intake remains available.
    service.grading_poisoned.store(true, Ordering::SeqCst);
    assert_eq!(
        call(
            router.clone(),
            "POST",
            "/submissions/later",
            Some(&later_token),
            b"new-private".to_vec()
        )
        .await,
        expected
    );
    assert_eq!(service.broker.lock().unwrap().submissions.len(), 3);
}

#[tokio::test]
async fn result_reads_are_only_on_authenticated_operator_router_and_append_is_scorer_only() {
    let f = Fixture::new();
    let service = f.init(1);
    let r = run("r");
    store(&service, &r, b"submission");
    let r = stopped(r);
    let job = service
        .claim(&r, &request("campaign", "key1"), now_unix())
        .unwrap()
        .job;
    let app = f.app(service.clone(), vec![r]);
    let result_router = results_router().with_state(app.clone());
    let signed = Signed::sign(&f.scorer, "scorer", &result(&job, Score::Correct));
    let forged = Signed::sign(&f.second_scorer, "scorer", &result(&job, Score::Correct));
    assert_eq!(
        call(
            result_router.clone(),
            "POST",
            "/results",
            None,
            serde_json::to_vec(&forged).unwrap()
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            result_router.clone(),
            "POST",
            "/results",
            None,
            serde_json::to_vec(&signed).unwrap()
        )
        .await,
        (StatusCode::OK, b"{\"status\":\"appended\"}".to_vec())
    );
    assert_eq!(
        call(
            result_router.clone(),
            "GET",
            "/results",
            Some("operator"),
            vec![]
        )
        .await
        .0,
        StatusCode::METHOD_NOT_ALLOWED
    );
    assert_eq!(
        call(
            result_router,
            "GET",
            "/grading/results",
            Some("operator"),
            vec![]
        )
        .await
        .0,
        StatusCode::METHOD_NOT_ALLOWED
    );
    let hostd = crate::hostd_router().with_state(app.clone());
    assert_eq!(
        call(hostd, "GET", "/grading/results", Some("operator"), vec![])
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    let ops = operator_router().with_state(app);
    assert_eq!(
        call(ops.clone(), "GET", "/grading/results", None, vec![])
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            ops.clone(),
            "GET",
            "/grading/results",
            Some("agent"),
            vec![]
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let response = call(ops, "GET", "/grading/results", Some("operator"), vec![]).await;
    assert_eq!(response.0, StatusCode::OK);
    let stored: Vec<Signed> = serde_json::from_slice(&response.1).unwrap();
    assert_eq!(stored, vec![signed]);
}

#[tokio::test]
async fn operator_authentication_gates_upload_and_grade_grants_before_any_claim() {
    let f = Fixture::new();
    let service = f.init(1);
    let r = run("r");
    let app = f.app(service.clone(), vec![r]);
    let ops = operator_router().with_state(app);
    assert_eq!(
        call(
            ops.clone(),
            "POST",
            "/grading/runs/r/upload-authorization",
            None,
            vec![]
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert!(service.broker.lock().unwrap().authorizations.is_empty());
    let response = call(
        ops,
        "POST",
        "/grading/runs/r/upload-authorization",
        Some("operator"),
        vec![],
    )
    .await;
    assert_eq!(response.0, StatusCode::OK);
    assert_eq!(service.broker.lock().unwrap().authorizations.len(), 1);
    assert_eq!(service.ledger.lock().unwrap().spent, 0);
}
