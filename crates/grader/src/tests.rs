use super::*;
use crate::state::{Binding, PendingJob, StateLock, Store};
use deadswitch_common::{pubkey_hex, random_hex};
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::Path;
use std::process::Command;

struct TestDir(PathBuf);

impl TestDir {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!("deadswitch-grader-test-{}", random_hex(16))))
    }
}

impl Drop for TestDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn fixture_job(bytes: &[u8], token: u64) -> GradingJob {
    let now = now_unix();
    GradingJob {
        v: PROTO_V,
        kind: JOB_TYPE.into(),
        aud: AUD_GRADER.into(),
        job_id: format!("job-{token}"),
        run_id: format!("run-{token}"),
        incarnation: "inc-1".into(),
        fencing_token: token,
        issued_at: now,
        expires_at: now + 120,
        submission_digest: sha256_hex(bytes),
        task_id: TASK_ID.into(),
        input_version: INPUT_VERSION.into(),
        scorer_version: SCORER_VERSION.into(),
    }
}

fn binding() -> Binding {
    Binding {
        controller_public_key: pubkey_hex(&SigningKey::from_bytes(&[1; 32])),
        scorer_public_key: pubkey_hex(&SigningKey::from_bytes(&[2; 32])),
        expected_output_digest: sha256_hex(b"42\n"),
    }
}

fn open_store(root: &Path) -> Store {
    Store::open(StateLock::acquire(root).unwrap(), &binding()).unwrap()
}

fn initialized() -> (TestDir, Arc<Mutex<Store>>) {
    let dir = TestDir::new();
    Store::initialize(&dir.0, binding()).unwrap();
    let store = Arc::new(Mutex::new(open_store(&dir.0)));
    (dir, store)
}

#[test]
fn scorer_uses_only_exact_candidate_bytes_and_bound_artifact() {
    let submission = b"import os; raise Exception('PASS'); arbitrary hostile code";
    let job = fixture_job(submission, 1);
    for (output, expected) in [
        (b"42\n".as_slice(), Score::Correct),
        (b"41\n".as_slice(), Score::Incorrect),
        (b"PASS".as_slice(), Score::Incorrect),
        (b"{\"PASS\":true,\"exit_code\":0,\"score\":1}".as_slice(), Score::Incorrect),
        (b"42\nPASS".as_slice(), Score::Incorrect),
        (b"".as_slice(), Score::Incorrect),
    ] {
        assert_eq!(score_candidate(&job, submission, &job.submission_digest, output, b"42\n").unwrap(), expected);
    }
    assert!(score_candidate(&job, b"replacement", &job.submission_digest, b"42\n", b"42\n").is_err());
    assert!(score_candidate(&job, submission, &sha256_hex(b"replacement"), b"42\n", b"42\n").is_err());
    assert!(score_candidate(&job, submission, &job.submission_digest, &vec![0; MAX_CAPTURED_OUTPUT_BYTES + 1], b"42\n").is_err());
}

#[test]
fn submitted_code_is_never_imported_executed_or_interpreted_by_scorer() {
    let dir = TestDir::new();
    let marker = dir.0.join("executed");
    let bytes = format!("#!/bin/sh\ntouch '{}'\nprintf 'PASS'\n", marker.display()).into_bytes();
    let job = fixture_job(&bytes, 1);
    assert_eq!(score_candidate(&job, &bytes, &job.submission_digest, b"42\n", b"42\n").unwrap(), Score::Correct);
    assert!(!marker.exists());
}

#[derive(Clone, Copy, PartialEq)]
enum Fault {
    None,
    LaunchError,
    WrongLaunchDigest,
    ObserveError,
    ObserveChanged,
    CaptureDigest,
    CaptureOverflow,
    CaptureWritable,
    CaptureSymlink,
    SubmissionChanged,
    Timeout,
    DestroyError,
    UnconfirmedDestroy,
    Shutdown,
    Expiry,
}

struct MockHooks {
    fault: Fault,
    output: Vec<u8>,
    events: Arc<Mutex<Vec<&'static str>>>,
    stopping: Arc<AtomicBool>,
    root: PathBuf,
    last_execution: Mutex<Option<LaunchObservation>>,
}

fn execution(ctx: &JobContext) -> LaunchObservation {
    LaunchObservation {
        sandbox_id: ctx.sandbox_id.clone(),
        launched_artifact_digest: ctx.job.submission_digest.clone(),
        started: true,
        exited: true,
        timed_out: false,
        started_at: ctx.job.issued_at,
        exited_at: now_unix(),
    }
}

fn replace_private(path: &Path, data: &[u8]) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(path, data).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o400)).unwrap();
}

impl SandboxHooks for MockHooks {
    fn launch(&self, ctx: &JobContext, authority: &Authority<'_>) -> anyhow::Result<LaunchObservation> {
        self.events.lock().unwrap().push("launch");
        // Proves admission persists the fencing+terminal authorization BEFORE launch.
        let ledger: serde_json::Value = serde_json::from_slice(&fs::read(self.root.join("ledger.json"))?)?;
        assert_eq!(ledger["high_water"], ctx.job.fencing_token);
        assert_eq!(ledger["claims"][&ctx.job.job_id]["status"], "execution_claimed");
        assert!(ledger["claims"][&ctx.job.job_id]["result"].is_null());
        state::verify_staged(ctx)?;
        if self.fault == Fault::LaunchError {
            anyhow::bail!("simulated partial launch crash");
        }
        let output = if self.fault == Fault::CaptureOverflow {
            vec![0; MAX_CAPTURED_OUTPUT_BYTES + 1]
        } else {
            self.output.clone()
        };
        state::write_new(&ctx.capture_path, &output, 0o400)?;
        if self.fault == Fault::CaptureWritable {
            fs::set_permissions(&ctx.capture_path, fs::Permissions::from_mode(0o600))?;
        }
        if self.fault == Fault::CaptureSymlink {
            fs::remove_file(&ctx.capture_path)?;
            symlink(&ctx.submission_path, &ctx.capture_path)?;
        }
        if self.fault == Fault::SubmissionChanged {
            replace_private(&ctx.submission_path, b"changed candidate");
        }
        if self.fault == Fault::Shutdown {
            self.stopping.store(true, Ordering::SeqCst);
        }
        if self.fault == Fault::Expiry {
            while !authority.deadline.expired(now_unix()) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        let mut observed = execution(ctx);
        if self.fault == Fault::WrongLaunchDigest {
            observed.launched_artifact_digest = sha256_hex(b"different launch");
        }
        if self.fault == Fault::Timeout {
            observed.timed_out = true;
        }
        *self.last_execution.lock().unwrap() = Some(observed.clone());
        Ok(observed)
    }

    fn observe(&self, ctx: &JobContext, _: &Authority<'_>) -> anyhow::Result<FrozenObservation> {
        self.events.lock().unwrap().push("freeze");
        if self.fault == Fault::ObserveError {
            anyhow::bail!("missing observation");
        }
        let mut observed = FrozenObservation {
            execution: self.last_execution.lock().unwrap().clone().unwrap_or_else(|| execution(ctx)),
            frozen: true,
            captured_output_digest: sha256_hex(&self.output),
            capture_bytes: self.output.len() as u64,
        };
        if self.fault == Fault::ObserveChanged {
            observed.execution.sandbox_id = random_hex(16);
        }
        if self.fault == Fault::CaptureDigest {
            observed.captured_output_digest = sha256_hex(b"forged evidence");
        }
        // Use the exact flat JSON shell-hook wire contract even in mocked execution tests.
        Ok(serde_json::from_slice(&serde_json::to_vec(&observed)?)?)
    }

    fn destroy(&self, ctx: &JobContext) -> anyhow::Result<TeardownObservation> {
        self.events.lock().unwrap().push("destroy");
        if self.fault == Fault::DestroyError {
            anyhow::bail!("actuator failure");
        }
        // Mutation after the freeze cannot alter the score or signed captured-output digest.
        if self.fault == Fault::None && ctx.capture_path.exists() {
            replace_private(&ctx.capture_path, b"POISON-A");
        }
        Ok(TeardownObservation {
            sandbox_id: ctx.sandbox_id.clone(),
            processes_gone: true,
            storage_gone: self.fault != Fault::UnconfirmedDestroy,
            teardown_confirmed_at: now_unix(),
        })
    }

    fn destroy_all(&self) -> anyhow::Result<GlobalTeardownObservation> {
        self.events.lock().unwrap().push("destroy_all");
        Ok(GlobalTeardownObservation {
            processes_gone: true,
            storage_gone: true,
            teardown_confirmed_at: now_unix(),
        })
    }
}

struct MockPublisher {
    events: Arc<Mutex<Vec<&'static str>>>,
    published: Arc<Mutex<Vec<Signed>>>,
    store: Arc<Mutex<Store>>,
    root: PathBuf,
    fail: bool,
}

impl ResultPublisher for MockPublisher {
    fn publish(&self, result: &Signed, authority: &Authority<'_>) -> anyhow::Result<()> {
        authority.check()?;
        self.events.lock().unwrap().push("publish");
        let parsed: GradingResult = result.verify(&SigningKey::from_bytes(&[2; 32]).verifying_key(), RESULT_TYPE, AUD_GRADING_RESULTS)?;
        assert_eq!(self.store.lock().unwrap().committed_result(&parsed.job_id), Some(result));
        assert_eq!(fs::read_dir(self.root.join("jobs"))?.count(), 0);
        self.published.lock().unwrap().push(result.clone());
        if self.fail { anyhow::bail!("ambiguous response loss"); }
        Ok(())
    }
}

type TestProcessor = Processor<MockHooks, MockPublisher>;

fn harness(fault: Fault, output: &[u8], publication_fails: bool) -> (TestDir, TestProcessor, PendingJob) {
    let (dir, store) = initialized();
    let events = Arc::new(Mutex::new(Vec::new()));
    let stopping = Arc::new(AtomicBool::new(false));
    let hooks = MockHooks {
        fault,
        output: output.to_vec(),
        events: events.clone(),
        stopping: stopping.clone(),
        root: dir.0.clone(),
        last_execution: Mutex::new(None),
    };
    let publisher = MockPublisher {
        events,
        published: Arc::new(Mutex::new(Vec::new())),
        store: store.clone(),
        root: dir.0.clone(),
        fail: publication_fails,
    };
    let bytes = b"#!/bin/sh\nprintf 'PASS'\n";
    let pending = store.lock().unwrap().claim(fixture_job(bytes, 1), bytes, now_unix()).unwrap();
    let processor = Processor {
        hooks,
        publisher,
        store,
        scorer_key: SigningKey::from_bytes(&[2; 32]),
        expected_output: b"42\n".to_vec(),
        stopping,
    };
    (dir, processor, pending)
}

#[test]
fn freeze_and_confirmed_teardown_and_commit_precede_publication() {
    let (_dir, processor, pending) = harness(Fault::None, b"42\n", false);
    processor.process(pending).unwrap();
    assert_eq!(*processor.hooks.events.lock().unwrap(), ["launch", "freeze", "destroy", "publish"]);
    let result = processor.publisher.published.lock().unwrap()[0].clone();
    let parsed: GradingResult = result.verify(&processor.scorer_key.verifying_key(), RESULT_TYPE, AUD_GRADING_RESULTS).unwrap();
    assert_eq!(parsed.score, Score::Correct);
    assert_eq!(parsed.captured_output_digest, sha256_hex(b"42\n"));
    assert!(!result.payload.contains("POISON-A"));
}

#[test]
fn wrong_and_forged_pass_execute_but_only_receive_trusted_incorrect_score() {
    for bytes in [b"41\n".as_slice(), b"PASS".as_slice(), b"{\"score\":1}".as_slice()] {
        let (_dir, processor, pending) = harness(Fault::None, bytes, false);
        processor.process(pending).unwrap();
        let result = processor.publisher.published.lock().unwrap()[0].clone();
        let parsed: GradingResult = result.verify(&processor.scorer_key.verifying_key(), RESULT_TYPE, AUD_GRADING_RESULTS).unwrap();
        assert_eq!(parsed.score, Score::Incorrect);
    }
}

#[test]
fn all_anomalies_destroy_and_release_no_result() {
    for fault in [
        Fault::LaunchError, Fault::WrongLaunchDigest, Fault::ObserveError, Fault::ObserveChanged,
        Fault::CaptureDigest, Fault::CaptureOverflow, Fault::CaptureWritable, Fault::CaptureSymlink,
        Fault::SubmissionChanged, Fault::Timeout, Fault::DestroyError, Fault::UnconfirmedDestroy,
        Fault::Shutdown, Fault::Expiry,
    ] {
        let (_dir, processor, mut pending) = harness(fault, b"42\n", false);
        if fault == Fault::Expiry {
            pending.deadline.mono = Instant::now() + Duration::from_millis(20);
        }
        assert!(processor.process(pending).is_err());
        assert!(processor.hooks.events.lock().unwrap().contains(&"destroy"));
        assert!(processor.publisher.published.lock().unwrap().is_empty());
        assert!(processor.store.lock().unwrap().committed_result("job-1").is_none());
        assert_eq!(processor.store.lock().unwrap().quarantined(), matches!(fault, Fault::DestroyError | Fault::UnconfirmedDestroy));
    }
}

#[test]
fn missing_authority_does_not_launch_but_still_destroys() {
    let (_dir, processor, mut pending) = harness(Fault::None, b"42\n", false);
    pending.deadline.mono = Instant::now();
    assert!(processor.process(pending).is_err());
    assert_eq!(*processor.hooks.events.lock().unwrap(), ["destroy"]);
}

#[test]
fn uncertain_teardown_quarantines_future_jobs_and_survives_restart() {
    let (dir, processor, pending) = harness(Fault::UnconfirmedDestroy, b"42\n", false);
    assert!(processor.process(pending).is_err());
    let bytes = b"different candidate";
    assert!(processor.store.lock().unwrap().claim(fixture_job(bytes, 2), bytes, now_unix()).is_err());
    drop(processor);
    let mut reopened = open_store(&dir.0);
    reopened.finish_recovery().unwrap();
    assert!(reopened.quarantined());
    assert!(reopened.claim(fixture_job(bytes, 2), bytes, now_unix()).is_err());
}

#[test]
fn ambiguous_delivery_retains_identical_committed_result_and_never_relaunches() {
    let (dir, processor, pending) = harness(Fault::None, b"42\n", true);
    let bytes = fs::read(&pending.context.submission_path).unwrap();
    let job = pending.context.job.clone();
    assert!(processor.process(pending).is_err());
    let committed = processor.store.lock().unwrap().committed_result(&job.job_id).unwrap().clone();
    assert_eq!(processor.publisher.published.lock().unwrap()[0], committed);
    drop(processor);
    let mut reopened = open_store(&dir.0);
    reopened.finish_recovery().unwrap();
    assert_eq!(reopened.committed_result(&job.job_id), Some(&committed));
    assert!(reopened.claim(job, &bytes, now_unix()).is_err());
}

#[test]
fn fresh_job_cannot_see_previous_sandbox_files() {
    let (_dir, processor, pending) = harness(Fault::None, b"42\n", false);
    let old = pending.context.clone();
    processor.process(pending).unwrap();
    let bytes = b"candidate B";
    let pending_b = processor.store.lock().unwrap().claim(fixture_job(bytes, 2), bytes, now_unix()).unwrap();
    assert_ne!(old.sandbox_id, pending_b.context.sandbox_id);
    assert!(!old.job_dir.exists());
    assert!(!pending_b.context.capture_path.exists());
    assert_eq!(fs::read_dir(&pending_b.context.job_dir).unwrap().count(), 1);
}

#[test]
fn durable_claims_fence_duplicates_conflicts_and_delayed_authorization() {
    let (_dir, store) = initialized();
    let bytes = b"candidate A";
    let job = fixture_job(bytes, 4);
    let pending = store.lock().unwrap().claim(job.clone(), bytes, now_unix()).unwrap();
    assert!(store.lock().unwrap().claim(fixture_job(b"B", 5), b"B", now_unix()).is_err());
    store.lock().unwrap().abort(&job.job_id, false).unwrap();
    state::remove_job_files(&pending.context).unwrap();
    assert!(store.lock().unwrap().claim(job.clone(), bytes, now_unix()).is_err());
    assert!(store.lock().unwrap().claim(fixture_job(bytes, 5), bytes, now_unix()).is_err());
    assert!(store.lock().unwrap().claim(fixture_job(b"B", 3), b"B", now_unix()).is_err());
    let mut delayed = fixture_job(b"B", 5);
    delayed.issued_at -= 6;
    delayed.expires_at -= 6;
    assert!(store.lock().unwrap().claim(delayed, b"B", now_unix()).is_err());
}

#[test]
fn restart_never_relaunches_ambiguous_execution_and_preserves_fencing() {
    let (dir, store) = initialized();
    let bytes = b"candidate A";
    let job = fixture_job(bytes, 7);
    let pending = store.lock().unwrap().claim(job.clone(), bytes, now_unix()).unwrap();
    drop(store);
    let mut reopened = open_store(&dir.0);
    assert!(reopened.busy());
    assert!(reopened.claim(fixture_job(b"B", 8), b"B", now_unix()).is_err());
    reopened.finish_recovery().unwrap();
    assert!(!pending.context.job_dir.exists());
    assert_eq!(reopened.high_water(), 7);
    assert!(!reopened.busy());
    assert!(reopened.claim(job, bytes, now_unix()).is_err());
    assert!(reopened.claim(fixture_job(b"B", 7), b"B", now_unix()).is_err());
}

#[test]
fn state_requires_explicit_initialization_and_rejects_loss_corruption_and_key_reset() {
    let dir = TestDir::new();
    assert!(StateLock::acquire(&dir.0).is_err());
    Store::initialize(&dir.0, binding()).unwrap();
    assert!(Store::initialize(&dir.0, binding()).is_err());
    let first = open_store(&dir.0);
    assert!(StateLock::acquire(&dir.0).is_err());
    drop(first);
    let mut wrong = binding();
    wrong.scorer_public_key = pubkey_hex(&SigningKey::from_bytes(&[3; 32]));
    assert!(Store::open(StateLock::acquire(&dir.0).unwrap(), &wrong).is_err());
    fs::write(dir.0.join("ledger.json"), b"{corrupt").unwrap();
    assert!(Store::open(StateLock::acquire(&dir.0).unwrap(), &binding()).is_err());
    fs::remove_file(dir.0.join("ledger.json")).unwrap();
    assert!(Store::open(StateLock::acquire(&dir.0).unwrap(), &binding()).is_err());
    assert!(Store::initialize(&dir.0, binding()).is_err());
}

#[test]
fn clock_rollback_cannot_reset_durable_authority() {
    let (dir, store) = initialized();
    let bytes = b"candidate";
    assert!(store.lock().unwrap().claim(fixture_job(bytes, 1), bytes, now_unix() - 1).is_err());
    drop(store);
    let ledger_path = dir.0.join("ledger.json");
    let mut ledger: serde_json::Value = serde_json::from_slice(&fs::read(&ledger_path).unwrap()).unwrap();
    ledger["wall_floor"] = serde_json::json!(now_unix() + 60);
    fs::write(&ledger_path, serde_json::to_vec(&ledger).unwrap()).unwrap();
    assert!(Store::open(StateLock::acquire(&dir.0).unwrap(), &binding()).is_err());
}

#[test]
fn private_capture_rejects_symlink_hardlink_exposure_and_writable_files() {
    let (dir, _store) = initialized();
    let path = dir.0.join("capture");
    state::write_new(&path, b"42\n", 0o400).unwrap();
    assert_eq!(state::read_private_file(&path, 4096, true).unwrap(), b"42\n");
    symlink(&path, dir.0.join("symlink")).unwrap();
    assert!(state::read_private_file(&dir.0.join("symlink"), 4096, true).is_err());
    fs::hard_link(&path, dir.0.join("hardlink")).unwrap();
    assert!(state::read_private_file(&path, 4096, true).is_err());
    fs::remove_file(dir.0.join("hardlink")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(state::read_private_file(&path, 4096, true).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(state::read_private_file(&path, 4096, true).is_err());
}

#[test]
fn actual_flat_hook_json_is_strict_and_requires_all_observations() {
    let raw = br#"{"sandbox_id":"0123456789abcdef0123456789abcdef","launched_artifact_digest":"1111111111111111111111111111111111111111111111111111111111111111","started":true,"exited":true,"timed_out":false,"started_at":1,"exited_at":2,"frozen":true,"captured_output_digest":"2222222222222222222222222222222222222222222222222222222222222222","capture_bytes":3}"#;
    let parsed: FrozenObservation = serde_json::from_slice(raw).unwrap();
    assert_eq!(parsed.execution.started_at, 1);
    let mut value: serde_json::Value = serde_json::from_slice(raw).unwrap();
    value["PASS"] = serde_json::json!(true);
    assert!(serde_json::from_value::<FrozenObservation>(value.clone()).is_err());
    value.as_object_mut().unwrap().remove("PASS");
    value.as_object_mut().unwrap().remove("frozen");
    assert!(serde_json::from_value::<FrozenObservation>(value).is_err());
    assert!(serde_json::from_str::<TeardownObservation>(r#"{"sandbox_id":"x","processes_gone":true,"storage_gone":true,"teardown_confirmed_at":1,"guest_report":"PASS"}"#).is_err());
    assert!(serde_json::from_str::<GlobalTeardownObservation>(r#"{"processes_gone":true,"teardown_confirmed_at":1}"#).is_err());
}

#[test]
fn hook_timeout_kills_hanging_process_group_and_bounds_output_floods() {
    for shell in ["sleep 60", "sleep 60 & wait", "while :; do printf 'xxxxxxxxxxxxxxxx'; done"] {
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg(shell);
        let start = Instant::now();
        assert!(hooks::run_bounded(command, None, Duration::from_millis(100)).is_err());
        assert!(start.elapsed() < Duration::from_secs(2));
    }
}

#[test]
fn hook_shutdown_and_both_clock_expiry_are_enforced_independently() {
    for (mono, wall, shutdown) in [
        (Instant::now(), now_unix() + 120, false),
        (Instant::now() + Duration::from_secs(120), now_unix(), false),
        (Instant::now() + Duration::from_secs(120), now_unix() + 120, true),
    ] {
        let stop = AtomicBool::new(shutdown);
        let deadline = Deadline { mono, wall, fencing_token: 1, epoch: 0 };
        let authority = Authority { deadline: &deadline, stopping: &stop };
        let mut command = Command::new("/bin/sh");
        command.arg("-c").arg("sleep 60");
        assert!(hooks::run_bounded(command, Some(&authority), Duration::from_millis(100)).is_err());
    }
}
