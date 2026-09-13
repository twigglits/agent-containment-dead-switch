//! Trusted grading coordinator. Submitted bytes and guest output are always inert byte strings
//! here. Only operator-installed hooks can execute anything; they launch the disposable guest.
//! Authorization is consumed durably before acknowledgement, and no result exists until trusted
//! observations have been frozen and both process and storage teardown have been confirmed.

pub mod hooks;
pub mod state;

use anyhow::{ensure, Context};
use deadswitch_common::grading::*;
use deadswitch_common::{now_unix, sha256_hex, Deadline, Signed, PROTO_V};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

pub const RESULT_URL: &str = "http://10.20.0.1:7201/results";
pub const DISPATCH_ADDR: &str = "10.20.0.4:7200";
pub const FIXED_DISPATCH_ACK: &str = "{\"status\":\"received\"}";

#[derive(Clone, Debug)]
pub struct JobContext {
    pub job: GradingJob,
    pub sandbox_id: String,
    pub job_dir: PathBuf,
    pub submission_path: PathBuf,
    pub capture_path: PathBuf,
}

/// Both clocks and operator shutdown are checked throughout execution, freezing and publication.
pub struct Authority<'a> {
    pub deadline: &'a Deadline,
    pub stopping: &'a AtomicBool,
}

impl Authority<'_> {
    pub fn check(&self) -> anyhow::Result<()> {
        ensure!(
            !self.stopping.load(Ordering::SeqCst) && !self.deadline.expired(now_unix()),
            "grading authority unavailable"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LaunchObservation {
    pub sandbox_id: String,
    pub launched_artifact_digest: String,
    pub started: bool,
    pub exited: bool,
    pub timed_out: bool,
    pub started_at: u64,
    pub exited_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrozenObservation {
    #[serde(flatten)]
    pub execution: LaunchObservation,
    pub frozen: bool,
    pub captured_output_digest: String,
    pub capture_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TeardownObservation {
    pub sandbox_id: String,
    pub processes_gone: bool,
    pub storage_gone: bool,
    pub teardown_confirmed_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GlobalTeardownObservation {
    pub processes_gone: bool,
    pub storage_gone: bool,
    pub teardown_confirmed_at: u64,
}

/// Production hooks enforce their own process, storage, credential and network boundary. Trait
/// implementations cannot turn guest-written assertions into trusted observations.
pub trait SandboxHooks: Send + Sync {
    fn launch(&self, job: &JobContext, authority: &Authority<'_>) -> anyhow::Result<LaunchObservation>;
    fn observe(&self, job: &JobContext, authority: &Authority<'_>) -> anyhow::Result<FrozenObservation>;
    /// Destruction remains authorized after expiry or shutdown; it is independently time-bounded.
    fn destroy(&self, job: &JobContext) -> anyhow::Result<TeardownObservation>;
    fn destroy_all(&self) -> anyhow::Result<GlobalTeardownObservation>;
}

pub trait ResultPublisher: Send + Sync {
    fn publish(&self, result: &Signed, authority: &Authority<'_>) -> anyhow::Result<()>;
}

/// Exact byte comparison: no imports, shell, JSON reports, guest exit status or guest PASS parser.
/// A forged PASS is simply an incorrect candidate answer for the fixed fixture.
pub fn score_candidate(
    job: &GradingJob,
    pinned_submission: &[u8],
    launched_artifact_digest: &str,
    captured_output: &[u8],
    expected_output: &[u8],
) -> anyhow::Result<Score> {
    job.bind_submission(pinned_submission)
        .map_err(|e| anyhow::anyhow!(e))?;
    ensure!(
        launched_artifact_digest == job.submission_digest,
        "launch digest mismatch"
    );
    ensure!(
        captured_output.len() <= MAX_CAPTURED_OUTPUT_BYTES
            && !expected_output.is_empty()
            && expected_output.len() <= MAX_CAPTURED_OUTPUT_BYTES,
        "output bound violated"
    );
    Ok(if captured_output == expected_output {
        Score::Correct
    } else {
        Score::Incorrect
    })
}

pub struct Processor<H: SandboxHooks, P: ResultPublisher> {
    pub hooks: H,
    pub publisher: P,
    pub store: Arc<Mutex<state::Store>>,
    pub scorer_key: SigningKey,
    pub expected_output: Vec<u8>,
    pub stopping: Arc<AtomicBool>,
}

impl<H: SandboxHooks, P: ResultPublisher> Processor<H, P> {
    /// No retry of execution exists. A consumed claim can only become aborted or committed.
    pub fn process(&self, pending: state::PendingJob) -> anyhow::Result<()> {
        let authority = Authority {
            deadline: &pending.deadline,
            stopping: &self.stopping,
        };
        let ctx = &pending.context;
        let execution = self.run_and_freeze(ctx, &authority);
        // ALWAYS attempt destruction, including failed/partial launch, digest mismatch and expiry.
        let teardown = self.hooks.destroy(ctx).and_then(|v| {
            ensure!(
                v.sandbox_id == ctx.sandbox_id
                    && v.processes_gone
                    && v.storage_gone
                    && v.teardown_confirmed_at <= now_unix(),
                "sandbox destruction unconfirmed"
            );
            Ok(v)
        });
        let clean = teardown.is_ok();
        let result = (|| {
            let frozen = execution?;
            let destroyed = teardown?;
            authority.check()?;
            ensure!(
                destroyed.teardown_confirmed_at >= frozen.frozen_at,
                "teardown precedes frozen observations"
            );
            let result = GradingResult {
                v: PROTO_V,
                kind: RESULT_TYPE.into(),
                aud: AUD_GRADING_RESULTS.into(),
                job_id: ctx.job.job_id.clone(),
                run_id: ctx.job.run_id.clone(),
                incarnation: ctx.job.incarnation.clone(),
                fencing_token: ctx.job.fencing_token,
                issued_at: now_unix(),
                expires_at: ctx.job.expires_at,
                submission_digest: ctx.job.submission_digest.clone(),
                task_id: ctx.job.task_id.clone(),
                input_version: ctx.job.input_version.clone(),
                scorer_version: ctx.job.scorer_version.clone(),
                sandbox_id: ctx.sandbox_id.clone(),
                launched_artifact_digest: frozen.execution.launched_artifact_digest,
                captured_output_digest: frozen.captured_output_digest,
                score: frozen.score,
                status: GradingStatus::Completed,
                observations: LifecycleObservations {
                    started: true,
                    exited: true,
                    timed_out: false,
                    teardown_confirmed: true,
                    started_at: frozen.execution.started_at,
                    exited_at: frozen.execution.exited_at,
                    frozen_at: frozen.frozen_at,
                    teardown_confirmed_at: destroyed.teardown_confirmed_at,
                },
            };
            result
                .validate_for(&ctx.job, now_unix())
                .map_err(|e| anyhow::anyhow!(e))?;
            let signed = Signed::sign(&self.scorer_key, "scorer", &result);
            // This terminal record is fsynced before anything reaches the result socket. If
            // publication is ambiguous, only these identical bytes could ever be redelivered.
            self.store
                .lock()
                .map_err(|_| anyhow::anyhow!("state lock poisoned"))?
                .commit(&ctx.job.job_id, &signed)?;
            authority.check()?;
            self.publisher.publish(&signed, &authority)?;
            authority.check()?;
            Ok(())
        })();
        // Capture was frozen in trusted memory before destroy, and never goes on the wire.
        let local_cleanup = state::remove_job_files(ctx);
        if result.is_err() || local_cleanup.is_err() {
            let mut store = self
                .store
                .lock()
                .map_err(|_| anyhow::anyhow!("state lock poisoned"))?;
            // Committed results stay immutable, including ambiguous HTTP delivery. An uncertain
            // teardown or local cleanup closes the entire service to future jobs.
            store.abort(&ctx.job.job_id, !clean || local_cleanup.is_err())?;
        }
        local_cleanup?;
        result
    }

    fn run_and_freeze(&self, ctx: &JobContext, authority: &Authority<'_>) -> anyhow::Result<Frozen> {
        authority.check()?;
        let submitted = state::read_private_file(&ctx.submission_path, MAX_SUBMISSION_BYTES, true)?;
        ctx.job
            .bind_submission(&submitted)
            .map_err(|e| anyhow::anyhow!(e))?;
        let launch = self.hooks.launch(ctx, authority)?;
        authority.check()?;
        ensure!(
            launch.sandbox_id == ctx.sandbox_id
                && launch.launched_artifact_digest == ctx.job.submission_digest
                && launch.started
                && launch.exited
                && !launch.timed_out
                && launch.started_at >= ctx.job.issued_at
                && launch.started_at <= launch.exited_at
                && launch.exited_at <= now_unix(),
            "untrusted or anomalous execution observations"
        );
        let observed = self.hooks.observe(ctx, authority)?;
        authority.check()?;
        ensure!(
            observed.execution == launch && observed.frozen,
            "observation changed before freeze"
        );
        let captured = state::read_private_file(&ctx.capture_path, MAX_CAPTURED_OUTPUT_BYTES, true)?;
        let digest = sha256_hex(&captured);
        ensure!(
            observed.capture_bytes == captured.len() as u64
                && observed.captured_output_digest == digest,
            "captured output digest mismatch"
        );
        // Re-read immutable submission after execution as well; hooks may never silently replace
        // the launch bytes. Captured bytes have already been copied into trusted memory.
        let submitted_after =
            state::read_private_file(&ctx.submission_path, MAX_SUBMISSION_BYTES, true)?;
        ensure!(submitted_after == submitted, "pinned submission changed");
        let score = score_candidate(
            &ctx.job,
            &submitted,
            &launch.launched_artifact_digest,
            &captured,
            &self.expected_output,
        )?;
        authority.check()?;
        Ok(Frozen {
            execution: launch,
            score,
            captured_output_digest: digest,
            frozen_at: now_unix(),
        })
    }
}

struct Frozen {
    execution: LaunchObservation,
    score: Score,
    captured_output_digest: String,
    frozen_at: u64,
}

/// Fixed numeric destination, no proxy, no redirect, no DNS, no response-body consumption. Each
/// blocking network operation is capped by both remaining clocks; the sandbox is already gone.
pub struct HttpPublisher;

impl ResultPublisher for HttpPublisher {
    fn publish(&self, result: &Signed, authority: &Authority<'_>) -> anyhow::Result<()> {
        authority.check()?;
        let remaining = authority.deadline.remaining_ms(now_unix());
        ensure!(remaining > 0, "result authority expired");
        let max_time = Duration::from_millis(remaining as u64).min(Duration::from_secs(5));
        let until = Instant::now() + max_time;
        let client = reqwest::blocking::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(max_time)
            .timeout(max_time)
            .build()?;
        authority.check()?;
        let response = client
            .post(RESULT_URL)
            .header("Content-Type", "application/json")
            .body(serde_json::to_vec(result)?)
            .timeout(until.saturating_duration_since(Instant::now()))
            .send()
            .context("result append failed")?;
        ensure!(response.status().is_success(), "result append rejected");
        authority.check()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
