//! Phase 3: the upload broker has its own durable ledger and never consults the grading queue,
//! budget, result, or scorer connection. Only the operator can spend a grading authorization.

use super::{bad, check_operator, App, RunRecord, RunState, S};
use anyhow::{ensure, Context};
use axum::{
    body::{to_bytes, Body},
    extract::{Path as AxPath, Request, State},
    http::{header, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use clap::Args;
use deadswitch_common::{grading::*, *};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::SocketAddr,
    os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::{Duration, Instant},
};
use tracing::warn;

const FORMAT: u32 = 1;
const MAX_BUDGET: u64 = 4096;
const MAX_SUBMISSIONS: usize = 4096;
const MAX_UPLOAD_AUTHORIZATIONS: usize = 8192;
const MAX_LEDGER_BYTES: u64 = 64 * 1024 * 1024;
const MAX_UPLOAD_ATTEMPTS: u64 = 8;
const MAX_UPLOADS_PER_MINUTE: u64 = 60;
const UPLOAD_TTL_S: u64 = 3600;
const GRADER_DISPATCH_URL: &str = "http://10.20.0.4:7200/dispatch";

#[derive(Args, Debug)]
pub(crate) struct GradingArgs {
    #[arg(long, env = "DS_GRADING_ENABLE", default_value_t = false)]
    pub grading_enable: bool,
    /// Create state once and exit without serving. Lost/partial state is never reinitialized.
    #[arg(long, default_value_t = false)]
    pub grading_init: bool,
    /// Immutable lifetime budget, supplied only on --grading-init. No campaign/key reset.
    #[arg(long)]
    pub grading_budget: Option<u64>,
    /// JSON map of operator-assigned held-out-key versions to pinned scorer public keys.
    #[arg(long, env = "DS_GRADING_SCORER_KEYS_FILE")]
    pub grading_scorer_keys_file: Option<PathBuf>,
    #[arg(
        long,
        env = "DS_GRADING_UPLOAD_LISTEN",
        default_value = "10.20.0.1:7202"
    )]
    pub grading_upload_listen: SocketAddr,
    #[arg(
        long,
        env = "DS_GRADING_RESULTS_LISTEN",
        default_value = "10.20.0.1:7201"
    )]
    pub grading_results_listen: SocketAddr,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Anchor {
    v: u32,
    ledger_id: String,
    max_jobs: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct UploadAuthorization {
    incarnation: String,
    token_digest: String,
    expires_at: u64,
    attempts: u64,
    submission_digest: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Submission {
    run_id: String,
    incarnation: String,
    digest: String,
    size: u64,
    stored_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerLedger {
    v: u32,
    ledger_id: String,
    wall_high_water: u64,
    minute: u64,
    minute_attempts: u64,
    authorizations: BTreeMap<String, UploadAuthorization>,
    /// Durable, globally unique digest claim. Never deleted or changed by grading.
    submissions: BTreeMap<String, Submission>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum JobState {
    /// Sending is consumed even if no delivery acknowledgment ever arrives.
    DispatchConsumed,
    ResultCommitted,
    Abandoned,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Claim {
    job: GradingJob,
    campaign: String,
    held_out_key_version: String,
    state: JobState,
    result: Option<Signed>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GradingLedger {
    v: u32,
    ledger_id: String,
    max_jobs: u64,
    spent: u64,
    high_water: u64,
    wall_high_water: u64,
    /// New versions may be appended by operator configuration; a pinned key cannot be replaced.
    scorer_keys: BTreeMap<String, String>,
    /// Indexed by immutable submission digest: variants are distinct, but every one spends budget.
    claims: BTreeMap<String, Claim>,
}

struct RateWindow {
    start: Instant,
    count: u64,
}

pub(crate) struct GradingService {
    dir: PathBuf,
    anchor: Anchor,
    broker: Mutex<BrokerLedger>,
    ledger: Mutex<GradingLedger>,
    deadlines: Mutex<BTreeMap<String, Deadline>>,
    // Grader errors must not alter broker admission. Poisoning the two stores is independent.
    broker_poisoned: AtomicBool,
    grading_poisoned: AtomicBool,
    rate: Mutex<RateWindow>,
    upload_slots: Arc<tokio::sync::Semaphore>,
    client: reqwest::Client,
    _lock: File,
}

fn protected(path: &Path, directory: bool) -> anyhow::Result<()> {
    let meta = std::fs::symlink_metadata(path)?;
    ensure!(
        if directory {
            meta.is_dir()
        } else {
            meta.is_file()
        } && !meta.file_type().is_symlink()
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o077 == 0,
        "grading state must be private, owned, and not a symlink: {}",
        path.display()
    );
    if !directory {
        ensure!(meta.nlink() == 1, "grading state must not be hard-linked");
    }
    Ok(())
}

fn load_private<T: serde::de::DeserializeOwned>(path: &Path) -> anyhow::Result<T> {
    protected(path, false)?;
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    ensure!(
        file.metadata()?.len() <= MAX_LEDGER_BYTES,
        "grading state too large"
    );
    let mut bytes = Vec::new();
    file.take(MAX_LEDGER_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_LEDGER_BYTES,
        "grading state too large"
    );
    serde_json::from_slice(&bytes).context("invalid grading state")
}

/// Unique O_EXCL temp files, restrictive initial permissions, fsync+rename+directory fsync.
/// After any ambiguous persistence error the corresponding service plane is poisoned until restart.
fn persist_private<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let parent = path.parent().context("grading state parent")?;
    protected(parent, true)?;
    if path.exists() {
        protected(path, false)?;
    }
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() as u64 <= MAX_LEDGER_BYTES,
        "grading ledger quota"
    );
    let temporary = parent.join(format!(".write-{}", random_hex(16)));
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    std::fs::rename(&temporary, path)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn create_private<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(&serde_json::to_vec(value)?)?;
    file.sync_all()?;
    File::open(path.parent().context("state parent")?)?.sync_all()?;
    Ok(())
}

fn validate_scorer_keys(keys: &BTreeMap<String, String>) -> anyhow::Result<()> {
    ensure!(
        !keys.is_empty() && keys.len() <= 64,
        "1..64 scorer key versions required"
    );
    for (version, key) in keys {
        ensure!(
            valid_id(version) && valid_digest(key),
            "invalid scorer key version"
        );
        pubkey_from_hex(key)?;
    }
    Ok(())
}

impl GradingService {
    fn open(
        root: &Path,
        initialize: bool,
        budget: Option<u64>,
        keys: BTreeMap<String, String>,
    ) -> anyhow::Result<Self> {
        validate_scorer_keys(&keys)?;
        let anchor_path = root.join("grading-anchor.json");
        let dir = root.join("grading");
        if initialize {
            ensure!(
                !anchor_path.exists() && !dir.exists(),
                "grading initialization is one-time only"
            );
            let max_jobs = budget.context("--grading-init requires --grading-budget")?;
            ensure!(
                (1..=MAX_BUDGET).contains(&max_jobs),
                "grading budget must be finite (1..4096)"
            );
            let anchor = Anchor {
                v: FORMAT,
                ledger_id: random_hex(32),
                max_jobs,
            };
            // The anchor lives outside the ledger directory. Partial initialization/loss blocks.
            create_private(&anchor_path, &anchor)?;
            std::fs::DirBuilder::new().mode(0o700).create(&dir)?;
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(dir.join("objects"))?;
            create_private(
                &dir.join("broker.json"),
                &BrokerLedger {
                    v: FORMAT,
                    ledger_id: anchor.ledger_id.clone(),
                    wall_high_water: 0,
                    minute: 0,
                    minute_attempts: 0,
                    authorizations: BTreeMap::new(),
                    submissions: BTreeMap::new(),
                },
            )?;
            create_private(
                &dir.join("ledger.json"),
                &GradingLedger {
                    v: FORMAT,
                    ledger_id: anchor.ledger_id.clone(),
                    max_jobs,
                    spent: 0,
                    high_water: 0,
                    wall_high_water: 0,
                    scorer_keys: keys.clone(),
                    claims: BTreeMap::new(),
                },
            )?;
        } else {
            ensure!(
                budget.is_none(),
                "budget is immutable; supply it only for initialization"
            );
        }
        let anchor: Anchor =
            load_private(&anchor_path).context("grading anchor missing/corrupt; refusing reset")?;
        ensure!(
            anchor.v == FORMAT
                && valid_digest(&anchor.ledger_id)
                && (1..=MAX_BUDGET).contains(&anchor.max_jobs),
            "invalid grading anchor"
        );
        protected(&dir, true)?;
        protected(&dir.join("objects"), true)?;
        let lock_path = dir.join("process.lock");
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&lock_path)?;
        protected(&lock_path, false)?;
        use std::os::fd::AsRawFd;
        ensure!(
            unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another controller owns the grading ledger"
        );
        let broker: BrokerLedger = load_private(&dir.join("broker.json"))?;
        let mut ledger: GradingLedger = load_private(&dir.join("ledger.json"))?;
        Self::validate_state(&anchor, &broker, &ledger)?;
        for (version, pinned) in &ledger.scorer_keys {
            ensure!(
                keys.get(version) == Some(pinned),
                "scorer key removal/replacement forbidden"
            );
        }
        let mut changed = ledger.scorer_keys != keys;
        ledger.scorer_keys = keys;
        for claim in ledger.claims.values_mut() {
            if claim.state == JobState::DispatchConsumed {
                // Delivery/execution may have happened. Restart revokes result authority and never
                // retries launch, while retaining its budget charge and expiry occupancy.
                claim.state = JobState::Abandoned;
                changed = true;
            }
        }
        if changed {
            persist_private(&dir.join("ledger.json"), &ledger)?;
        }
        Ok(Self {
            dir,
            anchor,
            broker: Mutex::new(broker),
            ledger: Mutex::new(ledger),
            deadlines: Mutex::new(BTreeMap::new()),
            broker_poisoned: AtomicBool::new(false),
            grading_poisoned: AtomicBool::new(false),
            rate: Mutex::new(RateWindow {
                start: Instant::now(),
                count: 0,
            }),
            upload_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            client: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .connect_timeout(Duration::from_secs(2))
                .timeout(Duration::from_secs(5))
                .build()?,
            _lock: lock,
        })
    }

    fn validate_state(
        anchor: &Anchor,
        broker: &BrokerLedger,
        ledger: &GradingLedger,
    ) -> anyhow::Result<()> {
        ensure!(
            broker.v == FORMAT
                && ledger.v == FORMAT
                && broker.ledger_id == anchor.ledger_id
                && ledger.ledger_id == anchor.ledger_id
                && ledger.max_jobs == anchor.max_jobs,
            "grading ledger/anchor mismatch"
        );
        ensure!(
            broker.authorizations.len() <= MAX_UPLOAD_AUTHORIZATIONS
                && broker.submissions.len() <= MAX_SUBMISSIONS
                && broker.minute_attempts <= MAX_UPLOADS_PER_MINUTE,
            "broker quota corruption"
        );
        validate_scorer_keys(&ledger.scorer_keys)?;
        ensure!(
            ledger.spent <= ledger.max_jobs
                && ledger.spent == ledger.claims.len() as u64
                && ledger.high_water == ledger.spent,
            "grading budget/high-water corruption"
        );
        for (run, auth) in &broker.authorizations {
            ensure!(
                valid_id(run)
                    && valid_id(&auth.incarnation)
                    && valid_digest(&auth.token_digest)
                    && auth.attempts <= MAX_UPLOAD_ATTEMPTS,
                "invalid upload authorization"
            );
            if let Some(digest) = &auth.submission_digest {
                let sub = broker
                    .submissions
                    .get(digest)
                    .context("missing submission claim")?;
                ensure!(
                    sub.run_id == *run && sub.incarnation == auth.incarnation,
                    "upload claim mismatch"
                );
            }
        }
        for (digest, sub) in &broker.submissions {
            ensure!(
                valid_digest(digest)
                    && sub.digest == *digest
                    && sub.size > 0
                    && sub.size <= MAX_SUBMISSION_BYTES as u64,
                "invalid submission binding"
            );
            let auth = broker
                .authorizations
                .get(&sub.run_id)
                .context("missing upload authorization")?;
            ensure!(
                auth.submission_digest.as_ref() == Some(digest)
                    && auth.incarnation == sub.incarnation,
                "submission/authorization mismatch"
            );
        }
        let mut tokens = std::collections::BTreeSet::new();
        let mut ids = std::collections::BTreeSet::new();
        for (digest, claim) in &ledger.claims {
            let sub = broker
                .submissions
                .get(digest)
                .context("grading without a broker claim")?;
            let job = &claim.job;
            // Validate historical shape at its issue time without reviving authority.
            job.validate(job.issued_at)?;
            ensure!(
                job.submission_digest == *digest
                    && job.run_id == sub.run_id
                    && job.incarnation == sub.incarnation
                    && valid_id(&claim.campaign)
                    && ledger.scorer_keys.contains_key(&claim.held_out_key_version)
                    && job.fencing_token <= ledger.high_water
                    && tokens.insert(job.fencing_token)
                    && ids.insert(&job.job_id),
                "invalid grading claim"
            );
            match (&claim.state, &claim.result) {
                (JobState::ResultCommitted, Some(signed)) => {
                    let key = pubkey_from_hex(&ledger.scorer_keys[&claim.held_out_key_version])?;
                    let result: GradingResult =
                        signed.verify(&key, RESULT_TYPE, AUD_GRADING_RESULTS)?;
                    verify_result(signed, &key, job, result.issued_at)?;
                }
                (JobState::DispatchConsumed | JobState::Abandoned, None) => {}
                _ => anyhow::bail!("result/terminal state corruption"),
            }
        }
        Ok(())
    }

    fn save_broker(&self, next: &BrokerLedger) -> anyhow::Result<()> {
        let result = persist_private(&self.dir.join("broker.json"), next);
        if result.is_err() {
            self.broker_poisoned.store(true, Ordering::SeqCst);
        }
        result
    }

    fn save_ledger(&self, next: &GradingLedger) -> anyhow::Result<()> {
        let result = persist_private(&self.dir.join("ledger.json"), next);
        if result.is_err() {
            self.grading_poisoned.store(true, Ordering::SeqCst);
        }
        result
    }

    fn request_slot(&self) -> bool {
        let mut rate = self.rate.lock().unwrap();
        if rate.start.elapsed() >= Duration::from_secs(60) {
            *rate = RateWindow {
                start: Instant::now(),
                count: 0,
            };
        }
        if rate.count >= MAX_UPLOADS_PER_MINUTE {
            return false;
        }
        rate.count += 1;
        true
    }

    fn issue_upload(&self, run: &RunRecord, now: u64) -> anyhow::Result<UploadGrant> {
        ensure!(
            !self.broker_poisoned.load(Ordering::SeqCst),
            "broker unavailable"
        );
        ensure!(
            run.state == RunState::Active && run.epoch >= 1,
            "upload requires an active eval"
        );
        let incarnation = run.incarnation.as_ref().context("run incarnation absent")?;
        ensure!(
            valid_id(&run.run_id) && valid_id(incarnation),
            "run identity invalid"
        );
        let mut broker = self.broker.lock().unwrap();
        ensure!(now >= broker.wall_high_water, "trusted clock rollback");
        ensure!(
            !broker.authorizations.contains_key(&run.run_id)
                && broker.authorizations.len() < MAX_UPLOAD_AUTHORIZATIONS,
            "upload already authorized or quota reached"
        );
        let token = random_hex(32);
        let expires_at = now
            .checked_add(UPLOAD_TTL_S)
            .context("upload expiry overflow")?;
        let mut next = broker.clone();
        next.wall_high_water = now;
        next.authorizations.insert(
            run.run_id.clone(),
            UploadAuthorization {
                incarnation: incarnation.clone(),
                token_digest: sha256_hex(token.as_bytes()),
                expires_at,
                attempts: 0,
                submission_digest: None,
            },
        );
        self.save_broker(&next)?;
        *broker = next;
        Ok(UploadGrant {
            run_id: run.run_id.clone(),
            upload_token: token,
            expires_at,
            max_submission_bytes: MAX_SUBMISSION_BYTES,
        })
    }

    /// Reserve an admission attempt before reading a body; no grading lock/state is accessed.
    fn reserve_upload(&self, run: &RunRecord, token: &str, now: u64) -> anyhow::Result<()> {
        ensure!(
            !self.broker_poisoned.load(Ordering::SeqCst),
            "broker unavailable"
        );
        ensure!(
            run.state == RunState::Active && run.epoch >= 1,
            "late submission"
        );
        ensure!(
            token.len() == 64 && valid_digest(token),
            "upload token shape"
        );
        let mut broker = self.broker.lock().unwrap();
        ensure!(now >= broker.wall_high_water, "trusted clock rollback");
        let auth = broker
            .authorizations
            .get(&run.run_id)
            .context("no upload authorization")?;
        ensure!(
            auth.token_digest == sha256_hex(token.as_bytes())
                && now < auth.expires_at
                && run.incarnation.as_ref() == Some(&auth.incarnation),
            "upload authorization mismatch"
        );
        ensure!(
            auth.attempts < MAX_UPLOAD_ATTEMPTS && auth.submission_digest.is_none(),
            "upload consumed"
        );
        let mut next = broker.clone();
        if next.minute != now / 60 {
            next.minute = now / 60;
            next.minute_attempts = 0;
        }
        ensure!(
            next.minute_attempts < MAX_UPLOADS_PER_MINUTE,
            "upload rate limit"
        );
        next.minute_attempts += 1;
        next.wall_high_water = now;
        next.authorizations.get_mut(&run.run_id).unwrap().attempts += 1;
        self.save_broker(&next)?;
        *broker = next;
        Ok(())
    }

    fn store_upload(
        &self,
        run: &RunRecord,
        token: &str,
        bytes: &[u8],
        now: u64,
    ) -> anyhow::Result<()> {
        ensure!(
            !self.broker_poisoned.load(Ordering::SeqCst),
            "broker unavailable"
        );
        ensure!(
            run.state == RunState::Active && run.epoch >= 1,
            "eval ended during upload"
        );
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_SUBMISSION_BYTES,
            "submission size"
        );
        let digest = sha256_hex(bytes);
        let mut broker = self.broker.lock().unwrap();
        ensure!(now >= broker.wall_high_water, "trusted clock rollback");
        let auth = broker
            .authorizations
            .get(&run.run_id)
            .context("no upload authorization")?;
        ensure!(
            auth.token_digest == sha256_hex(token.as_bytes())
                && now < auth.expires_at
                && run.incarnation.as_ref() == Some(&auth.incarnation)
                && auth.attempts > 0
                && auth.submission_digest.is_none(),
            "upload consumed/mismatched"
        );
        ensure!(
            broker.submissions.len() < MAX_SUBMISSIONS && !broker.submissions.contains_key(&digest),
            "submission duplicate or intake quota"
        );
        protected(&self.dir.join("objects"), true)?;
        let object = self.dir.join("objects").join(&digest);
        if !object.exists() {
            // Include crash-left orphan objects in the independent intake quota. A restart must not
            // buy fresh disk space merely because the durable index missed its final commit.
            let mut object_count = 0usize;
            let mut total_bytes = 0u64;
            for entry in std::fs::read_dir(self.dir.join("objects"))? {
                let entry = entry?;
                protected(&entry.path(), false)?;
                object_count += 1;
                total_bytes = total_bytes
                    .checked_add(entry.metadata()?.len())
                    .context("CAS quota overflow")?;
                ensure!(object_count < MAX_SUBMISSIONS, "CAS object quota");
            }
            ensure!(
                total_bytes
                    .checked_add(bytes.len() as u64)
                    .context("CAS quota overflow")?
                    <= (MAX_SUBMISSIONS * MAX_SUBMISSION_BYTES) as u64,
                "CAS byte quota"
            );
        }
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o400)
            .open(&object)
        {
            Ok(mut file) => {
                file.write_all(bytes)?;
                file.sync_all()?;
                File::open(self.dir.join("objects"))?.sync_all()?;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // A crash may have left an unacknowledged CAS object; revalidate it before claiming.
                let stored = self.read_object(&digest, bytes.len() as u64)?;
                ensure!(stored == bytes, "CAS conflict");
            }
            Err(error) => return Err(error.into()),
        }
        let mut next = broker.clone();
        next.wall_high_water = now;
        next.authorizations
            .get_mut(&run.run_id)
            .unwrap()
            .submission_digest = Some(digest.clone());
        next.submissions.insert(
            digest.clone(),
            Submission {
                run_id: run.run_id.clone(),
                incarnation: run.incarnation.clone().context("incarnation")?,
                digest,
                size: bytes.len() as u64,
                stored_at: now,
            },
        );
        self.save_broker(&next)?; // both object + unique claim durable before Stored is sent
        *broker = next;
        Ok(())
    }

    fn read_object(&self, digest: &str, size: u64) -> anyhow::Result<Vec<u8>> {
        ensure!(
            valid_digest(digest) && size > 0 && size <= MAX_SUBMISSION_BYTES as u64,
            "CAS binding"
        );
        protected(&self.dir.join("objects"), true)?;
        let path = self.dir.join("objects").join(digest);
        protected(&path, false)?;
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?;
        ensure!(file.metadata()?.len() == size, "CAS size mismatch");
        let mut bytes = Vec::new();
        file.take(MAX_SUBMISSION_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == size && sha256_hex(&bytes) == digest,
            "CAS digest mismatch"
        );
        Ok(bytes)
    }

    /// Atomic lifetime budget spend + fencing + one-job-per-submission. A successful return grants
    /// exactly ONE transmission attempt, and nothing in this function touches execution leases.
    fn claim(
        &self,
        run: &RunRecord,
        request: &AuthorizeBody,
        now: u64,
    ) -> anyhow::Result<Dispatch> {
        ensure!(
            !self.grading_poisoned.load(Ordering::SeqCst),
            "grading unavailable"
        );
        ensure!(
            run.state.terminal() && run.epoch >= 1 && run.termination_confirmed_at.is_some(),
            "grading requires a terminal eval and trusted teardown confirmation"
        );
        ensure!(
            valid_id(&request.campaign) && valid_id(&request.held_out_key_version),
            "operator labels invalid"
        );
        let submission = {
            let broker = self.broker.lock().unwrap();
            let auth = broker
                .authorizations
                .get(&run.run_id)
                .context("no submission authorization")?;
            ensure!(
                run.incarnation.as_ref() == Some(&auth.incarnation),
                "run incarnation mismatch"
            );
            let digest = auth
                .submission_digest
                .as_ref()
                .context("no captured submission")?;
            broker
                .submissions
                .get(digest)
                .context("missing submission claim")?
                .clone()
        };
        let bytes = self.read_object(&submission.digest, submission.size)?;
        let mut ledger = self.ledger.lock().unwrap();
        ensure!(now >= ledger.wall_high_water, "trusted clock rollback");
        ensure!(
            ledger
                .scorer_keys
                .contains_key(&request.held_out_key_version),
            "unknown pinned key version"
        );
        ensure!(
            ledger.spent < ledger.max_jobs,
            "cumulative grading budget exhausted"
        );
        ensure!(
            !ledger.claims.contains_key(&submission.digest),
            "submission already consumed; no relaunch"
        );
        ensure!(!ledger.claims.values().any(|claim| claim.state != JobState::ResultCommitted
            && claim.job.expires_at > now), "previous sandbox may still be executing");
        let mut next = ledger.clone();
        let token = next
            .high_water
            .checked_add(1)
            .context("grading fencing exhausted")?;
        let job = GradingJob {
            v: PROTO_V,
            kind: JOB_TYPE.into(),
            aud: AUD_GRADER.into(),
            job_id: ulid::Ulid::new().to_string(),
            run_id: run.run_id.clone(),
            incarnation: submission.incarnation,
            fencing_token: token,
            issued_at: now,
            expires_at: now
                .checked_add(MAX_GRADING_TTL_S)
                .context("grading expiry overflow")?,
            submission_digest: submission.digest.clone(),
            task_id: TASK_ID.into(),
            input_version: INPUT_VERSION.into(),
            scorer_version: SCORER_VERSION.into(),
        };
        job.validate(now)?;
        job.bind_submission(&bytes)?;
        let deadline = job.deadline(ledger.high_water, now)?;
        next.high_water = token;
        next.spent += 1;
        next.wall_high_water = now;
        next.claims.insert(
            submission.digest,
            Claim {
                job: job.clone(),
                campaign: request.campaign.clone(),
                held_out_key_version: request.held_out_key_version.clone(),
                state: JobState::DispatchConsumed,
                result: None,
            },
        );
        self.save_ledger(&next)?; // no send/ACK/signing authority escapes before this commit
        *ledger = next;
        self.deadlines
            .lock()
            .unwrap()
            .insert(job.job_id.clone(), deadline);
        Ok(Dispatch { job, bytes })
    }

    fn abandon(&self, job_id: &str) -> anyhow::Result<()> {
        ensure!(
            !self.grading_poisoned.load(Ordering::SeqCst),
            "grading unavailable"
        );
        let mut ledger = self.ledger.lock().unwrap();
        let mut next = ledger.clone();
        let claim = next
            .claims
            .values_mut()
            .find(|claim| claim.job.job_id == job_id)
            .context("unknown dispatch")?;
        if claim.state == JobState::DispatchConsumed {
            claim.state = JobState::Abandoned;
            self.save_ledger(&next)?;
            *ledger = next;
        }
        Ok(())
    }

    fn commit_result(&self, run: &RunRecord, signed: &Signed, now: u64) -> anyhow::Result<()> {
        ensure!(
            !self.grading_poisoned.load(Ordering::SeqCst),
            "grading unavailable"
        );
        ensure!(
            run.state.terminal() && run.termination_confirmed_at.is_some(),
            "eval stop authority lost"
        );
        // Decode only a bounded lookup hint; no hint grants authority or selects a filesystem path.
        ensure!(
            serde_json::to_vec(signed)?.len() <= MAX_GRADING_ENVELOPE_BYTES,
            "result envelope size"
        );
        let hint: GradingResult = serde_json::from_str(&signed.payload)?;
        let mut ledger = self.ledger.lock().unwrap();
        ensure!(now >= ledger.wall_high_water, "trusted clock rollback");
        let claim = ledger
            .claims
            .get(&hint.submission_digest)
            .context("unknown grading claim")?;
        ensure!(
            claim.job.run_id == run.run_id
                && run.incarnation.as_ref() == Some(&claim.job.incarnation),
            "run identity changed"
        );
        let key = pubkey_from_hex(&ledger.scorer_keys[&claim.held_out_key_version])?;
        verify_result(signed, &key, &claim.job, now)?;
        if claim.state == JobState::ResultCommitted {
            ensure!(
                claim.result.as_ref() == Some(signed),
                "conflicting replacement result"
            );
            return Ok(()); // identical still-live delivery retry, append exactly once
        }
        ensure!(
            claim.state == JobState::DispatchConsumed
                && claim.job.fencing_token == ledger.high_water,
            "terminal or fenced grading claim"
        );
        ensure!(
            self.deadlines
                .lock()
                .unwrap()
                .get(&claim.job.job_id)
                .is_some_and(|deadline| !deadline.expired(now)),
            "grading monotonic deadline expired or lost"
        );
        let mut next = ledger.clone();
        let claim = next.claims.get_mut(&hint.submission_digest).unwrap();
        claim.state = JobState::ResultCommitted;
        claim.result = Some(signed.clone());
        next.wall_high_water = now;
        self.save_ledger(&next)?;
        *ledger = next;
        Ok(())
    }
}

use std::os::unix::fs::DirBuilderExt;

pub(crate) fn configure(
    args: &GradingArgs,
    root: &Path,
    controller: &SigningKey,
    hostd_keys: &[VerifyingKey],
    operator_listen: Option<SocketAddr>,
) -> anyhow::Result<Option<Arc<GradingService>>> {
    if !args.grading_enable {
        ensure!(
            !args.grading_init && args.grading_budget.is_none(),
            "grading init requires --grading-enable"
        );
        return Ok(None);
    }
    ensure!(
        operator_listen.is_some_and(|addr| addr.ip().is_loopback()),
        "grading requires a separate loopback operator API on :7101"
    );
    for (addr, port) in [
        (args.grading_upload_listen, 7202),
        (args.grading_results_listen, 7201),
    ] {
        ensure!(
            addr.ip().is_loopback()
                || (addr.ip().to_string() == "10.20.0.1" && addr.port() == port),
            "grading listener must use its designated controller WG tuple (or local test loopback)"
        );
    }
    let key_file = args
        .grading_scorer_keys_file
        .as_ref()
        .context("scorer key registry required")?;
    let meta = std::fs::symlink_metadata(key_file)?;
    ensure!(
        meta.is_file()
            && !meta.file_type().is_symlink()
            && meta.len() <= 16384
            && meta.uid() == unsafe { libc::geteuid() }
            && meta.permissions().mode() & 0o022 == 0,
        "scorer key registry must be a bounded owned regular file without group/world write access"
    );
    let keys: BTreeMap<String, String> = serde_json::from_slice(&std::fs::read(key_file)?)?;
    for key in keys.values() {
        let scorer = pubkey_from_hex(key)?;
        ensure!(
            scorer != controller.verifying_key() && !hostd_keys.contains(&scorer),
            "scorer role must use a separate key"
        );
    }
    Ok(Some(Arc::new(GradingService::open(
        root,
        args.grading_init,
        args.grading_budget,
        keys,
    )?)))
}

#[derive(Debug, Serialize)]
struct UploadGrant {
    run_id: String,
    upload_token: String,
    expires_at: u64,
    max_submission_bytes: usize,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum AdmissionStatus {
    Received,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdmissionAck {
    status: AdmissionStatus,
}

fn admission() -> impl IntoResponse {
    // All broker responses use the same status and bounded vocabulary. They contain no digest,
    // grader queue position, result address, task answer, completion, or downstream error.
    // Received means the broker handled the request; it does not reveal durable admission. Returning
    // Stored/Rejected here would expose a cross-run CAS-membership oracle to later submissions.
    (
        StatusCode::ACCEPTED,
        [
            (header::CACHE_CONTROL, "no-store"),
            (header::CONNECTION, "close"),
        ],
        Json(AdmissionAck {
            status: AdmissionStatus::Received,
        }),
    )
}

async fn upload(
    State(app): S,
    path: Result<AxPath<String>, axum::extract::rejection::PathRejection>,
    request: Request<Body>,
) -> impl IntoResponse {
    let reject = admission;
    let Ok(AxPath(run_id)) = path else {
        return reject();
    };
    let Some(service) = app.grading.as_ref() else {
        return reject();
    };
    if !service.request_slot() {
        return reject();
    }
    let Ok(_slot) = service.upload_slots.clone().try_acquire_owned() else {
        return reject();
    };
    let Some(token) = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Bearer "))
        .map(str::to_owned)
    else {
        return reject();
    };
    {
        let ctl = app.ctl.lock().unwrap();
        let Some(run) = ctl.runs.get(&run_id) else {
            return reject();
        };
        if service.reserve_upload(run, &token, now_unix()).is_err() {
            return reject();
        }
    }
    let bytes = match tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(request.into_body(), MAX_SUBMISSION_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        _ => return reject(),
    };
    let ctl = app.ctl.lock().unwrap();
    let Some(run) = ctl.runs.get(&run_id) else {
        return reject();
    };
    if service
        .store_upload(run, &token, &bytes, now_unix())
        .is_ok()
    {
        admission()
    } else {
        reject()
    }
}

async fn upload_fallback() -> impl IntoResponse {
    admission()
}

pub(crate) fn upload_router() -> Router<Arc<App>> {
    Router::new()
        .route("/submissions/{run_id}", post(upload))
        .fallback(upload_fallback)
        .method_not_allowed_fallback(upload_fallback)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthorizeBody {
    campaign: String,
    held_out_key_version: String,
}

struct Dispatch {
    job: GradingJob,
    bytes: Vec<u8>,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum DispatchStatus {
    DispatchConsumed,
    DispatchUncertain,
}

#[derive(Serialize)]
struct DispatchAck {
    job_id: String,
    status: DispatchStatus,
}

fn service(app: &App) -> Result<&Arc<GradingService>, (StatusCode, String)> {
    app.grading
        .as_ref()
        .ok_or_else(|| bad(StatusCode::NOT_FOUND, "grading disabled"))
}

async fn issue_upload(
    State(app): S,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
) -> super::Resp<UploadGrant> {
    check_operator(&app, &headers)?;
    let service = service(&app)?;
    let ctl = app.ctl.lock().unwrap();
    let run = ctl
        .runs
        .get(&id)
        .ok_or_else(|| bad(StatusCode::NOT_FOUND, "no such run"))?;
    service
        .issue_upload(run, now_unix())
        .map(Json)
        .map_err(|error| bad(StatusCode::CONFLICT, error.to_string()))
}

async fn authorize(
    State(app): S,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
    Json(body): Json<AuthorizeBody>,
) -> super::Resp<DispatchAck> {
    check_operator(&app, &headers)?;
    let service = service(&app)?.clone();
    let run = app
        .ctl
        .lock()
        .unwrap()
        .runs
        .get(&id)
        .cloned()
        .ok_or_else(|| bad(StatusCode::NOT_FOUND, "no such run"))?;
    let dispatch = service
        .claim(&run, &body, now_unix())
        .map_err(|error| bad(StatusCode::CONFLICT, error.to_string()))?;
    let signed = Signed::sign(&app.key, "controller", &dispatch.job);
    let frame = match encode_dispatch(&signed, &dispatch.bytes) {
        Ok(frame) => frame,
        Err(error) => {
            service
                .abandon(&dispatch.job.job_id)
                .map_err(|e| bad(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            return Err(bad(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()));
        }
    };
    // Recheck immediately before transmission: storage delay cannot turn an old grant into a launch.
    if dispatch
        .job
        .deadline(dispatch.job.fencing_token - 1, now_unix())
        .is_err()
        || !service
            .deadlines
            .lock()
            .unwrap()
            .get(&dispatch.job.job_id)
            .is_some_and(|deadline| !deadline.expired(now_unix()))
    {
        service
            .abandon(&dispatch.job.job_id)
            .map_err(|error| bad(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
        return Ok(Json(DispatchAck {
            job_id: dispatch.job.job_id,
            status: DispatchStatus::DispatchUncertain,
        }));
    }
    // No redirects, environment proxy, URL supplied by agent, or automatic delivery retries.
    // The response body is intentionally never read. This path is operator-only.
    let delivered = service
        .client
        .post(GRADER_DISPATCH_URL)
        .header("content-type", "application/octet-stream")
        .body(frame)
        .send()
        .await
        .map(|response| response.status().is_success())
        .unwrap_or(false);
    let status = if delivered {
        DispatchStatus::DispatchConsumed
    } else {
        service
            .abandon(&dispatch.job.job_id)
            .map_err(|error| bad(StatusCode::INTERNAL_SERVER_ERROR, error.to_string()))?;
        DispatchStatus::DispatchUncertain
    };
    Ok(Json(DispatchAck {
        job_id: dispatch.job.job_id,
        status,
    }))
}

#[derive(Serialize)]
struct OperatorStatus {
    policy: &'static str,
    lifetime_budget: u64,
    spent: u64,
    high_water: u64,
    jobs: Vec<Claim>,
}

async fn operator_status(State(app): S, headers: HeaderMap) -> super::Resp<OperatorStatus> {
    check_operator(&app, &headers)?;
    let service = service(&app)?;
    let ledger = service.ledger.lock().unwrap();
    Ok(Json(OperatorStatus {
        policy: "zero_agent_feedback",
        lifetime_budget: service.anchor.max_jobs,
        spent: ledger.spent,
        high_water: ledger.high_water,
        jobs: ledger.claims.values().cloned().collect(),
    }))
}

async fn operator_results(State(app): S, headers: HeaderMap) -> super::Resp<Vec<Signed>> {
    check_operator(&app, &headers)?;
    let service = service(&app)?;
    let ledger = service.ledger.lock().unwrap();
    Ok(Json(
        ledger
            .claims
            .values()
            .filter_map(|claim| claim.result.clone())
            .collect(),
    ))
}

pub(crate) fn operator_router() -> Router<Arc<App>> {
    Router::new()
        .route(
            "/grading/runs/{id}/upload-authorization",
            post(issue_upload),
        )
        .route("/grading/runs/{id}/authorize", post(authorize))
        .route("/grading/status", get(operator_status))
        .route("/grading/results", get(operator_results))
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum AppendStatus {
    Appended,
    Rejected,
}
#[derive(Serialize)]
struct AppendAck {
    status: AppendStatus,
}

async fn append_result(State(app): S, request: Request<Body>) -> impl IntoResponse {
    let reject = || {
        (
            StatusCode::BAD_REQUEST,
            Json(AppendAck {
                status: AppendStatus::Rejected,
            }),
        )
    };
    let Some(service) = app.grading.as_ref() else {
        return reject();
    };
    let bytes = match tokio::time::timeout(
        Duration::from_secs(5),
        to_bytes(request.into_body(), MAX_GRADING_ENVELOPE_BYTES),
    )
    .await
    {
        Ok(Ok(bytes)) => bytes,
        _ => return reject(),
    };
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Envelope {
        payload: String,
        sig_hex: String,
        signer: String,
    }
    let raw: Envelope = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => return reject(),
    };
    let signed = Signed {
        payload: raw.payload,
        sig_hex: raw.sig_hex,
        signer: raw.signer,
    };
    let hint: GradingResult = match serde_json::from_str(&signed.payload) {
        Ok(value) => value,
        Err(_) => return reject(),
    };
    let run = match app.ctl.lock().unwrap().runs.get(&hint.run_id).cloned() {
        Some(run) => run,
        None => return reject(),
    };
    match service.commit_result(&run, &signed, now_unix()) {
        Ok(()) => (
            StatusCode::OK,
            Json(AppendAck {
                status: AppendStatus::Appended,
            }),
        ),
        Err(error) => {
            warn!(error = %error, "grading append rejected");
            reject()
        }
    }
}

async fn append_fallback() -> impl IntoResponse {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(AppendAck {
            status: AppendStatus::Rejected,
        }),
    )
}

pub(crate) fn results_router() -> Router<Arc<App>> {
    Router::new()
        .route("/results", post(append_result))
        .fallback(append_fallback)
        .method_not_allowed_fallback(append_fallback)
}

pub(crate) async fn start_listeners(args: &GradingArgs, app: Arc<App>) -> anyhow::Result<()> {
    if app.grading.is_none() {
        return Ok(());
    }
    // Bind both before spawning either: a misconfigured airlock never starts only one half.
    let uploads = tokio::net::TcpListener::bind(args.grading_upload_listen).await?;
    let results = tokio::net::TcpListener::bind(args.grading_results_listen).await?;
    let upload_app = app.clone();
    tokio::spawn(async move {
        if let Err(error) = axum::serve(uploads, upload_router().with_state(upload_app)).await {
            warn!(error = %error, "upload-only listener failed");
        }
    });
    tokio::spawn(async move {
        if let Err(error) = axum::serve(results, results_router().with_state(app)).await {
            warn!(error = %error, "scorer append listener failed");
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests;
