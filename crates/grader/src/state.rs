//! Protected, append-only-in-meaning authorization ledger. Claims and fencing never disappear;
//! a missing/corrupt ledger cannot be reinitialized by `run`. No outcome permits another launch.

use crate::JobContext;
use anyhow::{ensure, Context};
use deadswitch_common::grading::{valid_digest, valid_id, GradingJob, MAX_SUBMISSION_BYTES};
use deadswitch_common::{random_hex, sha256_hex, Deadline, Signed};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

const MAX_STATE_BYTES: usize = 64 * 1024 * 1024;
const MAX_CLAIMS: usize = 10_000;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Binding {
    pub controller_public_key: String,
    pub scorer_public_key: String,
    pub expected_output_digest: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClaimStatus {
    /// Consumed authorization, already terminal for replay/launch permission. A crash in this
    /// status is indistinguishable from execution and must never be retried.
    ExecutionClaimed,
    Aborted,
    ResultCommitted,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Claim {
    pub job: GradingJob,
    pub sandbox_id: String,
    pub status: ClaimStatus,
    pub result: Option<Signed>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Ledger {
    v: u32,
    binding: Binding,
    high_water: u64,
    quarantined: bool,
    claims: BTreeMap<String, Claim>,
}

pub struct PendingJob {
    pub context: JobContext,
    pub deadline: Deadline,
}

/// A process-lifetime lock protects against two local services launching at once. Acquire this
/// before global sandbox cleanup, including recovery from a corrupt or missing ledger.
pub struct StateLock {
    _file: File,
    root: PathBuf,
}

impl StateLock {
    pub fn acquire(root: &Path) -> anyhow::Result<Self> {
        check_private_directory(root)?;
        let file = open_private(&root.join("lock"), false)?;
        ensure!(
            unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } == 0,
            "another grader owns the state lock"
        );
        Ok(Self {
            _file: file,
            root: root.to_path_buf(),
        })
    }
}

pub struct Store {
    root: PathBuf,
    ledger: Ledger,
    poisoned: bool,
    _lock: StateLock,
}

impl Store {
    /// Explicit, operator-only bootstrap. An existing directory is NEVER reset, even empty.
    pub fn initialize(root: &Path, binding: Binding) -> anyhow::Result<()> {
        validate_binding(&binding)?;
        std::fs::DirBuilder::new().mode(0o700).create(root)?;
        for name in ["jobs"] {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(root.join(name))?;
        }
        write_new(&root.join("lock"), b"", 0o600)?;
        let ledger = Ledger {
            v: 1,
            binding,
            high_water: 0,
            quarantined: false,
            claims: BTreeMap::new(),
        };
        write_atomic(&root.join("ledger.json"), &ledger)?;
        sync_dir(root)?;
        if let Some(parent) = root.parent() {
            sync_dir(parent)?;
        }
        Ok(())
    }

    pub fn open(lock: StateLock, binding: &Binding) -> anyhow::Result<Self> {
        let bytes = read_private_file(&lock.root.join("ledger.json"), MAX_STATE_BYTES, false)?;
        let ledger: Ledger = serde_json::from_slice(&bytes).context("invalid grader ledger")?;
        validate_ledger(&ledger, binding)?;
        check_private_directory(&lock.root.join("jobs"))?;
        Ok(Self {
            root: lock.root.clone(),
            ledger,
            poisoned: false,
            _lock: lock,
        })
    }

    pub fn quarantined(&self) -> bool {
        self.poisoned || self.ledger.quarantined
    }

    pub fn busy(&self) -> bool {
        self.ledger
            .claims
            .values()
            .any(|c| c.status == ClaimStatus::ExecutionClaimed)
    }

    pub fn high_water(&self) -> u64 {
        self.ledger.high_water
    }

    pub fn claim(&mut self, job: GradingJob, submission: &[u8], now: u64) -> anyhow::Result<PendingJob> {
        ensure!(!self.quarantined() && !self.busy(), "grader unavailable");
        ensure!(self.ledger.claims.len() < MAX_CLAIMS, "grader lifetime claim cap");
        ensure!(
            !self.ledger.claims.contains_key(&job.job_id)
                && !self
                    .ledger
                    .claims
                    .values()
                    .any(|c| c.job.submission_digest == job.submission_digest),
            "authorization or submission already consumed"
        );
        job.bind_submission(submission)?;
        let deadline = job.deadline(self.ledger.high_water, now)?;
        let sandbox_id = random_hex(16);
        let context = self.context(&job, &sandbox_id);
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&context.job_dir)?;
        if let Err(error) = write_new(&context.submission_path, submission, 0o400) {
            self.poisoned = true;
            return Err(error);
        }
        sync_dir(&context.job_dir)?;
        sync_dir(&self.root.join("jobs"))?;
        let mut next = self.ledger.clone();
        next.high_water = job.fencing_token;
        next.claims.insert(
            job.job_id.clone(),
            Claim {
                job,
                sandbox_id,
                status: ClaimStatus::ExecutionClaimed,
                result: None,
            },
        );
        // A failed write poisons this process; restart still performs destroy-all before readiness.
        self.persist(next)?;
        Ok(PendingJob { context, deadline })
    }

    pub fn commit(&mut self, job_id: &str, result: &Signed) -> anyhow::Result<()> {
        ensure!(!self.quarantined(), "grader quarantined");
        let mut next = self.ledger.clone();
        let claim = next.claims.get_mut(job_id).context("unknown job")?;
        ensure!(claim.status == ClaimStatus::ExecutionClaimed, "terminal job");
        // Bind again at the durable release boundary, including the local high-water fencing.
        ensure!(claim.job.fencing_token == next.high_water, "superseded job");
        let key = deadswitch_common::pubkey_from_hex(&next.binding.scorer_public_key)?;
        deadswitch_common::grading::verify_result(result, &key, &claim.job, deadswitch_common::now_unix())?;
        claim.status = ClaimStatus::ResultCommitted;
        claim.result = Some(result.clone());
        self.persist(next)
    }

    pub fn abort(&mut self, job_id: &str, quarantine: bool) -> anyhow::Result<()> {
        let mut next = self.ledger.clone();
        next.quarantined |= quarantine;
        let claim = next.claims.get_mut(job_id).context("unknown job")?;
        if claim.status == ClaimStatus::ExecutionClaimed {
            claim.status = ClaimStatus::Aborted;
        }
        self.persist(next)
    }

    /// Call only AFTER trusted destroy-all positively confirms no process/storage remains.
    /// All ambiguous authorizations stay spent. A persisted quarantine requires operator action;
    /// restart alone never removes it.
    pub fn finish_recovery(&mut self) -> anyhow::Result<()> {
        let mut next = self.ledger.clone();
        for claim in next.claims.values_mut() {
            if claim.status == ClaimStatus::ExecutionClaimed {
                claim.status = ClaimStatus::Aborted;
            }
            remove_job_files(&self.context(&claim.job, &claim.sandbox_id))?;
        }
        // Orphan files may be from a crash between staging and claim fsync. These are never used.
        for entry in std::fs::read_dir(self.root.join("jobs"))? {
            let entry = entry?;
            ensure!(entry.file_type()?.is_dir(), "unexpected recovery entry");
            std::fs::remove_dir_all(entry.path())?;
        }
        sync_dir(&self.root.join("jobs"))?;
        self.persist(next)
    }

    pub fn quarantine(&mut self) -> anyhow::Result<()> {
        let mut next = self.ledger.clone();
        next.quarantined = true;
        self.persist(next)
    }

    pub fn committed_result(&self, job_id: &str) -> Option<&Signed> {
        self.ledger.claims.get(job_id)?.result.as_ref()
    }

    fn context(&self, job: &GradingJob, sandbox_id: &str) -> JobContext {
        let job_dir = self.root.join("jobs").join(sandbox_id);
        JobContext {
            job: job.clone(),
            sandbox_id: sandbox_id.to_owned(),
            submission_path: job_dir.join("submission.bin"),
            capture_path: job_dir.join("capture.bin"),
            job_dir,
        }
    }

    fn persist(&mut self, next: Ledger) -> anyhow::Result<()> {
        if let Err(error) = write_atomic(&self.root.join("ledger.json"), &next) {
            self.poisoned = true;
            return Err(error);
        }
        self.ledger = next;
        Ok(())
    }
}

fn validate_binding(binding: &Binding) -> anyhow::Result<()> {
    deadswitch_common::pubkey_from_hex(&binding.controller_public_key)?;
    deadswitch_common::pubkey_from_hex(&binding.scorer_public_key)?;
    ensure!(valid_digest(&binding.expected_output_digest), "expected output binding");
    Ok(())
}

fn validate_ledger(ledger: &Ledger, binding: &Binding) -> anyhow::Result<()> {
    validate_binding(binding)?;
    ensure!(ledger.v == 1 && &ledger.binding == binding, "grader state binding mismatch");
    ensure!(ledger.claims.len() <= MAX_CLAIMS, "grader state bound");
    let mut tokens = BTreeSet::new();
    let mut digests = BTreeSet::new();
    let mut sandbox_ids = BTreeSet::new();
    let mut pending = 0;
    let scorer_key = deadswitch_common::pubkey_from_hex(&binding.scorer_public_key)?;
    for (id, claim) in &ledger.claims {
        ensure!(valid_id(id) && id == &claim.job.job_id, "claim identity");
        claim.job.validate(claim.job.issued_at)?;
        ensure!(
            claim.sandbox_id.len() == 32
                && claim.sandbox_id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()),
            "sandbox identity"
        );
        ensure!(
            tokens.insert(claim.job.fencing_token)
                && digests.insert(&claim.job.submission_digest)
                && sandbox_ids.insert(&claim.sandbox_id),
            "conflicting claims"
        );
        match (&claim.status, &claim.result) {
            (ClaimStatus::ExecutionClaimed, None) => pending += 1,
            (ClaimStatus::Aborted, None) => {}
            (ClaimStatus::ResultCommitted, Some(result)) => {
                let parsed: deadswitch_common::grading::GradingResult = result.verify(
                    &scorer_key,
                    deadswitch_common::grading::RESULT_TYPE,
                    deadswitch_common::grading::AUD_GRADING_RESULTS,
                )?;
                deadswitch_common::grading::verify_result(result, &scorer_key, &claim.job, parsed.issued_at)?;
                ensure!(parsed.sandbox_id == claim.sandbox_id, "result sandbox mismatch");
            }
            _ => anyhow::bail!("invalid claim transition"),
        }
    }
    ensure!(
        pending <= 1 && tokens.last().copied().unwrap_or(0) == ledger.high_water,
        "invalid fencing state"
    );
    Ok(())
}

fn check_private_directory(path: &Path) -> anyhow::Result<()> {
    let m = std::fs::symlink_metadata(path)?;
    ensure!(
        m.file_type().is_dir() && m.uid() == unsafe { libc::geteuid() } && m.permissions().mode() & 0o077 == 0,
        "state directory must be private and owned by the grader"
    );
    Ok(())
}

fn open_private(path: &Path, read_only_mode: bool) -> anyhow::Result<File> {
    let f = OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path)?;
    let m = f.metadata()?;
    ensure!(
        m.is_file() && m.nlink() == 1 && m.uid() == unsafe { libc::geteuid() } && m.permissions().mode() & 0o077 == 0,
        "private regular singly-linked owned file required"
    );
    if read_only_mode {
        ensure!(m.permissions().mode() & 0o222 == 0, "immutable file required");
    }
    Ok(f)
}

pub fn read_private_file(path: &Path, max: usize, read_only_mode: bool) -> anyhow::Result<Vec<u8>> {
    let f = open_private(path, read_only_mode)?;
    ensure!(f.metadata()?.len() <= max as u64, "private file too large");
    let mut bytes = Vec::new();
    f.take(max as u64 + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() <= max, "private file grew beyond bound");
    Ok(bytes)
}

pub fn write_new(path: &Path, bytes: &[u8], mode: u32) -> anyhow::Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    Ok(())
}

fn write_atomic<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAX_STATE_BYTES, "grader state too large");
    let tmp = path.with_extension(format!("{}.tmp", random_hex(16)));
    write_new(&tmp, &bytes, 0o600)?;
    std::fs::rename(&tmp, path)?;
    sync_dir(path.parent().context("state parent")?)
}

fn sync_dir(path: &Path) -> anyhow::Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

pub fn remove_job_files(ctx: &JobContext) -> anyhow::Result<()> {
    match std::fs::symlink_metadata(&ctx.job_dir) {
        Ok(meta) => {
            ensure!(meta.is_dir() && !meta.file_type().is_symlink(), "job directory replaced");
            std::fs::remove_dir_all(&ctx.job_dir)?;
            sync_dir(ctx.job_dir.parent().context("job directory parent")?)?;
            ensure!(!ctx.job_dir.exists(), "job files remain");
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Only private immutable bytes make it to the launcher; no caller-supplied filename is involved.
pub fn verify_staged(ctx: &JobContext) -> anyhow::Result<()> {
    let bytes = read_private_file(&ctx.submission_path, MAX_SUBMISSION_BYTES, true)?;
    ensure!(sha256_hex(&bytes) == ctx.job.submission_digest, "staged digest changed");
    Ok(())
}

use std::os::unix::fs::DirBuilderExt;
