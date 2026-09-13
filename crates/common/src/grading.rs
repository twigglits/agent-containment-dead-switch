//! Phase 3 authorization and evidence. Submission bytes are never signed JSON fields: both
//! trusted intake boundaries recompute the digest over the exact, separately transported bytes.
//! A grading grant is independent of an evaluation lease and cannot restart an evaluation.

use crate::{sha256_hex, Deadline, Signed, CLOCK_SKEW_S, PROTO_V};
use anyhow::{ensure, Result};
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};

pub const AUD_GRADER: &str = "grader";
pub const AUD_GRADING_RESULTS: &str = "grading_results";
pub const JOB_TYPE: &str = "grading_job";
pub const RESULT_TYPE: &str = "grading_result";
pub const MAX_SUBMISSION_BYTES: usize = 64 * 1024;
pub const MAX_CAPTURED_OUTPUT_BYTES: usize = 4096;
pub const MAX_GRADING_ENVELOPE_BYTES: usize = 16 * 1024;
pub const MAX_DISPATCH_BYTES: usize = 4 + MAX_GRADING_ENVELOPE_BYTES + MAX_SUBMISSION_BYTES;
/// Separate from MAX_LEASE_TTL_S. No Phase 1/2 execution lease is extended by this constant.
pub const MAX_GRADING_TTL_S: u64 = 120;
pub const TASK_ID: &str = "tiny-sum";
pub const INPUT_VERSION: &str = "1";
pub const SCORER_VERSION: &str = "1";

/// IDs are opaque bindings, not a text evidence channel or a path/URL supplied by a guest.
pub fn valid_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

pub fn valid_digest(value: &str) -> bool {
    valid_hex(value, 64)
}

fn valid_hex(value: &str, size: usize) -> bool {
    value.len() == size
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GradingJob {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub aud: String,
    pub job_id: String,
    pub run_id: String,
    pub incarnation: String,
    pub fencing_token: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub submission_digest: String,
    pub task_id: String,
    pub input_version: String,
    pub scorer_version: String,
}

impl GradingJob {
    /// Shape and wall expiry checks, also usable when rechecking result-commit authority.
    /// Durable high-water, terminal claims and role-key pinning belong to the trusted caller.
    pub fn validate(&self, now: u64) -> Result<()> {
        ensure!(
            self.v == PROTO_V && self.kind == JOB_TYPE && self.aud == AUD_GRADER,
            "job header"
        );
        ensure!(
            valid_id(&self.job_id) && valid_id(&self.run_id) && valid_id(&self.incarnation),
            "job identity"
        );
        ensure!(
            self.fencing_token > 0 && valid_digest(&self.submission_digest),
            "job binding"
        );
        ensure!(
            self.task_id == TASK_ID
                && self.input_version == INPUT_VERSION
                && self.scorer_version == SCORER_VERSION,
            "unpinned fixture"
        );
        let ttl = self.expires_at.saturating_sub(self.issued_at);
        ensure!((1..=MAX_GRADING_TTL_S).contains(&ttl), "job lifetime");
        ensure!(
            self.issued_at <= now.saturating_add(CLOCK_SKEW_S) && now < self.expires_at,
            "job expired or future dated"
        );
        Ok(())
    }

    /// Never execute decoded, normalized, or replacement bytes in place of these exact bytes.
    pub fn bind_submission(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            !bytes.is_empty() && bytes.len() <= MAX_SUBMISSION_BYTES,
            "submission size"
        );
        ensure!(
            valid_digest(&self.submission_digest) && sha256_hex(bytes) == self.submission_digest,
            "submission digest mismatch"
        );
        Ok(())
    }

    /// Both-clock deadline, with delayed delivery receiving only its remaining lifetime.
    /// This constructs no Lease and calls none of the evaluation authority transitions.
    pub fn deadline(&self, high_water: u64, now: u64) -> Result<Deadline> {
        self.validate(now)?;
        ensure!(
            self.fencing_token > high_water,
            "grading fencing high-water"
        );
        ensure!(
            now.abs_diff(self.issued_at) <= CLOCK_SKEW_S,
            "delayed grading dispatch"
        );
        let remaining = self
            .expires_at
            .saturating_sub(now)
            .min(self.expires_at - self.issued_at);
        Ok(Deadline {
            mono: Instant::now() + Duration::from_secs(remaining),
            wall: self.expires_at,
            fencing_token: self.fencing_token,
            epoch: 0,
        })
    }
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Score {
    Correct,
    Incorrect,
}

/// Anomalies are private terminal records, never grading results sent across the airlock.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GradingStatus {
    Completed,
}

/// Launcher observations only. Guest status, exit codes and test reports are not authority.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LifecycleObservations {
    pub started: bool,
    pub exited: bool,
    pub timed_out: bool,
    pub teardown_confirmed: bool,
    pub started_at: u64,
    pub exited_at: u64,
    pub frozen_at: u64,
    pub teardown_confirmed_at: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GradingResult {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String,
    pub aud: String,
    pub job_id: String,
    pub run_id: String,
    pub incarnation: String,
    pub fencing_token: u64,
    pub issued_at: u64,
    pub expires_at: u64,
    pub submission_digest: String,
    pub task_id: String,
    pub input_version: String,
    pub scorer_version: String,
    pub sandbox_id: String,
    pub launched_artifact_digest: String,
    pub captured_output_digest: String,
    pub score: Score,
    pub status: GradingStatus,
    pub observations: LifecycleObservations,
}

impl GradingResult {
    pub fn validate_for(&self, job: &GradingJob, now: u64) -> Result<()> {
        job.validate(now)?;
        ensure!(
            self.v == PROTO_V && self.kind == RESULT_TYPE && self.aud == AUD_GRADING_RESULTS,
            "result header"
        );
        ensure!(
            self.job_id == job.job_id
                && self.run_id == job.run_id
                && self.incarnation == job.incarnation
                && self.fencing_token == job.fencing_token,
            "result identity mismatch"
        );
        ensure!(
            self.submission_digest == job.submission_digest
                && self.launched_artifact_digest == job.submission_digest,
            "launched digest mismatch"
        );
        ensure!(
            self.task_id == job.task_id
                && self.input_version == job.input_version
                && self.scorer_version == job.scorer_version,
            "result fixture mismatch"
        );
        ensure!(
            valid_hex(&self.sandbox_id, 32) && valid_digest(&self.captured_output_digest),
            "result digest or sandbox identity"
        );
        ensure!(
            self.expires_at == job.expires_at
                && self.issued_at < self.expires_at
                && self.issued_at <= now.saturating_add(CLOCK_SKEW_S),
            "result lifetime"
        );
        let o = &self.observations;
        ensure!(
            o.started && o.exited && !o.timed_out && o.teardown_confirmed,
            "incomplete trusted lifecycle"
        );
        ensure!(
            o.started_at > 0
                && o.started_at.saturating_add(CLOCK_SKEW_S) >= job.issued_at
                && o.started_at <= o.exited_at
                && o.exited_at <= o.frozen_at
                && o.frozen_at <= o.teardown_confirmed_at
                && o.teardown_confirmed_at <= self.issued_at,
            "freeze/teardown/publication order"
        );
        Ok(())
    }

    pub fn bind_captured_output(&self, bytes: &[u8]) -> Result<()> {
        ensure!(
            bytes.len() <= MAX_CAPTURED_OUTPUT_BYTES
                && sha256_hex(bytes) == self.captured_output_digest,
            "captured output mismatch"
        );
        Ok(())
    }
}

fn envelope_bounds(signed: &Signed, role: &str) -> Result<()> {
    // signer is an unauthenticated hint in Signed, so check it only in addition to the pinned key.
    ensure!(
        signed.signer == role && valid_hex(&signed.sig_hex, 128),
        "grading signer shape"
    );
    ensure!(
        serde_json::to_vec(signed)?.len() <= MAX_GRADING_ENVELOPE_BYTES,
        "grading envelope size"
    );
    Ok(())
}

pub fn verify_job(signed: &Signed, key: &VerifyingKey, now: u64) -> Result<GradingJob> {
    envelope_bounds(signed, "controller")?;
    let job: GradingJob = signed.verify(key, JOB_TYPE, AUD_GRADER)?;
    job.validate(now)?;
    Ok(job)
}

pub fn verify_result(
    signed: &Signed,
    key: &VerifyingKey,
    job: &GradingJob,
    now: u64,
) -> Result<GradingResult> {
    envelope_bounds(signed, "scorer")?;
    let result: GradingResult = signed.verify(key, RESULT_TYPE, AUD_GRADING_RESULTS)?;
    result.validate_for(job, now)?;
    Ok(result)
}

/// HTTP POST /dispatch, application/octet-stream. A 4-byte unsigned big-endian envelope byte
/// count, exactly that many UTF-8 Signed JSON bytes, then 1..=65536 raw submission bytes.
pub fn encode_dispatch(signed: &Signed, submission: &[u8]) -> Result<Vec<u8>> {
    envelope_bounds(signed, "controller")?;
    ensure!(
        !submission.is_empty() && submission.len() <= MAX_SUBMISSION_BYTES,
        "submission size"
    );
    let envelope = serde_json::to_vec(signed)?;
    let mut frame = Vec::with_capacity(4 + envelope.len() + submission.len());
    frame.extend_from_slice(&(envelope.len() as u32).to_be_bytes());
    frame.extend_from_slice(&envelope);
    frame.extend_from_slice(submission);
    Ok(frame)
}

pub fn decode_dispatch(frame: &[u8]) -> Result<(Signed, Vec<u8>)> {
    ensure!(
        (5..=MAX_DISPATCH_BYTES).contains(&frame.len()),
        "dispatch size"
    );
    let size = u32::from_be_bytes(frame[..4].try_into()?) as usize;
    ensure!(
        (1..=MAX_GRADING_ENVELOPE_BYTES).contains(&size) && 4 + size < frame.len(),
        "dispatch framing"
    );
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct StrictSigned {
        payload: String,
        sig_hex: String,
        signer: String,
    }
    let raw: StrictSigned = serde_json::from_slice(&frame[4..4 + size])?;
    let signed = Signed {
        payload: raw.payload,
        sig_hex: raw.sig_hex,
        signer: raw.signer,
    };
    envelope_bounds(&signed, "controller")?;
    let submission = &frame[4 + size..];
    ensure!(submission.len() <= MAX_SUBMISSION_BYTES, "submission size");
    Ok((signed, submission.to_vec()))
}

#[cfg(test)]
mod tests;
