//! Signed, single-use challenge/evidence exchange, driven only by successful lease ticks.
//! Transport errors never renew the evidence watchdog; explicit rejection is terminal.

use super::{authority::Authority, observe_vm2, proxy::Proxy, RunArgs};
use anyhow::Context;
use deadswitch_common::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use reqwest::{blocking::Client, StatusCode};
use serde::Deserialize;
use std::time::{Duration, Instant};

// Controller ticker: 10 s * 3 = 30 s. Stop locally one full challenge window earlier.
pub const MAX_EVIDENCE_AGE: Duration =
    Duration::from_secs(CHALLENGE_TTL_S * (MISSED_CHALLENGES_TO_TRIP as u64 - 1));
const REQUEST_TIMEOUT: Duration = Duration::from_secs(2);
const NONCE_MARGIN: Duration = Duration::from_secs(1);

pub fn validate_interval(seconds: u64) -> anyhow::Result<()> {
    anyhow::ensure!(
        seconds > 0 && Duration::from_secs(seconds) < MAX_EVIDENCE_AGE / 2,
        "DS_LEASE_RENEW_INTERVAL_S must be in 1..{} to leave a heartbeat retry inside the {}s evidence deadline",
        MAX_EVIDENCE_AGE.as_secs() / 2,
        MAX_EVIDENCE_AGE.as_secs(),
    );
    Ok(())
}

pub enum Outcome {
    Healthy { sent_at: Instant },
    Deferred,
    Rejected(String),
}

#[derive(Deserialize)]
struct EvidenceResponse {
    healthy: bool,
    state: String,
    reason: Option<String>,
}

// The normal endpoint responses are Signed Challenge and EvidenceResponse. Accept a signed
// authority-reducing order too, including the lease-style denial wrapper, and stop immediately.
#[derive(Deserialize)]
#[serde(untagged)]
enum Reply<T> {
    Message(T),
    Order(Signed),
    Denied { order: Signed },
}

fn order_reason(signed: &Signed, pk: &VerifyingKey, a: &RunArgs) -> anyhow::Result<String> {
    let order: Order = signed.verify(pk, "order", AUD_HOSTD)?;
    anyhow::ensure!(
        order.run_id == a.run_id && order.incarnation == a.incarnation,
        "order for another run/incarnation"
    );
    Ok(format!(
        "controller heartbeat order {:?}: {}",
        order.order, order.reason
    ))
}

fn challenge_request(a: &RunArgs, issued_at: u64) -> ChallengeRequest {
    ChallengeRequest {
        v: PROTO_V,
        kind: "challenge_request".into(),
        run_id: a.run_id.clone(),
        aud: AUD_CONTROLLER.into(),
        incarnation: a.incarnation.clone(),
        request_id: random_hex(32),
        issued_at,
    }
}

struct PendingChallenge {
    challenge: Challenge,
    expires_at: Instant,
}

impl PendingChallenge {
    fn verify(
        signed: &Signed,
        pk: &VerifyingKey,
        a: &RunArgs,
        epoch: u64,
        started: Instant,
        wall_now: u64,
    ) -> anyhow::Result<Self> {
        let ch: Challenge = signed.verify(pk, "challenge", AUD_HOSTD)?;
        anyhow::ensure!(
            ch.run_id == a.run_id && ch.incarnation == a.incarnation && ch.epoch == epoch,
            "challenge for another run/incarnation/epoch"
        );
        anyhow::ensure!(
            wall_now.abs_diff(ch.issued_at) <= CLOCK_SKEW_S,
            "stale challenge"
        );
        anyhow::ensure!(
            (1..=CHALLENGE_TTL_S).contains(&ch.expires_in_s),
            "invalid challenge lifetime"
        );
        anyhow::ensure!(
            ch.nonce.len() == 64 && ch.nonce.bytes().all(|b| b.is_ascii_hexdigit()),
            "invalid challenge nonce"
        );
        let wall_expiry = ch
            .issued_at
            .checked_add(ch.expires_in_s)
            .context("challenge expiry overflow")?;
        anyhow::ensure!(wall_now < wall_expiry, "expired challenge");
        // Anchor to request SEND as well as the trusted wall clock; receipt cannot extend a nonce.
        let expires_at = (started + Duration::from_secs(ch.expires_in_s))
            .min(Instant::now() + Duration::from_secs(wall_expiry - wall_now));
        anyhow::ensure!(Instant::now() < expires_at, "expired challenge");
        Ok(Self {
            challenge: ch,
            expires_at,
        })
    }

    fn can_answer(&self, now: Instant) -> bool {
        self.expires_at.saturating_duration_since(now) > REQUEST_TIMEOUT + NONCE_MARGIN
    }
}

fn evidence(
    a: &RunArgs,
    nonce: String,
    measured_at: u64,
    vm2: Vm2Obs,
    gate: GateObs,
    watchdog: WatchdogObs,
    chokepoint: ChokepointObs,
) -> HostEvidence {
    HostEvidence {
        v: PROTO_V,
        kind: "host_evidence".into(),
        run_id: a.run_id.clone(),
        aud: AUD_CONTROLLER.into(),
        incarnation: a.incarnation.clone(),
        nonce,
        measured_at,
        vm2,
        gate,
        watchdog,
        chokepoint,
        untrusted_vm2_report: None,
    }
}

fn verdict(reply: EvidenceResponse, sent_at: Instant) -> Outcome {
    if reply.healthy && reply.state == "active" {
        Outcome::Healthy { sent_at }
    } else {
        Outcome::Rejected(format!(
            "controller evidence verdict ({}): {}",
            reply.state,
            reply
                .reason
                .as_deref()
                .unwrap_or("unhealthy or inactive run")
        ))
    }
}

#[derive(Default)]
pub struct Heartbeat {
    pending: Option<PendingChallenge>,
    retry_challenge_at: Option<Instant>,
}

impl Heartbeat {
    fn awaiting_challenge(&self, now: Instant) -> bool {
        self.pending.is_none() && self.retry_challenge_at.is_some_and(|at| now < at)
    }

    fn defer_outstanding(&mut self, now: Instant) {
        // We may have lost the challenge response and therefore not know its nonce. The controller
        // does not return that nonce on 429. Allow its full TTL to elapse; do not churn requests.
        self.retry_challenge_at = Some(now + Duration::from_secs(CHALLENGE_TTL_S));
    }

    fn discard_expiring(&mut self, now: Instant) -> bool {
        if self.pending.as_ref().is_some_and(|p| !p.can_answer(now)) {
            let old = self.pending.take().unwrap();
            self.retry_challenge_at = Some(old.expires_at + NONCE_MARGIN);
            tracing::warn!("challenge too close to expiry; awaiting next nonce");
            return true;
        }
        false
    }

    pub fn exchange(
        &mut self,
        http: &Client,
        a: &RunArgs,
        key: &SigningKey,
        pk: &VerifyingKey,
        authority: &Authority,
        proxy: &Proxy,
    ) -> anyhow::Result<Outcome> {
        let deadline = authority
            .deadline()
            .context("heartbeat requires a live lease")?;
        if self.awaiting_challenge(Instant::now()) {
            tracing::debug!("awaiting outstanding challenge expiry; evidence deadline unchanged");
            return Ok(Outcome::Deferred);
        }
        if self.pending.is_none() {
            let signed = Signed::sign(key, "hostd", &challenge_request(a, now_unix()));
            let started = Instant::now();
            let resp = http
                .post(format!("{}/challenge", a.controller_url))
                .timeout(REQUEST_TIMEOUT)
                .json(&signed)
                .send()
                .context("challenge request")?;
            if resp.status() == StatusCode::TOO_MANY_REQUESTS {
                self.defer_outstanding(Instant::now());
                tracing::warn!(
                    "challenge still outstanding; awaiting expiry before requesting another"
                );
                return Ok(Outcome::Deferred);
            }
            if resp.status() == StatusCode::CONFLICT {
                return Ok(Outcome::Rejected(
                    "controller refused challenge: run/incarnation inactive or tripped".into(),
                ));
            }
            let reply = resp
                .error_for_status()?
                .json::<Reply<Signed>>()
                .context("challenge response")?;
            let signed = match reply {
                Reply::Message(s) => s,
                Reply::Order(s) | Reply::Denied { order: s } => {
                    return Ok(Outcome::Rejected(order_reason(&s, pk, a)?))
                }
            };
            if let Ok(reason) = order_reason(&signed, pk, a) {
                return Ok(Outcome::Rejected(reason));
            }
            self.pending = Some(PendingChallenge::verify(
                &signed,
                pk,
                a,
                deadline.epoch,
                started,
                now_unix(),
            )?);
            self.retry_challenge_at = None;
        }
        if self.discard_expiring(Instant::now()) {
            return Ok(Outcome::Deferred);
        }
        let vm2 = observe_vm2(a);
        let (gate, watchdog) = authority.observations();
        anyhow::ensure!(
            watchdog.lease_token > 0 && watchdog.deadline_remaining_ms > 0,
            "heartbeat lost lease authority while observing"
        );
        if self.discard_expiring(Instant::now()) {
            return Ok(Outcome::Deferred);
        }
        // Never reuse after a POST attempt, even if its response is lost: the controller consumes
        // the nonce once and treats a duplicate /evidence as a terminal policy failure.
        let pending = self.pending.take().unwrap();
        let ev = evidence(
            a,
            pending.challenge.nonce,
            now_unix(),
            vm2,
            gate,
            watchdog,
            proxy.observations(),
        );
        let signed = Signed::sign(key, "hostd", &ev);
        let sent_at = Instant::now();
        let resp = http
            .post(format!("{}/evidence", a.controller_url))
            .timeout(REQUEST_TIMEOUT)
            .json(&signed)
            .send()
            .context("evidence request")?;
        if matches!(
            resp.status(),
            StatusCode::CONFLICT | StatusCode::INSUFFICIENT_STORAGE
        ) {
            return Ok(Outcome::Rejected(format!(
                "controller refused evidence: {}",
                resp.status()
            )));
        }
        match resp
            .error_for_status()?
            .json::<Reply<EvidenceResponse>>()
            .context("evidence response")?
        {
            Reply::Message(reply) => Ok(verdict(reply, sent_at)),
            Reply::Order(s) | Reply::Denied { order: s } => {
                Ok(Outcome::Rejected(order_reason(&s, pk, a)?))
            }
        }
    }
}

#[cfg(test)]
mod tests;
