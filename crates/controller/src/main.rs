//! Off-host controller: mints runs, issues fail-closed leases, challenges hostd for host-rooted
//! evidence, applies the health policy, trips, and persists revocation before acknowledging it.
//! Phase 1 runs it on the Mac; Phase 2 runs the same binary on Hetzner.

mod grading;

use anyhow::Context;
use axum::{
    extract::{Path as AxPath, State},
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use deadswitch_common::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Instant;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(name = "deadswitch-controller")]
struct Args {
    #[arg(long, default_value = "127.0.0.1:7100", env = "DS_LISTEN")]
    listen: String,
    /// Separate loopback-only operator API; Phase 2 must set this (SSH forwarding only).
    #[arg(long, env = "DS_OPERATOR_LISTEN")]
    operator_listen: Option<std::net::SocketAddr>,
    #[arg(long, env = "DS_STATE_DIR")]
    state_dir: PathBuf,
    /// Hex ed25519 seed file. Generated if missing.
    #[arg(long, env = "DS_KEY_FILE")]
    key_file: PathBuf,
    /// Operator bearer token file (mints runs, revokes).
    #[arg(long, env = "DS_OPERATOR_TOKEN_FILE")]
    operator_token_file: PathBuf,
    /// Enrolled hostd public keys (hex), one per line.
    #[arg(long, env = "DS_HOSTD_PUBKEYS_FILE")]
    hostd_pubkeys_file: PathBuf,
    #[arg(long, default_value_t = DEFAULT_LEASE_TTL_S)]
    lease_ttl_s: u64,
    #[command(flatten)]
    grading: grading::GradingArgs,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RunState {
    Created,
    Enrolled,
    Active,
    Tripped,
    Revoked,
    Terminated,
}

impl RunState {
    fn terminal(self) -> bool {
        matches!(
            self,
            RunState::Tripped | RunState::Revoked | RunState::Terminated
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct RunRecord {
    run_id: String,
    state: RunState,
    incarnation: Option<String>,
    hostd_pubkey: Option<String>,
    epoch: u64,
    /// last fencing token issued (lease or order); strictly increasing.
    fencing_token: u64,
    created_at: u64,
    last_evidence_at: Option<u64>,
    bypass_baseline: Option<u64>,
    /// expected VM2 identity, pinned at enrollment; evidence must match (Codex end-of-P1 #3).
    #[serde(default)]
    expected_template_digest: Option<String>,
    #[serde(default)]
    expected_base_digest: Option<String>,
    reasons: Vec<String>,
    defender_actions: Vec<String>,
    #[serde(default)]
    request_replay: RequestReplay,
    /// Trusted hostd teardown acknowledgment. Revocation alone is not proof the eval has stopped.
    #[serde(default)]
    termination_confirmed_at: Option<u64>,
}

/// Persist before applying a request. The clock floor prevents a wall rollback (including across
/// restart) from making a pruned, formerly fresh request valid again. Trusted nodes must synchronize
/// clocks within CLOCK_SKEW_S; the untrusted guest's receipt-based Deadline is not appropriate here.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct RequestReplay {
    wall_high_water: u64,
    seen: BTreeMap<String, u64>,
}

impl RequestReplay {
    fn accept(&mut self, request_id: &str, issued_at: u64, now: u64) -> Result<(), String> {
        if now.abs_diff(issued_at) > CLOCK_SKEW_S || now < self.wall_high_water {
            return Err("request outside trusted clock window".into());
        }
        if request_id.len() != 64 || !request_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("request_id must be 32 random bytes encoded as hex".into());
        }
        let id = request_id.to_ascii_lowercase();
        self.seen.retain(|_, expires| *expires >= now);
        if self.seen.contains_key(&id) {
            return Err("request replay".into());
        }
        if self.seen.len() >= 128 {
            return Err("request window full".into());
        }
        self.seen.insert(id, issued_at.saturating_add(CLOCK_SKEW_S));
        self.wall_high_water = now;
        Ok(())
    }
}

struct Live {
    last_valid_evidence: Option<Instant>,
    missed_challenges: u32,
    outstanding_nonce: Option<(String, Instant)>,
}

struct Ctl {
    runs: HashMap<String, RunRecord>,
    live: HashMap<String, Live>,
    nonces: HashMap<String, (String, String, Instant)>, // nonce -> (run_id, incarnation, expires)
}

struct App {
    key: SigningKey,
    operator_token: String,
    hostd_keys: Vec<VerifyingKey>,
    state_dir: PathBuf,
    lease_ttl_s: u64,
    ctl: Mutex<Ctl>,
    grading: Option<Arc<grading::GradingService>>,
}

type S = State<Arc<App>>;
type Resp<T> = Result<Json<T>, (StatusCode, String)>;

fn bad(code: StatusCode, msg: impl Into<String>) -> (StatusCode, String) {
    (code, msg.into())
}

impl App {
    /// Retain the exact verified signed envelope OFF-host before acknowledging evidence. Serialized
    /// under ctl, bounded in aggregate, and synced; storage failure reduces authority.
    fn persist_evidence(&self, run_id: &str, signed: &Signed) -> anyhow::Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let dir = self.state_dir.join("evidence");
        let mut record =
            serde_json::to_vec(&serde_json::json!({"received_at": now_unix(), "signed": signed}))?;
        record.push(b'\n');
        let mut used = 0u64;
        for entry in std::fs::read_dir(&dir)? {
            used = used
                .checked_add(entry?.metadata()?.len())
                .ok_or_else(|| anyhow::anyhow!("evidence size overflow"))?;
        }
        anyhow::ensure!(
            used.saturating_add(record.len() as u64) <= 256 * 1024 * 1024,
            "off-host evidence quota exceeded"
        );
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(dir.join(format!("{run_id}.jsonl")))?;
        file.write_all(&record)?;
        file.sync_all()?;
        std::fs::File::open(dir)?.sync_all()?;
        Ok(())
    }

    fn accept_request(
        &self,
        r: &mut RunRecord,
        id: &str,
        issued_at: u64,
    ) -> Result<(), (StatusCode, String)> {
        let mut next = r.clone();
        next.request_replay
            .accept(id, issued_at, now_unix())
            .map_err(|m| bad(StatusCode::BAD_REQUEST, m))?;
        self.persist(&next)
            .map_err(|e| bad(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        *r = next;
        Ok(())
    }

    fn persist(&self, r: &RunRecord) -> anyhow::Result<()> {
        atomic_write_json(
            &self
                .state_dir
                .join("runs")
                .join(format!("{}.json", r.run_id)),
            r,
        )
    }

    fn next_token(&self, r: &mut RunRecord) -> anyhow::Result<u64> {
        r.fencing_token += 1;
        self.persist(r)?; // durable before it leaves the process
        Ok(r.fencing_token)
    }

    fn signed_order(
        &self,
        r: &mut RunRecord,
        order: OrderKind,
        reason: &str,
    ) -> anyhow::Result<Signed> {
        let tok = self.next_token(r)?;
        let o = Order {
            v: PROTO_V,
            kind: "order".into(),
            run_id: r.run_id.clone(),
            aud: AUD_HOSTD.into(),
            incarnation: r.incarnation.clone().unwrap_or_default(),
            order,
            fencing_token: tok,
            issued_at: now_unix(),
            reason: reason.into(),
        };
        Ok(Signed::sign(&self.key, "controller", &o))
    }

    /// End the run. Persisted before returning; a terminal state never goes back.
    fn end_run(&self, r: &mut RunRecord, to: RunState, reason: &str) -> anyhow::Result<()> {
        if r.state.terminal() {
            r.reasons
                .push(format!("(already {:?}) {}", r.state, reason));
        } else {
            warn!(run = %r.run_id, ?to, reason, "run ended");
            r.state = to;
            r.reasons.push(reason.into());
        }
        if r.reasons.len() > 100 {
            r.reasons.drain(0..r.reasons.len() - 100);
        }
        self.persist(r)
    }

    /// Verify a hostd-signed envelope against the key bound to the run (or any enrolled key
    /// before binding).
    fn verify_hostd<T: serde::de::DeserializeOwned>(
        &self,
        r: &RunRecord,
        s: &Signed,
        ty: &str,
    ) -> Result<(T, String), String> {
        let keys: Vec<(VerifyingKey, String)> = match &r.hostd_pubkey {
            Some(h) => vec![(pubkey_from_hex(h).map_err(|e| e.to_string())?, h.clone())],
            None => self
                .hostd_keys
                .iter()
                .map(|k| (*k, hex::encode(k.to_bytes())))
                .collect(),
        };
        for (k, h) in keys {
            if let Ok(v) = s.verify::<T>(&k, ty, AUD_CONTROLLER) {
                return Ok((v, h));
            }
        }
        Err("signature not from an enrolled hostd key".into())
    }
}

// ------------------------------------------------------------ operator API

fn check_operator(app: &App, headers: &HeaderMap) -> Result<(), (StatusCode, String)> {
    let ok = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.strip_prefix("Bearer ").unwrap_or("") == app.operator_token)
        .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(bad(StatusCode::UNAUTHORIZED, "operator token required"))
    }
}

async fn create_run(State(app): S, headers: HeaderMap) -> Resp<RunRecord> {
    check_operator(&app, &headers)?;
    let run_id = ulid::Ulid::new().to_string();
    let r = RunRecord {
        run_id: run_id.clone(),
        state: RunState::Created,
        incarnation: None,
        hostd_pubkey: None,
        epoch: 0,
        fencing_token: 0,
        created_at: now_unix(),
        last_evidence_at: None,
        bypass_baseline: None,
        expected_template_digest: None,
        expected_base_digest: None,
        reasons: vec![],
        defender_actions: vec![],
        request_replay: RequestReplay::default(),
        termination_confirmed_at: None,
    };
    app.persist(&r)
        .map_err(|e| bad(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let mut c = app.ctl.lock().unwrap();
    c.runs.insert(run_id.clone(), r.clone());
    c.live.insert(
        run_id,
        Live {
            last_valid_evidence: None,
            missed_challenges: 0,
            outstanding_nonce: None,
        },
    );
    info!(run = %r.run_id, "run created");
    Ok(Json(r))
}

async fn list_runs(State(app): S, headers: HeaderMap) -> Resp<Vec<RunRecord>> {
    check_operator(&app, &headers)?;
    let c = app.ctl.lock().unwrap();
    let mut v: Vec<_> = c.runs.values().cloned().collect();
    v.sort_by_key(|a| a.created_at);
    Ok(Json(v))
}

async fn get_run(State(app): S, headers: HeaderMap, AxPath(id): AxPath<String>) -> Resp<RunRecord> {
    check_operator(&app, &headers)?;
    let c = app.ctl.lock().unwrap();
    c.runs
        .get(&id)
        .cloned()
        .map(Json)
        .ok_or(bad(StatusCode::NOT_FOUND, "no such run"))
}

#[derive(Deserialize)]
struct RevokeBody {
    reason: String,
}

async fn revoke_run(
    State(app): S,
    headers: HeaderMap,
    AxPath(id): AxPath<String>,
    Json(b): Json<RevokeBody>,
) -> Resp<RunRecord> {
    check_operator(&app, &headers)?;
    let mut c = app.ctl.lock().unwrap();
    let r = c
        .runs
        .get_mut(&id)
        .ok_or(bad(StatusCode::NOT_FOUND, "no such run"))?;
    app.end_run(r, RunState::Revoked, &format!("operator: {}", b.reason))
        .map_err(|e| bad(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(r.clone()))
}

// ------------------------------------------------------------ hostd API

#[derive(Serialize)]
struct EnrollResp {
    state: RunState,
    order: Option<Signed>,
}

async fn enroll(State(app): S, Json(s): Json<Signed>) -> Resp<EnrollResp> {
    let hdr: serde_json::Value = serde_json::from_str(&s.payload)
        .map_err(|e| bad(StatusCode::BAD_REQUEST, e.to_string()))?;
    let run_id = hdr["run_id"].as_str().unwrap_or("").to_string();
    let mut c = app.ctl.lock().unwrap();
    let r = c
        .runs
        .get_mut(&run_id)
        .ok_or(bad(StatusCode::NOT_FOUND, "no such run"))?;
    let (e, key_hex): (Enroll, String) = app
        .verify_hostd(r, &s, "enroll")
        .map_err(|m| bad(StatusCode::UNAUTHORIZED, m))?;
    if now_unix().abs_diff(e.issued_at) > CLOCK_SKEW_S {
        return Err(bad(StatusCode::BAD_REQUEST, "stale enrollment"));
    }
    if r.state.terminal() {
        let order = app
            .signed_order(r, OrderKind::Destroy, "enroll on terminal run")
            .map_err(|x| bad(StatusCode::INTERNAL_SERVER_ERROR, x.to_string()))?;
        return Ok(Json(EnrollResp {
            state: r.state,
            order: Some(order),
        }));
    }
    match &r.incarnation {
        Some(inc) if *inc != e.incarnation => {
            // A run has exactly one incarnation. A second one is a restart attempt: end the run.
            app.end_run(r, RunState::Revoked, "second incarnation enrolled")
                .map_err(|x| bad(StatusCode::INTERNAL_SERVER_ERROR, x.to_string()))?;
            let order = app
                .signed_order(r, OrderKind::Destroy, "incarnation mismatch")
                .map_err(|x| bad(StatusCode::INTERNAL_SERVER_ERROR, x.to_string()))?;
            return Ok(Json(EnrollResp {
                state: r.state,
                order: Some(order),
            }));
        }
        _ => {}
    }
    // Bind the expected VM2 image/template identity at enrollment so later evidence must match it
    // (Codex end-of-P1 #3); enrolling with empty digests is refused.
    if e.incarnation.is_empty()
        || e.vm2.template_digest.is_empty()
        || e.vm2.base_image_digest.is_empty()
    {
        return Err(bad(
            StatusCode::BAD_REQUEST,
            "enroll missing incarnation or image/template digest",
        ));
    }
    if r.incarnation.is_some()
        && (r.expected_template_digest.as_deref() != Some(e.vm2.template_digest.as_str())
            || r.expected_base_digest.as_deref() != Some(e.vm2.base_image_digest.as_str()))
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "enrollment cannot replace pinned digests",
        ));
    }
    r.incarnation = Some(e.incarnation.clone());
    r.hostd_pubkey = Some(key_hex);
    r.expected_template_digest = Some(e.vm2.template_digest.clone());
    r.expected_base_digest = Some(e.vm2.base_image_digest.clone());
    if r.state == RunState::Created {
        r.state = RunState::Enrolled;
    }
    app.persist(r)
        .map_err(|x| bad(StatusCode::INTERNAL_SERVER_ERROR, x.to_string()))?;
    info!(run = %run_id, incarnation = %e.incarnation, "enrolled");
    Ok(Json(EnrollResp {
        state: r.state,
        order: None,
    }))
}

async fn lease(State(app): S, Json(s): Json<Signed>) -> Resp<LeaseResponse> {
    let hdr: serde_json::Value = serde_json::from_str(&s.payload)
        .map_err(|e| bad(StatusCode::BAD_REQUEST, e.to_string()))?;
    let run_id = hdr["run_id"].as_str().unwrap_or("").to_string();
    let mut c = app.ctl.lock().unwrap();
    let r = c
        .runs
        .get_mut(&run_id)
        .ok_or(bad(StatusCode::NOT_FOUND, "no such run"))?;
    let (req, _): (LeaseRequest, String) = app
        .verify_hostd(r, &s, "lease_request")
        .map_err(|m| bad(StatusCode::UNAUTHORIZED, m))?;
    let ise = |x: anyhow::Error| bad(StatusCode::INTERNAL_SERVER_ERROR, x.to_string());
    let deny = |app: &App,
                r: &mut RunRecord,
                reason: &str|
     -> Result<LeaseResponse, (StatusCode, String)> {
        let order = app
            .signed_order(r, OrderKind::Destroy, reason)
            .map_err(ise)?;
        Ok(LeaseResponse::Denied {
            order,
            reason: reason.into(),
        })
    };
    if r.incarnation.as_deref() != Some(req.incarnation.as_str()) {
        return Ok(Json(deny(&app, r, "lease for unknown incarnation")?));
    }
    if now_unix().abs_diff(req.issued_at) > CLOCK_SKEW_S {
        return Err(bad(StatusCode::BAD_REQUEST, "stale lease request"));
    }
    if r.state.terminal() {
        return Ok(Json(deny(&app, r, &format!("run is {:?}", r.state))?));
    }
    if req.epoch < r.epoch {
        return Ok(Json(deny(&app, r, "epoch cannot go backwards")?));
    }
    if req.epoch >= 1 && req.gate != GateState::Sealed {
        return Ok(Json(deny(&app, r, "eval epoch requires sealed gate")?));
    }
    if req.epoch > r.epoch {
        info!(run = %run_id, from = r.epoch, to = req.epoch, "epoch advance");
        r.epoch = req.epoch;
        r.bypass_baseline = None; // sealing resets the bypass baseline
    }
    r.state = RunState::Active;
    let tok = app.next_token(r).map_err(ise)?;
    let l = Lease {
        v: PROTO_V,
        kind: "lease".into(),
        run_id: run_id.clone(),
        aud: AUD_HOSTD.into(),
        incarnation: req.incarnation,
        epoch: r.epoch,
        fencing_token: tok,
        issued_at: now_unix(),
        ttl_s: app.lease_ttl_s,
    };
    Ok(Json(LeaseResponse::Granted {
        lease: Signed::sign(&app.key, "controller", &l),
    }))
}

async fn challenge(State(app): S, Json(s): Json<Signed>) -> Resp<Signed> {
    let hdr: serde_json::Value = serde_json::from_str(&s.payload)
        .map_err(|e| bad(StatusCode::BAD_REQUEST, e.to_string()))?;
    let run_id = hdr["run_id"].as_str().unwrap_or("").to_string();
    let mut c = app.ctl.lock().unwrap();
    let r = c
        .runs
        .get(&run_id)
        .ok_or(bad(StatusCode::NOT_FOUND, "no such run"))?
        .clone();
    // Phase 2: the challenge REQUEST must be signed by the enrolled hostd key (network hop).
    let (q, _): (ChallengeRequest, String) = app
        .verify_hostd(&r, &s, "challenge_request")
        .map_err(|m| bad(StatusCode::UNAUTHORIZED, m))?;
    if r.incarnation.as_deref() != Some(q.incarnation.as_str()) || r.state.terminal() {
        return Err(bad(
            StatusCode::CONFLICT,
            "no challenge for this run/incarnation",
        ));
    }
    app.accept_request(c.runs.get_mut(&run_id).unwrap(), &q.request_id, q.issued_at)?;
    // Only an EXPIRED unanswered challenge counts as missed. Repeated polls cannot evict a live
    // nonce and manufacture three misses while its answer is still in flight.
    let Ctl { live, nonces, .. } = &mut *c;
    let live = live.entry(q.run_id.clone()).or_insert(Live {
        last_valid_evidence: None,
        missed_challenges: 0,
        outstanding_nonce: None,
    });
    if live
        .outstanding_nonce
        .as_ref()
        .is_some_and(|(_, exp)| Instant::now() < *exp)
    {
        return Err(bad(
            StatusCode::TOO_MANY_REQUESTS,
            "challenge still outstanding",
        ));
    }
    if let Some((old, _)) = live.outstanding_nonce.take() {
        nonces.remove(&old);
        live.missed_challenges += 1;
    }
    let missed = live.missed_challenges;
    if missed >= MISSED_CHALLENGES_TO_TRIP && r.state == RunState::Active {
        let rr = c.runs.get_mut(&q.run_id).unwrap();
        app.end_run(rr, RunState::Tripped, "missed challenges")
            .map_err(|e| bad(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        return Err(bad(StatusCode::CONFLICT, "run tripped: missed challenges"));
    }
    let nonce = random_hex(32);
    let exp = Instant::now() + std::time::Duration::from_secs(CHALLENGE_TTL_S);
    c.nonces.insert(
        nonce.clone(),
        (q.run_id.clone(), q.incarnation.clone(), exp),
    );
    c.live.get_mut(&q.run_id).unwrap().outstanding_nonce = Some((nonce.clone(), exp));
    let ch = Challenge {
        v: PROTO_V,
        kind: "challenge".into(),
        run_id: q.run_id,
        aud: AUD_HOSTD.into(),
        incarnation: q.incarnation,
        epoch: r.epoch,
        nonce,
        issued_at: now_unix(),
        expires_in_s: CHALLENGE_TTL_S,
    };
    Ok(Json(Signed::sign(&app.key, "controller", &ch)))
}

#[derive(Serialize)]
struct EvidenceResp {
    healthy: bool,
    state: RunState,
    reason: Option<String>,
}

/// The health policy (docs §3). Only hostd-observed fields decide; the VM2 report may only trip by
/// being absent or stale, never make things healthier.
fn policy(r: &RunRecord, ev: &HostEvidence, now: u64) -> Result<(), String> {
    if ev.vm2.running != Some(true) {
        return Err(format!("vm2 not observed running: {:?}", ev.vm2.running));
    }
    // An unobservable config field (None) is NOT healthy: require positively-observed values, so
    // "couldn't observe" can never pass as healthy (Codex end-of-P1 #3 / N5).
    if ev.vm2.nested_virt != Some(true) {
        return Err(format!(
            "vm2 nested_virt not positively observed: {:?}",
            ev.vm2.nested_virt
        ));
    }
    if ev.vm2.port_forwards != Some(0) || ev.vm2.writable_mounts != Some(0) {
        return Err(format!(
            "vm2 config drift: port_forwards={:?} writable_mounts={:?}",
            ev.vm2.port_forwards, ev.vm2.writable_mounts
        ));
    }
    // Evidence must describe the SAME image/template pinned at enrollment (Codex end-of-P1 #3).
    if r.expected_template_digest.as_deref() != Some(ev.vm2.template_digest.as_str())
        || r.expected_base_digest.as_deref() != Some(ev.vm2.base_image_digest.as_str())
    {
        return Err("vm2 image/template digest differs from enrolled identity".into());
    }
    // Bind health to the run's own incarnation and the current lease authority: the evidence must
    // carry the fencing token the controller last issued and a positive remaining deadline.
    if ev.incarnation.is_empty() || r.incarnation.as_deref() != Some(ev.incarnation.as_str()) {
        return Err("evidence incarnation mismatch".into());
    }
    // hostd must hold a live, non-stale lease (its token must be one this controller actually
    // issued, i.e. ≤ the current high-water, and > 0, with time left). We do NOT require exact
    // equality with the latest token: leases renew every 5 s while evidence arrives every 2 s, so a
    // brief lag behind the newest token is normal and must not false-trip.
    if r.epoch >= 1
        && (ev.watchdog.lease_token == 0
            || ev.watchdog.lease_token > r.fencing_token
            || ev.watchdog.deadline_remaining_ms <= 0)
    {
        return Err(format!(
            "watchdog not holding a valid live lease: token={} high_water={} remaining_ms={}",
            ev.watchdog.lease_token, r.fencing_token, ev.watchdog.deadline_remaining_ms
        ));
    }
    if now.abs_diff(ev.measured_at) > CLOCK_SKEW_S {
        return Err("evidence measured_at out of window".into());
    }
    if r.epoch >= 1 {
        if ev.gate.state != GateState::Sealed {
            return Err(format!("gate not sealed: {:?}", ev.gate.state));
        }
        // A rising pf block-label counter means the gate is DENYING VM2 egress, i.e. working as
        // designed; it is an attempted-egress signal (fed to the defender / evidence log), never a
        // containment failure. Containment fails only if the gate is not effectively sealed, which
        // the gate.state check above already covers. So bypass_packets is recorded, not tripped on.
        let _ = ev.gate.bypass_packets;
        // The untrusted VM2 self-report is ADVISORY liveness only — it is NOT a containment control
        // and is NOT trusted for positive health, so a missing/stale/foreign report does NOT trip
        // the run. Containment rests entirely on hostd's OWN, host-enforced observations already
        // checked above: vm2.running (host process table), gate == Sealed (host pf), and a valid live
        // watchdog lease (host-owned deadline). A compromised VM2 that stops reporting still cannot
        // egress (sealed pf gate) nor outlive its lease (host watchdog + host-independent kill).
        // Tripping on this untrusted signal caused false positives when an honest supervisor's report
        // thread was starved during nested-VM1 boot + inference; the report remains recorded as
        // evidence and can feed the defender / an operator alert. (REPORT_MAX_AGE_S still bounds
        // whether hostd attaches the report to evidence at all.)
        let _ = (REPORT_MAX_AGE_S, &ev.untrusted_vm2_report);
    }
    Ok(())
}

async fn evidence(State(app): S, Json(s): Json<Signed>) -> Resp<EvidenceResp> {
    let hdr: serde_json::Value = serde_json::from_str(&s.payload)
        .map_err(|e| bad(StatusCode::BAD_REQUEST, e.to_string()))?;
    let run_id = hdr["run_id"].as_str().unwrap_or("").to_string();
    let mut c = app.ctl.lock().unwrap();
    let r = c
        .runs
        .get(&run_id)
        .ok_or(bad(StatusCode::NOT_FOUND, "no such run"))?
        .clone();
    let (ev, _): (HostEvidence, String) = app
        .verify_hostd(&r, &s, "host_evidence")
        .map_err(|m| bad(StatusCode::UNAUTHORIZED, m))?;
    // nonce: must exist, be bound to this run+incarnation, unexpired; consumed exactly once.
    let ok_nonce = match c.nonces.remove(&ev.nonce) {
        Some((rid, inc, exp)) => rid == run_id && inc == ev.incarnation && Instant::now() < exp,
        None => false,
    };
    if let Some(l) = c.live.get_mut(&run_id) {
        if matches!(&l.outstanding_nonce, Some((n, _)) if *n == ev.nonce) {
            l.outstanding_nonce = None;
        }
    }
    let ise = |x: anyhow::Error| bad(StatusCode::INTERNAL_SERVER_ERROR, x.to_string());
    let now = now_unix();
    let verdict = if !ok_nonce {
        Err("nonce invalid, expired, or reused".to_string())
    } else {
        policy(&r, &ev, now)
    };
    let rr = c.runs.get_mut(&run_id).unwrap();
    if ok_nonce {
        if let Err(error) = app.persist_evidence(&run_id, &s) {
            app.end_run(rr, RunState::Tripped, "off-host evidence storage failed")
                .map_err(ise)?;
            return Err(bad(StatusCode::INSUFFICIENT_STORAGE, error.to_string()));
        }
    }
    match verdict {
        Ok(()) => {
            rr.last_evidence_at = Some(now);
            if rr.epoch >= 1 && rr.bypass_baseline.is_none() {
                rr.bypass_baseline = ev.gate.bypass_packets;
                app.persist(rr).map_err(ise)?;
            }
            let l = c.live.get_mut(&run_id).unwrap();
            l.last_valid_evidence = Some(Instant::now());
            l.missed_challenges = 0;
            let st = c.runs[&run_id].state;
            Ok(Json(EvidenceResp {
                healthy: !st.terminal(),
                state: st,
                reason: None,
            }))
        }
        Err(reason) => {
            if rr.state == RunState::Active || rr.state == RunState::Enrolled {
                app.end_run(rr, RunState::Tripped, &format!("evidence: {reason}"))
                    .map_err(ise)?;
            }
            Ok(Json(EvidenceResp {
                healthy: false,
                state: rr.state,
                reason: Some(reason),
            }))
        }
    }
}

/// Relayed by hostd from the (untrusted) defender. Every variant only reduces authority, so an
/// untrusted source can at worst end its own run early.
async fn defender(State(app): S, Json(s): Json<Signed>) -> Resp<RunRecord> {
    let hdr: serde_json::Value = serde_json::from_str(&s.payload)
        .map_err(|e| bad(StatusCode::BAD_REQUEST, e.to_string()))?;
    let run_id = hdr["run_id"].as_str().unwrap_or("").to_string();
    let mut c = app.ctl.lock().unwrap();
    // Phase 2: the defender relay must be signed by the enrolled hostd key (network hop) — an on-net
    // party must not be able to force-terminate a run via unsigned /defender.
    let rec = c
        .runs
        .get(&run_id)
        .ok_or(bad(StatusCode::NOT_FOUND, "no such run"))?
        .clone();
    let (q, _): (DefenderReport, String) = app
        .verify_hostd(&rec, &s, "defender_report")
        .map_err(|m| bad(StatusCode::UNAUTHORIZED, m))?;
    let r = c
        .runs
        .get_mut(&run_id)
        .ok_or(bad(StatusCode::NOT_FOUND, "no such run"))?;
    if r.incarnation.as_deref() != Some(q.incarnation.as_str()) {
        return Err(bad(StatusCode::CONFLICT, "unknown incarnation"));
    }
    if r.state.terminal() {
        return Err(bad(StatusCode::CONFLICT, "run is terminal"));
    }
    app.accept_request(r, &q.request_id, q.issued_at)?;
    // Bound the VM2-influenced history so a compromised VM2 cannot grow the durable record without
    // limit via /defender (Codex end-of-P1 #6): keep the most recent 100.
    r.defender_actions
        .push(serde_json::to_string(&q.action).unwrap());
    if r.defender_actions.len() > 100 {
        let drop = r.defender_actions.len() - 100;
        r.defender_actions.drain(0..drop);
    }
    let ise = |x: anyhow::Error| bad(StatusCode::INTERNAL_SERVER_ERROR, x.to_string());
    match q.action {
        DefenderAction::TerminateVm1 { reason } => app
            .end_run(
                r,
                RunState::Revoked,
                &format!("defender terminate: {reason}"),
            )
            .map_err(ise)?,
        _ => app.persist(r).map_err(ise)?,
    }
    Ok(Json(r.clone()))
}

async fn terminated(State(app): S, Json(s): Json<Signed>) -> Resp<RunRecord> {
    let hdr: serde_json::Value = serde_json::from_str(&s.payload)
        .map_err(|e| bad(StatusCode::BAD_REQUEST, e.to_string()))?;
    let run_id = hdr["run_id"].as_str().unwrap_or("").to_string();
    let mut c = app.ctl.lock().unwrap();
    let r = c
        .runs
        .get_mut(&run_id)
        .ok_or(bad(StatusCode::NOT_FOUND, "no such run"))?;
    let (t, _): (TerminatedMsg, String) = app
        .verify_hostd(r, &s, "terminated")
        .map_err(|m| bad(StatusCode::UNAUTHORIZED, m))?;
    if r.incarnation.as_deref() != Some(t.incarnation.as_str())
        || now_unix().abs_diff(t.issued_at) > CLOCK_SKEW_S
    {
        return Err(bad(
            StatusCode::CONFLICT,
            "termination for stale or unknown incarnation",
        ));
    }
    app.end_run(
        r,
        RunState::Terminated,
        &format!("hostd confirmed termination in {} ms", t.latency_ms),
    )
    .map_err(|e| bad(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    r.termination_confirmed_at = Some(now_unix());
    if r.state != RunState::Terminated {
        // keep the original terminal reason, but record that VM2 is gone
        r.reasons.push("terminated (confirmed)".into());
    }
    app.persist(r)
        .map_err(|e| bad(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(r.clone()))
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct TerminatedMsg {
    v: u32,
    #[serde(rename = "type")]
    kind: String,
    run_id: String,
    aud: String,
    incarnation: String,
    issued_at: u64,
    latency_ms: u64,
}
async fn health() -> &'static str {
    "ok"
}

/// Time-based trip: an Active run with no valid evidence for 3 challenge windows is tripped even if
/// hostd never asks for a challenge at all.
async fn ticker(app: Arc<App>) {
    let window = std::time::Duration::from_secs(CHALLENGE_TTL_S * MISSED_CHALLENGES_TO_TRIP as u64);
    loop {
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
        let mut c = app.ctl.lock().unwrap();
        let ids: Vec<String> = c
            .runs
            .values()
            .filter(|r| r.state == RunState::Active)
            .map(|r| r.run_id.clone())
            .collect();
        for id in ids {
            let silent = match c.live.get(&id).and_then(|l| l.last_valid_evidence) {
                Some(t) => t.elapsed() > window,
                None => c.runs[&id].created_at + window.as_secs() < now_unix(),
            };
            if silent {
                let r = c.runs.get_mut(&id).unwrap();
                if let Err(e) = app.end_run(r, RunState::Tripped, "no valid evidence within window")
                {
                    warn!(error = %e, "persist failed while tripping");
                }
            }
        }
        // drop expired nonces
        c.nonces.retain(|_, (_, _, exp)| Instant::now() < *exp);
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?),
        )
        .init();
    let a = Args::parse();
    std::fs::create_dir_all(a.state_dir.join("runs"))?;
    std::fs::create_dir_all(a.state_dir.join("evidence"))?;
    let key = load_or_create_signing_key(&a.key_file)?;
    let operator_token = std::fs::read_to_string(&a.operator_token_file)
        .context("operator token")?
        .trim()
        .to_string();
    anyhow::ensure!(
        !operator_token.is_empty(),
        "operator token must not be empty"
    );
    let hostd_keys: Vec<VerifyingKey> = std::fs::read_to_string(&a.hostd_pubkeys_file)
        .context("hostd pubkeys")?
        .lines()
        .filter(|l| !l.trim().is_empty())
        .map(pubkey_from_hex)
        .collect::<Result<_, _>>()?;
    anyhow::ensure!(!hostd_keys.is_empty(), "no hostd public keys enrolled");

    // Startup default: everything on disk that was active is treated as needing fresh evidence;
    // no lease survives a restart, and lost/corrupt records read as revoked.
    let mut runs = HashMap::new();
    for e in std::fs::read_dir(a.state_dir.join("runs"))? {
        let p = e?.path();
        if p.extension().map(|x| x == "json").unwrap_or(false) {
            match read_json::<RunRecord>(&p) {
                Ok(Some(mut r)) => {
                    // No old active authority survives restart. A run ID is never reactivated;
                    // the operator must mint a new one after cleanup.
                    if matches!(r.state, RunState::Active | RunState::Enrolled) {
                        r.state = RunState::Revoked;
                        r.reasons
                            .push("controller restarted; previous authority revoked".into());
                        atomic_write_json(&p, &r)?;
                    }
                    runs.insert(r.run_id.clone(), r);
                }
                other => {
                    warn!(path = %p.display(), ?other, "unreadable run record: treating as revoked");
                    let id = p.file_stem().unwrap().to_string_lossy().to_string();
                    let r = RunRecord {
                        run_id: id.clone(),
                        state: RunState::Revoked,
                        incarnation: None,
                        hostd_pubkey: None,
                        epoch: 0,
                        fencing_token: u64::MAX / 2,
                        created_at: 0,
                        last_evidence_at: None,
                        bypass_baseline: None,
                        expected_template_digest: None,
                        expected_base_digest: None,
                        reasons: vec!["corrupt record".into()],
                        defender_actions: vec![],
                        request_replay: RequestReplay::default(),
                        termination_confirmed_at: None,
                    };
                    atomic_write_json(&p, &r)?;
                    runs.insert(id, r);
                }
            }
        }
    }
    let grading = grading::configure(&a.grading, &a.state_dir, &key, &hostd_keys, a.operator_listen)?;
    info!(controller_pubkey = %pubkey_hex(&key), runs = runs.len(), "controller up");
    let app = Arc::new(App {
        key,
        operator_token,
        hostd_keys,
        state_dir: a.state_dir.clone(),
        lease_ttl_s: a.lease_ttl_s.min(MAX_LEASE_TTL_S),
        ctl: Mutex::new(Ctl {
            runs,
            live: HashMap::new(),
            nonces: HashMap::new(),
        }),
        grading,
    });
    tokio::spawn(ticker(app.clone()));
    let operator_router = Router::new()
        .route("/runs", post(create_run).get(list_runs))
        .route("/runs/{id}", get(get_run))
        .route("/runs/{id}/revoke", post(revoke_run))
        .merge(grading::operator_router());
    let mut router = Router::new()
        .route("/health", get(health))
        .route("/enroll", post(enroll))
        .route("/lease", post(lease))
        .route("/challenge", post(challenge))
        .route("/evidence", post(evidence))
        .route("/defender", post(defender))
        .route("/terminated", post(terminated));
    if let Some(addr) = a.operator_listen {
        anyhow::ensure!(
            addr.ip().is_loopback(),
            "operator listener must be loopback (use SSH forwarding)"
        );
        let ops = operator_router
            .layer(axum::extract::DefaultBodyLimit::max(MAX_MSG_BYTES + 4096))
            .with_state(app.clone());
        let listener = tokio::net::TcpListener::bind(addr).await?;
        tokio::spawn(async move {
            if let Err(e) = axum::serve(listener, ops).await {
                warn!(error = %e, "operator listener failed");
            }
        });
    } else {
        anyhow::ensure!(
            a.listen.parse::<std::net::SocketAddr>()?.ip().is_loopback(),
            "non-loopback hostd listener requires a separate operator listener"
        );
        router = router.merge(operator_router); // Phase 1 loopback profile
    }
    grading::start_listeners(&a.grading, app.clone()).await?;
    let router = router
        .layer(axum::extract::DefaultBodyLimit::max(MAX_MSG_BYTES + 4096))
        .with_state(app);
    let listener = tokio::net::TcpListener::bind(&a.listen).await?;
    info!(listen = %a.listen, "listening");
    axum::serve(listener, router).await?;
    Ok(())
}

#[cfg(test)]
mod policy_tests {
    use super::*;
    use deadswitch_common::{
        ChokepointObs, GateObs, GateState, HostEvidence, UntrustedReport, Vm1State, Vm2Obs,
        Vm2Report, VmiResult, WatchdogObs, AUD_CONTROLLER, PROTO_V,
    };

    fn run() -> RunRecord {
        RunRecord {
            run_id: "r".into(),
            state: RunState::Active,
            incarnation: Some("inc".into()),
            hostd_pubkey: None,
            epoch: 1,
            fencing_token: 5,
            created_at: 0,
            last_evidence_at: None,
            bypass_baseline: Some(0),
            expected_template_digest: Some("tmpl".into()),
            expected_base_digest: Some("base".into()),
            reasons: vec![],
            defender_actions: vec![],
            request_replay: RequestReplay::default(),
            termination_confirmed_at: None,
        }
    }
    fn report(now: u64) -> UntrustedReport {
        UntrustedReport {
            received_at: now,
            digest: "d".into(),
            body: Vm2Report {
                run_id: "r".into(),
                seq: 1,
                sent_at: now,
                phase: "eval".into(),
                vm1_state: Vm1State::Running,
                vmi: VmiResult::Unmeasured,
                gateway_allowed: 0,
                gateway_denied: 0,
                defender_actions: 0,
                log_dropped: 0,
            },
        }
    }
    fn healthy(now: u64) -> HostEvidence {
        HostEvidence {
            v: PROTO_V,
            kind: "host_evidence".into(),
            run_id: "r".into(),
            aud: AUD_CONTROLLER.into(),
            incarnation: "inc".into(),
            nonce: "n".into(),
            measured_at: now,
            vm2: Vm2Obs {
                running: Some(true),
                instance: "i".into(),
                pid: Some(1),
                started_at: Some(1),
                template_digest: "tmpl".into(),
                base_image_digest: "base".into(),
                nested_virt: Some(true),
                port_forwards: Some(0),
                writable_mounts: Some(0),
            },
            gate: GateObs {
                state: GateState::Sealed,
                bypass_packets: Some(0),
            },
            watchdog: WatchdogObs {
                lease_token: 5,
                deadline_remaining_ms: 9000,
            },
            chokepoint: ChokepointObs::default(),
            untrusted_vm2_report: Some(report(now)),
        }
    }

    struct Fixture {
        app: Arc<App>,
        host: SigningKey,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("ds-controller-{}", random_hex(8)));
            std::fs::create_dir_all(dir.join("runs")).unwrap();
            std::fs::create_dir(dir.join("evidence")).unwrap();
            let host = SigningKey::generate(&mut rand::rngs::OsRng);
            let mut r = run();
            r.hostd_pubkey = Some(pubkey_hex(&host));
            let app = Arc::new(App {
                key: SigningKey::generate(&mut rand::rngs::OsRng),
                operator_token: "operator".into(),
                hostd_keys: vec![host.verifying_key()],
                state_dir: dir,
                lease_ttl_s: 15,
                ctl: Mutex::new(Ctl {
                    runs: HashMap::from([("r".into(), r)]),
                    live: HashMap::new(),
                    nonces: HashMap::new(),
                }),
                grading: None,
            });
            Self { app, host }
        }
        fn challenge(&self) -> ChallengeRequest {
            ChallengeRequest {
                v: PROTO_V,
                kind: "challenge_request".into(),
                run_id: "r".into(),
                aud: AUD_CONTROLLER.into(),
                incarnation: "inc".into(),
                issued_at: now_unix(),
                request_id: random_hex(32),
            }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.app.state_dir);
        }
    }

    #[test]
    fn replay_window_is_bounded_durable_and_rollback_safe() {
        let now = 1000;
        let mut window = RequestReplay::default();
        let id = random_hex(32);
        assert!(window.accept(&id, now - CLOCK_SKEW_S, now).is_ok());
        let mut restarted: RequestReplay =
            serde_json::from_str(&serde_json::to_string(&window).unwrap()).unwrap();
        assert!(restarted.accept(&id, now - CLOCK_SKEW_S, now).is_err());
        assert!(restarted
            .accept(&random_hex(32), now - CLOCK_SKEW_S - 1, now)
            .is_err());
        assert!(restarted
            .accept(&random_hex(32), now + CLOCK_SKEW_S + 1, now)
            .is_err());
        assert!(restarted
            .accept(&random_hex(32), now + CLOCK_SKEW_S, now)
            .is_ok());
        // Prune the old entry, roll time back, and try it again: still refused.
        assert!(restarted
            .accept(&random_hex(32), now + 20, now + 20)
            .is_ok());
        assert!(restarted.accept(&id, now - CLOCK_SKEW_S, now).is_err());
        let mut window = RequestReplay::default();
        for _ in 0..128 {
            window.accept(&random_hex(32), now, now).unwrap();
        }
        assert!(window.accept(&random_hex(32), now, now).is_err());
    }

    #[tokio::test]
    async fn challenge_replays_and_early_polls_cannot_evict_the_nonce_or_trip() {
        let f = Fixture::new();
        let q = f.challenge();
        let signed = Signed::sign(&f.host, "hostd", &q);
        assert!(challenge(State(f.app.clone()), Json(signed.clone()))
            .await
            .is_ok());
        let nonce = f.app.ctl.lock().unwrap().live["r"]
            .outstanding_nonce
            .clone();
        assert!(challenge(State(f.app.clone()), Json(signed)).await.is_err());
        for _ in 0..4 {
            let response = challenge(
                State(f.app.clone()),
                Json(Signed::sign(&f.host, "hostd", &f.challenge())),
            )
            .await;
            assert_eq!(response.unwrap_err().0, StatusCode::TOO_MANY_REQUESTS);
        }
        let c = f.app.ctl.lock().unwrap();
        assert_eq!(c.live["r"].outstanding_nonce, nonce);
        assert_eq!(c.live["r"].missed_challenges, 0);
        assert_eq!(c.runs["r"].state, RunState::Active);
        let disk: RunRecord = read_json(&f.app.state_dir.join("runs/r.json"))
            .unwrap()
            .unwrap();
        assert!(disk.request_replay.seen.contains_key(&q.request_id));
    }

    #[tokio::test]
    async fn challenge_authentication_and_expired_misses_are_enforced() {
        let f = Fixture::new();
        let mut q = f.challenge();
        let other = SigningKey::generate(&mut rand::rngs::OsRng);
        assert_eq!(
            challenge(
                State(f.app.clone()),
                Json(Signed::sign(&other, "hostd", &q))
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::UNAUTHORIZED
        );
        q.issued_at -= CLOCK_SKEW_S + 1;
        assert!(challenge(
            State(f.app.clone()),
            Json(Signed::sign(&f.host, "hostd", &q))
        )
        .await
        .is_err());
        let expired = Instant::now() - std::time::Duration::from_secs(1);
        f.app.ctl.lock().unwrap().live.insert(
            "r".into(),
            Live {
                last_valid_evidence: None,
                missed_challenges: 2,
                outstanding_nonce: Some(("expired".into(), expired)),
            },
        );
        // Even if ticker already removed the nonce, the expired outstanding challenge counts.
        assert_eq!(
            challenge(
                State(f.app.clone()),
                Json(Signed::sign(&f.host, "hostd", &f.challenge()))
            )
            .await
            .unwrap_err()
            .0,
            StatusCode::CONFLICT
        );
        assert_eq!(f.app.ctl.lock().unwrap().runs["r"].state, RunState::Tripped);
    }

    #[tokio::test]
    async fn defender_and_termination_check_freshness_identity_and_replay() {
        let f = Fixture::new();
        let mut report = DefenderReport {
            v: PROTO_V,
            kind: "defender_report".into(),
            run_id: "r".into(),
            aud: AUD_CONTROLLER.into(),
            incarnation: "inc".into(),
            issued_at: now_unix() - 20,
            request_id: random_hex(32),
            action: DefenderAction::Pause {
                reason: "test".into(),
            },
        };
        assert!(defender(
            State(f.app.clone()),
            Json(Signed::sign(&f.host, "hostd", &report))
        )
        .await
        .is_err());
        report.issued_at = now_unix();
        let signed = Signed::sign(&f.host, "hostd", &report);
        assert!(defender(State(f.app.clone()), Json(signed.clone()))
            .await
            .is_ok());
        assert!(defender(State(f.app.clone()), Json(signed)).await.is_err());
        let msg = TerminatedMsg {
            v: PROTO_V,
            kind: "terminated".into(),
            run_id: "r".into(),
            aud: AUD_CONTROLLER.into(),
            incarnation: "other-boot".into(),
            issued_at: now_unix(),
            latency_ms: 1,
        };
        assert!(terminated(
            State(f.app.clone()),
            Json(Signed::sign(&f.host, "hostd", &msg))
        )
        .await
        .is_err());
        assert_eq!(f.app.ctl.lock().unwrap().runs["r"].state, RunState::Active);
        assert_eq!(
            f.app.ctl.lock().unwrap().runs["r"].defender_actions.len(),
            1
        );
    }

    #[tokio::test]
    async fn reenrollment_cannot_replace_digest_pins() {
        let f = Fixture::new();
        let mut vm = healthy(now_unix()).vm2;
        vm.base_image_digest = "different".into();
        let e = Enroll {
            v: PROTO_V,
            kind: "enroll".into(),
            run_id: "r".into(),
            aud: AUD_CONTROLLER.into(),
            incarnation: "inc".into(),
            issued_at: now_unix(),
            vm2: vm,
        };
        assert!(enroll(
            State(f.app.clone()),
            Json(Signed::sign(&f.host, "hostd", &e))
        )
        .await
        .is_err());
        assert_eq!(
            f.app.ctl.lock().unwrap().runs["r"]
                .expected_base_digest
                .as_deref(),
            Some("base")
        );
    }

    #[tokio::test]
    async fn verified_evidence_is_stored_off_host_and_storage_failure_trips() {
        let f = Fixture::new();
        for over_quota in [false, true] {
            let Json(signed_challenge) = challenge(
                State(f.app.clone()),
                Json(Signed::sign(&f.host, "hostd", &f.challenge())),
            )
            .await
            .unwrap();
            let ch: Challenge = signed_challenge
                .verify(&f.app.key.verifying_key(), "challenge", AUD_HOSTD)
                .unwrap();
            let mut ev = healthy(now_unix());
            ev.nonce = ch.nonce;
            let signed = Signed::sign(&f.host, "hostd", &ev);
            if over_quota {
                let file = std::fs::File::create(f.app.state_dir.join("evidence/quota")).unwrap();
                file.set_len(256 * 1024 * 1024).unwrap();
                assert!(evidence(State(f.app.clone()), Json(signed)).await.is_err());
                assert_eq!(f.app.ctl.lock().unwrap().runs["r"].state, RunState::Tripped);
            } else {
                assert!(
                    evidence(State(f.app.clone()), Json(signed.clone()))
                        .await
                        .unwrap()
                        .0
                        .healthy
                );
                let line =
                    std::fs::read_to_string(f.app.state_dir.join("evidence/r.jsonl")).unwrap();
                let stored: serde_json::Value = serde_json::from_str(&line).unwrap();
                assert_eq!(
                    serde_json::from_value::<Signed>(stored["signed"].clone()).unwrap(),
                    signed
                );
            }
        }
    }

    #[test]
    fn healthy_passes_but_each_tampering_trips() {
        let now = 1_000_000;
        let r = run();
        assert!(
            policy(&r, &healthy(now), now).is_ok(),
            "a fully-observed sealed run is healthy"
        );

        // forged "healthy" report while the gate is actually CUT ⇒ trip (host-observed gate wins).
        let mut e = healthy(now);
        e.gate.state = GateState::Cut;
        assert!(policy(&r, &e, now).is_err());

        // image/template digest differs from the enrolled identity ⇒ trip.
        let mut e = healthy(now);
        e.vm2.template_digest = "other".into();
        assert!(policy(&r, &e, now).is_err());

        // unobservable (None) config must NOT pass as healthy.
        let mut e = healthy(now);
        e.vm2.nested_virt = None;
        assert!(policy(&r, &e, now).is_err());
        let mut e = healthy(now);
        e.vm2.port_forwards = None;
        assert!(policy(&r, &e, now).is_err());

        // The untrusted VM2 report is ADVISORY: a missing or stale report does NOT trip (containment
        // rests on hostd's own host-enforced observations). These must stay healthy.
        let mut e = healthy(now);
        e.untrusted_vm2_report = None;
        assert!(
            policy(&r, &e, now).is_ok(),
            "missing untrusted report is advisory, not a trip"
        );
        let mut e = healthy(now);
        e.untrusted_vm2_report = Some(report(now - 100));
        assert!(
            policy(&r, &e, now).is_ok(),
            "stale untrusted report is advisory, not a trip"
        );

        // watchdog not holding a live lease ⇒ trip.
        let mut e = healthy(now);
        e.watchdog.deadline_remaining_ms = 0;
        assert!(policy(&r, &e, now).is_err());
        let mut e = healthy(now);
        e.watchdog.lease_token = 999; // above high-water = not issued by us
        assert!(policy(&r, &e, now).is_err());

        // incarnation mismatch ⇒ trip.
        let mut e = healthy(now);
        e.incarnation = "evil".into();
        assert!(policy(&r, &e, now).is_err());
    }
}
