//! hostd — the trusted Mac-side component below VM2 (docs/phase1-local-host.md §3–§4).
//!
//! Owns, and VM2 cannot touch: the lease watchdog (both clocks), the pf user-gate, VM2's
//! lifecycle (clone / start / destroy-with-delete), the evidence signer (signs only what it
//! observed itself), the trusted evidence store, and the inference chokepoint (Phase 1 only).
//! Runs as root via the sudoers entry installed by infra/mac/install-hostd.sh.

mod evidence;

use anyhow::{anyhow, Context};
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand};
use deadswitch_common::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::task::Poll;
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{error, info, warn};

const EVIDENCE_QUOTA_BYTES: u64 = 256 * 1024 * 1024;

/// Run a command with a hard timeout, killing it on overrun. The watchdog, gate, and destroy paths
/// must never block indefinitely on a wedged limactl/pfctl (Codex end-of-P1 #1).
fn output_bounded(mut c: Command, secs: u64) -> std::io::Result<std::process::Output> {
    use std::io::{Error, ErrorKind};
    let child = c.stdout(Stdio::piped()).stderr(Stdio::piped()).stdin(Stdio::null()).spawn()?;
    let pid = child.id();
    // Collect the child on a dedicated thread so a >64 KiB output filling the OS pipe buffer cannot
    // wedge us, and so the call ALWAYS returns within `secs` even if a grandchild keeps the pipe
    // open: on timeout we SIGKILL by pid and return immediately, leaving the reader thread to drain
    // and exit on its own (Codex end-of-P1 #1 — bound the whole call including pipe collection, not
    // just wait()).
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(child.wait_with_output());
    });
    match rx.recv_timeout(Duration::from_secs(secs)) {
        Ok(r) => r,
        Err(_) => {
            let _ = Command::new("/bin/kill").args(["-9", &pid.to_string()]).status();
            Err(Error::new(ErrorKind::TimedOut, format!("command timed out after {secs}s")))
        }
    }
}

fn pid_alive(pid: u32) -> bool {
    Command::new("/bin/kill").args(["-0", &pid.to_string()]).status().map(|s| s.success()).unwrap_or(false)
}

const SERVICE_USER: &str = "_deadswitch";
const STATE_DIR: &str = "/var/lib/deadswitch";
const LIMA_HOME: &str = "/var/lib/deadswitch/lima";
const BASE_INSTANCE: &str = "vm2-base";
const HOSTD_PORT: u16 = 7001;
const LIMA_SSH_PORT: u16 = 60022;
const LOG_RATE_PER_S: u64 = 100;
const LOG_MAX_BYTES: usize = 8 * 1024;
const RENEW_EVERY_S: u64 = 5;
const CHALLENGE_EVERY_S: u64 = 2;

#[derive(Parser)]
#[command(name = "deadswitch-hostd")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate the hostd signing key (prints the public key to enroll in the controller).
    Keygen,
    /// Set the pf gate: open | sealed | cut
    Gate { state: String },
    /// Fail-closed cleanup: destroy every vm2-* instance except the base image.
    Cleanup,
    /// Always-on independent watchdog (launchd KeepAlive). Destroys any eval VM2 whose run process
    /// has died, whose lease has expired, or that has no valid active-lease handoff — so a crashed
    /// `run` cannot leave VM2 alive.
    Guard,
    /// Build the provisioned base instance (gate open during provisioning, sealed after).
    ProvisionBase {
        #[arg(long)]
        template: PathBuf,
        /// Directory with the supervisor binary, scripts and harness to copy in.
        #[arg(long)]
        payload: PathBuf,
    },
    /// Run one evaluation: clone base, enroll, lease, watch, destroy.
    Run {
        #[arg(long)]
        run_id: String,
        #[arg(long, default_value = "http://127.0.0.1:7100")]
        controller: String,
        #[arg(long)]
        controller_pubkey: String,
        #[arg(long, default_value = "qwen2.5:7b")]
        model: String,
        #[arg(long, default_value = "http://127.0.0.1:11434")]
        ollama: String,
        /// Skip the eval start until the supervisor reports prestage done (default). For tests.
        #[arg(long, default_value_t = 3600)]
        max_run_s: u64,
        #[arg(long)]
        template: PathBuf,
    },
}

// ------------------------------------------------------------------ lima / pf helpers

fn lima() -> Command {
    let mut c = Command::new("/usr/bin/sudo");
    c.args(["-n", "-u", SERVICE_USER, "-H", "env", &format!("LIMA_HOME={LIMA_HOME}"), "/opt/homebrew/bin/limactl"]);
    c
}

fn run_ok(c: Command, what: &str) -> anyhow::Result<String> {
    run_ok_t(c, what, 45)
}
fn run_ok_t(c: Command, what: &str, secs: u64) -> anyhow::Result<String> {
    let out = output_bounded(c, secs).with_context(|| what.to_string())?;
    if !out.status.success() {
        return Err(anyhow!("{what} failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

/// pf must be ENABLED for the anchor rules to have any effect; a disabled pf still lists rules.
fn pf_enabled() -> bool {
    output_bounded({ let mut c = Command::new("/sbin/pfctl"); c.args(["-s", "info"]); c }, 5)
        .ok()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("Status: Enabled"))
        .unwrap_or(false)
}

#[derive(Deserialize, Debug, Clone)]
struct LimaInstance {
    name: String,
    status: String,
    #[serde(default)]
    dir: String,
    #[serde(default)]
    config: serde_json::Value,
}

fn lima_list() -> anyhow::Result<Vec<LimaInstance>> {
    // Bounded to 15s so enumeration cannot stall the challenge/guard paths for the 45s default
    // (Codex end-of-P1 #1); a healthy `limactl list` is sub-second.
    let out = run_ok_t({ let mut c = lima(); c.args(["list", "--json"]); c }, "limactl list", 15)?;
    out.lines().filter(|l| l.trim_start().starts_with('{')).map(|l| serde_json::from_str(l).map_err(Into::into)).collect()
}

fn gate_rules(state: GateState) -> String {
    match state {
        GateState::Open => format!("pass out quick all user {SERVICE_USER} keep state\n"),
        GateState::Sealed => format!(
            "pass out quick proto tcp from any to 127.0.0.1 port {{ {HOSTD_PORT} {LIMA_SSH_PORT} }} user {SERVICE_USER} keep state\nblock out log quick all user {SERVICE_USER} label \"deadswitch_bypass\"\n"
        ),
        GateState::Cut | GateState::Unknown => format!("block out log quick all user {SERVICE_USER} label \"deadswitch_bypass\"\n"),
    }
}

fn gate_set(state: GateState) -> anyhow::Result<()> {
    let p = Path::new(STATE_DIR).join("pf.anchor");
    std::fs::write(&p, gate_rules(state))?;
    run_ok_t({ let mut c = Command::new("/sbin/pfctl"); c.args(["-q", "-a", "deadswitch", "-f", p.to_str().unwrap()]); c }, "pfctl load anchor", 10)?;
    // On SEAL and CUT, tear down existing pf states so egress flows opened while the gate was OPEN
    // (prestage-era package fetches) cannot survive into the sealed/eval phase — a real containment
    // hole otherwise (Codex end-of-P1 #2). The raw-TCP reporter opens a fresh VM2->hostd connection
    // every REPORT_EVERY_S, so the one permitted flow re-establishes immediately under the sealed
    // rule; only the idle prior socket is dropped. Note (dev-Mac profile): pf cannot kill states by
    // socket-user, so this also briefly resets unrelated host connections (they recover); the Phase-2
    // per-host cloud profile scopes teardown to the eval host's egress interface.
    if matches!(state, GateState::Sealed | GateState::Cut) {
        // `pfctl -F states` flushes the whole state table and exits 0 on success. On SEAL the
        // teardown MUST succeed (nonzero exit ⇒ we cannot vouch the OPEN-era flows are gone) before
        // evaluation is allowed — check the EXIT STATUS, not merely that the subprocess ran (Codex
        // end-of-P1 #2). On CUT it is best-effort (we are already tearing the run down).
        let mk = || { let mut c = Command::new("/sbin/pfctl"); c.args(["-q", "-F", "states"]); c };
        if state == GateState::Sealed {
            run_ok_t(mk(), "pf flush states on seal", 5)?;
        } else {
            let _ = output_bounded(mk(), 5);
        }
    }
    info!(?state, "gate set");
    Ok(())
}

/// (state as read back from pf, blocked packet count for the bypass label)
fn gate_observe() -> (GateState, Option<u64>) {
    let rules = match run_ok({ let mut c = Command::new("/sbin/pfctl"); c.args(["-a", "deadswitch", "-sr"]); c }, "pfctl -sr") {
        Ok(s) => s,
        Err(_) => return (GateState::Unknown, None),
    };
    let has_pass_all = rules.lines().any(|l| l.starts_with("pass out quick all"));
    let has_pass_hostd = rules.lines().any(|l| l.starts_with("pass out quick") && l.contains(&HOSTD_PORT.to_string()));
    let has_block = rules.lines().any(|l| l.starts_with("block drop out log quick all"));
    // Rules present but pf disabled ⇒ NOT effectively enforcing ⇒ Unknown (never reported healthy).
    let state = if !pf_enabled() {
        GateState::Unknown
    } else {
        match (has_pass_all, has_pass_hostd, has_block) {
            (true, _, _) => GateState::Open,
            (false, true, true) => GateState::Sealed,
            (false, false, true) => GateState::Cut,
            _ => GateState::Unknown,
        }
    };
    let labels = run_ok({ let mut c = Command::new("/sbin/pfctl"); c.args(["-a", "deadswitch", "-sl"]); c }, "pfctl -sl").unwrap_or_default();
    let packets = labels.lines().find(|l| l.starts_with("deadswitch_bypass")).and_then(|l| l.split_whitespace().nth(2)).and_then(|n| n.parse().ok());
    (state, packets)
}

fn pid_start_time(pid: u32) -> Option<u64> {
    let out = Command::new("/bin/ps").args(["-o", "lstart=", "-p", &pid.to_string()]).output().ok()?;
    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if s.is_empty() {
        return None;
    }
    // stable enough as an incarnation component: hash of the ps start string
    Some(u64::from_str_radix(&sha256_hex(s.as_bytes())[..15], 16).ok()?)
}

fn observe_vm2(instance: &str, template_digest: &str, base_image_digest: &str) -> Vm2Obs {
    let mut o = Vm2Obs { instance: instance.into(), template_digest: template_digest.into(), base_image_digest: base_image_digest.into(), ..Default::default() };
    let Ok(list) = lima_list() else { return o };
    let Some(i) = list.into_iter().find(|i| i.name == instance) else {
        o.running = Some(false);
        return o;
    };
    let pid = std::fs::read_to_string(Path::new(&i.dir).join("vz.pid")).ok().and_then(|s| s.trim().parse::<u32>().ok());
    let alive = pid.map(|p| Path::new(&format!("/proc/{p}")).exists() || Command::new("/bin/kill").args(["-0", &p.to_string()]).status().map(|s| s.success()).unwrap_or(false)).unwrap_or(false);
    o.running = Some(i.status == "Running" && alive);
    o.pid = pid;
    o.started_at = pid.and_then(pid_start_time);
    // We have the instance config object here, so absent list fields mean "none configured" = 0
    // (Some(0)), NOT "unobservable" (None). None is reserved for a field type we truly cannot read.
    let have_config = i.config.is_object();
    o.nested_virt = i.config.get("nestedVirtualization").and_then(|v| v.as_bool()).or(if have_config { Some(false) } else { None });
    o.port_forwards = if have_config {
        Some(i.config.get("portForwards").and_then(|v| v.as_array()).map(|a| a.iter().filter(|r| !r.get("ignore").and_then(|x| x.as_bool()).unwrap_or(false)).count() as u32).unwrap_or(0))
    } else { None };
    o.writable_mounts = if have_config {
        Some(i.config.get("mounts").and_then(|v| v.as_array()).map(|a| a.iter().filter(|m| m.get("writable").and_then(|x| x.as_bool()).unwrap_or(false)).count() as u32).unwrap_or(0))
    } else { None };
    o
}

fn incarnation_of(instance: &str, obs: &Vm2Obs) -> String {
    sha256_hex(format!("{}|{}|{}|{}", instance, obs.started_at.unwrap_or(0), obs.template_digest, obs.base_image_digest).as_bytes())
}

/// stop -f, delete, confirm. Returns latency. Confirmation requires the recorded VMM pid to be gone
/// AND the instance/dir gone — an unavailable pid is NOT treated as "gone" (Codex end-of-P1 #1).
/// All subprocess calls are bounded so a wedged limactl cannot hang the kill path.
fn destroy_instance(instance: &str, pid: Option<u32>) -> anyhow::Result<Instant> {
    // SIGKILL the recorded VMM pid FIRST — before the (possibly slow) pf anchor reload or any
    // limactl — so process containment never waits on CLI work (Codex end-of-P1 #1). Without a pid
    // we cannot confirm termination at all — a hard failure, never "assumed gone". Returns the
    // Instant of confirmed VMM death, so the caller measures the containment window ending exactly
    // there (not at cleanup/notify).
    let Some(p) = pid else {
        return Err(anyhow!("cannot confirm termination of {instance}: no VMM pid recorded"));
    };
    let mut death = None;
    for _ in 0..50 {
        let _ = Command::new("/bin/kill").args(["-9", &p.to_string()]).status();
        if !pid_alive(p) {
            death = Some(Instant::now());
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let Some(death) = death else {
        return Err(anyhow!("VMM pid {p} for {instance} did not die under SIGKILL"));
    };
    // VMM dead (a dead process cannot egress). Now cut the gate (bounded pf reload) and tear down the
    // instance/disk — both off the containment-critical path — requiring the disk dir removed.
    let _ = gate_set(GateState::Cut);
    let _ = run_ok_t({ let mut c = lima(); c.args(["stop", "-f", instance]); c }, "limactl stop", 10);
    for _ in 0..10 {
        let _ = run_ok_t({ let mut c = lima(); c.args(["delete", "-f", instance]); c }, "limactl delete", 10);
        if !Path::new(LIMA_HOME).join(instance).exists() {
            return Ok(death);
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(anyhow!("VMM {p} killed (contained) but instance {instance} disk dir not removed"))
}

// ------------------------------------------------------------------ run state

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum HostRunState {
    Starting,
    Prestage,
    Eval,
    Destroying,
    Terminated,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct HostRunRecord {
    run_id: String,
    instance: String,
    incarnation: String,
    state: HostRunState,
    /// VMM (vz) pid captured at creation — termination is confirmed against THIS exact pid.
    vz_pid: Option<u32>,
    lease_high_water: u64,
    lease_wall_deadline: u64,
    epoch: u64,
    reasons: Vec<String>,
    destroy_latency_ms: Option<u64>,
}

/// Independent-watchdog handoff file. `run` refreshes it on every renewal; the always-on `guard`
/// daemon reads it and destroys VM2 if the run process dies, the lease expires, or it goes stale —
/// so `kill -9 hostd(run)` cannot leave VM2 alive (Codex end-of-P1 #1).
#[derive(Clone, Debug, Serialize, Deserialize)]
struct ActiveLease {
    instance: String,
    incarnation: String,
    vz_pid: Option<u32>,
    wall_deadline: u64,
    run_pid: u32,
    updated_at: u64,
}
fn active_path() -> PathBuf {
    Path::new(STATE_DIR).join("active.json")
}

struct Live {
    deadline: Option<Deadline>,
    /// wall+mono instant of the last accepted lease renewal — the containment bound is measured from
    /// here (last moment authority was refreshed) to confirmed VMM death, so a stalled DETECTION is
    /// included, not excluded (Codex end-of-P1 #1).
    last_lease_at: Option<Instant>,
    lease_signed: Option<Signed>,
    gate: GateState,
    last_report: Option<UntrustedReport>,
    report_seq: u64,
    prestage_done: bool,
    log_seq_expected: u64,
    log_tokens: f64,
    log_last: Instant,
    log_dropped: u64,
    chokepoint: ChokepointObs,
    destroy_reason: Option<String>,
}

struct App {
    run_id: String,
    instance: String,
    incarnation: String,
    token: String,
    key: SigningKey,
    controller: String,
    controller_pk: VerifyingKey,
    model: String,
    ollama: String,
    http: reqwest::Client,
    record_path: PathBuf,
    evidence: evidence::EvidenceStore,
    live: Mutex<Live>,
    record: Mutex<HostRunRecord>,
    ollama_sem: tokio::sync::Semaphore,
    /// bounds total concurrent VM2-facing requests (shed when exhausted; Codex end-of-P1 #6)
    admission: tokio::sync::Semaphore,
    /// fires `true` once the run is terminating, so an in-flight chokepoint request awaiting the
    /// backend is cancelled rather than completing after authority is gone (Codex end-of-P1 #4).
    cancel_tx: tokio::sync::watch::Sender<bool>,
}

impl App {
    fn persist(&self) -> anyhow::Result<()> {
        atomic_write_json(&self.record_path, &*self.record.lock().unwrap())
    }
    fn evidence_append(&self, kind: &str, data: serde_json::Value) {
        let line = serde_json::json!({"ts": now_unix(), "src": "hostd", "kind": kind, "data": data});
        // Fail-closed on lost mandatory evidence: if the store is over quota, on a different device,
        // or unwritable, trip the run rather than silently dropping (Codex end-of-P1 #6). fsync so a
        // crash cannot lose the tail. Does NOT hold the `live` mutex (the watchdog needs it).
        // Aggregate budget across the whole evidence directory, not just this run's file (Codex
        // end-of-P1 #6): a compromised VM2 must not be able to fill the trusted store via any path.
        // append releases its evidence-only lock before reporting failure; request_destroy may
        // then take `live`. Concurrent log/inference writers cannot interleave JSON or race quota.
        if let Err(e) = self.evidence.append(&line) {
            self.request_destroy(&format!("evidence store failure: {e}"));
        }
    }
    fn request_destroy(&self, reason: &str) {
        let mut l = self.live.lock().unwrap();
        if l.destroy_reason.is_none() {
            warn!(reason, "destroy requested");
            l.destroy_reason = Some(reason.into());
        }
        drop(l);
        // Signal in-flight chokepoint work to cancel; the watch is independent of `live`.
        let _ = self.cancel_tx.send(true);
    }
    fn signed<T: Serialize>(&self, v: &T) -> Signed {
        Signed::sign(&self.key, "hostd", v)
    }
}

fn check_token(app: &App, h: &HeaderMap) -> Result<(), (StatusCode, String)> {
    let ok = h.get("authorization").and_then(|v| v.to_str().ok()).map(|v| v.strip_prefix("Bearer ").unwrap_or("") == app.token).unwrap_or(false);
    if ok { Ok(()) } else { Err((StatusCode::UNAUTHORIZED, "bad token".into())) }
}

// ------------------------------------------------------------------ VM2-facing HTTP (untrusted peer)

/// Admission control for every VM2-facing request: shed immediately when 8 are already in flight
/// (bounds waiting work — no queue), and cap total handler time incl. body read (Codex end-of-P1
/// #6). The connection count is separately capped by `CappedListener`.
async fn admission(
    State(app): State<Arc<App>>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let Ok(_permit) = app.admission.try_acquire() else {
        return (StatusCode::SERVICE_UNAVAILABLE, "overloaded").into_response();
    };
    match tokio::time::timeout(Duration::from_secs(75), next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => (StatusCode::GATEWAY_TIMEOUT, "request timeout").into_response(),
    }
}

#[derive(Serialize)]
struct LeaseView {
    run_id: String,
    epoch: u64,
    gate: GateState,
    lease: Option<Signed>,
    controller_pubkey: String,
}

async fn get_lease(State(app): State<Arc<App>>, h: HeaderMap) -> Result<Json<LeaseView>, (StatusCode, String)> {
    check_token(&app, &h)?;
    let l = app.live.lock().unwrap();
    let expired = l.deadline.as_ref().map(|d| d.expired(now_unix())).unwrap_or(true);
    let view = LeaseView {
        run_id: app.run_id.clone(),
        epoch: l.deadline.as_ref().map(|d| d.epoch).unwrap_or(0),
        gate: l.gate,
        lease: if expired || l.destroy_reason.is_some() { None } else { l.lease_signed.clone() },
        controller_pubkey: hex::encode(app.controller_pk.to_bytes()),
    };
    Ok(Json(view))
}

async fn post_report(State(app): State<Arc<App>>, h: HeaderMap, body: axum::body::Bytes) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    check_token(&app, &h)?;
    if body.len() > MAX_MSG_BYTES {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "report too large".into()));
    }
    let rep: Vm2Report = serde_json::from_slice(&body).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let (rep_seq, rep_run) = (rep.seq, rep.run_id.clone());
    // NEVER call evidence_append while holding `live`: evidence_append may request_destroy, which
    // re-locks `live` — a std Mutex is not reentrant, so that self-deadlocks (Codex end-of-P1 #6,
    // reproduced via duplicate reports at quota). Compute under the lock, append after dropping it.
    let ok_vals = {
        let mut l = app.live.lock().unwrap();
        if rep.run_id != app.run_id || (rep.seq <= l.report_seq && l.report_seq != 0) {
            None
        } else {
            l.report_seq = rep.seq;
            let phase = rep.phase.clone();
            l.last_report = Some(UntrustedReport { received_at: now_unix(), digest: sha256_hex(&body), body: rep });
            Some((rep_seq, phase))
        }
    };
    match ok_vals {
        Some((seq, phase)) => {
            app.evidence_append("vm2_report_ok", serde_json::json!({"seq": seq, "phase": phase}));
            Ok(Json(serde_json::json!({"ok": true})))
        }
        None => {
            app.evidence_append("vm2_report_rejected", serde_json::json!({"seq": rep_seq, "run_id": rep_run}));
            Err((StatusCode::CONFLICT, "wrong run or non-monotonic seq".into()))
        }
    }
}

async fn post_log(State(app): State<Arc<App>>, h: HeaderMap, body: axum::body::Bytes) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    check_token(&app, &h)?;
    if body.len() > LOG_MAX_BYTES {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "log event too large".into()));
    }
    let ev: LogEvent = serde_json::from_slice(&body).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let mut l = app.live.lock().unwrap();
    // token bucket: LOG_RATE_PER_S
    let dt = l.log_last.elapsed().as_secs_f64();
    l.log_last = Instant::now();
    l.log_tokens = (l.log_tokens + dt * LOG_RATE_PER_S as f64).min(LOG_RATE_PER_S as f64);
    if l.log_tokens < 1.0 {
        l.log_dropped += 1;
        return Err((StatusCode::TOO_MANY_REQUESTS, "rate limited".into()));
    }
    l.log_tokens -= 1.0;
    // Capture the gap under the lock but append AFTER dropping it: evidence_append can
    // request_destroy → re-lock `live` (non-reentrant self-deadlock; Codex end-of-P1 #6, reproduced
    // via a log-sequence gap at quota).
    let gap = if ev.seq != l.log_seq_expected { Some((l.log_seq_expected, ev.seq)) } else { None };
    l.log_seq_expected = ev.seq + 1;
    drop(l);
    if let Some((expected, got)) = gap {
        app.evidence_append("vm2_log_gap", serde_json::json!({"expected": expected, "got": got}));
    }
    app.evidence_append("vm2_log", serde_json::to_value(&ev).unwrap());
    Ok(Json(serde_json::json!({"ok": true})))
}

async fn post_defender(State(app): State<Arc<App>>, h: HeaderMap, Json(a): Json<DefenderAction>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    check_token(&app, &h)?;
    app.evidence_append("defender_action", serde_json::to_value(&a).unwrap());
    let body = serde_json::json!({"run_id": app.run_id, "incarnation": app.incarnation, "action": a});
    let r = app.http.post(format!("{}/defender", app.controller)).json(&body).send().await;
    match r {
        Ok(resp) if resp.status().is_success() => Ok(Json(serde_json::json!({"ok": true}))),
        Ok(resp) => Err((StatusCode::BAD_GATEWAY, format!("controller: {}", resp.status()))),
        Err(e) => Err((StatusCode::BAD_GATEWAY, e.to_string())),
    }
}

#[derive(Deserialize)]
struct PrestageDone {
    manifest_digest: String,
    image_digest: String,
}

async fn post_prestage_done(State(app): State<Arc<App>>, h: HeaderMap, Json(p): Json<PrestageDone>) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    check_token(&app, &h)?;
    app.evidence_append("prestage_done", serde_json::json!({"manifest_digest": p.manifest_digest, "image_digest": p.image_digest}));
    app.live.lock().unwrap().prestage_done = true;
    Ok(Json(serde_json::json!({"ok": true})))
}

/// Inference chokepoint (Phase 1 stand-in for the off-host chokepoint). Exactly one operation.
async fn chat(State(app): State<Arc<App>>, h: HeaderMap, body: axum::body::Bytes) -> Result<(StatusCode, Json<serde_json::Value>), (StatusCode, String)> {
    check_token(&app, &h)?;
    let deny = |app: &App, why: &str| {
        app.live.lock().unwrap().chokepoint.denied += 1;
        app.evidence_append("chokepoint_denied", serde_json::json!({"why": why}));
        Err((StatusCode::FORBIDDEN, why.to_string()))
    };
    if body.len() > MAX_MSG_BYTES {
        return deny(&app, "body too large");
    }
    let Ok(v) = serde_json::from_slice::<serde_json::Value>(&body) else { return deny(&app, "not json") };
    let Some(obj) = v.as_object() else { return deny(&app, "not an object") };
    if obj.get("model").and_then(|m| m.as_str()) != Some(app.model.as_str()) {
        return deny(&app, "model not pinned");
    }
    for k in ["tools", "functions", "tool_choice", "function_call", "response_format"] {
        if obj.contains_key(k) {
            return deny(&app, "tool/function fields not allowed");
        }
    }
    if obj.get("n").and_then(|n| n.as_u64()).unwrap_or(1) != 1 {
        return deny(&app, "n must be 1");
    }
    // max_tokens must be a non-negative integer ≤ 1024 (reject -1 etc.; see gateway note).
    let max_tokens = match obj.get("max_tokens") {
        None => 512u64,
        Some(mt) => match mt.as_u64() {
            Some(n) if n <= 1024 => n,
            _ => return deny(&app, "max_tokens must be an integer in [0,1024]"),
        },
    };
    // Rebuild `messages` from scratch as strictly {role, content:String}; a message carrying any
    // other field is rejected, not forwarded.
    let Some(in_msgs) = obj.get("messages").and_then(|m| m.as_array()).filter(|a| !a.is_empty()) else {
        return deny(&app, "messages required");
    };
    let mut messages = Vec::with_capacity(in_msgs.len());
    for m in in_msgs {
        match (m.get("role").and_then(|r| r.as_str()), m.get("content").and_then(|c| c.as_str())) {
            (Some(role), Some(content)) if matches!(role, "system" | "user" | "assistant" | "tool") => {
                messages.push(serde_json::json!({"role": role, "content": content}));
            }
            _ => return deny(&app, "each message must be {role, content:string} with a known role"),
        }
    }
    // Construct a FRESH backend request containing only allowed fields. We do NOT forward the
    // client's JSON: Ollama's Go decoder case-folds field names (e.g. `max_tokenſ` → `max_tokens`),
    // so any preserved extra field could re-set the generation cap — a real bypass (Codex end-of-P1
    // #5, backend field-name interpretation). Sending to the native `/api/chat` API is where
    // `options.num_ctx`/`num_predict` are actually honored; the OpenAI-compat `/v1` endpoint ignores
    // `options`, so the advertised context cap was ineffective there.
    let backend = serde_json::json!({
        "model": app.model,
        "messages": messages,
        "stream": false,
        "options": {"num_ctx": 4096, "num_predict": max_tokens},
    });
    let active = |app: &App| {
        let l = app.live.lock().unwrap();
        !(l.deadline.as_ref().map(|d| d.expired(now_unix())).unwrap_or(true) || l.destroy_reason.is_some() || l.deadline.as_ref().map(|d| d.epoch).unwrap_or(0) < 1)
    };
    // active lease required at dispatch time (bind review to execution)
    if !active(&app) {
        return deny(&app, "no active eval lease");
    }
    let _permit = app.ollama_sem.acquire().await.map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "closed".to_string()))?;
    // re-check AFTER acquiring the permit: a queued request must not dispatch once its authority has
    // expired or the run is terminating while it waited (Codex end-of-P1 #4).
    if !active(&app) {
        return deny(&app, "lease expired while queued");
    }
    // Subscribe to the cancel signal BEFORE the final checks so a request_destroy that fires from
    // here on cannot be missed; the watch retains its latest value, so we also read it directly with
    // borrow() rather than only awaiting a change (Codex end-of-P1 #4, missed-notification window).
    let mut cancel = app.cancel_tx.subscribe();
    app.live.lock().unwrap().chokepoint.inference_requests += 1;
    app.evidence_append("chokepoint_forward", serde_json::json!({"digest": sha256_hex(&body)}));
    // The forward-evidence append can itself trip the run (evidence over quota → request_destroy).
    // Deny if the run is no longer active OR the cancel signal is already set.
    if !active(&app) || *cancel.borrow() {
        return deny(&app, "run terminating before dispatch");
    }
    // Cover the WHOLE backend exchange — send AND response-body collection — with the cancel select,
    // so termination DURING body read still cancels (dropping the future aborts the request) rather
    // than completing with backend content after authority is gone (Codex end-of-P1 #3, reproduced).
    let ollama = app.ollama.clone();
    let http = app.http.clone();
    let fetch = async move {
        let resp = http.post(format!("{ollama}/api/chat")).timeout(Duration::from_secs(60)).json(&backend).send().await?;
        let st = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
        let native = resp.json::<serde_json::Value>().await.unwrap_or(serde_json::json!({"error": "bad upstream body"}));
        Ok::<_, reqwest::Error>((st, native))
    };
    let (st, native) = tokio::select! {
        r = fetch => match r { Ok(v) => v, Err(e) => return Err((StatusCode::BAD_GATEWAY, e.to_string())) },
        _ = cancel.changed() => return deny(&app, "run terminated; in-flight inference cancelled"),
    };
    // tokio::select! is NOT fair: it may pick a ready `fetch` even when cancellation is also ready.
    // Fence the RESPONSE with a final authority check before returning any backend content, so a
    // request that completed just as the run terminated is withheld (Codex end-of-P1 #3, reproduced).
    if !active(&app) || *cancel.borrow() {
        return deny(&app, "run terminated during inference; response withheld");
    }
    // Map Ollama /api/chat → OpenAI chat.completion shape (the harness reads choices[0].message.content).
    let content = native.pointer("/message/content").and_then(|c| c.as_str()).unwrap_or("");
    let mapped = serde_json::json!({
        "id": format!("chatcmpl-{}", &sha256_hex(&body)[..24]),
        "object": "chat.completion",
        "model": app.model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": native.get("done_reason").and_then(|d| d.as_str()).unwrap_or("stop")}],
        "usage": {"prompt_tokens": native.get("prompt_eval_count").and_then(|n| n.as_u64()).unwrap_or(0), "completion_tokens": native.get("eval_count").and_then(|n| n.as_u64()).unwrap_or(0)}
    });
    Ok((st, Json(mapped)))
}

// ------------------------------------------------------------------ controller-facing loops

async fn renew_lease(app: &App) {
    let (epoch, gate) = {
        let l = app.live.lock().unwrap();
        let want = if l.prestage_done { 1 } else { 0 };
        (want, l.gate)
    };
    // sealing must precede the eval lease
    if epoch >= 1 && gate != GateState::Sealed {
        match gate_set(GateState::Sealed) {
            Ok(()) => {
                app.live.lock().unwrap().gate = GateState::Sealed;
                app.evidence_append("gate", serde_json::json!({"state": "sealed"}));
            }
            Err(e) => {
                app.request_destroy(&format!("cannot seal gate: {e}"));
                return;
            }
        }
    }
    let gate = gate_observe().0;
    let req = LeaseRequest { v: PROTO_V, kind: "lease_request".into(), run_id: app.run_id.clone(), aud: AUD_CONTROLLER.into(), incarnation: app.incarnation.clone(), issued_at: now_unix(), epoch, gate };
    let resp = app.http.post(format!("{}/lease", app.controller)).json(&app.signed(&req)).send().await;
    let resp = match resp {
        Ok(r) if r.status().is_success() => r.json::<LeaseResponse>().await,
        Ok(r) => {
            warn!(status = %r.status(), "lease request refused");
            return;
        }
        Err(e) => {
            warn!(error = %e, "controller unreachable; lease will expire");
            return;
        }
    };
    match resp {
        Ok(LeaseResponse::Granted { lease }) => {
            let hw = app.record.lock().unwrap().lease_high_water;
            match lease.verify::<Lease>(&app.controller_pk, "lease", AUD_HOSTD) {
                Ok(l) if l.run_id == app.run_id && l.incarnation == app.incarnation => match Deadline::accept(&l, hw, now_unix()) {
                    Ok(d) => {
                        {
                            let mut r = app.record.lock().unwrap();
                            r.lease_high_water = l.fencing_token;
                            r.lease_wall_deadline = d.wall;
                            r.epoch = l.epoch;
                            if l.epoch >= 1 && r.state == HostRunState::Prestage {
                                r.state = HostRunState::Eval;
                            }
                        }
                        if let Err(e) = app.persist() {
                            app.request_destroy(&format!("cannot persist lease: {e}"));
                            return;
                        }
                        let mut live = app.live.lock().unwrap();
                        live.deadline = Some(d);
                        live.last_lease_at = Some(Instant::now());
                        live.lease_signed = Some(lease);
                    }
                    Err(e) => {
                        app.evidence_append("lease_rejected", serde_json::json!({"why": e}));
                        warn!(why = %e, "lease rejected");
                    }
                },
                Ok(_) => app.evidence_append("lease_rejected", serde_json::json!({"why": "wrong run/incarnation"})),
                Err(e) => app.evidence_append("lease_rejected", serde_json::json!({"why": e.to_string()})),
            }
        }
        Ok(LeaseResponse::Denied { order, reason }) => {
            let hw = app.record.lock().unwrap().lease_high_water;
            match order.verify::<Order>(&app.controller_pk, "order", AUD_HOSTD) {
                Ok(o) if o.run_id == app.run_id && o.fencing_token > hw => {
                    app.evidence_append("order", serde_json::to_value(&o).unwrap());
                    app.request_destroy(&format!("controller order {:?}: {reason}", o.order));
                }
                _ => {
                    // an unverifiable denial is still a denial: the lease is simply not renewed
                    app.evidence_append("lease_denied_unverified", serde_json::json!({"reason": reason}));
                }
            }
        }
        Err(e) => warn!(error = %e, "bad lease response"),
    }
}

async fn answer_challenge(app: &App, template_digest: &str, base_digest: &str) {
    let body = serde_json::json!({"run_id": app.run_id, "incarnation": app.incarnation});
    let ch = match app.http.post(format!("{}/challenge", app.controller)).json(&body).send().await {
        Ok(r) if r.status().is_success() => r.json::<Signed>().await.ok(),
        Ok(r) => {
            let st = r.status();
            let txt = r.text().await.unwrap_or_default();
            warn!(status = %st, txt, "challenge refused");
            if st == StatusCode::CONFLICT {
                app.request_destroy(&format!("controller refused challenge: {txt}"));
            }
            None
        }
        Err(e) => {
            warn!(error = %e, "challenge: controller unreachable");
            None
        }
    };
    let Some(ch) = ch else { return };
    let ch = match ch.verify::<Challenge>(&app.controller_pk, "challenge", AUD_HOSTD) {
        Ok(c) if c.run_id == app.run_id && c.incarnation == app.incarnation && now_unix().abs_diff(c.issued_at) <= CLOCK_SKEW_S => c,
        other => {
            app.evidence_append("challenge_rejected", serde_json::json!({"why": format!("{other:?}")}));
            return;
        }
    };
    // Observe. Everything below is hostd's own observation.
    let vm2 = observe_vm2(&app.instance, template_digest, base_digest);
    let (gstate, bypass) = gate_observe();
    let (watchdog, chokepoint, report) = {
        let l = app.live.lock().unwrap();
        (
            WatchdogObs { lease_token: l.deadline.as_ref().map(|d| d.fencing_token).unwrap_or(0), deadline_remaining_ms: l.deadline.as_ref().map(|d| d.remaining_ms(now_unix())).unwrap_or(-1) },
            l.chokepoint.clone(),
            l.last_report.clone(),
        )
    };
    let ev = HostEvidence {
        v: PROTO_V,
        kind: "host_evidence".into(),
        run_id: app.run_id.clone(),
        aud: AUD_CONTROLLER.into(),
        incarnation: app.incarnation.clone(),
        nonce: ch.nonce,
        measured_at: now_unix(),
        vm2,
        gate: GateObs { state: gstate, bypass_packets: bypass },
        watchdog,
        chokepoint,
        untrusted_vm2_report: report,
    };
    match app.http.post(format!("{}/evidence", app.controller)).json(&app.signed(&ev)).send().await {
        Ok(r) if r.status().is_success() => {
            if let Ok(j) = r.json::<serde_json::Value>().await {
                if j["healthy"].as_bool() != Some(true) {
                    let reason = j["reason"].as_str().unwrap_or("controller unhealthy verdict").to_string();
                    app.evidence_append("evidence_verdict", j.clone());
                    app.request_destroy(&format!("evidence verdict: {reason}"));
                }
            }
        }
        Ok(r) => warn!(status = %r.status(), "evidence refused"),
        Err(e) => warn!(error = %e, "evidence: controller unreachable"),
    }
}

async fn do_destroy(app: &App, reason: &str) -> anyhow::Result<Instant> {
    let start = Instant::now();
    // Set destroy_reason FIRST so any queued/in-flight chokepoint request that re-checks the lease
    // after this point is denied (Codex end-of-P1 #4) — fence dispatch before tearing down.
    app.request_destroy(reason);
    {
        let mut r = app.record.lock().unwrap();
        r.state = HostRunState::Destroying;
        r.reasons.push(reason.into());
    }
    let _ = app.persist();
    app.evidence_append("destroy_begin", serde_json::json!({"reason": reason}));
    // Prefer the pid captured at creation (confirm against the exact VMM), fall back to observation.
    let pid = app.record.lock().unwrap().vz_pid.or_else(|| observe_vm2(&app.instance, "", "").pid);
    let mut death = None;
    for attempt in 1..=30 {
        match destroy_instance(&app.instance, pid) {
            Ok(d) => {
                death = Some(d);
                break;
            }
            Err(e) => {
                error!(attempt, error = %e, "destroy failed; retrying (gate stays cut)");
                app.evidence_append("destroy_retry", serde_json::json!({"attempt": attempt, "error": e.to_string()}));
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    let Some(death) = death else {
        error!("VM2 could not be confirmed destroyed after 30 attempts; alarm");
        app.evidence_append("destroy_unconfirmed", serde_json::json!({}));
        // Propagate: the caller must NOT disarm the cleanup guard or claim containment complete
        // (Codex end-of-P1 #1). The gate stays cut.
        return Err(anyhow!("VM2 {} termination not confirmed", app.instance));
    };
    // Latency to CONFIRMED VMM DEATH (not to cleanup/notify): death − destroy start.
    let lat_ms = death.saturating_duration_since(start).as_millis() as u64;
    {
        let mut r = app.record.lock().unwrap();
        r.state = HostRunState::Terminated;
        r.destroy_latency_ms = Some(lat_ms);
    }
    let _ = app.persist();
    app.evidence_append("destroy_confirmed", serde_json::json!({"latency_ms": lat_ms}));
    info!(latency_ms = lat_ms, "VM2 destroyed and confirmed");
    let t = serde_json::json!({"v": PROTO_V, "type": "terminated", "run_id": app.run_id, "aud": AUD_CONTROLLER, "incarnation": app.incarnation, "issued_at": now_unix(), "latency_ms": lat_ms});
    let _ = app.http.post(format!("{}/terminated", app.controller)).json(&app.signed(&t)).send().await;
    Ok(death)
}

// ------------------------------------------------------------------ commands

// ------------------------------------------------------------------ connection-capped listener

/// Bounds concurrent connections to the trusted VM2-facing service: `accept()` waits for a
/// semaphore permit and ties it to the accepted connection's lifetime, so the compromised VM2 (the
/// only client) cannot open unbounded sockets (Codex end-of-P1 #6).
struct CappedListener {
    inner: tokio::net::TcpListener,
    sem: Arc<tokio::sync::Semaphore>,
}
impl CappedListener {
    async fn bind(addr: (&str, u16), max_conns: usize) -> std::io::Result<Self> {
        Ok(CappedListener { inner: tokio::net::TcpListener::bind(addr).await?, sem: Arc::new(tokio::sync::Semaphore::new(max_conns)) })
    }
}
impl axum::serve::Listener for CappedListener {
    type Io = CappedStream;
    type Addr = std::net::SocketAddr;
    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let permit = self.sem.clone().acquire_owned().await.expect("connection semaphore never closed");
            match self.inner.accept().await {
                Ok((stream, addr)) => return (CappedStream { inner: stream, _permit: permit }, addr),
                Err(_) => {
                    drop(permit);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    }
    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

/// A TcpStream that releases its connection permit when dropped (i.e. when the connection closes).
struct CappedStream {
    inner: tokio::net::TcpStream,
    _permit: tokio::sync::OwnedSemaphorePermit,
}
impl AsyncRead for CappedStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for CappedStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, buf: &[u8]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
    fn poll_write_vectored(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>, bufs: &[std::io::IoSlice<'_>]) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

fn keygen() -> anyhow::Result<()> {
    let p = Path::new(STATE_DIR).join("keys/hostd.key");
    std::fs::create_dir_all(p.parent().unwrap())?;
    let k = if p.exists() { key_from_hex(&std::fs::read_to_string(&p)?)? } else {
        let k = SigningKey::generate(&mut rand::rngs::OsRng);
        std::fs::write(&p, hex::encode(k.to_bytes()))?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600))?;
        k
    };
    println!("{}", pubkey_hex(&k));
    Ok(())
}

/// Destroys the instance on drop unless disarmed — guarantees cleanup on ANY early return from
/// run() after the clone (enroll failure, lease failure, panic) so VM2 never leaks with an open
/// gate (Codex end-of-P1 #1).
struct InstanceGuard {
    instance: String,
    pid: Option<u32>,
    armed: bool,
}
impl Drop for InstanceGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = gate_set(GateState::Cut);
            // Resolve the VMM pid WITHOUT depending on `limactl` enumeration (which may be the very
            // thing that is broken): the instance dir's vz.pid file, then the durable handoff (Codex
            // end-of-P1 #1).
            let pid = self.pid
                .or_else(|| std::fs::read_to_string(Path::new(LIMA_HOME).join(&self.instance).join("vz.pid")).ok().and_then(|s| s.trim().parse().ok()))
                .or_else(|| read_json::<ActiveLease>(&active_path()).ok().flatten().and_then(|a| a.vz_pid));
            // Remove the durable handoff ONLY on a confirmed teardown; on failure keep it so the
            // always-on guard daemon keeps retrying (do not orphan the instance).
            match destroy_instance(&self.instance, pid) {
                Ok(_) => {
                    let _ = std::fs::remove_file(active_path());
                }
                Err(e) => {
                    error!(instance = %self.instance, error = %e, "InstanceGuard cleanup unconfirmed; keeping handoff for the guard daemon");
                }
            }
        }
    }
}

/// Exclusive host-gate ownership: only one run may drive the single pf gate at a time. Held by an
/// OS-level `flock(LOCK_EX)` on the lock file, taken atomically in the kernel — no check-then-write
/// TOCTOU, so two runs cannot both acquire it (Codex end-of-P1 #2, reproduced with the old code).
/// The kernel releases the lock automatically when the fd closes (normal exit OR crash/SIGKILL), so
/// there is no stale-pid to reclaim; the file content is a diagnostic owner pid only.
struct RunLock {
    path: PathBuf,
    _file: std::fs::File,
}
impl RunLock {
    fn acquire() -> anyhow::Result<RunLock> {
        use std::io::Write;
        use std::os::unix::io::AsRawFd;
        const LOCK_EX: i32 = 2;
        const LOCK_NB: i32 = 4;
        let path = Path::new(STATE_DIR).join("run.lock");
        let mut file = std::fs::OpenOptions::new().create(true).read(true).write(true).open(&path)?;
        let rc = unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) };
        anyhow::ensure!(rc == 0, "another run holds the host gate; one run per host");
        let _ = file.set_len(0);
        let _ = write!(file, "{}", std::process::id());
        Ok(RunLock { path, _file: file })
    }
}
impl Drop for RunLock {
    fn drop(&mut self) {
        // Do NOT unlink the lock file: closing `_file` (implicit) releases the kernel flock, which is
        // enough. Unlinking would let a contender that already opened the OLD inode hold a lock on it
        // while a new run creates+locks a NEW inode — two simultaneous "exclusive" owners on
        // different inodes (Codex end-of-P1 #2). Keeping one persistent inode makes flock authoritative.
        let _ = &self.path; // retained intentionally
    }
}

/// Independent watchdog daemon. Fail-closed: destroys any eval VM2 that is not covered by a fresh,
/// live active-lease handoff from a running `run` process.
fn guard() -> anyhow::Result<()> {
    info!("guard daemon up");
    loop {
        let active: Option<ActiveLease> = read_json(&active_path()).ok().flatten();
        // FAST PATH (Codex end-of-P1 #1): if the handoff names a run that is dead or whose lease has
        // expired, SIGKILL its recorded VMM pid IMMEDIATELY — before the (up-to-15s) enumeration or
        // any pf reload — so the containment latency is bounded by the 1s tick, not by CLI work. The
        // confirmed teardown (gate cut + delete + confirm) follows via destroy_instance.
        if let Some(a) = &active {
            if !(pid_alive(a.run_pid) && now_unix() < a.wall_deadline) {
                if let Some(vz) = a.vz_pid {
                    if pid_alive(vz) {
                        warn!(instance = %a.instance, vz, "guard: handoff run dead/expired — immediate SIGKILL of the VMM");
                        let _ = Command::new("/bin/kill").args(["-9", &vz.to_string()]).status();
                    }
                }
            }
        }
        // Enumerate, THEN read the clock (a clock captured before the up-to-15s enumeration would be
        // stale, letting a just-expired lease read as still-covered). A handoff covers an instance
        // iff a live run owns THIS exact instance with time left. destroy_instance cuts the gate
        // itself AFTER killing, so we do not do a pre-kill pf reload here.
        let listed = lima_list();
        let now = now_unix();
        let covered = |name: &str| matches!(&active, Some(a) if a.instance == name && pid_alive(a.run_pid) && now < a.wall_deadline);
        match listed {
            Ok(list) => {
                for i in list.into_iter().filter(|i| i.name.starts_with("vm2-") && i.name != BASE_INSTANCE) {
                    if !covered(&i.name) {
                        warn!(instance = %i.name, ?active, "guard: eval VM2 without a live lease handoff — destroying");
                        let pid = std::fs::read_to_string(Path::new(&i.dir).join("vz.pid")).ok().and_then(|s| s.trim().parse().ok())
                            .or_else(|| active.as_ref().and_then(|a| a.vz_pid));
                        if let Err(e) = destroy_instance(&i.name, pid) {
                            error!(instance = %i.name, error = %e, "guard: destroy failed; retrying");
                        } else {
                            let _ = std::fs::remove_file(active_path());
                        }
                    }
                }
            }
            Err(e) => {
                // Could NOT enumerate. Do not conclude "nothing to kill" (Codex end-of-P1 #1): the
                // handoff-named instance was already fast-killed above; complete its teardown here.
                warn!(error = %e, "guard: limactl enumeration failed; enforcing via active-lease handoff");
                if let Some(a) = &active {
                    if !(pid_alive(a.run_pid) && now < a.wall_deadline) {
                        if let Err(e) = destroy_instance(&a.instance, a.vz_pid) {
                            error!(instance = %a.instance, error = %e, "guard: handoff destroy failed");
                        } else {
                            let _ = std::fs::remove_file(active_path());
                        }
                    }
                }
            }
        }
        std::thread::sleep(Duration::from_secs(1));
    }
}

fn cleanup() -> anyhow::Result<()> {
    // Enumeration MUST succeed: if we cannot see the instance table we cannot assert a clean slate,
    // so we refuse to proceed (fail-closed) rather than treat "unobservable" as "nothing to clean"
    // and then remove a prior orphan's handoff / open the gate on top of it (Codex end-of-P1 #1,
    // startup handoff-loss). The gate stays cut (its startup default) and the caller aborts.
    let evals: Vec<LimaInstance> = lima_list()
        .context("cleanup cannot enumerate instances; refusing to proceed (fail-closed)")?
        .into_iter()
        .filter(|i| i.name.starts_with("vm2-") && i.name != BASE_INSTANCE)
        .collect();
    let mut destroyed = 0;
    for i in &evals {
        let pid = std::fs::read_to_string(Path::new(&i.dir).join("vz.pid")).ok().and_then(|s| s.trim().parse().ok());
        warn!(instance = %i.name, status = %i.status, "unmanaged VM2 instance: destroying (fail-closed startup)");
        destroy_instance(&i.name, pid)?;
        destroyed += 1;
    }
    if destroyed == 0 {
        gate_set(GateState::Sealed)?;
    }
    println!("cleanup: destroyed {destroyed} instance(s); gate {:?}", gate_observe().0);
    Ok(())
}

fn provision_base(template: &Path, payload: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(LIMA_HOME)?;
    let _ = Command::new("/usr/sbin/chown").args(["-R", &format!("{SERVICE_USER}:staff"), LIMA_HOME]).status();
    // the service user cannot read Jean's home: stage the template and payload under STATE_DIR
    let stage = Path::new(STATE_DIR).join("stage");
    let _ = std::fs::remove_dir_all(&stage);
    std::fs::create_dir_all(&stage)?;
    std::fs::copy(template, stage.join("vm2.yaml"))?;
    run_ok({ let mut c = Command::new("/bin/cp"); c.args(["-R", payload.to_str().unwrap(), stage.join("payload").to_str().unwrap()]); c }, "copy payload")?;
    let _ = Command::new("/usr/sbin/chown").args(["-R", &format!("{SERVICE_USER}:staff"), stage.to_str().unwrap()]).status();
    let template_digest = sha256_hex(&std::fs::read(stage.join("vm2.yaml"))?);
    if lima_list()?.iter().any(|i| i.name == BASE_INSTANCE) {
        run_ok({ let mut c = lima(); c.args(["delete", "-f", BASE_INSTANCE]); c }, "delete old base")?;
    }
    gate_set(GateState::Open)?;
    let res = (|| -> anyhow::Result<()> {
        // Generous timeouts: base provisioning boots a guest, copies a payload, and (in
        // install-in-vm2.sh) BUILDS the VM1 browser image by booting a nested cloud-init VM — tens of
        // minutes. The bounded run_ok default (45s) is for the hot watchdog/gate/destroy paths, not
        // for one-off provisioning (Codex end-of-P1 #1 bounding must not strangle provisioning).
        run_ok_t({ let mut c = lima(); c.args(["start", "--name", BASE_INSTANCE, "--tty=false", stage.join("vm2.yaml").to_str().unwrap()]); c }, "limactl start base", 600)?;
        run_ok_t({ let mut c = lima(); c.args(["copy", "-r", stage.join("payload").to_str().unwrap(), &format!("{BASE_INSTANCE}:/tmp/payload")]); c }, "copy payload into base", 300)?;
        run_ok_t({ let mut c = lima(); c.args(["shell", BASE_INSTANCE, "--", "sudo", "bash", "/tmp/payload/install-in-vm2.sh"]); c }, "install payload in base", 3000)?;
        run_ok_t({ let mut c = lima(); c.args(["stop", BASE_INSTANCE]); c }, "stop base", 120)?;
        Ok(())
    })();
    gate_set(GateState::Sealed)?;
    res?;
    let disk = Path::new(LIMA_HOME).join(BASE_INSTANCE).join("basedisk");
    let base_digest = if disk.exists() { sha256_file(&disk)? } else { "none".into() };
    atomic_write_json(&Path::new(STATE_DIR).join("base.json"), &serde_json::json!({"template_digest": template_digest, "base_image_digest": base_digest, "provisioned_at": now_unix()}))?;
    println!("base provisioned: template {template_digest} base_image {base_digest}");
    Ok(())
}

fn sha256_file(p: &Path) -> anyhow::Result<String> {
    use sha2::Digest;
    let mut f = std::fs::File::open(p)?;
    let mut h = sha2::Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(hex::encode(h.finalize()))
}

#[allow(clippy::too_many_arguments)]
async fn run(run_id: String, controller: String, controller_pubkey: String, model: String, ollama: String, max_run_s: u64, template: PathBuf) -> anyhow::Result<()> {
    let key = key_from_hex(&std::fs::read_to_string(Path::new(STATE_DIR).join("keys/hostd.key")).context("run `hostd keygen` first")?)?;
    let controller_pk = pubkey_from_hex(&controller_pubkey)?;
    let base: serde_json::Value = read_json(&Path::new(STATE_DIR).join("base.json"))?.ok_or_else(|| anyhow!("run `hostd provision-base` first"))?;
    let template_digest_now = sha256_hex(&std::fs::read(&template)?);
    let template_digest = base["template_digest"].as_str().unwrap_or("").to_string();
    anyhow::ensure!(template_digest == template_digest_now, "template changed since base was provisioned; re-provision");
    let base_digest = base["base_image_digest"].as_str().unwrap_or("").to_string();

    // Exclusive host-gate ownership (one run per host) + fail-closed startup: nothing survives.
    let _lock = RunLock::acquire()?;
    cleanup()?;
    let _ = std::fs::remove_file(active_path());
    std::fs::create_dir_all(Path::new(STATE_DIR).join("runs"))?;
    std::fs::create_dir_all(Path::new(STATE_DIR).join("evidence"))?;
    let record_path = Path::new(STATE_DIR).join("runs").join(format!("{run_id}.json"));
    if let Some(old) = read_json::<HostRunRecord>(&record_path)? {
        anyhow::bail!("run {run_id} already has a record in state {:?}; a run gets one incarnation", old.state);
    }
    let instance = format!("vm2-{}", run_id.to_lowercase());
    let token = random_hex(32);

    // Publish the active-lease handoff BEFORE cloning, with a bounded setup grace, so the always-on
    // guard daemon does not destroy the freshly-cloned VM2 during bring-up (before the main loop
    // starts refreshing it). run_pid lets the guard detect this process dying at any point.
    const SETUP_GRACE_S: u64 = 180;
    let _ = atomic_write_json(&active_path(), &ActiveLease {
        instance: instance.clone(), incarnation: String::new(), vz_pid: None,
        wall_deadline: now_unix() + SETUP_GRACE_S, run_pid: std::process::id(), updated_at: now_unix(),
    });

    // Gate OPEN for the trusted setup window (clone -> start -> enroll -> prestage): limactl start
    // blocks on guest SSH (port 60022), and prestage fetches packages. No untrusted code runs until
    // VM1 boots, which is only after the eval seal. Sealed is re-applied before the eval lease.
    gate_set(GateState::Open)?;
    info!(%instance, "cloning base");
    run_ok_t({ let mut c = lima(); c.args(["clone", "--tty=false", BASE_INSTANCE, &instance]); c }, "limactl clone", 300)?;
    // Arm the cleanup guard the instant the clone exists, BEFORE the fallible start — so a start
    // that ultimately fails (or any early return / panic afterwards) still tears the clone down
    // (Codex end-of-P1 #1). Its Drop resolves the VMM pid from the instance dir if we don't yet
    // have it. pid is filled in after the post-start observation below.
    let mut inst_guard = InstanceGuard { instance: instance.clone(), pid: None, armed: true };
    let t0 = Instant::now();
    // `limactl start` can transiently fail right after a clone ("Using the existing instance …")
    // before the clone's state settles; retry once after a short settle.
    if let Err(e) = run_ok_t({ let mut c = lima(); c.args(["start", "--tty=false", &instance]); c }, "limactl start", 300) {
        warn!(error = %e, "limactl start failed; settling and retrying once");
        std::thread::sleep(Duration::from_secs(3));
        run_ok_t({ let mut c = lima(); c.args(["start", "--tty=false", &instance]); c }, "limactl start (retry)", 300)?;
    }
    info!(boot_ms = t0.elapsed().as_millis() as u64, "VM2 started");
    let obs = observe_vm2(&instance, &template_digest, &base_digest);
    inst_guard.pid = obs.pid;
    anyhow::ensure!(obs.running == Some(true), "VM2 not observed running after start: {obs:?}");
    let incarnation = incarnation_of(&instance, &obs);

    let record = HostRunRecord { run_id: run_id.clone(), instance: instance.clone(), incarnation: incarnation.clone(), state: HostRunState::Starting, vz_pid: obs.pid, lease_high_water: 0, lease_wall_deadline: 0, epoch: 0, reasons: vec![], destroy_latency_ms: None };
    atomic_write_json(&record_path, &record)?;
    let app = Arc::new(App {
        run_id: run_id.clone(),
        instance: instance.clone(),
        incarnation: incarnation.clone(),
        token: token.clone(),
        key,
        controller: controller.clone(),
        controller_pk,
        model,
        ollama,
        http: reqwest::Client::builder().timeout(Duration::from_secs(5)).build()?,
        record_path: record_path.clone(),
        evidence: evidence::EvidenceStore::new(Path::new(STATE_DIR).join("evidence").join(format!("{run_id}.jsonl")), EVIDENCE_QUOTA_BYTES),
        live: Mutex::new(Live { deadline: None, last_lease_at: None, lease_signed: None, gate: GateState::Sealed, last_report: None, report_seq: 0, prestage_done: false, log_seq_expected: 0, log_tokens: LOG_RATE_PER_S as f64, log_last: Instant::now(), log_dropped: 0, chokepoint: ChokepointObs::default(), destroy_reason: None }),
        record: Mutex::new(record),
        ollama_sem: tokio::sync::Semaphore::new(1),
        admission: tokio::sync::Semaphore::new(8),
        cancel_tx: tokio::sync::watch::channel(false).0,
    });
    app.evidence_append("run_start", serde_json::json!({"instance": instance, "incarnation": incarnation, "vm2": obs}));

    // Enroll.
    let e = Enroll { v: PROTO_V, kind: "enroll".into(), run_id: run_id.clone(), aud: AUD_CONTROLLER.into(), incarnation: incarnation.clone(), issued_at: now_unix(), vm2: obs.clone() };
    let resp = app.http.post(format!("{controller}/enroll")).json(&app.signed(&e)).send().await.context("enroll")?;
    anyhow::ensure!(resp.status().is_success(), "enroll refused: {}", resp.text().await.unwrap_or_default());
    let er: serde_json::Value = resp.json().await?;
    if er.get("order").map(|o| !o.is_null()).unwrap_or(false) {
        app.request_destroy("controller refused enrollment");
    }

    // Serve VM2.
    let router = Router::new()
        .route("/v1/lease", get(get_lease))
        .route("/v1/report", post(post_report))
        .route("/v1/log", post(post_log))
        .route("/v1/defender", post(post_defender))
        .route("/v1/prestage-done", post(post_prestage_done))
        .route("/v1/chat/completions", post(chat))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_MSG_BYTES + 4096))
        // Bound VM2-facing work so a compromised VM2 cannot exhaust the trusted service (Codex
        // end-of-P1 #6): the admission middleware sheds (503) the moment 8 requests are in flight
        // — no unbounded queue — and times out any request (incl. its body read, which happens
        // inside the handler under this timeout) at 75s.
        .layer(axum::middleware::from_fn_with_state(app.clone(), admission))
        .with_state(app.clone());
    // Cap concurrent CONNECTIONS at accept time (the only client is VM2, which could otherwise open
    // unbounded sockets to the trusted service): a semaphore permit is tied to each accepted
    // connection's lifetime and released on close.
    let listener = CappedListener::bind(("127.0.0.1", HOSTD_PORT), 64).await?;
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

    // First lease (prestage epoch 0) before anything runs in VM2.
    renew_lease(&app).await;
    if app.live.lock().unwrap().deadline.is_none() && app.live.lock().unwrap().destroy_reason.is_none() {
        app.request_destroy("no initial lease");
    }
    if app.live.lock().unwrap().destroy_reason.is_none() {
        // hand VM2 its token + config and start the supervisor; gate opens for prestage only now
        {
            let mut r = app.record.lock().unwrap();
            r.state = HostRunState::Prestage;
        }
        app.persist()?;
        let cfg = format!("RUN_ID={run_id}\nTOKEN={token}\nHOSTD=http://192.168.5.2:{HOSTD_PORT}\nCONTROLLER_PUBKEY={controller_pubkey}\nMODEL={}\n", app.model);
        run_ok({ let mut c = lima(); c.args(["shell", &instance, "--", "sudo", "bash", "-c", &format!("umask 077; printf '%s' '{}' > /etc/deadswitch/run.env", cfg.replace('\'', ""))]); c }, "write run.env")?;
        gate_set(GateState::Open)?;
        app.live.lock().unwrap().gate = GateState::Open;
        app.evidence_append("gate", serde_json::json!({"state": "open", "why": "prestage"}));
        run_ok({ let mut c = lima(); c.args(["shell", &instance, "--", "sudo", "systemd-run", "--unit=deadswitch-supervisor", "--property=KillMode=control-group", "/usr/local/bin/deadswitch-supervisor", "run", "--env-file", "/etc/deadswitch/run.env"]); c }, "start supervisor")?;
        app.evidence_append("supervisor_started", serde_json::json!({}));
    }

    // Main loops.
    let started = Instant::now();
    let mut last_renew = Instant::now();
    let mut last_challenge = Instant::now() - Duration::from_secs(CHALLENGE_EVERY_S);
    let expiry_detected = loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        // Refresh the independent-guard handoff every tick: instance, the current lease wall
        // deadline, this run's pid. If this process dies, the guard sees a dead run_pid / stale file
        // and destroys VM2 (crash survival).
        {
            let (dl, pid) = { let l = app.live.lock().unwrap(); (l.deadline.as_ref().map(|d| d.wall), app.record.lock().unwrap().vz_pid) };
            let al = ActiveLease { instance: instance.clone(), incarnation: incarnation.clone(), vz_pid: pid, wall_deadline: dl.unwrap_or(0), run_pid: std::process::id(), updated_at: now_unix() };
            let _ = atomic_write_json(&active_path(), &al);
        }
        // watchdog: both clocks
        let (expired, reason) = {
            let l = app.live.lock().unwrap();
            match (&l.deadline, &l.destroy_reason) {
                (_, Some(r)) => (true, r.clone()),
                (Some(d), None) if d.expired(now_unix()) => (true, "lease expired (watchdog)".into()),
                (None, None) => (true, "no lease".into()),
                _ => (false, String::new()),
            }
        };
        if expired {
            break Some((Instant::now(), reason));
        }
        if started.elapsed() > Duration::from_secs(max_run_s) {
            break Some((Instant::now(), "max_run_s reached".to_string()));
        }
        if last_renew.elapsed() >= Duration::from_secs(RENEW_EVERY_S) {
            last_renew = Instant::now();
            renew_lease(&app).await;
        }
        if last_challenge.elapsed() >= Duration::from_secs(CHALLENGE_EVERY_S) {
            last_challenge = Instant::now();
            answer_challenge(&app, &template_digest, &base_digest).await;
        }
    };
    if let Some((detected_at, reason)) = expiry_detected {
        // Latency measured two ways (Codex end-of-P1 #1): from the last accepted lease renewal (the
        // real containment-exposure window, which INCLUDES any stalled detection) and from expiry
        // detection. Assert the declared bound against the last-renewal figure.
        let last_lease_at = app.live.lock().unwrap().last_lease_at;
        match do_destroy(&app, &reason).await {
            Ok(death) => {
                // Both figures END at confirmed VMM death (not cleanup/notify): since detection, and
                // since the last accepted lease renewal (the true containment-exposure window, which
                // includes any stalled detection) (Codex end-of-P1 #1).
                let since_detection_ms = death.saturating_duration_since(detected_at).as_millis() as u64;
                let since_renewal_ms = last_lease_at.map(|t| death.saturating_duration_since(t).as_millis() as u64);
                const CONTAINMENT_BOUND_MS: u64 = 25_000; // §2 declared bound (Mac profile)
                app.evidence_append("containment_latency", serde_json::json!({
                    "since_last_renewal_ms": since_renewal_ms,
                    "since_detection_ms": since_detection_ms,
                    "bound_ms": CONTAINMENT_BOUND_MS,
                    "within_bound": since_renewal_ms.map(|m| m <= CONTAINMENT_BOUND_MS),
                    "reason": reason,
                }));
                info!(since_renewal_ms = ?since_renewal_ms, since_detection_ms, "containment complete");
                inst_guard.armed = false; // confirmed gone — safe to disarm the cleanup guard
                let _ = std::fs::remove_file(active_path());
                // A bound violation is a VALIDATION FAILURE, not a warning (Codex end-of-P1 #1): the
                // VM2 is destroyed, but we exit non-zero so the run is reported as out-of-spec.
                if let Some(m) = since_renewal_ms {
                    if m > CONTAINMENT_BOUND_MS {
                        error!(since_renewal_ms = m, bound_ms = CONTAINMENT_BOUND_MS, "containment latency exceeded declared bound");
                        app.evidence_append("containment_bound_exceeded", serde_json::json!({"since_last_renewal_ms": m}));
                        anyhow::bail!("containment latency {m}ms exceeded declared bound {CONTAINMENT_BOUND_MS}ms");
                    }
                }
            }
            Err(e) => {
                // Destruction NOT confirmed: leave the cleanup guard armed (its Drop retries) and the
                // gate cut, and exit non-zero — never claim containment (Codex end-of-P1 #1).
                error!(error = %e, "destroy unconfirmed; leaving cleanup guard armed and gate cut");
                return Err(e);
            }
        }
    } else {
        inst_guard.armed = false;
        let _ = std::fs::remove_file(active_path());
    }
    let rec = app.record.lock().unwrap().clone();
    println!("{}", serde_json::to_string_pretty(&rec)?);
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?)).init();
    anyhow::ensure!(unsafe { libc_geteuid() } == 0, "hostd must run as root (sudo -n /usr/local/sbin/deadswitch-hostd ...)");
    std::fs::create_dir_all(STATE_DIR)?;
    match Args::parse().cmd {
        Cmd::Keygen => keygen(),
        Cmd::Gate { state } => {
            let s = match state.as_str() { "open" => GateState::Open, "sealed" => GateState::Sealed, "cut" => GateState::Cut, _ => anyhow::bail!("open|sealed|cut") };
            gate_set(s)?;
            let (st, n) = gate_observe();
            println!("gate {:?} bypass_packets {:?}", st, n);
            Ok(())
        }
        Cmd::Cleanup => cleanup(),
        Cmd::Guard => guard(),
        Cmd::ProvisionBase { template, payload } => provision_base(&template, &payload),
        Cmd::Run { run_id, controller, controller_pubkey, model, ollama, max_run_s, template } => run(run_id, controller, controller_pubkey, model, ollama, max_run_s, template).await,
    }
}

extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
    #[link_name = "flock"]
    fn flock(fd: i32, operation: i32) -> i32;
}
