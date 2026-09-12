//! hostd — the trusted Mac-side component below VM2 (docs/phase1-local-host.md §3–§4).
//!
//! Owns, and VM2 cannot touch: the lease watchdog (both clocks), the pf user-gate, VM2's
//! lifecycle (clone / start / destroy-with-delete), the evidence signer (signs only what it
//! observed itself), the trusted evidence store, and the inference chokepoint (Phase 1 only).
//! Runs as root via the sudoers entry installed by infra/mac/install-hostd.sh.

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
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

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

fn run_ok(mut c: Command, what: &str) -> anyhow::Result<String> {
    let out = c.output().with_context(|| what.to_string())?;
    if !out.status.success() {
        return Err(anyhow!("{what} failed: {}", String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
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
    let out = run_ok({ let mut c = lima(); c.args(["list", "--json"]); c }, "limactl list")?;
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
    run_ok({ let mut c = Command::new("/sbin/pfctl"); c.args(["-q", "-a", "deadswitch", "-f", p.to_str().unwrap()]); c }, "pfctl load anchor")?;
    // On CUT (destroy path) drop all of the service user's states so established egress dies with the
    // run. NOT on SEAL: a blanket `pfctl -k` there also tears down the VM2->hostd control path
    // (192.168.5.2:7001) and the reporter never recovers (observed 2026-09-13). Sealing relies on the
    // block rule for NEW egress; scoped teardown of prestage-era egress flows on seal is a post-MVP
    // refinement (pf cannot kill states by socket-user, so it needs per-destination kills).
    if matches!(state, GateState::Cut) {
        let _ = Command::new("/sbin/pfctl").args(["-q", "-k", "0.0.0.0/0"]).output();
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
    let state = match (has_pass_all, has_pass_hostd, has_block) {
        (true, _, _) => GateState::Open,
        (false, true, true) => GateState::Sealed,
        (false, false, true) => GateState::Cut,
        _ => GateState::Unknown,
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
    o.nested_virt = i.config.get("nestedVirtualization").and_then(|v| v.as_bool());
    o.port_forwards = i.config.get("portForwards").and_then(|v| v.as_array()).map(|a| a.iter().filter(|r| !r.get("ignore").and_then(|x| x.as_bool()).unwrap_or(false)).count() as u32);
    o.writable_mounts = i.config.get("mounts").and_then(|v| v.as_array()).map(|a| a.iter().filter(|m| m.get("writable").and_then(|x| x.as_bool()).unwrap_or(false)).count() as u32);
    o
}

fn incarnation_of(instance: &str, obs: &Vm2Obs) -> String {
    sha256_hex(format!("{}|{}|{}|{}", instance, obs.started_at.unwrap_or(0), obs.template_digest, obs.base_image_digest).as_bytes())
}

/// stop -f, delete, confirm. Returns latency. Never reports success on dispatch alone.
fn destroy_instance(instance: &str, pid: Option<u32>) -> anyhow::Result<Duration> {
    let t0 = Instant::now();
    let _ = gate_set(GateState::Cut);
    let _ = run_ok({ let mut c = lima(); c.args(["stop", "-f", instance]); c }, "limactl stop");
    let _ = run_ok({ let mut c = lima(); c.args(["delete", "-f", instance]); c }, "limactl delete");
    for _ in 0..20 {
        let gone_from_lima = lima_list().map(|l| !l.iter().any(|i| i.name == instance)).unwrap_or(false);
        let pid_gone = pid.map(|p| !Command::new("/bin/kill").args(["-0", &p.to_string()]).status().map(|s| s.success()).unwrap_or(false)).unwrap_or(true);
        let dir_gone = !Path::new(LIMA_HOME).join(instance).exists();
        if gone_from_lima && pid_gone && dir_gone {
            return Ok(t0.elapsed());
        }
        if let Some(p) = pid {
            let _ = Command::new("/bin/kill").args(["-9", &p.to_string()]).status();
        }
        std::thread::sleep(Duration::from_millis(500));
    }
    Err(anyhow!("instance {instance} still present after destroy"))
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
    lease_high_water: u64,
    lease_wall_deadline: u64,
    epoch: u64,
    reasons: Vec<String>,
    destroy_latency_ms: Option<u64>,
}

struct Live {
    deadline: Option<Deadline>,
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
    evidence_path: PathBuf,
    live: Mutex<Live>,
    record: Mutex<HostRunRecord>,
    ollama_sem: tokio::sync::Semaphore,
}

impl App {
    fn persist(&self) -> anyhow::Result<()> {
        atomic_write_json(&self.record_path, &*self.record.lock().unwrap())
    }
    fn evidence_append(&self, kind: &str, data: serde_json::Value) {
        use std::io::Write;
        let line = serde_json::json!({"ts": now_unix(), "src": "hostd", "kind": kind, "data": data});
        if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&self.evidence_path) {
            let _ = writeln!(f, "{line}");
        }
    }
    fn request_destroy(&self, reason: &str) {
        let mut l = self.live.lock().unwrap();
        if l.destroy_reason.is_none() {
            warn!(reason, "destroy requested");
            l.destroy_reason = Some(reason.into());
        }
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
    Ok(Json(LeaseView {
        run_id: app.run_id.clone(),
        epoch: l.deadline.as_ref().map(|d| d.epoch).unwrap_or(0),
        gate: l.gate,
        lease: if expired || l.destroy_reason.is_some() { None } else { l.lease_signed.clone() },
        controller_pubkey: hex::encode(app.controller_pk.to_bytes()),
    }))
}

async fn post_report(State(app): State<Arc<App>>, h: HeaderMap, body: axum::body::Bytes) -> Result<Json<serde_json::Value>, (StatusCode, String)> {
    check_token(&app, &h)?;
    if body.len() > MAX_MSG_BYTES {
        return Err((StatusCode::PAYLOAD_TOO_LARGE, "report too large".into()));
    }
    let rep: Vm2Report = serde_json::from_slice(&body).map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;
    let mut l = app.live.lock().unwrap();
    if rep.run_id != app.run_id || rep.seq <= l.report_seq && l.report_seq != 0 {
        app.evidence_append("vm2_report_rejected", serde_json::json!({"seq": rep.seq, "run_id": rep.run_id}));
        return Err((StatusCode::CONFLICT, "wrong run or non-monotonic seq".into()));
    }
    l.report_seq = rep.seq;
    let (seq, phase) = (rep.seq, rep.phase.clone());
    l.last_report = Some(UntrustedReport { received_at: now_unix(), digest: sha256_hex(&body), body: rep });
    drop(l);
    app.evidence_append("vm2_report_ok", serde_json::json!({"seq": seq, "phase": phase}));
    Ok(Json(serde_json::json!({"ok": true})))
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
    if ev.seq != l.log_seq_expected {
        app.evidence_append("vm2_log_gap", serde_json::json!({"expected": l.log_seq_expected, "got": ev.seq}));
    }
    l.log_seq_expected = ev.seq + 1;
    drop(l);
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
    let Ok(mut v) = serde_json::from_slice::<serde_json::Value>(&body) else { return deny(&app, "not json") };
    let Some(obj) = v.as_object_mut() else { return deny(&app, "not an object") };
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
    if obj.get("max_tokens").and_then(|n| n.as_u64()).unwrap_or(0) > 1024 {
        return deny(&app, "max_tokens > 1024");
    }
    if !obj.get("messages").map(|m| m.is_array()).unwrap_or(false) {
        return deny(&app, "messages required");
    }
    obj.insert("stream".into(), serde_json::json!(false));
    obj.entry("max_tokens").or_insert(serde_json::json!(512));
    obj.insert("options".into(), serde_json::json!({"num_ctx": 4096}));
    // active lease required at dispatch time (bind review to execution)
    {
        let l = app.live.lock().unwrap();
        if l.deadline.as_ref().map(|d| d.expired(now_unix())).unwrap_or(true) || l.destroy_reason.is_some() || l.deadline.as_ref().map(|d| d.epoch).unwrap_or(0) < 1 {
            drop(l);
            return deny(&app, "no active eval lease");
        }
    }
    let _permit = app.ollama_sem.acquire().await.map_err(|_| (StatusCode::SERVICE_UNAVAILABLE, "closed".to_string()))?;
    app.live.lock().unwrap().chokepoint.inference_requests += 1;
    app.evidence_append("chokepoint_forward", serde_json::json!({"digest": sha256_hex(&body)}));
    let r = app.http.post(format!("{}/v1/chat/completions", app.ollama)).timeout(Duration::from_secs(60)).json(&v).send().await;
    match r {
        Ok(resp) => {
            let st = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
            let j = resp.json::<serde_json::Value>().await.unwrap_or(serde_json::json!({"error": "bad upstream body"}));
            Ok((st, Json(j)))
        }
        Err(e) => Err((StatusCode::BAD_GATEWAY, e.to_string())),
    }
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

async fn do_destroy(app: &App, reason: &str) {
    {
        let mut r = app.record.lock().unwrap();
        r.state = HostRunState::Destroying;
        r.reasons.push(reason.into());
    }
    let _ = app.persist();
    app.evidence_append("destroy_begin", serde_json::json!({"reason": reason}));
    let pid = observe_vm2(&app.instance, "", "").pid;
    let mut latency = None;
    for attempt in 1..=30 {
        match destroy_instance(&app.instance, pid) {
            Ok(d) => {
                latency = Some(d);
                break;
            }
            Err(e) => {
                error!(attempt, error = %e, "destroy failed; retrying (gate stays cut)");
                app.evidence_append("destroy_retry", serde_json::json!({"attempt": attempt, "error": e.to_string()}));
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        }
    }
    let Some(lat) = latency else {
        error!("VM2 could not be confirmed destroyed after 30 attempts; alarm");
        app.evidence_append("destroy_unconfirmed", serde_json::json!({}));
        return;
    };
    {
        let mut r = app.record.lock().unwrap();
        r.state = HostRunState::Terminated;
        r.destroy_latency_ms = Some(lat.as_millis() as u64);
    }
    let _ = app.persist();
    app.evidence_append("destroy_confirmed", serde_json::json!({"latency_ms": lat.as_millis() as u64}));
    info!(latency_ms = lat.as_millis() as u64, "VM2 destroyed and confirmed");
    let t = serde_json::json!({"v": PROTO_V, "type": "terminated", "run_id": app.run_id, "aud": AUD_CONTROLLER, "incarnation": app.incarnation, "issued_at": now_unix(), "latency_ms": lat.as_millis() as u64});
    let _ = app.http.post(format!("{}/terminated", app.controller)).json(&app.signed(&t)).send().await;
}

// ------------------------------------------------------------------ commands

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

fn cleanup() -> anyhow::Result<()> {
    let mut destroyed = 0;
    for i in lima_list()? {
        if i.name.starts_with("vm2-") && i.name != BASE_INSTANCE {
            let pid = std::fs::read_to_string(Path::new(&i.dir).join("vz.pid")).ok().and_then(|s| s.trim().parse().ok());
            warn!(instance = %i.name, status = %i.status, "unmanaged VM2 instance: destroying (fail-closed startup)");
            destroy_instance(&i.name, pid)?;
            destroyed += 1;
        }
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
        run_ok({ let mut c = lima(); c.args(["start", "--name", BASE_INSTANCE, "--tty=false", stage.join("vm2.yaml").to_str().unwrap()]); c }, "limactl start base")?;
        run_ok({ let mut c = lima(); c.args(["copy", "-r", stage.join("payload").to_str().unwrap(), &format!("{BASE_INSTANCE}:/tmp/payload")]); c }, "copy payload into base")?;
        run_ok({ let mut c = lima(); c.args(["shell", BASE_INSTANCE, "--", "sudo", "bash", "/tmp/payload/install-in-vm2.sh"]); c }, "install payload in base")?;
        run_ok({ let mut c = lima(); c.args(["stop", BASE_INSTANCE]); c }, "stop base")?;
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

    // Fail-closed startup: nothing survives from before.
    cleanup()?;
    std::fs::create_dir_all(Path::new(STATE_DIR).join("runs"))?;
    std::fs::create_dir_all(Path::new(STATE_DIR).join("evidence"))?;
    let record_path = Path::new(STATE_DIR).join("runs").join(format!("{run_id}.json"));
    if let Some(old) = read_json::<HostRunRecord>(&record_path)? {
        anyhow::bail!("run {run_id} already has a record in state {:?}; a run gets one incarnation", old.state);
    }
    let instance = format!("vm2-{}", run_id.to_lowercase());
    let token = random_hex(32);

    // Gate OPEN for the trusted setup window (clone -> start -> enroll -> prestage): limactl start
    // blocks on guest SSH (port 60022), and prestage fetches packages. No untrusted code runs until
    // VM1 boots, which is only after the eval seal. Sealed is re-applied before the eval lease.
    gate_set(GateState::Open)?;
    info!(%instance, "cloning base");
    run_ok({ let mut c = lima(); c.args(["clone", "--tty=false", BASE_INSTANCE, &instance]); c }, "limactl clone")?;
    let t0 = Instant::now();
    run_ok({ let mut c = lima(); c.args(["start", "--tty=false", &instance]); c }, "limactl start")?;
    info!(boot_ms = t0.elapsed().as_millis() as u64, "VM2 started");
    let obs = observe_vm2(&instance, &template_digest, &base_digest);
    anyhow::ensure!(obs.running == Some(true), "VM2 not observed running after start: {obs:?}");
    let incarnation = incarnation_of(&instance, &obs);

    let record = HostRunRecord { run_id: run_id.clone(), instance: instance.clone(), incarnation: incarnation.clone(), state: HostRunState::Starting, lease_high_water: 0, lease_wall_deadline: 0, epoch: 0, reasons: vec![], destroy_latency_ms: None };
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
        evidence_path: Path::new(STATE_DIR).join("evidence").join(format!("{run_id}.jsonl")),
        live: Mutex::new(Live { deadline: None, lease_signed: None, gate: GateState::Sealed, last_report: None, report_seq: 0, prestage_done: false, log_seq_expected: 0, log_tokens: LOG_RATE_PER_S as f64, log_last: Instant::now(), log_dropped: 0, chokepoint: ChokepointObs::default(), destroy_reason: None }),
        record: Mutex::new(record),
        ollama_sem: tokio::sync::Semaphore::new(1),
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
        .with_state(app.clone());
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", HOSTD_PORT)).await?;
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
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
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
            do_destroy(&app, &reason).await;
            break;
        }
        if started.elapsed() > Duration::from_secs(max_run_s) {
            do_destroy(&app, "max_run_s reached").await;
            break;
        }
        if last_renew.elapsed() >= Duration::from_secs(RENEW_EVERY_S) {
            last_renew = Instant::now();
            renew_lease(&app).await;
        }
        if last_challenge.elapsed() >= Duration::from_secs(CHALLENGE_EVERY_S) {
            last_challenge = Instant::now();
            answer_challenge(&app, &template_digest, &base_digest).await;
        }
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
        Cmd::ProvisionBase { template, payload } => provision_base(&template, &payload),
        Cmd::Run { run_id, controller, controller_pubkey, model, ollama, max_run_s, template } => run(run_id, controller, controller_pubkey, model, ollama, max_run_s, template).await,
    }
}

extern "C" {
    #[link_name = "geteuid"]
    fn libc_geteuid() -> u32;
}
