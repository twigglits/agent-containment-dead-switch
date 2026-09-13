//! deadswitch-evalagent — minimal Linux eval-host agent (Phase 2). Plays the same role hostd plays
//! on the Mac (docs/phase1-local-host.md §3–§4): enrolls with the controller, holds the fail-closed
//! lease loop on BOTH clocks via `Deadline::accept` (trusted/synced host clock — this agent runs on
//! the eval host, not inside the untrusted guest, so `accept_guest` does not apply here), and dies
//! the instant fresh authority lapses. QEMU/nftables specifics are deliberately kept OUT of this
//! binary: DS_BOOT_CMD / DS_SEAL_CMD / DS_DESTROY_CMD / DS_OBSERVE_CMD are shell hooks supplied by
//! the operator. The embedded exact-action proxy shares the lease/gate authority with this loop;
//! its independent runtime cancels inference even while a controller call or shell hook is blocked.
//!
//! Every accepted lease is followed by signed challenge/evidence heartbeats. Missing healthy
//! evidence revokes the same authority before the controller's no-evidence trip window elapses.

use anyhow::Context;
use clap::{Parser, Subcommand};
use deadswitch_common::*;
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

mod authority;
mod heartbeat;
mod proxy;
mod termination;

#[cfg(test)]
mod lifecycle_tests;

use authority::Authority;

#[derive(Parser)]
#[command(name = "deadswitch-evalagent")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Generate the eval-host signing key (prints the public key to enroll in the controller's
    /// hostd_pubkeys.txt).
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Boot the workload, enroll, and hold the fail-closed lease loop until told to die.
    Run(Box<RunArgs>),
}

#[derive(Parser, Debug)]
struct RunArgs {
    #[arg(long, env = "DS_CONTROLLER_URL")]
    controller_url: String,
    #[arg(long, env = "DS_RUN_ID")]
    run_id: String,
    /// Hex ed25519 seed file (as produced by `keygen`).
    #[arg(long, env = "DS_KEY_FILE")]
    key_file: PathBuf,
    /// Controller's public key (hex), to verify Lease/Challenge/Order signatures.
    #[arg(long, env = "DS_CONTROLLER_PUBKEY")]
    controller_pubkey: String,
    #[arg(long, env = "DS_INCARNATION")]
    incarnation: String,
    #[arg(long, env = "DS_VM2_TEMPLATE_DIGEST")]
    vm2_template_digest: String,
    #[arg(long, env = "DS_VM2_BASE_DIGEST")]
    vm2_base_digest: String,
    #[arg(long, env = "DS_LEASE_RENEW_INTERVAL_S", default_value_t = 5)]
    lease_renew_interval_s: u64,
    /// Boots the workload (VM2 -> VM1).
    #[arg(long, env = "DS_BOOT_CMD")]
    boot_cmd: String,
    /// Seals the nft egress gate.
    #[arg(long, env = "DS_SEAL_CMD")]
    seal_cmd: String,
    /// Destroys VM2.
    #[arg(long, env = "DS_DESTROY_CMD")]
    destroy_cmd: String,
    /// Prints host-observed VM2 JSON: running, pid, nested_virt, port_forwards, writable_mounts.
    /// Missing observations remain unknown; the controller requires true/true/0/0 for health.
    #[arg(long, env = "DS_OBSERVE_CMD")]
    observe_cmd: String,
    /// Workload-facing tap IPv4; the proxy always listens on TCP 7001. DS_WL_HOST_IP is an alias.
    #[arg(long, env = "HOSTD_IP")]
    hostd_ip: Option<Ipv4Addr>,
    /// Only this VM2 source IPv4 is admitted by the proxy's listener.
    #[arg(long, env = "DS_VM2_IP", default_value = "10.99.0.2")]
    vm2_ip: Ipv4Addr,
    /// Native inference backend IPv4 over WireGuard; TCP 11434, no URL/DNS/port override.
    #[arg(long, env = "DS_CHOKE_WGIP")]
    choke_wgip: Option<Ipv4Addr>,
    /// The only model the workload may request; must match the pre-staged VM1 workload.
    #[arg(long, env = "DS_MODEL", default_value = "qwen2.5:7b")]
    model: String,
}

// ---------------------------------------------------------------- fail-closed core (pure, tested)

/// Is it time to fail closed right now? A missing deadline (nothing granted yet, or the last grant
/// was rejected) and an expired one both mean "no fresh authority" — the one decision this whole
/// agent exists to get right, kept separate from the network/exec loop so it is unit-testable
/// without a controller or subprocesses.
fn should_fail_closed(deadline: Option<&Deadline>, wall_now: u64) -> bool {
    deadline.map(|d| d.expired(wall_now)).unwrap_or(true)
}

// ---------------------------------------------------------------- durable high-water state

/// Survives an agent restart: `Deadline::accept` already refuses a fencing token at or below this,
/// but that only holds within one process — persist it so a crashed-and-restarted agent cannot be
/// handed a replayed/stale lease and accept it as fresh.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
struct AgentState {
    high_water: u64,
}

fn state_path(key_file: &Path, run_id: &str) -> PathBuf {
    key_file.with_file_name(format!("evalagent-state-{run_id}.json"))
}

// ---------------------------------------------------------------- shell hooks

/// Run an opaque operator-supplied shell hook to completion. Never inspects what it does — QEMU /
/// nftables specifics stay out of this binary by design.
fn hook_command(a: &RunArgs, cmd: &str) -> Command {
    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(cmd)
        .env("DS_VM2_IP", a.vm2_ip.to_string())
        .env("DS_MODEL", &a.model);
    if let Some(ip) = a.hostd_ip {
        command
            .env("HOSTD_IP", ip.to_string())
            .env("DS_WL_HOST_IP", ip.to_string());
    }
    if let Some(ip) = a.choke_wgip {
        command
            .env("DS_CHOKE_WGIP", ip.to_string())
            .env("CHOKE_WGIP", ip.to_string());
    }
    command
}

fn run_hook(a: &RunArgs, cmd: &str, what: &str) -> anyhow::Result<()> {
    let out = hook_command(a, cmd)
        .output()
        .with_context(|| format!("{what} hook spawn"))?;
    if !out.status.success() {
        anyhow::bail!(
            "{what} hook exited {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    info!(what, "hook ok");
    Ok(())
}

#[derive(Deserialize, Default)]
struct ObserveOut {
    running: Option<bool>,
    pid: Option<u32>,
    nested_virt: Option<bool>,
    port_forwards: Option<u32>,
    writable_mounts: Option<u32>,
}

/// A missing or failing observe hook is conservative: `running: None` reads as unobservable, which
/// the controller's health policy already treats as unhealthy (it requires a positively-observed
/// `Some(true)`), never as healthy-by-default.
fn observe_vm2(a: &RunArgs) -> Vm2Obs {
    let mut o = Vm2Obs {
        instance: a.incarnation.clone(),
        template_digest: a.vm2_template_digest.clone(),
        base_image_digest: a.vm2_base_digest.clone(),
        ..Default::default()
    };
    match hook_command(a, &a.observe_cmd).output() {
        Ok(out) if out.status.success() => {
            match serde_json::from_slice::<ObserveOut>(&out.stdout) {
                Ok(v) => {
                    o.running = v.running;
                    o.pid = v.pid;
                    o.nested_virt = v.nested_virt;
                    o.port_forwards = v.port_forwards;
                    o.writable_mounts = v.writable_mounts;
                }
                Err(e) => {
                    warn!(error = %e, "observe hook: unparsable output; treating as unobservable")
                }
            }
        }
        Ok(out) => {
            warn!(status = %out.status, stderr = %String::from_utf8_lossy(&out.stderr), "observe hook failed; treating as unobservable")
        }
        Err(e) => warn!(error = %e, "observe hook: spawn failed; treating as unobservable"),
    }
    o
}

// ---------------------------------------------------------------- controller wire calls

enum RenewOutcome {
    Granted(Deadline),
    Denied,
    /// Response received but not actionable (bad signature, wrong run, stale/replayed token). The
    /// existing deadline (if any) is left as-is; the caller's expiry check decides what happens next.
    Unusable(String),
}

#[allow(clippy::too_many_arguments)]
fn renew(
    http: &reqwest::blocking::Client,
    a: &RunArgs,
    key: &SigningKey,
    controller_pk: &VerifyingKey,
    epoch: u64,
    gate: GateState,
    high_water: u64,
) -> anyhow::Result<RenewOutcome> {
    let req = LeaseRequest {
        v: PROTO_V,
        kind: "lease_request".into(),
        run_id: a.run_id.clone(),
        aud: AUD_CONTROLLER.into(),
        incarnation: a.incarnation.clone(),
        issued_at: now_unix(),
        epoch,
        gate,
    };
    let signed = Signed::sign(key, "hostd", &req);
    let resp = http
        .post(format!("{}/lease", a.controller_url))
        .json(&signed)
        .send()
        .context("lease request")?;
    anyhow::ensure!(
        resp.status().is_success(),
        "lease request refused: {}",
        resp.status()
    );
    match resp.json::<LeaseResponse>().context("lease response")? {
        LeaseResponse::Granted { lease } => {
            let l: Lease = match lease.verify(controller_pk, "lease", AUD_HOSTD) {
                Ok(l) => l,
                Err(e) => return Ok(RenewOutcome::Unusable(format!("bad lease signature: {e}"))),
            };
            if l.run_id != a.run_id || l.incarnation != a.incarnation {
                return Ok(RenewOutcome::Unusable(
                    "lease for another run/incarnation".into(),
                ));
            }
            if l.epoch != epoch {
                return Ok(RenewOutcome::Unusable("lease for another epoch".into()));
            }
            match Deadline::accept(&l, high_water, now_unix()) {
                Ok(d) => Ok(RenewOutcome::Granted(d)),
                Err(e) => Ok(RenewOutcome::Unusable(format!("lease rejected: {e}"))),
            }
        }
        LeaseResponse::Denied { order, reason } => {
            match order.verify::<Order>(controller_pk, "order", AUD_HOSTD) {
                Ok(o) => {
                    info!(order = ?o.order, reason, "controller denied lease with a signed order")
                }
                Err(e) => {
                    warn!(error = %e, reason, "controller denied lease; order did not verify")
                }
            }
            Ok(RenewOutcome::Denied)
        }
    }
}

// ---------------------------------------------------------------- fail-closed shutdown

static SHOULD_DIE: AtomicBool = AtomicBool::new(false);

extern "C" fn handle_signal(_: i32) {
    SHOULD_DIE.store(true, Ordering::SeqCst);
}

const SIGINT: i32 = 2;
const SIGTERM: i32 = 15;

extern "C" {
    fn signal(signum: i32, handler: extern "C" fn(i32)) -> usize;
}

/// The dead-switch itself: absence of a fresh lease => death. Seal first (best-effort, logged) so
/// egress is blackholed even if the destroy step below fails; both steps run regardless of the
/// other's outcome, then the process exits non-zero.
fn fail_closed(a: &RunArgs, authority: &Authority, key: &SigningKey, reason: &str) -> anyhow::Error {
    let started = Instant::now();
    // Revoke in-process authority BEFORE either shell hook. A failed/hanging hook cannot keep
    // dispatch alive, nor deliver backend content from an already-running inference.
    authority.stop(reason);
    error!(reason, "FAIL CLOSED: sealing and destroying");
    if let Err(e) = run_hook(a, &a.seal_cmd, "seal") {
        error!(error = %e, "fail-closed: seal hook failed (continuing to destroy)");
    }
    match run_hook(a, &a.destroy_cmd, "destroy") {
        Err(e) => error!(error = %e, "fail-closed: destroy hook failed"),
        Ok(()) => {
            // An exit status is not independent proof of death. This additional observation and
            // optional controller notification happen only AFTER authority was revoked and both
            // original cleanup hooks ran. Failure leaves grading blocked and never resumes a run.
            if let Err(e) = termination::notify_after_destroy(a, key, started) {
                warn!(error = %e, "teardown confirmation unavailable; grading remains blocked");
            }
        }
    }
    anyhow::anyhow!("fail closed: {reason}")
}

/// As in hostd's InstanceGuard, any error or unwind after boot begins must seal/destroy. In
/// particular, boot, bind, enroll, and durable high-water failures must not leak a live workload.
struct RunGuard<'a> {
    args: &'a RunArgs,
    key: &'a SigningKey,
    authority: std::sync::Arc<Authority>,
    armed: bool,
}

impl Drop for RunGuard<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = fail_closed(self.args, &self.authority, self.key, "run exited before cleanup");
        }
    }
}

fn address_alias(
    value: Option<Ipv4Addr>,
    alias: &str,
    default: Ipv4Addr,
) -> anyhow::Result<Ipv4Addr> {
    let alternative = std::env::var(alias)
        .ok()
        .map(|v| v.parse::<Ipv4Addr>())
        .transpose()
        .with_context(|| format!("invalid {alias}"))?;
    resolve_address(value, alternative, default)
        .with_context(|| format!("invalid/conflicting address configuration for {alias}"))
}

fn resolve_address(
    value: Option<Ipv4Addr>,
    alternative: Option<Ipv4Addr>,
    default: Ipv4Addr,
) -> anyhow::Result<Ipv4Addr> {
    if let (Some(value), Some(alternative)) = (value, alternative) {
        anyhow::ensure!(value == alternative, "address aliases disagree");
    }
    let result = value.or(alternative).unwrap_or(default);
    anyhow::ensure!(
        !result.is_unspecified()
            && !result.is_loopback()
            && !result.is_multicast()
            && !result.is_broadcast(),
        "requires a unicast interface IPv4, got {result}"
    );
    Ok(result)
}

// ---------------------------------------------------------------- commands

fn keygen(out: &Path) -> anyhow::Result<()> {
    if let Some(parent) = out.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)?;
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))?;
    }
    let k = load_or_create_signing_key(out)?;
    println!("{}", pubkey_hex(&k));
    Ok(())
}

fn run(mut a: RunArgs) -> anyhow::Result<()> {
    anyhow::ensure!(
        !a.incarnation.is_empty(),
        "DS_INCARNATION must not be empty"
    );
    anyhow::ensure!(
        !a.vm2_template_digest.is_empty(),
        "DS_VM2_TEMPLATE_DIGEST must not be empty"
    );
    anyhow::ensure!(
        !a.vm2_base_digest.is_empty(),
        "DS_VM2_BASE_DIGEST must not be empty"
    );
    heartbeat::validate_interval(a.lease_renew_interval_s)?;
    anyhow::ensure!(!a.model.trim().is_empty(), "DS_MODEL must not be empty");
    for (cmd, name) in [
        (&a.boot_cmd, "DS_BOOT_CMD"),
        (&a.seal_cmd, "DS_SEAL_CMD"),
        (&a.destroy_cmd, "DS_DESTROY_CMD"),
        (&a.observe_cmd, "DS_OBSERVE_CMD"),
    ] {
        anyhow::ensure!(!cmd.trim().is_empty(), "{name} must not be empty");
    }

    unsafe {
        signal(SIGINT, handle_signal);
        signal(SIGTERM, handle_signal);
    }

    let key = key_from_hex(
        &std::fs::read_to_string(&a.key_file).context("run `deadswitch-evalagent keygen` first")?,
    )?;
    let controller_pk = pubkey_from_hex(&a.controller_pubkey)?;
    let sp = state_path(&a.key_file, &a.run_id);
    let high_water = read_json::<AgentState>(&sp)?.unwrap_or_default().high_water;
    let http = reqwest::blocking::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .http1_only()
        .pool_max_idle_per_host(0)
        .timeout(Duration::from_secs(10))
        .build()?;
    let hostd_ip = address_alias(a.hostd_ip, "DS_WL_HOST_IP", Ipv4Addr::new(10, 99, 0, 1))?;
    let choke_wgip = address_alias(a.choke_wgip, "CHOKE_WGIP", Ipv4Addr::new(10, 20, 0, 2))?;
    resolve_address(Some(a.vm2_ip), None, a.vm2_ip)?;
    anyhow::ensure!(
        a.vm2_ip != hostd_ip && a.vm2_ip != choke_wgip && hostd_ip != choke_wgip,
        "VM2, hostd, and backend addresses must differ"
    );
    // Pass resolved values to every hook as well as the listener. CLI overrides must not silently
    // leave the kernel gate using different defaults from the in-process proxy.
    a.hostd_ip = Some(hostd_ip);
    a.choke_wgip = Some(choke_wgip);
    let authority = Authority::new(&SHOULD_DIE);
    let mut guard = RunGuard {
        args: &a,
        key: &key,
        authority: authority.clone(),
        armed: true,
    };
    let outcome = run_workload(
        &a,
        &http,
        &key,
        &controller_pk,
        &sp,
        high_water,
        hostd_ip,
        choke_wgip,
        &authority,
    );
    let reason = match outcome {
        Ok(()) => "run stopped".to_string(),
        Err(e) => format!("{e:#}"),
    };
    let error = fail_closed(&a, &authority, &key, &reason);
    guard.armed = false;
    Err(error)
}

#[allow(clippy::too_many_arguments)]
fn run_workload(
    a: &RunArgs,
    http: &reqwest::blocking::Client,
    key: &SigningKey,
    controller_pk: &VerifyingKey,
    sp: &Path,
    mut high_water: u64,
    hostd_ip: Ipv4Addr,
    choke_wgip: Ipv4Addr,
    authority: &std::sync::Arc<Authority>,
) -> anyhow::Result<()> {
    // (a) boot the workload (VM2 -> VM1).
    if let Some(reason) = authority.stop_reason() {
        anyhow::bail!(reason);
    }
    run_hook(a, &a.boot_cmd, "boot")?;
    if let Some(reason) = authority.stop_reason() {
        anyhow::bail!(reason);
    }
    // The boot hook prepares the tap under CUT. Bind only that address after it exists, with no
    // authority granted yet. Bind failures go through RunGuard's fail-closed cleanup.
    let proxy = proxy::ProxyRuntime::start(
        hostd_ip,
        a.vm2_ip,
        choke_wgip,
        a.model.clone(),
        authority.clone(),
    )?;

    // (b) enroll.
    let vm2 = observe_vm2(a);
    let enroll_msg = Enroll {
        v: PROTO_V,
        kind: "enroll".into(),
        run_id: a.run_id.clone(),
        aud: AUD_CONTROLLER.into(),
        incarnation: a.incarnation.clone(),
        issued_at: now_unix(),
        vm2,
    };
    let resp = http
        .post(format!("{}/enroll", a.controller_url))
        .json(&Signed::sign(key, "hostd", &enroll_msg))
        .send()
        .context("enroll")?;
    anyhow::ensure!(
        resp.status().is_success(),
        "enroll refused: {}",
        resp.status()
    );
    let enrolled: serde_json::Value = resp.json().context("enroll response")?;
    anyhow::ensure!(
        enrolled.get("order").is_none_or(|o| o.is_null()),
        "controller refused enrollment"
    );
    info!(run_id = %a.run_id, incarnation = %a.incarnation, "enrolled");

    // (c) lease loop: epoch 0 (gate Open) for a short prestage, then seal and advance to epoch 1.
    let mut epoch = 0u64;
    let mut gate = GateState::Open;
    let mut heartbeat = heartbeat::Heartbeat::default();
    authority.expect_evidence_by(Instant::now() + heartbeat::MAX_EVIDENCE_AGE)?;
    let mut last_renew = Instant::now() - Duration::from_secs(a.lease_renew_interval_s);
    loop {
        if let Some(reason) = authority.stop_reason() {
            anyhow::bail!(reason);
        }
        let deadline = authority.deadline();
        if deadline.is_none()
            || last_renew.elapsed() >= Duration::from_secs(a.lease_renew_interval_s)
        {
            last_renew = Instant::now();
            // The prestage epoch only ever needs one granted lease; seal before asking for epoch 1.
            if epoch == 0 && deadline.is_some() {
                // Cancel/invalidate before changing kernel rules, then mark sealed ONLY on success.
                authority.set_gate(GateState::Cut);
                run_hook(a, &a.seal_cmd, "seal")?;
                authority.set_gate(GateState::Sealed);
                epoch = 1;
                gate = GateState::Sealed;
            }
            if let Some(reason) = authority.stop_reason() {
                anyhow::bail!(reason);
            }
            match renew(http, a, key, controller_pk, epoch, gate, high_water) {
                Ok(RenewOutcome::Granted(d)) => {
                    high_water = d.fencing_token;
                    atomic_write_json(sp, &AgentState { high_water })
                        .context("persist lease high-water")?;
                    authority.accept(d)?;
                    tracing::debug!(high_water, epoch, chokepoint = ?proxy.proxy.observations(), "lease accepted");
                    match heartbeat.exchange(http, a, key, controller_pk, authority, &proxy.proxy) {
                        Ok(heartbeat::Outcome::Healthy { sent_at }) => {
                            // Start from SEND, not receipt: a delayed acknowledgement cannot buy
                            // more time than the controller's actual last-valid-evidence instant.
                            authority.expect_evidence_by(sent_at + heartbeat::MAX_EVIDENCE_AGE)?;
                            tracing::debug!(
                                high_water,
                                epoch,
                                "controller accepted healthy evidence"
                            );
                        }
                        Ok(heartbeat::Outcome::Deferred) => {}
                        Ok(heartbeat::Outcome::Rejected(reason)) => {
                            authority.stop(&reason);
                            anyhow::bail!(reason);
                        }
                        Err(e) => {
                            warn!(error = %e, "heartbeat failed; retry on next lease tick; evidence deadline unchanged")
                        }
                    }
                }
                Ok(RenewOutcome::Denied) => {
                    authority.stop("controller denied the lease");
                    anyhow::bail!("controller denied the lease");
                }
                Ok(RenewOutcome::Unusable(reason)) => {
                    warn!(reason, "lease renewal unusable; deadline unchanged")
                }
                Err(e) => {
                    warn!(error = %e, "lease renewal request failed; controller may be unreachable")
                }
            }
        }
        if should_fail_closed(authority.deadline().as_ref(), now_unix()) {
            anyhow::bail!("no fresh lease before deadline");
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn main() -> anyhow::Result<()> {
    // Keep explicit RUST_LOG settings effective; enable development diagnostics for this agent
    // without logging controller credentials or the workload's prompt/response bodies.
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,deadswitch_evalagent=debug"));
    tracing_subscriber::fmt().with_env_filter(filter).init();
    match Args::parse().cmd {
        Cmd::Keygen { out } => keygen(&out),
        Cmd::Run(a) => run(*a),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lease(tok: u64, issued: u64, ttl: u64) -> Lease {
        Lease {
            v: PROTO_V,
            kind: "lease".into(),
            run_id: "r".into(),
            aud: AUD_HOSTD.into(),
            incarnation: "inc".into(),
            epoch: 1,
            fencing_token: tok,
            issued_at: issued,
            ttl_s: ttl,
        }
    }

    #[test]
    fn no_deadline_yet_is_fail_closed() {
        assert!(should_fail_closed(None, 1_000_000));
    }

    #[test]
    fn expired_deadline_is_fail_closed_fresh_one_is_not() {
        let now = 1_000_000;
        let d = Deadline::accept(&lease(1, now, 5), 0, now).unwrap();
        assert!(
            !should_fail_closed(Some(&d), now),
            "freshly granted lease must not fail closed"
        );
        assert!(
            should_fail_closed(Some(&d), now + 5),
            "a lease past its ttl must fail closed"
        );
    }

    #[test]
    fn a_higher_fencing_token_renews_and_keeps_running() {
        let now = 1_000_000;
        let d1 = Deadline::accept(&lease(5, now, 15), 0, now).unwrap();
        assert!(!should_fail_closed(Some(&d1), now));
        // renewal: controller issues a strictly higher token, accepted against the prior high-water
        let d2 = Deadline::accept(&lease(6, now, 15), d1.fencing_token, now).unwrap();
        assert!(!should_fail_closed(Some(&d2), now));
        assert_eq!(d2.epoch, 1);
    }

    #[test]
    fn a_lower_or_equal_fencing_token_is_rejected_not_accepted() {
        let now = 1_000_000;
        // equal to high-water: replay of the same lease
        assert!(Deadline::accept(&lease(5, now, 15), 5, now).is_err());
        // strictly below high-water: stale/out-of-order delivery
        assert!(Deadline::accept(&lease(4, now, 15), 5, now).is_err());
    }
}
