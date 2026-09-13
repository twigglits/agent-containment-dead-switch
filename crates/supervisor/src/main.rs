//! deadswitch-supervisor — runs inside VM2 (untrusted during the run). Prestage → wait for the
//! eval lease → nft → boot VM1 → gateway/defender/VMI/report loop → fail-closed on lease loss.
//! It is the rung-1 enforcer: everything it does can be undone by a compromised VM2, which is why
//! hostd (below VM2) is the one that kills VM2.

mod defender;
mod gateway;
mod hostd;
mod prestage;
mod vm1;
mod vmi;

use clap::{Parser, Subcommand};
use deadswitch_common::*;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;
use std::sync::Mutex;
use std::net::ToSocketAddrs;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{info, warn};

const VM1_DIR: &str = "/var/lib/deadswitch/vm1";
const HARNESS_SRC: &str = "/var/lib/deadswitch/harness";
const RUN_DIR: &str = "/var/lib/deadswitch/run";
const REPORT_EVERY_S: u64 = 2;
const VMI_EVERY_S: u64 = 30;
const VMI_MAX_AGE_S: u64 = 60;

#[derive(Parser)]
#[command(name = "deadswitch-supervisor")]
struct Args {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Full run driven by /etc/deadswitch/run.env (written by hostd).
    Run {
        #[arg(long)]
        env_file: PathBuf,
        /// rules | approve_all | deny_all  (advisory judge; hard rules always apply)
        #[arg(long, default_value = "rules", env = "DS_JUDGE")]
        judge: String,
    },
}

/// Minimal HTTP/1.1 POST over raw TCP — no async runtime, no reqwest. Used by the report thread so
/// nothing the main runtime does can starve or panic it. Returns Ok on any HTTP response received.
fn raw_http_post(hostport: &str, path: &str, bearer: &str, body: &[u8]) -> std::io::Result<()> {
    use std::io::{Read, Write};
    let mut s = std::net::TcpStream::connect_timeout(
        &hostport.to_socket_addrs()?.next().ok_or(std::io::ErrorKind::AddrNotAvailable)?,
        Duration::from_secs(3),
    )?;
    s.set_write_timeout(Some(Duration::from_secs(3)))?;
    s.set_read_timeout(Some(Duration::from_secs(3)))?;
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: {hostport}\r\nAuthorization: Bearer {bearer}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    s.write_all(head.as_bytes())?;
    s.write_all(body)?;
    s.flush()?;
    let mut buf = [0u8; 64];
    let _ = s.read(&mut buf); // drain first bytes; we only need the POST to have been delivered
    Ok(())
}

fn read_env(p: &Path) -> anyhow::Result<HashMap<String, String>> {
    Ok(std::fs::read_to_string(p)?.lines().filter_map(|l| l.split_once('=')).map(|(k, v)| (k.trim().into(), v.trim().into())).collect())
}

/// VM2's own egress: only hostd. Untrusted second layer under the Mac-side gate.
fn vm2_self_restrict(hostd_ip: &str, hostd_port: &str) {
    let rules = format!(
        "table inet vm2self {{ }}\ndelete table inet vm2self\ntable inet vm2self {{\n chain output {{\n  type filter hook output priority 0; policy drop;\n  oifname \"lo\" accept\n  oifname \"tap0\" accept\n  ip daddr {hostd_ip} tcp dport {hostd_port} accept\n  ct state established,related accept\n  counter drop\n }}\n}}\n"
    );
    let _ = std::process::Command::new("/bin/bash").args(["-c", &format!("printf '%s' '{rules}' | nft -f -")]).status();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt().with_env_filter(tracing_subscriber::EnvFilter::from_default_env().add_directive("info".parse()?)).init();
    let Cmd::Run { env_file, judge } = Args::parse().cmd;
    let env = read_env(&env_file)?;
    let get = |k: &str| env.get(k).cloned().ok_or_else(|| anyhow::anyhow!("{k} missing from env file"));
    let run_id = get("RUN_ID")?;
    let hostd_url = get("HOSTD")?;
    let model = get("MODEL")?;
    let controller_pk = pubkey_from_hex(&get("CONTROLLER_PUBKEY")?)?;
    let judge = defender::Judge::parse(&env.get("JUDGE").cloned().unwrap_or(judge));
    let h = hostd::Hostd::new(hostd_url.clone(), get("TOKEN")?);
    h.log("supervisor_start", "supervisor up", serde_json::json!({"run_id": run_id, "judge": format!("{judge:?}")}));

    let run_dir = Path::new(RUN_DIR).join(&run_id);
    std::fs::create_dir_all(&run_dir)?;
    let defender = Arc::new(defender::Defender::new(judge));
    let gw = Arc::new(gateway::Gateway { hostd: h.clone(), defender: defender.clone(), model: model.clone(), allowed: 0.into(), denied: 0.into(), lease_active: false.into(), sem: tokio::sync::Semaphore::new(4) });

    // Shared report state: the main flow updates {phase, vm1_state, vmi}; a background task posts a
    // fresh report to hostd every REPORT_EVERY_S no matter what the main flow is blocked on (VM1
    // boot, rootfs copy, VMI). Without this, a long synchronous step lets the report go stale and
    // the controller trips it (observed 2026-09-12: "vm2 report stale" during VM1 bring-up).
    let rs = Arc::new(Mutex::new((String::from("prestage"), Vm1State::NotStarted, VmiResult::Unmeasured)));
    // The reporter runs on its OWN OS thread with a blocking HTTP client. The main flow makes long
    // synchronous calls (QEMU boot wait, qemu-img, nft), which would starve an async task on the
    // shared runtime and let the report go stale — the controller then trips ("vm2 report stale",
    // observed 2026-09-12). A dedicated thread posts every REPORT_EVERY_S regardless.
    {
        let (gw, defender, rs, run_id) = (gw.clone(), defender.clone(), rs.clone(), run_id.clone());
        // host:port from the hostd URL (http only, literal IP), for a raw-TCP POST with no runtime.
        let hostport = hostd_url.trim_start_matches("http://").to_string();
        let rep_token = get("TOKEN")?;
        let log_dropped = h.log_dropped_handle();
        std::thread::spawn(move || {
            let mut seq = 0u64;
            loop {
                let (phase, vm1_state, vmi) = { let g = rs.lock().unwrap(); (g.0.clone(), g.1, g.2.clone()) };
                seq += 1;
                let r = Vm2Report {
                    run_id: run_id.clone(),
                    seq,
                    sent_at: now_unix(),
                    phase,
                    vm1_state,
                    vmi,
                    gateway_allowed: gw.allowed.load(Ordering::SeqCst),
                    gateway_denied: gw.denied.load(Ordering::SeqCst),
                    defender_actions: defender.stats().actions.len() as u64,
                    log_dropped: log_dropped.load(Ordering::SeqCst),
                };
                let body = serde_json::to_vec(&r).unwrap();
                if let Err(e) = raw_http_post(&hostport, "/v1/report", &rep_token, &body) {
                    tracing::warn!(error = %e, "report failed");
                }
                std::thread::sleep(Duration::from_secs(REPORT_EVERY_S));
            }
        });
    }
    // helpers the main flow uses to publish state to the reporter
    let set_phase = { let rs = rs.clone(); move |p: &str| rs.lock().unwrap().0 = p.to_string() };
    let set_vm1 = { let rs = rs.clone(); move |v: Vm1State| rs.lock().unwrap().1 = v };
    let set_vmi = { let rs = rs.clone(); move |v: VmiResult| rs.lock().unwrap().2 = v };
    let mut vm1_state = Vm1State::NotStarted;
    let mut vmi_result = VmiResult::Unmeasured;

    // ---- wait for the prestage lease (epoch 0)
    let mut high_water = 0u64;
    let mut deadline: Option<Deadline> = None;
    let wait_start = Instant::now();
    while deadline.is_none() {
        anyhow::ensure!(wait_start.elapsed() < Duration::from_secs(60), "no prestage lease within 60s");
        if let Ok(Some((l, _))) = h.verified_lease(&controller_pk, &run_id).await {
            if let Ok(d) = Deadline::accept(&l, high_water, now_unix()) {
                high_water = l.fencing_token;
                deadline = Some(d);
            }
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // ---- prestage (gate open on the Mac side only now)
    let staged = match prestage::run(Path::new(HARNESS_SRC), &run_dir, &model) {
        Ok(s) => s,
        Err(e) => {
            h.log("prestage_failed", e.to_string(), serde_json::json!({}));
            anyhow::bail!("prestage failed: {e}");
        }
    };
    h.log("prestage_complete", "dependency image built", serde_json::json!({"image_digest": staged.image_digest, "manifest_digest": staged.manifest_digest, "files": staged.manifest["file_count"]}));
    h.prestage_done(&staged.manifest_digest, &staged.image_digest).await?;

    // ---- wait for the eval lease (epoch ≥ 1): hostd seals the gate first
    let (hostd_ip, hostd_port) = hostd_url.trim_start_matches("http://").split_once(':').map(|(a, b)| (a.to_string(), b.to_string())).unwrap_or(("192.168.5.2".into(), "7001".into()));
    loop {
        match h.verified_lease(&controller_pk, &run_id).await {
            Ok(Some((l, gate))) => {
                if let Ok(d) = Deadline::accept(&l, high_water, now_unix()) {
                    high_water = l.fencing_token;
                    let epoch = d.epoch;
                    deadline = Some(d);
                    if epoch >= 1 && gate == GateState::Sealed {
                        break;
                    }
                }
            }
            Ok(None) => anyhow::bail!("lease withdrawn before eval started"),
            Err(e) => warn!(error = %e, "lease poll failed"),
        }
        if deadline.as_ref().map(|d| d.expired(now_unix())).unwrap_or(true) {
            anyhow::bail!("prestage lease expired before eval");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    // vm2_self_restrict DISABLED for the MVP: it is an untrusted, redundant second egress
    // layer, and its output-drop policy was starving the report path to hostd. The Mac-owned pf
    // user-gate is the enforcing egress control (proven in §13); VM2 self-restriction is a
    // post-MVP refinement (must allow-list the hostd path without dropping in-flight reports).
    let _ = (&hostd_ip, &hostd_port);
    set_phase("eval");

    // ---- VM1: verify image, network first, gateway up, then boot
    prestage::verify(&staged.image, &staged.image_digest)?;
    vm1::Vm1::net_up()?;
    let listener = tokio::net::TcpListener::bind("172.16.0.1:3128").await?;
    let gw2 = gw.clone();
    tokio::spawn(async move { axum::serve(listener, gateway::router(gw2)).await.unwrap() });
    // Disposable per-run disk = a qcow2 overlay on the read-only base image (fast, no full copy).
    let base_disk = Path::new(VM1_DIR).join("vm1.qcow2");
    let overlay = run_dir.join("vm1-overlay.qcow2");
    let _ = std::fs::remove_file(&overlay);
    let qi = std::process::Command::new("/usr/bin/qemu-img")
        .args(["create", "-q", "-f", "qcow2", "-F", "qcow2", "-b", base_disk.to_str().unwrap(), overlay.to_str().unwrap()])
        .status()?;
    anyhow::ensure!(qi.success(), "qemu-img overlay create failed");
    let firmware = Path::new(VM1_DIR).join("QEMU_EFI.fd");
    let varstore = run_dir.join("efivars.fd");
    std::fs::copy(Path::new(VM1_DIR).join("efivars-template.fd"), &varstore)?;
    let mut vm = vm1::Vm1::new(&run_dir.join("vm1"));
    if let Err(e) = vm.boot(&firmware, &varstore, &overlay, &staged.image, 2, 4096) {
        h.log("vm1_boot_failed", e.to_string(), serde_json::json!({}));
        anyhow::bail!("VM1 boot failed: {e}");
    }
    vm1_state = vm.state; set_vm1(vm1_state);
    h.log("vm1_booted", "VM1 up", serde_json::json!({"boot_ms": vm.boot_ms, "pid": vm.pid()}));

    // ---- VMI baseline (pre-adversarial: the harness waits for VMI_BASELINE_OK on its console? no —
    // the harness starts on its own; the baseline is taken as early as the symbols are visible.)
    let mut vmi = None;
    let vmi_work = run_dir.join("vm1");
    let ks_wait = Instant::now();
    while vmi.is_none() && ks_wait.elapsed() < Duration::from_secs(30) {
        if let Some(km) = vm.kmem() {
            let mut m = vmi::Vmi::new(km.clone(), &vmi_work);
            vmi_result = m.measure(&mut vm, || true); set_vmi(vmi_result.clone());
            h.log("vmi_baseline", "VM1 kernel baseline", serde_json::json!({"kmem": km, "baseline": m.baseline, "result": vmi_result}));
            vmi = Some(m);
        } else {
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }
    if vmi.is_none() {
        vmi_result = VmiResult::Unknown { reason: "kernel symbols never reported".into() }; set_vmi(vmi_result.clone());
        h.log("vmi_unavailable", "no KSYMS line from VM1 init", serde_json::json!({}));
    }
    let mut last_vmi = Instant::now();
    let mut done_reported = false;

    // ---- eval loop
    loop {
        tokio::time::sleep(Duration::from_millis(500)).await;
        // rung-1 lease copy
        match h.verified_lease(&controller_pk, &run_id).await {
            Ok(Some((l, _))) => {
                if let Ok(d) = Deadline::accept(&l, high_water, now_unix()) {
                    high_water = l.fencing_token;
                    deadline = Some(d);
                }
            }
            Ok(None) => deadline = None, // withdrawn ⇒ fail closed now
            Err(e) => warn!(error = %e, "hostd unreachable; lease will expire"),
        }
        let active = deadline.as_ref().map(|d| !d.expired(now_unix())).unwrap_or(false);
        gw.lease_active.store(active, Ordering::SeqCst);
        // defender's TerminateVm1 is executed locally, immediately
        let terminate = defender.stats().actions.iter().any(|a| matches!(a, DefenderAction::TerminateVm1 { .. }));
        if (!active || terminate) && vm.alive() {
            let why = if terminate { "defender terminate" } else { "lease lost (rung-1 fail-closed)" };
            vm1::Vm1::net_deny_all();
            let lat = vm.kill()?;
            vm1_state = vm.state; set_vm1(vm1_state); set_phase("stopped");
            h.log("vm1_killed", why, serde_json::json!({"kill_ms": lat.as_millis() as u64, "nft": vm1::Vm1::nft_drop_counters()}));
        }
        if vm.alive() {
            vm1_state = vm.state; set_vm1(vm1_state);
            if !done_reported {
                if let Some(d) = vm.harness_done() {
                    done_reported = true;
                    h.log("harness_done", "VM1 harness finished", d);
                }
            }
            if let Some(m) = vmi.as_mut() {
                if last_vmi.elapsed() >= Duration::from_secs(VMI_EVERY_S) {
                    last_vmi = Instant::now();
                    let dl = deadline.clone();
                    vmi_result = m.measure(&mut vm, move || dl.as_ref().map(|d| !d.expired(now_unix())).unwrap_or(false)); set_vmi(vmi_result.clone());
                    // VMI is ADVISORY for the MVP (does not trip): a coarse iomem-region hash can't
                    // distinguish a rootkit from the kernel's own legitimate self-patching of .text
                    // AND rodata without an immutable-region/patch-site map (deferred; Codex F7). We
                    // record the measurement as evidence for the trusted side to assess; a real
                    // VMI tripwire (e.g. sys_call_table-scoped) is roadmap. Enforcement rests on the
                    // egress gate, the fail-closed lease, defender authority, and the out-of-band kill.
                    if let VmiResult::Tampered { .. } = &vmi_result {
                        h.log("vmi_drift", "kernel measurement changed (advisory; not a trip)", serde_json::json!(vmi_result));
                    }
                } else if let VmiResult::Healthy { measured_at, .. } = &vmi_result {
                    if now_unix().saturating_sub(*measured_at) > VMI_MAX_AGE_S {
                        vmi_result = VmiResult::Unknown { reason: "measurement too old".into() }; set_vmi(vmi_result.clone());
                    }
                }
            }
        } else if vm1_state != Vm1State::Killed {
            vm1_state = Vm1State::Killed; set_vm1(vm1_state); set_phase("stopped");
            h.log("vm1_exited", "firecracker exited on its own", serde_json::json!({"serial_tail": vm.serial_tail(5)}));
        }
    }
}

#[allow(dead_code)]
fn _unused(_: &mut vm1::Vm1) {
    info!("");
}
