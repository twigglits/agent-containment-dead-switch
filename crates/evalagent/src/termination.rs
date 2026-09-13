//! Optional Phase 3 bridge: an already stopped eval may become eligible for grading only after
//! successful destruction AND a separate bounded host observation of absence. This grants no lease.

use super::{hook_command, ObserveOut, RunArgs};
use anyhow::{ensure, Context};
use deadswitch_common::{now_unix, Signed, AUD_CONTROLLER, PROTO_V};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::{
    io::Read,
    os::{fd::AsRawFd, unix::process::CommandExt},
    process::{Child, Stdio},
    time::{Duration, Instant},
};

const OBSERVE_TIMEOUT: Duration = Duration::from_secs(2);
const OBSERVE_BYTES: usize = 4096;
const NOTIFY_TIMEOUT: Duration = Duration::from_secs(3);

/// Existing controller /terminated protocol, shared semantically with the Phase 1 hostd. The
/// signing key is the already-loaded, enrolled hostd key; no key is generated or reloaded on error.
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Terminated {
    v: u32,
    #[serde(rename = "type")]
    kind: String,
    pub(super) run_id: String,
    aud: String,
    pub(super) incarnation: String,
    pub(super) issued_at: u64,
    pub(super) latency_ms: u64,
}

fn stop_observer(child: &mut Child) {
    // The shell is a process-group leader. It is not reaped until stdout has closed, so its PID
    // cannot be recycled before this negative-PGID signal. Kill children holding the output pipe.
    if let Ok(pid) = i32::try_from(child.id()) {
        unsafe { libc::kill(-pid, libc::SIGKILL); }
    }
    let _ = child.kill();
    let deadline = Instant::now() + Duration::from_millis(250);
    while Instant::now() < deadline {
        if matches!(child.try_wait(), Ok(Some(_))) { return; }
        std::thread::sleep(Duration::from_millis(5));
    }
    // An unobservable/stuck observer is never evidence of teardown. Its kill has been requested;
    // optional notification is withheld rather than waiting indefinitely during shutdown.
}

/// Same trusted hook/schema as observe_vm2, with a new bounded execution/capture used exclusively
/// after destruction. The existing health-observation and shutdown hooks remain unchanged.
fn observe_stopped(a: &RunArgs) -> anyhow::Result<()> {
    let mut child = hook_command(a, &a.observe_cmd)
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::null())
        .process_group(0).spawn().context("teardown observe spawn")?;
    let mut stdout = child.stdout.take().expect("piped observer stdout");
    let descriptor = stdout.as_raw_fd();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        stop_observer(&mut child);
        anyhow::bail!("cannot bound teardown observation");
    }
    let deadline = Instant::now() + OBSERVE_TIMEOUT;
    let mut bytes = Vec::new();
    let mut eof = false;
    loop {
        let mut buffer = [0; 1024];
        match stdout.read(&mut buffer) {
            Ok(0) => eof = true,
            Ok(size) => {
                bytes.extend_from_slice(&buffer[..size]);
                if bytes.len() > OBSERVE_BYTES {
                    stop_observer(&mut child);
                    anyhow::bail!("teardown observation exceeds bound");
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                stop_observer(&mut child);
                return Err(error).context("teardown observation read");
            }
        }
        if eof {
            match child.try_wait() {
                Ok(Some(status)) => {
                    ensure!(status.success(), "teardown observation failed");
                    let observed: ObserveOut = serde_json::from_slice(&bytes).context("teardown observation invalid")?;
                    ensure!(observed.running == Some(false) && observed.pid.is_none(),
                        "teardown not independently confirmed");
                    return Ok(());
                }
                Ok(None) => {}
                Err(error) => {
                    stop_observer(&mut child);
                    return Err(error).context("teardown observer wait");
                }
            }
        }
        if Instant::now() >= deadline {
            stop_observer(&mut child);
            anyhow::bail!("teardown observation timed out");
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

pub(super) fn notify_after_destroy(a: &RunArgs, key: &SigningKey, started: Instant) -> anyhow::Result<()> {
    observe_stopped(a)?;
    let mut endpoint = reqwest::Url::parse(&a.controller_url).context("controller URL")?;
    ensure!(matches!(endpoint.scheme(), "http" | "https") && endpoint.host().is_some()
        && endpoint.username().is_empty() && endpoint.password().is_none()
        && endpoint.query().is_none() && endpoint.fragment().is_none()
        && endpoint.path() == "/", "controller URL must be a bare trusted origin");
    // Preserve the configured controller scheme/host/port; no callback URL or second authority.
    endpoint.set_path("/terminated");
    let client = reqwest::blocking::Client::builder().no_proxy()
        .redirect(reqwest::redirect::Policy::none()).retry(reqwest::retry::never())
        .http1_only().pool_max_idle_per_host(0)
        .connect_timeout(Duration::from_secs(2)).timeout(NOTIFY_TIMEOUT).build()?;
    let message = Terminated { v: PROTO_V, kind: "terminated".into(), run_id: a.run_id.clone(),
        aud: AUD_CONTROLLER.into(), incarnation: a.incarnation.clone(), issued_at: now_unix(),
        latency_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX) };
    let signed = Signed::sign(key, "hostd", &message);
    let response = client.post(endpoint).json(&signed).send().context("termination notification")?;
    ensure!(response.status().is_success(), "controller refused termination notification");
    // The body is irrelevant, never parsed or relayed to the workload. Failure never restores
    // authority, and a missed notification leaves operator grading authorization unavailable.
    Ok(())
}
