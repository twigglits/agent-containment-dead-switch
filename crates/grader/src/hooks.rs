//! Bounded operator hooks. Every command is an absolute, private operator-installed executable;
//! no shell interpolation, inherited environment, credentials or submitted arguments are used.
//! Hook process groups are killed on deadline, shutdown, malformed output, and normal completion.

use crate::{
    Authority, FrozenObservation, GlobalTeardownObservation, JobContext, LaunchObservation,
    SandboxHooks, TeardownObservation,
};
use anyhow::{ensure, Context};
use serde::de::DeserializeOwned;
use std::io::Read;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

const MAX_HOOK_OUTPUT: usize = 4096;
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Clone)]
pub struct HookPaths {
    pub launch: PathBuf,
    pub observe: PathBuf,
    pub destroy: PathBuf,
    pub destroy_all: PathBuf,
}

impl HookPaths {
    pub fn validate(&self) -> anyhow::Result<()> {
        for path in [&self.launch, &self.observe, &self.destroy, &self.destroy_all] {
            ensure!(path.is_absolute(), "hook path must be absolute");
            crate::state::check_trusted_ancestors(path)?;
            let metadata = std::fs::symlink_metadata(path)?;
            ensure!(
                metadata.is_file()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == unsafe { libc::geteuid() }
                    && metadata.permissions().mode() & 0o022 == 0
                    && metadata.permissions().mode() & 0o100 != 0,
                "hook must be an owned executable, unwritable by other users"
            );
        }
        Ok(())
    }
}

pub struct ShellHooks {
    pub paths: HookPaths,
}

impl ShellHooks {
    fn invoke<T: DeserializeOwned>(
        &self,
        path: &Path,
        job: Option<&JobContext>,
        authority: Option<&Authority<'_>>,
        max_time: Duration,
    ) -> anyhow::Result<T> {
        let mut command = Command::new(path);
        command
            .env_clear()
            .env("PATH", "/usr/sbin:/usr/bin:/sbin:/bin")
            .env("LANG", "C")
            .env("LC_ALL", "C")
            .env("PYTHONDONTWRITEBYTECODE", "1");
        if let Some(ctx) = job {
            command
                .env("DS_JOB_ID", &ctx.job.job_id)
                .env("DS_SANDBOX_ID", &ctx.sandbox_id)
                .env("DS_JOB_DIR", &ctx.job_dir)
                .env("DS_SUBMISSION_PATH", &ctx.submission_path)
                .env("DS_SUBMISSION_DIGEST", &ctx.job.submission_digest)
                .env("DS_TASK_ID", &ctx.job.task_id)
                .env("DS_INPUT_VERSION", &ctx.job.input_version)
                .env("DS_SCORER_VERSION", &ctx.job.scorer_version)
                .env("DS_JOB_EXPIRES_AT", ctx.job.expires_at.to_string())
                .env("DS_WALL_TIMEOUT_SECS", ctx.wall_timeout_secs.to_string())
                .env("DS_CAPTURE_PATH", &ctx.capture_path);
        }
        let bytes = run_bounded(command, authority, max_time)?;
        serde_json::from_slice(&bytes).context("malformed trusted hook observations")
    }
}

impl SandboxHooks for ShellHooks {
    fn launch(&self, job: &JobContext, authority: &Authority<'_>) -> anyhow::Result<LaunchObservation> {
        authority.check()?;
        ensure!(
            authority.deadline.remaining_ms(deadswitch_common::now_unix()) > 20_000,
            "insufficient remaining lifecycle authority"
        );
        self.invoke(&self.paths.launch, Some(job), Some(authority), Duration::from_secs(95))
    }

    fn observe(&self, job: &JobContext, authority: &Authority<'_>) -> anyhow::Result<FrozenObservation> {
        self.invoke(&self.paths.observe, Some(job), Some(authority), Duration::from_secs(5))
    }

    fn destroy(&self, job: &JobContext) -> anyhow::Result<TeardownObservation> {
        self.invoke(&self.paths.destroy, Some(job), None, CLEANUP_TIMEOUT)
    }

    fn destroy_all(&self) -> anyhow::Result<GlobalTeardownObservation> {
        self.invoke(&self.paths.destroy_all, None, None, CLEANUP_TIMEOUT)
    }
}

struct ChildGroup {
    child: Child,
}

impl Drop for ChildGroup {
    fn drop(&mut self) {
        // The hook cannot retain a hanging child/pipe after return. The independent systemd
        // sandbox cgroup is deliberately cleaned by destroy, with positive trusted confirmation.
        unsafe {
            libc::kill(-(self.child.id() as i32), libc::SIGKILL);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

pub(crate) fn run_bounded(
    mut command: Command,
    authority: Option<&Authority<'_>>,
    max_time: Duration,
) -> anyhow::Result<Vec<u8>> {
    if let Some(authority) = authority {
        authority.check()?;
    }
    command
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        // Do not echo candidate-derived hook error strings into APIs or unbounded log files.
        .stderr(Stdio::null())
        .process_group(0);
    let mut group = ChildGroup {
        child: command.spawn().context("hook spawn failed")?,
    };
    let mut stdout = group.child.stdout.take().context("hook stdout unavailable")?;
    let fd = stdout.as_raw_fd();
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    ensure!(flags >= 0, "hook pipe flags unavailable");
    ensure!(unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } >= 0, "hook pipe nonblocking failed");
    let until = Instant::now() + max_time;
    let mut output = Vec::new();
    let mut child_exit = None;
    let mut eof = false;
    loop {
        if let Some(authority) = authority {
            authority.check()?;
        }
        ensure!(Instant::now() < until, "trusted hook timed out");
        // Drain only a bounded amount per tick; an output flood must not starve the clock check.
        for _ in 0..5 {
            let mut buffer = [0_u8; 1024];
            match stdout.read(&mut buffer) {
                Ok(0) => {
                    eof = true;
                    break;
                }
                Ok(count) => {
                    output.extend_from_slice(&buffer[..count]);
                    ensure!(output.len() <= MAX_HOOK_OUTPUT, "trusted hook output exceeded bound");
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => break,
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error.into()),
            }
        }
        if child_exit.is_none() {
            child_exit = group.child.try_wait()?;
        }
        if let Some(status) = child_exit {
            ensure!(status.success(), "trusted hook failed");
            if eof {
                return Ok(output);
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
