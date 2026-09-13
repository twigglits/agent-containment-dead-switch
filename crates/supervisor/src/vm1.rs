//! VM1 lifecycle under **QEMU/KVM** (spec decision 9, amended 2026-09-12 for browser support).
//!
//! QEMU is a direct child (pid tracked, exit confirmed by waitpid). Control is over QMP (a JSON
//! line protocol on a unix socket): `stop`/`cont` for the VMI pause, `pmemsave` to dump exact
//! guest-physical ranges for the scoped kernel measurement, `quit`/SIGKILL to terminate. The guest
//! CPU model exposes no nested-virt (`-cpu host` without vmx/svm), a virtio-only device set, and
//! `-sandbox on` seccomp. The guest reaches only tap0 → the gateway (docs §6).

use anyhow::{anyhow, Context};
use deadswitch_common::Vm1State;
use serde_json::json;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const NET_SCRIPT: &str = "/usr/local/lib/deadswitch/vm1-net.sh";
pub const QEMU: &str = "/usr/bin/qemu-system-aarch64";

pub struct Vm1 {
    pub work: PathBuf,
    pub qmp: PathBuf,
    pub serial: PathBuf,
    child: Option<Child>,
    pub state: Vm1State,
    pub boot_ms: Option<u64>,
}

/// Physical memory ranges the guest reports for its own kernel (from /proc/iomem, printed by the
/// pre-adversarial init as a `KMEM {...}` serial line). Physical because QMP `pmemsave` takes a
/// guest-physical address; stable under `nokaslr`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Kmem {
    pub code_start: u64,
    pub code_end: u64,
    pub rodata_start: u64,
    pub rodata_end: u64,
}

impl Vm1 {
    pub fn new(work: &Path) -> Self {
        Vm1 {
            work: work.into(),
            qmp: work.join("qmp.sock"),
            serial: work.join("serial.log"),
            child: None,
            state: Vm1State::NotStarted,
            boot_ms: None,
        }
    }

    pub fn net_up() -> anyhow::Result<()> {
        let out = Command::new("/bin/bash")
            .arg(NET_SCRIPT)
            .output()
            .context("vm1-net.sh")?;
        anyhow::ensure!(
            out.status.success(),
            "vm1-net.sh: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        Ok(())
    }

    pub fn net_deny_all() {
        let _ = Command::new("/usr/sbin/nft")
            .args(["flush", "chain", "inet", "vm1", "input"])
            .status();
        let _ = Command::new("/usr/sbin/nft")
            .args([
                "add", "rule", "inet", "vm1", "input", "iifname", "tap0", "counter", "drop",
            ])
            .status();
        let _ = Command::new("/usr/sbin/nft")
            .args(["flush", "chain", "inet", "vm1", "output"])
            .status();
        let _ = Command::new("/usr/sbin/nft")
            .args([
                "add", "rule", "inet", "vm1", "output", "oifname", "tap0", "counter", "drop",
            ])
            .status();
        let _ = Command::new("/usr/sbin/conntrack")
            .args(["-F"])
            .stderr(Stdio::null())
            .status();
    }

    pub fn nft_drop_counters() -> serde_json::Value {
        let out = Command::new("/usr/sbin/nft")
            .args(["-j", "list", "table", "inet", "vm1"])
            .output();
        let Ok(out) = out else { return json!(null) };
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or(json!(null));
        let mut drops = 0u64;
        if let Some(items) = v["nftables"].as_array() {
            for it in items {
                if let Some(exprs) = it["rule"]["expr"].as_array() {
                    if exprs.iter().any(|e| e.get("drop").is_some()) {
                        for e in exprs {
                            if let Some(p) = e["counter"]["packets"].as_u64() {
                                drops += p;
                            }
                        }
                    }
                }
            }
        }
        json!({ "tap0_dropped_packets": drops })
    }

    /// Boot the browser-capable VM1 disk under UEFI. `disk` is the qcow2 (self-contained: baked
    /// netplan static IP, the pre-adversarial init unit, browser + harness). `deps` is the read-only
    /// prestaged image. `firmware` = QEMU_EFI code; `varstore` = a per-run writable EFI var copy.
    /// KASLR is fine: the guest reports its own per-boot kernel physical ranges (KMEM), and VMI
    /// compares within the same boot, so no `nokaslr` is needed.
    pub fn boot(
        &mut self,
        firmware: &Path,
        varstore: &Path,
        disk: &Path,
        deps: &Path,
        vcpus: u32,
        mem_mib: u32,
    ) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.work)?;
        let _ = std::fs::remove_file(&self.qmp);
        // Accelerate with KVM if VM2 exposes it (nested virt); else TCG (slow, still correct).
        let accel = if Path::new("/dev/kvm").exists() {
            "accel=kvm"
        } else {
            "accel=tcg"
        };
        let cpu = if Path::new("/dev/kvm").exists() {
            "host"
        } else {
            "cortex-a57"
        };
        let mut cmd = Command::new(QEMU);
        cmd.args([
            "-machine",
            &format!("virt,gic-version=3,{accel}"),
            // -cpu host with NO +vmx/+svm ⇒ VM1 gets no nested-virt (spec decision 9 / Januscape).
            "-cpu",
            cpu,
            "-smp",
            &vcpus.to_string(),
            "-m",
            &mem_mib.to_string(),
            "-nographic",
            "-sandbox",
            "on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny",
            "-nodefaults",
            "-no-user-config",
            "-drive",
            &format!(
                "if=pflash,format=raw,unit=0,readonly=on,file={}",
                firmware.display()
            ),
            "-drive",
            &format!("if=pflash,format=raw,unit=1,file={}", varstore.display()),
            "-drive",
            &format!("if=virtio,format=qcow2,file={}", disk.display()),
            "-drive",
            &format!("if=virtio,format=raw,file={},readonly=on", deps.display()),
            "-netdev",
            "tap,id=n0,ifname=tap0,script=no,downscript=no",
            "-device",
            "virtio-net-pci,netdev=n0,mac=06:00:AC:10:00:02,romfile=",
            "-device",
            "virtio-gpu-pci", // browser rendering surface
            "-device",
            "virtio-rng-pci",
            "-serial",
            "chardev:ser0",
            "-chardev",
            &format!("file,id=ser0,path={}", self.serial.display()),
            "-qmp",
            &format!("unix:{},server=on,wait=off", self.qmp.display()),
        ]);
        let child = cmd
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .context("spawn qemu")?;
        self.child = Some(child);
        self.state = Vm1State::Booting;
        let t0 = Instant::now();
        for _ in 0..1200 {
            std::thread::sleep(Duration::from_millis(100));
            if let Some(c) = self.child.as_mut() {
                if let Some(st) = c.try_wait()? {
                    return Err(anyhow!(
                        "qemu exited during boot: {st}; serial tail:\n{}",
                        self.serial_tail(25)
                    ));
                }
            }
            let s = std::fs::read_to_string(&self.serial).unwrap_or_default();
            if s.contains("KMEM ") || s.contains("VM1_READY") {
                self.state = Vm1State::Running;
                self.boot_ms = Some(t0.elapsed().as_millis() as u64);
                return Ok(());
            }
        }
        Err(anyhow!(
            "VM1 did not signal ready in 120s; serial tail:\n{}",
            self.serial_tail(25)
        ))
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    pub fn serial_tail(&self, n: usize) -> String {
        let s = std::fs::read_to_string(&self.serial).unwrap_or_default();
        let lines: Vec<&str> = s.lines().collect();
        lines[lines.len().saturating_sub(n)..].join("\n")
    }

    fn serial_json_line(&self, prefix: &str) -> Option<serde_json::Value> {
        let s = std::fs::read_to_string(&self.serial).ok()?;
        // Return the LAST parseable line carrying the prefix — so a malformed/partial earlier line
        // (e.g. a truncated burst) does not mask a later valid one, and the freshest marker wins.
        s.lines()
            .filter(|l| l.trim_start().starts_with(prefix))
            .filter_map(|l| {
                serde_json::from_str(l.trim_start().trim_start_matches(prefix).trim()).ok()
            })
            .next_back()
    }

    /// Physical kernel ranges the guest reported (from /proc/iomem) before the harness started.
    pub fn kmem(&self) -> Option<Kmem> {
        let v = self.serial_json_line("KMEM ")?;
        let g = |k: &str| {
            v[k].as_str()
                .and_then(|h| u64::from_str_radix(h.trim_start_matches("0x"), 16).ok())
        };
        Some(Kmem {
            code_start: g("code_start")?,
            code_end: g("code_end")?,
            rodata_start: g("rodata_start")?,
            rodata_end: g("rodata_end")?,
        })
    }

    pub fn harness_done(&self) -> Option<serde_json::Value> {
        self.serial_json_line("HARNESS_DONE ")
    }

    // ---- QMP ----
    fn qmp_call(
        &self,
        execute: &str,
        args: serde_json::Value,
    ) -> anyhow::Result<serde_json::Value> {
        let mut stream = UnixStream::connect(&self.qmp)
            .with_context(|| format!("connect QMP {}", self.qmp.display()))?;
        stream.set_read_timeout(Some(Duration::from_secs(30)))?;
        let mut reader = BufReader::new(stream.try_clone()?);
        let mut line = String::new();
        reader.read_line(&mut line)?; // greeting
        writeln!(stream, "{}", json!({"execute":"qmp_capabilities"}))?;
        // read until the return for capabilities
        loop {
            line.clear();
            reader.read_line(&mut line)?;
            let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap_or(json!({}));
            if v.get("return").is_some() || v.get("error").is_some() {
                break;
            }
        }
        let req = if args.is_null() {
            json!({"execute": execute})
        } else {
            json!({"execute": execute, "arguments": args})
        };
        writeln!(stream, "{req}")?;
        loop {
            line.clear();
            if reader.read_line(&mut line)? == 0 {
                return Err(anyhow!("QMP closed before reply to {execute}"));
            }
            let v: serde_json::Value = serde_json::from_str(line.trim()).unwrap_or(json!({}));
            if let Some(e) = v.get("error") {
                return Err(anyhow!("QMP {execute} error: {e}"));
            }
            if let Some(r) = v.get("return") {
                return Ok(r.clone());
            }
            // else an async event line: skip
        }
    }

    pub fn pause(&mut self) -> anyhow::Result<()> {
        self.qmp_call("stop", serde_json::Value::Null)?;
        self.state = Vm1State::Paused;
        Ok(())
    }
    pub fn resume(&mut self) -> anyhow::Result<()> {
        self.qmp_call("cont", serde_json::Value::Null)?;
        self.state = Vm1State::Running;
        Ok(())
    }

    /// Save a guest-physical range to a host file and return its sha256 + bytes read back.
    pub fn pmemsave(&self, phys: u64, size: u64, out: &Path) -> anyhow::Result<()> {
        let _ = std::fs::remove_file(out);
        self.qmp_call(
            "pmemsave",
            json!({"val": phys, "size": size, "filename": out}),
        )?;
        Ok(())
    }

    pub fn read_file_sha256(out: &Path, expect_len: u64) -> anyhow::Result<String> {
        use sha2::{Digest, Sha256};
        let mut f = std::fs::File::open(out)?;
        let len = f.metadata()?.len();
        anyhow::ensure!(
            len == expect_len,
            "pmemsave wrote {len} bytes, expected {expect_len}"
        );
        f.seek(SeekFrom::Start(0))?;
        let mut h = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = f.read(&mut buf)?;
            if n == 0 {
                break;
            }
            h.update(&buf[..n]);
        }
        Ok(hex::encode(h.finalize()))
    }

    pub fn alive(&mut self) -> bool {
        match self.child.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        }
    }

    /// SIGKILL the QEMU process and confirm exit via waitpid. Idempotent.
    pub fn kill(&mut self) -> anyhow::Result<Duration> {
        let t0 = Instant::now();
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            c.wait()?;
        }
        self.state = Vm1State::Killed;
        let _ = std::fs::remove_file(&self.qmp);
        Ok(t0.elapsed())
    }
}
