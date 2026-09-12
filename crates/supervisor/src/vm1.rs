//! VM1 lifecycle: Firecracker as a direct child (pid tracked, exit confirmed by waitpid), its API
//! over the unix socket, serial-log parsing, and the VM2-side network chain around tap0.

use anyhow::{anyhow, Context};
use deadswitch_common::Vm1State;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

pub const DRAM_BASE: u64 = 0x8000_0000; // aarch64 Firecracker guest DRAM start
pub const TEXT_OFFSET: u64 = 0x8_0000; // Image header text_offset for the CI kernels (checked at boot)
pub const NET_SCRIPT: &str = "/usr/local/lib/deadswitch/vm1-net.sh";

pub struct Vm1 {
    pub work: PathBuf,
    pub api: PathBuf,
    pub serial: PathBuf,
    child: Option<Child>,
    pub state: Vm1State,
    pub boot_ms: Option<u64>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Ksyms {
    pub _text: u64,
    pub _stext: u64,
    pub _etext: u64,
    pub __start_rodata: u64,
    pub __end_rodata: u64,
    pub sys_call_table: u64,
}

impl Vm1 {
    pub fn new(work: &Path) -> Self {
        Vm1 { work: work.into(), api: work.join("fc.sock"), serial: work.join("serial.log"), child: None, state: Vm1State::NotStarted, boot_ms: None }
    }

    /// tap0 + nftables BEFORE the VMM starts (docs §6).
    pub fn net_up() -> anyhow::Result<()> {
        let out = Command::new("/bin/bash").arg(NET_SCRIPT).output().context("vm1-net.sh")?;
        anyhow::ensure!(out.status.success(), "vm1-net.sh: {}", String::from_utf8_lossy(&out.stderr));
        Ok(())
    }

    /// Deny everything on tap0 and drop established flows.
    pub fn net_deny_all() {
        let _ = Command::new("/usr/sbin/nft").args(["flush", "chain", "inet", "vm1", "input"]).status();
        let _ = Command::new("/usr/sbin/nft").args(["add", "rule", "inet", "vm1", "input", "iifname", "tap0", "counter", "drop"]).status();
        let _ = Command::new("/usr/sbin/nft").args(["flush", "chain", "inet", "vm1", "output"]).status();
        let _ = Command::new("/usr/sbin/nft").args(["add", "rule", "inet", "vm1", "output", "oifname", "tap0", "counter", "drop"]).status();
        let _ = Command::new("/usr/sbin/conntrack").args(["-F"]).stderr(Stdio::null()).status();
    }

    pub fn nft_drop_counters() -> serde_json::Value {
        let out = Command::new("/usr/sbin/nft").args(["-j", "list", "table", "inet", "vm1"]).output();
        let Ok(out) = out else { return serde_json::json!(null) };
        let v: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap_or(serde_json::json!(null));
        let mut drops = 0u64;
        if let Some(items) = v["nftables"].as_array() {
            for it in items {
                if let Some(exprs) = it["rule"]["expr"].as_array() {
                    let is_drop = exprs.iter().any(|e| e.get("drop").is_some());
                    if is_drop {
                        for e in exprs {
                            if let Some(p) = e["counter"]["packets"].as_u64() {
                                drops += p;
                            }
                        }
                    }
                }
            }
        }
        serde_json::json!({"tap0_dropped_packets": drops})
    }

    pub fn boot(&mut self, kernel: &Path, rootfs: &Path, deps_image: &Path, vcpus: u32, mem_mib: u32) -> anyhow::Result<()> {
        std::fs::create_dir_all(&self.work)?;
        let _ = std::fs::remove_file(&self.api);
        let cfg = serde_json::json!({
            "boot-source": {
                "kernel_image_path": kernel,
                "boot_args": "keep_bootcon console=ttyS0 reboot=k panic=1 pci=off nokaslr ip=172.16.0.2::172.16.0.1:255.255.255.252::eth0:off init=/sbin/init"
            },
            "drives": [
                {"drive_id": "rootfs", "path_on_host": rootfs, "is_root_device": true, "is_read_only": false},
                {"drive_id": "deps", "path_on_host": deps_image, "is_root_device": false, "is_read_only": true}
            ],
            "network-interfaces": [{"iface_id": "eth0", "guest_mac": "06:00:AC:10:00:02", "host_dev_name": "tap0"}],
            "machine-config": {"vcpu_count": vcpus, "mem_size_mib": mem_mib, "smt": false}
        });
        let cfg_path = self.work.join("config.json");
        std::fs::write(&cfg_path, serde_json::to_vec_pretty(&cfg)?)?;
        let serial = std::fs::File::create(&self.serial)?;
        let t0 = Instant::now();
        let child = Command::new("/usr/local/bin/firecracker")
            .args(["--api-sock", self.api.to_str().unwrap(), "--config-file", cfg_path.to_str().unwrap()])
            .stdin(Stdio::null())
            .stdout(serial.try_clone()?)
            .stderr(serial)
            .spawn()
            .context("spawn firecracker")?;
        self.child = Some(child);
        self.state = Vm1State::Booting;
        // wait for the serial console to show userland
        for _ in 0..600 {
            std::thread::sleep(Duration::from_millis(100));
            if let Some(c) = self.child.as_mut() {
                if let Some(st) = c.try_wait()? {
                    return Err(anyhow!("firecracker exited during boot: {st}; serial tail: {}", self.serial_tail(20)));
                }
            }
            let s = std::fs::read_to_string(&self.serial).unwrap_or_default();
            if s.contains("KSYMS ") || s.contains("login:") {
                self.state = Vm1State::Running;
                self.boot_ms = Some(t0.elapsed().as_millis() as u64);
                return Ok(());
            }
        }
        Err(anyhow!("VM1 did not reach userland in 60s; serial tail: {}", self.serial_tail(20)))
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    pub fn serial_tail(&self, n: usize) -> String {
        let s = std::fs::read_to_string(&self.serial).unwrap_or_default();
        let lines: Vec<&str> = s.lines().collect();
        lines[lines.len().saturating_sub(n)..].join("\n")
    }

    /// The pre-adversarial init in VM1 prints `KSYMS {json}` once, before the harness starts.
    pub fn ksyms(&self) -> Option<Ksyms> {
        let s = std::fs::read_to_string(&self.serial).ok()?;
        let line = s.lines().find(|l| l.starts_with("KSYMS "))?;
        let v: serde_json::Value = serde_json::from_str(line.trim_start_matches("KSYMS ").trim()).ok()?;
        let g = |k: &str| v[k].as_str().and_then(|h| u64::from_str_radix(h.trim_start_matches("0x"), 16).ok());
        Some(Ksyms { _text: g("_text")?, _stext: g("_stext")?, _etext: g("_etext")?, __start_rodata: g("__start_rodata")?, __end_rodata: g("__end_rodata")?, sys_call_table: g("sys_call_table")? })
    }

    pub fn harness_done(&self) -> Option<serde_json::Value> {
        let s = std::fs::read_to_string(&self.serial).ok()?;
        let line = s.lines().find(|l| l.starts_with("HARNESS_DONE "))?;
        serde_json::from_str(line.trim_start_matches("HARNESS_DONE ").trim()).ok()
    }

    fn api(&self, method: &str, path: &str, body: Option<&str>) -> anyhow::Result<String> {
        let mut c = Command::new("/usr/bin/curl");
        c.args(["-sS", "-f", "--unix-socket", self.api.to_str().unwrap(), "-X", method, &format!("http://localhost{path}"), "-H", "Content-Type: application/json"]);
        if let Some(b) = body {
            c.args(["-d", b]);
        }
        let out = c.output()?;
        anyhow::ensure!(out.status.success(), "fc api {method} {path}: {}", String::from_utf8_lossy(&out.stderr));
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    }

    pub fn pause(&mut self) -> anyhow::Result<()> {
        self.api("PATCH", "/vm", Some(r#"{"state":"Paused"}"#))?;
        self.state = Vm1State::Paused;
        Ok(())
    }
    pub fn resume(&mut self) -> anyhow::Result<()> {
        self.api("PATCH", "/vm", Some(r#"{"state":"Resumed"}"#))?;
        self.state = Vm1State::Running;
        Ok(())
    }
    /// Full memory snapshot; caller deletes the files after hashing.
    pub fn snapshot(&self, mem: &Path, vmstate: &Path) -> anyhow::Result<()> {
        let body = serde_json::json!({"snapshot_type": "Full", "snapshot_path": vmstate, "mem_file_path": mem}).to_string();
        self.api("PUT", "/snapshot/create", Some(&body))?;
        Ok(())
    }

    pub fn alive(&mut self) -> bool {
        match self.child.as_mut() {
            Some(c) => matches!(c.try_wait(), Ok(None)),
            None => false,
        }
    }

    /// SIGKILL the VMM itself and confirm exit with waitpid. Idempotent.
    pub fn kill(&mut self) -> anyhow::Result<Duration> {
        let t0 = Instant::now();
        if let Some(mut c) = self.child.take() {
            let _ = c.kill();
            c.wait()?; // reaps; guarantees the pid is gone
        }
        self.state = Vm1State::Killed;
        let _ = std::fs::remove_file(&self.api);
        Ok(t0.elapsed())
    }
}
