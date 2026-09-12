//! Package prestage (docs §8, JEAN_SUGGESTIONS "host-mediated package provisioning").
//!
//! Runs the dependency resolution as the unprivileged `prestage` user (no access to
//! /etc/deadswitch or the VMI baseline), wheels only (no build scripts), records a manifest of
//! sha256 digests, builds an ext4 image, verifies its digest, and makes it immutable. VM1 gets it
//! read-only; the fetch path is gone once the gate is sealed.

use anyhow::{anyhow, Context};
use deadswitch_common::sha256_hex;
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

pub struct Prestaged {
    pub image: PathBuf,
    pub image_digest: String,
    pub manifest_digest: String,
    pub manifest: serde_json::Value,
}

fn sh(user: Option<&str>, script: &str) -> anyhow::Result<String> {
    let mut c = match user {
        Some(u) => {
            let mut c = Command::new("/usr/bin/sudo");
            c.args(["-n", "-u", u, "-H", "/bin/bash", "-euo", "pipefail", "-c", script]);
            c
        }
        None => {
            let mut c = Command::new("/bin/bash");
            c.args(["-euo", "pipefail", "-c", script]);
            c
        }
    };
    let out = c.output().context("spawn bash")?;
    if !out.status.success() {
        return Err(anyhow!("script failed ({}): {}", out.status, String::from_utf8_lossy(&out.stderr).trim()));
    }
    Ok(String::from_utf8_lossy(&out.stdout).to_string())
}

pub fn sha256_file(p: &Path) -> anyhow::Result<String> {
    let mut f = std::fs::File::open(p)?;
    let mut h = Sha256::new();
    std::io::copy(&mut f, &mut h)?;
    Ok(hex::encode(h.finalize()))
}

/// `harness_src` = /var/lib/deadswitch/harness (pyproject + agent.py), `out_dir` = per-run work dir.
pub fn run(harness_src: &Path, out_dir: &Path) -> anyhow::Result<Prestaged> {
    let stage = Path::new("/var/lib/deadswitch/prestage/stage");
    // 1. resolve + download as the prestage user; wheels only ⇒ no package build scripts run.
    sh(None, &format!("rm -rf {s} && mkdir -p {s} && cp -r {src}/. {s}/ && chown -R prestage:prestage {s}", s = stage.display(), src = harness_src.display()))?;
    sh(Some("prestage"), &format!(
        "cd {s} && export UV_CACHE_DIR={s}/.uv-cache UV_PYTHON_INSTALL_DIR={s}/python HOME={s} \
         && /usr/local/bin/uv python install --no-bin 3.12 \
         && /usr/local/bin/uv venv --python 3.12 --relocatable {s}/venv \
         && /usr/local/bin/uv sync --frozen --no-dev --no-build --active --python {s}/venv/bin/python",
        s = stage.display()
    ))
    .context("uv resolve/sync (wheels only)")?;
    // 2. manifest: lockfile + every file that will be visible in VM1.
    let mut files = Vec::new();
    fn walk(p: &Path, out: &mut Vec<(String, String)>) -> anyhow::Result<()> {
        for e in std::fs::read_dir(p)? {
            let e = e?;
            let path = e.path();
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if name == ".uv-cache" || name == "__pycache__" {
                continue;
            }
            if e.file_type()?.is_dir() {
                walk(&path, out)?;
            } else if e.file_type()?.is_file() {
                out.push((path.to_string_lossy().to_string(), sha256_file(&path)?));
            }
        }
        Ok(())
    }
    walk(stage, &mut files)?;
    files.sort();
    let manifest = serde_json::json!({
        "uv_lock_sha256": sha256_file(&stage.join("uv.lock")).unwrap_or_else(|_| "missing".into()),
        "file_count": files.len(),
        "files": files.iter().map(|(p, h)| serde_json::json!({"path": p, "sha256": h})).collect::<Vec<_>>(),
    });
    let manifest_bytes = serde_json::to_vec(&manifest)?;
    let manifest_digest = sha256_hex(&manifest_bytes);
    std::fs::create_dir_all(out_dir)?;
    std::fs::write(out_dir.join("manifest.json"), &manifest_bytes)?;
    // 3. immutable ext4 image, digest verified after build, chattr +i, root-owned.
    let image = out_dir.join("deps.ext4");
    sh(None, &format!(
        "rm -rf {s}/.uv-cache; size=$(( $(du -sm {s} | cut -f1) + 64 )); rm -f {img}; truncate -s ${{size}}M {img} && mkfs.ext4 -q -F -d {s} {img} && chown root:root {img} && chmod 0400 {img} && chattr +i {img}",
        s = stage.display(), img = image.display()
    ))
    .context("build deps image")?;
    let image_digest = sha256_file(&image)?;
    Ok(Prestaged { image, image_digest, manifest_digest, manifest })
}

/// Re-verify at attach time (docs §8): the file we attach is the file we built.
pub fn verify(image: &Path, expected: &str) -> anyhow::Result<()> {
    let got = sha256_file(image)?;
    anyhow::ensure!(got == expected, "deps image digest changed: {got} != {expected}");
    let attrs = sh(None, &format!("lsattr -d {}", image.display()))?;
    anyhow::ensure!(attrs.split_whitespace().next().map(|a| a.contains('i')).unwrap_or(false), "deps image is not immutable");
    Ok(())
}
