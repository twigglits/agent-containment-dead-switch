//! Scoped VMI over VM1 from VM2 (docs §7), QEMU/QMP variant. Rung-1 evidence only: trusted while
//! VM2 is.
//!
//! Regions: the guest's own kernel code and rodata **physical** ranges, taken from `/proc/iomem`
//! ("Kernel code" / "Kernel rodata") by the pre-adversarial init and printed as a `KMEM {...}`
//! serial line. QMP `pmemsave` then dumps exactly those guest-physical ranges from below the guest,
//! and we hash them. Physical (not virtual) because `pmemsave` addresses guest-physical memory;
//! stable under `nokaslr`. Baseline = the first measurement, before the harness starts. Anything
//! unmeasurable is `Unknown`, never `Healthy`.

use crate::vm1::{Kmem, Vm1};
use deadswitch_common::{now_unix, VmiResult};
use std::path::PathBuf;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Baseline {
    pub text_sha256: String,
    pub rodata_sha256: String,
    pub text_bytes: u64,
    pub rodata_bytes: u64,
    pub measured_at: u64,
}

pub struct Vmi {
    pub kmem: Kmem,
    pub baseline: Option<Baseline>,
    pub last: VmiResult,
    work: PathBuf,
}

impl Vmi {
    pub fn new(kmem: Kmem, work: &std::path::Path) -> Self {
        Vmi {
            kmem,
            baseline: None,
            last: VmiResult::Unmeasured,
            work: work.into(),
        }
    }

    /// Pause vCPUs, pmemsave the code+rodata physical ranges, resume (only if `resume_ok`), hash.
    pub fn measure(&mut self, vm: &mut Vm1, resume_ok: impl Fn() -> bool) -> VmiResult {
        let r = self.measure_inner(vm, resume_ok);
        self.last = r.clone();
        r
    }

    fn measure_inner(&mut self, vm: &mut Vm1, resume_ok: impl Fn() -> bool) -> VmiResult {
        let k = self.kmem.clone();
        if k.code_end <= k.code_start || k.rodata_end <= k.rodata_start {
            return VmiResult::Unknown {
                reason: "implausible kernel physical ranges".into(),
            };
        }
        let text_len = k.code_end - k.code_start + 1;
        let ro_len = k.rodata_end - k.rodata_start + 1;
        let text_f = self.work.join("vmi.text");
        let ro_f = self.work.join("vmi.rodata");
        if let Err(e) = vm.pause() {
            return VmiResult::Unknown {
                reason: format!("pause failed: {e}"),
            };
        }
        let dump = (|| -> anyhow::Result<(String, String)> {
            vm.pmemsave(k.code_start, text_len, &text_f)?;
            vm.pmemsave(k.rodata_start, ro_len, &ro_f)?;
            let t = Vm1::read_file_sha256(&text_f, text_len)?;
            let r = Vm1::read_file_sha256(&ro_f, ro_len)?;
            Ok((t, r))
        })();
        // Resume before anything else, so a hash error never leaves VM1 paused (unless lease lost).
        if resume_ok() {
            if let Err(e) = vm.resume() {
                let _ = std::fs::remove_file(&text_f);
                let _ = std::fs::remove_file(&ro_f);
                return VmiResult::Unknown {
                    reason: format!("resume failed: {e}"),
                };
            }
        }
        let _ = std::fs::remove_file(&text_f);
        let _ = std::fs::remove_file(&ro_f);
        let (text_sha, ro_sha) = match dump {
            Ok(v) => v,
            Err(e) => {
                return VmiResult::Unknown {
                    reason: format!("pmemsave/hash: {e}"),
                }
            }
        };
        let now = now_unix();
        match &self.baseline {
            None => {
                self.baseline = Some(Baseline {
                    text_sha256: text_sha.clone(),
                    rodata_sha256: ro_sha.clone(),
                    text_bytes: text_len,
                    rodata_bytes: ro_len,
                    measured_at: now,
                });
                VmiResult::Healthy {
                    text_sha256: text_sha,
                    rodata_sha256: ro_sha,
                    measured_at: now,
                }
            }
            Some(b) => {
                // Scoped-VMI trip decision (Codex F7): the kernel legitimately self-patches its
                // .text at runtime (jump labels, static keys, ftrace, arm64 alternatives), so a
                // byte-exact .text hash false-positives on benign activity. We therefore TRIP only on
                // the read-only data region — which contains `sys_call_table` on arm64, the primary
                // syscall-hooking target and normally immutable after init. .text drift is recorded
                // as evidence (`text_drift`) but is NOT a trip; distinguishing malicious from
                // legitimate .text edits needs a patch-site allowlist (deferred, stated blind spot).
                if ro_sha != b.rodata_sha256 {
                    VmiResult::Tampered {
                        region: "kernel_rodata".into(),
                        expected: b.rodata_sha256.clone(),
                        actual: ro_sha,
                        measured_at: now,
                    }
                } else {
                    if text_sha != b.text_sha256 {
                        tracing::info!(
                            region = "kernel_code",
                            "text drift (expected: kernel self-patching); not a trip"
                        );
                    }
                    VmiResult::Healthy {
                        text_sha256: text_sha,
                        rodata_sha256: ro_sha,
                        measured_at: now,
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use sha2::{Digest, Sha256};
    // The pmemsave→hash→compare logic is exercised end-to-end in the QEMU qualification run;
    // here we lock the invariant that a one-byte change in a measured region changes the digest
    // (the T-VMI1 positive control), independent of QEMU.
    #[test]
    fn byte_flip_changes_digest() {
        let mut region = vec![0u8; 4096];
        region[123] = 0xAA;
        let h1 = hex::encode(Sha256::digest(&region));
        region[123] = 0xAB;
        let h2 = hex::encode(Sha256::digest(&region));
        assert_ne!(h1, h2);
    }
}
