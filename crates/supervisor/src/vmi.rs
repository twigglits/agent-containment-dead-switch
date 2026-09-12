//! Scoped VMI over VM1 from VM2 (docs §7). Rung-1 evidence only: trusted while VM2 is.
//!
//! Regions: kernel text `[_stext,_etext)` and rodata `[__start_rodata,__end_rodata)` (which holds
//! `sys_call_table` on arm64). Mapping: `phys = DRAM_BASE + TEXT_OFFSET + (vaddr - _text)`;
//! snapshot file offset = `phys - DRAM_BASE` (single guest memory region on aarch64 Firecracker).
//! Baseline = first measurement after boot, before the harness starts. Anything unmeasurable is
//! `Unknown`, never `Healthy`.

use crate::vm1::{Ksyms, Vm1, DRAM_BASE, TEXT_OFFSET};
use deadswitch_common::{now_unix, VmiResult};
use sha2::{Digest, Sha256};
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

#[derive(Debug, Clone, serde::Serialize)]
pub struct Baseline {
    pub text_sha256: String,
    pub rodata_sha256: String,
    pub text_bytes: u64,
    pub rodata_bytes: u64,
    /// bytes in the runtime text that differ from the on-disk Image (ARM alternatives patching)
    pub text_diff_vs_image: u64,
    pub measured_at: u64,
}

pub struct Vmi {
    pub ksyms: Ksyms,
    pub baseline: Option<Baseline>,
    pub last: VmiResult,
    pub image: std::path::PathBuf,
}

fn region_offset(k: &Ksyms, vaddr: u64) -> u64 {
    DRAM_BASE + TEXT_OFFSET + (vaddr - k._text) - DRAM_BASE
}

fn hash_region(mem: &Path, off: u64, len: u64) -> anyhow::Result<(String, Vec<u8>)> {
    let mut f = std::fs::File::open(mem)?;
    let size = f.metadata()?.len();
    anyhow::ensure!(off + len <= size, "region [{off:#x},+{len:#x}) outside snapshot of {size:#x} bytes");
    f.seek(SeekFrom::Start(off))?;
    let mut buf = vec![0u8; len as usize];
    f.read_exact(&mut buf)?;
    Ok((hex::encode(Sha256::digest(&buf)), buf))
}

impl Vmi {
    pub fn new(ksyms: Ksyms, image: &Path) -> Self {
        Vmi { ksyms, baseline: None, last: VmiResult::Unmeasured, image: image.into() }
    }

    /// Pause all vCPUs, snapshot, resume, hash. `resume_ok` is checked by the caller before resume
    /// (lease still valid); if it returns false we leave VM1 paused.
    pub fn measure(&mut self, vm: &mut Vm1, resume_ok: impl Fn() -> bool) -> VmiResult {
        let r = self.measure_inner(vm, resume_ok);
        self.last = r.clone();
        r
    }

    fn measure_inner(&mut self, vm: &mut Vm1, resume_ok: impl Fn() -> bool) -> VmiResult {
        let k = self.ksyms.clone();
        if k._etext <= k._stext || k.__end_rodata <= k.__start_rodata || k._stext < k._text {
            return VmiResult::Unknown { reason: "implausible kernel symbols".into() };
        }
        let mem = vm.work.join("vmi.mem");
        let st = vm.work.join("vmi.vmstate");
        let _ = std::fs::remove_file(&mem);
        let _ = std::fs::remove_file(&st);
        if let Err(e) = vm.pause() {
            return VmiResult::Unknown { reason: format!("pause failed: {e}") };
        }
        let snap = vm.snapshot(&mem, &st);
        if resume_ok() {
            if let Err(e) = vm.resume() {
                return VmiResult::Unknown { reason: format!("resume failed: {e}") };
            }
        }
        if let Err(e) = snap {
            return VmiResult::Unknown { reason: format!("snapshot failed: {e}") };
        }
        let text_off = region_offset(&k, k._stext);
        let text_len = k._etext - k._stext;
        let ro_off = region_offset(&k, k.__start_rodata);
        let ro_len = k.__end_rodata - k.__start_rodata;
        let text = hash_region(&mem, text_off, text_len);
        let ro = hash_region(&mem, ro_off, ro_len);
        let _ = std::fs::remove_file(&st);
        let now = now_unix();
        let (text_sha, text_buf) = match text {
            Ok(v) => v,
            Err(e) => {
                let _ = std::fs::remove_file(&mem);
                return VmiResult::Unknown { reason: format!("text: {e}") };
            }
        };
        let (ro_sha, _) = match ro {
            Ok(v) => v,
            Err(e) => {
                let _ = std::fs::remove_file(&mem);
                return VmiResult::Unknown { reason: format!("rodata: {e}") };
            }
        };
        let _ = std::fs::remove_file(&mem);
        match &self.baseline {
            None => {
                // sanity: how far is runtime text from the on-disk Image? (alternatives patching)
                let img_off = TEXT_OFFSET + (k._stext - k._text) - TEXT_OFFSET; // Image file offset of _stext
                let diff = std::fs::File::open(&self.image)
                    .and_then(|mut f| {
                        f.seek(SeekFrom::Start(img_off))?;
                        let mut b = vec![0u8; text_len as usize];
                        f.read_exact(&mut b)?;
                        Ok(b.iter().zip(text_buf.iter()).filter(|(a, b)| a != b).count() as u64)
                    })
                    .unwrap_or(u64::MAX);
                self.baseline = Some(Baseline { text_sha256: text_sha.clone(), rodata_sha256: ro_sha.clone(), text_bytes: text_len, rodata_bytes: ro_len, text_diff_vs_image: diff, measured_at: now });
                VmiResult::Healthy { text_sha256: text_sha, rodata_sha256: ro_sha, measured_at: now }
            }
            Some(b) => {
                if text_sha != b.text_sha256 {
                    VmiResult::Tampered { region: "kernel_text".into(), expected: b.text_sha256.clone(), actual: text_sha, measured_at: now }
                } else if ro_sha != b.rodata_sha256 {
                    VmiResult::Tampered { region: "kernel_rodata".into(), expected: b.rodata_sha256.clone(), actual: ro_sha, measured_at: now }
                } else {
                    VmiResult::Healthy { text_sha256: text_sha, rodata_sha256: ro_sha, measured_at: now }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets_and_positive_control() {
        let k = Ksyms { _text: 0xffff800080000000, _stext: 0xffff800080010000, _etext: 0xffff800080010010, __start_rodata: 0xffff800080020000, __end_rodata: 0xffff800080020008, sys_call_table: 0xffff800080020000 };
        assert_eq!(region_offset(&k, k._stext), TEXT_OFFSET + 0x10000);
        let dir = std::env::temp_dir().join(format!("vmi-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let mem = dir.join("mem");
        let mut data = vec![0u8; (TEXT_OFFSET + 0x30000) as usize];
        data[(TEXT_OFFSET + 0x10000) as usize..(TEXT_OFFSET + 0x10010) as usize].copy_from_slice(b"0123456789abcdef");
        std::fs::write(&mem, &data).unwrap();
        let (h1, _) = hash_region(&mem, region_offset(&k, k._stext), 16).unwrap();
        // byte flip inside the measured text must change the hash (T-VMI1 positive control)
        data[(TEXT_OFFSET + 0x10003) as usize] ^= 0xff;
        std::fs::write(&mem, &data).unwrap();
        let (h2, _) = hash_region(&mem, region_offset(&k, k._stext), 16).unwrap();
        assert_ne!(h1, h2);
        // region outside the snapshot is Unknown, not Healthy
        assert!(hash_region(&mem, 0, u64::MAX / 4).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
