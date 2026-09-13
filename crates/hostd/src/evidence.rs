//! Serialize complete JSONL records and reserve aggregate quota under an evidence-only lock.
//! This lock must never be held with the watchdog's live-state lock.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Mutex;

pub struct EvidenceStore {
    path: PathBuf,
    quota_bytes: u64,
    writer: Mutex<()>,
}

impl EvidenceStore {
    pub fn new(path: PathBuf, quota_bytes: u64) -> Self {
        Self {
            path,
            quota_bytes,
            writer: Mutex::new(()),
        }
    }

    pub fn append(&self, event: &serde_json::Value) -> io::Result<()> {
        // Display(Value) streams many writes; O_APPEND alone cannot keep those fragments together.
        let mut record = serde_json::to_vec(event)?;
        record.push(b'\n');
        let _writer = self
            .writer
            .lock()
            .map_err(|_| io::Error::other("evidence lock poisoned"))?;
        let dir = self
            .path
            .parent()
            .ok_or_else(|| io::Error::other("no evidence directory"))?;
        let mut used = 0u64;
        for entry in fs::read_dir(dir)? {
            used = used
                .checked_add(entry?.metadata()?.len())
                .ok_or_else(|| io::Error::other("evidence size overflow"))?;
        }
        if used
            .checked_add(record.len() as u64)
            .is_none_or(|n| n > self.quota_bytes)
        {
            return Err(io::Error::other("evidence store over quota"));
        }
        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        file.write_all(&record)?;
        file.sync_data()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn directory() -> PathBuf {
        let p = std::env::temp_dir().join(format!("deadswitch-evidence-{}", rand::random::<u64>()));
        fs::create_dir(&p).unwrap();
        p
    }

    #[test]
    fn concurrent_records_are_complete_and_unique() {
        let dir = directory();
        let path = dir.join("run.jsonl");
        let store = EvidenceStore::new(path.clone(), 1 << 20);
        std::thread::scope(|scope| {
            for writer in 0..6 {
                let store = &store;
                scope.spawn(move || {
                    for seq in 0..20 {
                        store
                            .append(&serde_json::json!({"writer": writer, "seq": seq,
                            "data": {"text": "quoted \"text\" and unicode λ\n".repeat(20)}}))
                            .unwrap();
                    }
                });
            }
        });
        let text = fs::read_to_string(path).unwrap();
        assert!(text.ends_with('\n'));
        let mut records = BTreeSet::new();
        for line in text.lines() {
            let v: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(records.insert((v["writer"].as_u64().unwrap(), v["seq"].as_u64().unwrap())));
        }
        assert_eq!(records.len(), 120);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn concurrent_appends_respect_the_aggregate_quota() {
        let dir = directory();
        fs::write(dir.join("previous.jsonl"), [b' '; 40]).unwrap();
        let event = serde_json::json!({"x": 1});
        let size = serde_json::to_vec(&event).unwrap().len() as u64 + 1;
        let path = dir.join("run.jsonl");
        let store = EvidenceStore::new(path.clone(), 40 + 2 * size);
        let successes = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| scope.spawn(|| store.append(&event).is_ok()))
                .collect();
            handles
                .into_iter()
                .map(|h| usize::from(h.join().unwrap()))
                .sum::<usize>()
        });
        assert_eq!(successes, 2);
        assert_eq!(fs::metadata(path).unwrap().len(), 2 * size);
        fs::remove_dir_all(dir).unwrap();
    }
}
