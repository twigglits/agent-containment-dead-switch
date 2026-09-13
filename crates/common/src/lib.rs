//! Wire protocol v1 for the dead switch (docs/phase1-local-host.md §2–§3).
//!
//! Roles and what they may sign:
//!   controller → hostd:      Lease, Challenge, Order
//!   hostd      → controller: Enroll, HostEvidence, LeaseRequest
//!   VM2 (untrusted, unsigned, bearer token): Vm2Report, DefenderAction, LogEvent
//!
//! A lease is *permission to continue*, never proof of integrity. Evidence is only what the
//! signer observed itself. Enforcement is fail-closed on both a monotonic and a wall clock.

pub mod inference;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

pub const PROTO_V: u32 = 1;
pub const MAX_MSG_BYTES: usize = 64 * 1024;
pub const MAX_LEASE_TTL_S: u64 = 15; // Mac profile bound; a delayed lease gets less, never more
pub const DEFAULT_LEASE_TTL_S: u64 = 15;
pub const CLOCK_SKEW_S: u64 = 5;
pub const CHALLENGE_TTL_S: u64 = 10;
// VM2's report is an *untrusted liveness/rung-1* signal, NOT the kill bound. hostd's own
// host-observed evidence (vm2.running, gate sealed, bypass counters) is the authoritative health
// signal and is unaffected by VM2 load. Prestage (uv + a CPython fetch) and a nested-virt VM1 boot
// saturate VM2's vCPUs and can starve the VM2 report thread for tens of seconds; this window rides
// that out. The real liveness gate is the controller's no-evidence ticker on hostd's OWN evidence
// (hostd runs on the trusted host and is never starved by VM2), which trips independently.
pub const REPORT_MAX_AGE_S: u64 = 60;
pub const MISSED_CHALLENGES_TO_TRIP: u32 = 3;

pub const AUD_HOSTD: &str = "hostd";
pub const AUD_CONTROLLER: &str = "controller";

pub fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

// ---------------------------------------------------------------- messages

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String, // "lease"
    pub run_id: String,
    pub aud: String, // hostd
    pub incarnation: String,
    pub epoch: u64,
    pub fencing_token: u64,
    pub issued_at: u64,
    pub ttl_s: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Challenge {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String, // "challenge"
    pub run_id: String,
    pub aud: String, // hostd
    pub incarnation: String,
    pub epoch: u64,
    pub nonce: String, // 32 random bytes, hex
    pub issued_at: u64,
    pub expires_in_s: u64,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum OrderKind {
    Destroy,
    CutEgress,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Order {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String, // "order"
    pub run_id: String,
    pub aud: String, // hostd
    pub incarnation: String,
    pub order: OrderKind,
    pub fencing_token: u64,
    pub issued_at: u64,
    pub reason: String,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum GateState {
    Open,
    Sealed,
    Cut,
    Unknown,
}

/// Everything here is observed by hostd itself (Lima, process table, pf, its own state).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct Vm2Obs {
    pub running: Option<bool>, // None = could not observe
    pub instance: String,
    pub pid: Option<u32>,
    pub started_at: Option<u64>,
    pub template_digest: String,
    pub base_image_digest: String,
    pub nested_virt: Option<bool>,
    pub port_forwards: Option<u32>,
    pub writable_mounts: Option<u32>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct GateObs {
    pub state: GateState,
    pub bypass_packets: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct WatchdogObs {
    pub lease_token: u64,
    pub deadline_remaining_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct ChokepointObs {
    pub inference_requests: u64,
    pub denied: u64,
}

/// VM2's own words. Carried for rung-1 analysis, never promoted to health.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UntrustedReport {
    pub received_at: u64,
    pub digest: String,
    pub body: Vm2Report,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HostEvidence {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String, // "host_evidence"
    pub run_id: String,
    pub aud: String, // controller
    pub incarnation: String,
    pub nonce: String,
    pub measured_at: u64,
    pub vm2: Vm2Obs,
    pub gate: GateObs,
    pub watchdog: WatchdogObs,
    pub chokepoint: ChokepointObs,
    pub untrusted_vm2_report: Option<UntrustedReport>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Enroll {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String, // "enroll"
    pub run_id: String,
    pub aud: String, // controller
    pub incarnation: String,
    pub issued_at: u64,
    pub vm2: Vm2Obs,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LeaseRequest {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String, // "lease_request"
    pub run_id: String,
    pub aud: String, // controller
    pub incarnation: String,
    pub issued_at: u64,
    /// hostd asks to enter this epoch (0 = prestage, gate open; ≥1 = eval, gate must be sealed).
    pub epoch: u64,
    pub gate: GateState,
}

/// Controller's answer to a lease request.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum LeaseResponse {
    Granted {
        lease: Signed,
    },
    /// Terminal: hostd must destroy. Carries a signed Order.
    Denied {
        order: Signed,
        reason: String,
    },
}

// ------------------------------------------------- untrusted VM2 → hostd

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Vm1State {
    NotStarted,
    Booting,
    Running,
    Paused,
    Killed,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case", tag = "status")]
pub enum VmiResult {
    Unmeasured,
    Unknown {
        reason: String,
    },
    Healthy {
        text_sha256: String,
        rodata_sha256: String,
        measured_at: u64,
    },
    Tampered {
        region: String,
        expected: String,
        actual: String,
        measured_at: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Vm2Report {
    pub run_id: String,
    pub seq: u64,
    pub sent_at: u64,
    pub phase: String, // prestage | eval | stopped
    pub vm1_state: Vm1State,
    pub vmi: VmiResult,
    pub gateway_allowed: u64,
    pub gateway_denied: u64,
    pub defender_actions: u64,
    pub log_dropped: u64,
}

/// The defender's whole authority. Deliberately no variant relaxes anything.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DefenderAction {
    Veto {
        request_digest: String,
        reason: String,
    },
    Pause {
        reason: String,
    },
    TerminateVm1 {
        reason: String,
    },
}

/// Signed challenge REQUEST from hostd. Phase 2: controller↔hostd crosses a network (not loopback),
/// so the REQUEST is authenticated against the enrolled hostd key too — not just the signed response.
/// Prevents an on-net party from flooding `/challenge` to force missed-challenge trips.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChallengeRequest {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String, // "challenge_request"
    pub run_id: String,
    pub aud: String, // controller
    pub incarnation: String,
    pub issued_at: u64,
    /// Unique per request, retained durably by the controller for the freshness window.
    pub request_id: String,
}

/// Signed defender relay from hostd: the untrusted in-guest defender's action, relayed and SIGNED by
/// the per-run hostd key so the controller only accepts authority-reducing actions from the real
/// hostd (Phase 2 network hop). Every DefenderAction only reduces authority.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefenderReport {
    pub v: u32,
    #[serde(rename = "type")]
    pub kind: String, // "defender_report"
    pub run_id: String,
    pub aud: String, // controller
    pub incarnation: String,
    pub issued_at: u64,
    pub request_id: String,
    pub action: DefenderAction,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LogEvent {
    pub seq: u64,
    pub ts: u64,
    pub kind: String,
    pub msg: String,
    #[serde(default)]
    pub data: serde_json::Value,
}

// ---------------------------------------------------------------- envelope

/// Canonical JSON payload + detached ed25519 signature over sha256(payload).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Signed {
    pub payload: String,
    pub sig_hex: String,
    pub signer: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("bad signature")]
    BadSignature,
    #[error("message too large")]
    TooLarge,
    #[error("wrong type: expected {expected}, got {got}")]
    WrongType { expected: String, got: String },
    #[error("wrong audience: expected {expected}, got {got}")]
    WrongAud { expected: String, got: String },
    #[error("unsupported protocol version {0}")]
    Version(u32),
    #[error("payload: {0}")]
    Payload(#[from] serde_json::Error),
    #[error("hex: {0}")]
    Hex(#[from] hex::FromHexError),
}

#[derive(Deserialize)]
struct Header {
    v: u32,
    #[serde(rename = "type")]
    kind: String,
    aud: String,
}

impl Signed {
    pub fn sign<T: Serialize>(key: &SigningKey, signer: &str, value: &T) -> Self {
        let payload = serde_json::to_string(value).expect("serializable");
        let sig = key.sign(&Sha256::digest(payload.as_bytes()));
        Signed {
            payload,
            sig_hex: hex::encode(sig.to_bytes()),
            signer: signer.to_string(),
        }
    }

    /// Verify signature, then version/type/audience, then decode. Nothing is parsed into `T`
    /// before the signature and header checks pass.
    pub fn verify<T: DeserializeOwned>(
        &self,
        pk: &VerifyingKey,
        expected_type: &str,
        expected_aud: &str,
    ) -> Result<T, ProtoError> {
        if self.payload.len() > MAX_MSG_BYTES {
            return Err(ProtoError::TooLarge);
        }
        let sig = Signature::from_slice(&hex::decode(&self.sig_hex)?)
            .map_err(|_| ProtoError::BadSignature)?;
        pk.verify(&Sha256::digest(self.payload.as_bytes()), &sig)
            .map_err(|_| ProtoError::BadSignature)?;
        let h: Header = serde_json::from_str(&self.payload)?;
        if h.v != PROTO_V {
            return Err(ProtoError::Version(h.v));
        }
        if h.kind != expected_type {
            return Err(ProtoError::WrongType {
                expected: expected_type.into(),
                got: h.kind,
            });
        }
        if h.aud != expected_aud {
            return Err(ProtoError::WrongAud {
                expected: expected_aud.into(),
                got: h.aud,
            });
        }
        Ok(serde_json::from_str(&self.payload)?)
    }

    pub fn digest(&self) -> String {
        sha256_hex(self.payload.as_bytes())
    }
}

pub fn key_from_hex(hex_seed: &str) -> anyhow::Result<SigningKey> {
    let b: [u8; 32] = hex::decode(hex_seed.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("seed must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&b))
}
pub fn pubkey_from_hex(h: &str) -> anyhow::Result<VerifyingKey> {
    let b: [u8; 32] = hex::decode(h.trim())?
        .try_into()
        .map_err(|_| anyhow::anyhow!("pubkey must be 32 bytes"))?;
    Ok(VerifyingKey::from_bytes(&b)?)
}
pub fn pubkey_hex(k: &SigningKey) -> String {
    hex::encode(k.verifying_key().to_bytes())
}

/// Create with restrictive permissions on the FIRST write (chmod-after-write leaks under a normal
/// umask). Existing keys must also be private regular files; never silently follow a key symlink.
pub fn load_or_create_signing_key(path: &Path) -> anyhow::Result<SigningKey> {
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    match std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
    {
        Ok(mut file) => {
            file.write_all(hex::encode(key.to_bytes()).as_bytes())?;
            file.sync_all()?;
            std::fs::File::open(
                path.parent()
                    .ok_or_else(|| anyhow::anyhow!("key has no parent"))?,
            )?
            .sync_all()?;
            Ok(key)
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            extern "C" {
                fn geteuid() -> u32;
            }
            let meta = std::fs::symlink_metadata(path)?;
            anyhow::ensure!(
                meta.file_type().is_file()
                    && meta.permissions().mode() & 0o077 == 0
                    && meta.uid() == unsafe { geteuid() },
                "key must be a private regular file owned by this user"
            );
            key_from_hex(&std::fs::read_to_string(path)?)
        }
        Err(e) => Err(e.into()),
    }
}
pub fn random_hex(n: usize) -> String {
    use rand::RngCore;
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

// ---------------------------------------------------------------- deadlines

/// A lease deadline evaluated on BOTH clocks. Either clock alone can expire it; neither can
/// extend it (docs §2 clock rule).
#[derive(Clone, Debug)]
pub struct Deadline {
    pub mono: Instant,
    pub wall: u64,
    pub fencing_token: u64,
    pub epoch: u64,
}

impl Deadline {
    /// Accept a lease received now. Rejects delayed/replayed delivery and caps the TTL.
    pub fn accept(lease: &Lease, high_water: u64, wall_now: u64) -> Result<Deadline, String> {
        if lease.fencing_token <= high_water {
            return Err(format!(
                "fencing token {} not above high-water {}",
                lease.fencing_token, high_water
            ));
        }
        if wall_now.abs_diff(lease.issued_at) > CLOCK_SKEW_S {
            return Err(format!(
                "lease issued_at {} too far from now {}",
                lease.issued_at, wall_now
            ));
        }
        let ttl = lease.ttl_s.min(MAX_LEASE_TTL_S);
        let wall_deadline = lease
            .issued_at
            .checked_add(ttl)
            .ok_or("lease deadline overflow")?;
        // A delayed lease gets only the time remaining until its wall deadline on the monotonic
        // clock too (N4): it can never buy back a full TTL, so a later wall rollback cannot extend
        // execution past issued_at+ttl.
        let remaining = wall_deadline.saturating_sub(wall_now).min(ttl);
        Ok(Deadline {
            mono: Instant::now() + Duration::from_secs(remaining),
            wall: wall_deadline,
            fencing_token: lease.fencing_token,
            epoch: lease.epoch,
        })
    }
    /// Accept a lease on the UNTRUSTED guest side (the in-VM2 supervisor), whose wall clock is NOT
    /// synced to the trusted controller/host clock. Freshness and anti-replay come from the
    /// strictly-increasing fencing token; the trusted hostd already validated `issued_at` against the
    /// synced controller clock before serving this lease, so re-checking it against the guest's own
    /// (possibly skewed) clock is wrong and was silently rejecting every eval lease when a freshly
    /// cloned guest's clock drifted from the host. The fail-closed deadline is computed monotonically
    /// from RECEIPT (full capped TTL), and the wall deadline is expressed in the guest's own clock so
    /// `expired()` stays self-consistent. This only governs the guest's defense-in-depth self-kill;
    /// the authoritative timing is enforced by hostd (trusted, synced clock) + the host pf gate + the
    /// host-independent kill.
    pub fn accept_guest(
        lease: &Lease,
        high_water: u64,
        guest_wall_now: u64,
    ) -> Result<Deadline, String> {
        if lease.fencing_token <= high_water {
            return Err(format!(
                "fencing token {} not above high-water {}",
                lease.fencing_token, high_water
            ));
        }
        let ttl = lease.ttl_s.min(MAX_LEASE_TTL_S);
        Ok(Deadline {
            mono: Instant::now() + Duration::from_secs(ttl),
            wall: guest_wall_now + ttl,
            fencing_token: lease.fencing_token,
            epoch: lease.epoch,
        })
    }
    pub fn expired(&self, wall_now: u64) -> bool {
        Instant::now() >= self.mono || wall_now >= self.wall
    }
    pub fn remaining_ms(&self, wall_now: u64) -> i64 {
        let m = self
            .mono
            .saturating_duration_since(Instant::now())
            .as_millis() as i64;
        let w = (self.wall as i64 - wall_now as i64) * 1000;
        m.min(w)
    }
}

// ---------------------------------------------------------------- durable state

/// temp file + fsync + rename. Callers persist BEFORE acknowledging (docs §2 revocation).
pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> anyhow::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let tmp = path.with_extension("tmp");
    let bytes = serde_json::to_vec_pretty(value)?;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)?;
    f.write_all(&bytes)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path)?;
    if let Some(dir) = path.parent() {
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

/// Lost or corrupt state must read as "stopped": the caller treats `Err`/`None` as revoked.
pub fn read_json<T: DeserializeOwned>(path: &Path) -> anyhow::Result<Option<T>> {
    match std::fs::read(path) {
        Ok(b) => Ok(Some(serde_json::from_slice(&b)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn lease(tok: u64, issued: u64, ttl: u64) -> Lease {
        Lease {
            v: 1,
            kind: "lease".into(),
            run_id: "r".into(),
            aud: AUD_HOSTD.into(),
            incarnation: "i".into(),
            epoch: 1,
            fencing_token: tok,
            issued_at: issued,
            ttl_s: ttl,
        }
    }

    #[test]
    fn envelope_checks_signature_then_header() {
        let k = SigningKey::generate(&mut OsRng);
        let s = Signed::sign(&k, "ctl", &lease(7, 10, 15));
        let back: Lease = s.verify(&k.verifying_key(), "lease", AUD_HOSTD).unwrap();
        assert_eq!(back.fencing_token, 7);
        // tamper
        let mut t = s.clone();
        t.payload = t
            .payload
            .replace("\"fencing_token\":7", "\"fencing_token\":8");
        assert!(matches!(
            t.verify::<Lease>(&k.verifying_key(), "lease", AUD_HOSTD),
            Err(ProtoError::BadSignature)
        ));
        // wrong key
        let other = SigningKey::generate(&mut OsRng);
        assert!(s
            .verify::<Lease>(&other.verifying_key(), "lease", AUD_HOSTD)
            .is_err());
        // right key, wrong type / audience: a lease can never be read as an order or for another role
        assert!(matches!(
            s.verify::<Lease>(&k.verifying_key(), "order", AUD_HOSTD),
            Err(ProtoError::WrongType { .. })
        ));
        assert!(matches!(
            s.verify::<Lease>(&k.verifying_key(), "lease", AUD_CONTROLLER),
            Err(ProtoError::WrongAud { .. })
        ));
        // unknown fields rejected
        let mut u = lease(9, 10, 15);
        u.kind = "lease".into();
        let mut v = serde_json::to_value(&u).unwrap();
        v["extra"] = serde_json::json!(1);
        let s2 = Signed::sign(&k, "ctl", &v);
        assert!(s2
            .verify::<Lease>(&k.verifying_key(), "lease", AUD_HOSTD)
            .is_err());
    }

    #[test]
    fn deadline_rules() {
        let now = 1_000_000;
        // fencing
        assert!(Deadline::accept(&lease(5, now, 15), 5, now).is_err());
        // delayed delivery
        assert!(Deadline::accept(&lease(6, now - 6, 15), 5, now).is_err());
        // ttl capped
        let d = Deadline::accept(&lease(6, now, 999), 5, now).unwrap();
        assert_eq!(d.wall, now + MAX_LEASE_TTL_S);
        assert!(!d.expired(now));
        // wall clock alone expires it
        assert!(d.expired(now + MAX_LEASE_TTL_S));
        // N4: a lease delayed within the skew window gets only its remaining monotonic time
        let late = Deadline::accept(&lease(7, now - 4, 15), 6, now).unwrap();
        assert_eq!(late.wall, now + 11);
        assert!(late.mono <= Instant::now() + Duration::from_secs(11));
        // delivery delayed beyond the skew window is rejected outright (even safer)
        assert!(Deadline::accept(&lease(8, now - 10, 15), 7, now).is_err());
        // wall clock rolled back cannot extend past the monotonic deadline
        let short = Deadline {
            mono: Instant::now(),
            wall: now + 1000,
            fencing_token: 6,
            epoch: 1,
        };
        assert!(short.expired(now - 500));
    }

    #[test]
    fn accept_guest_ignores_clock_skew_but_honors_fencing() {
        let now = 1_000_000;
        // A guest whose clock is wildly skewed from the lease's issued_at STILL accepts (unlike
        // accept(), which would reject) — the guest clock is untrusted/unsynced; freshness comes
        // from the fencing token (hostd already validated issued_at on the trusted side).
        let skewed_guest = now + 10_000; // guest clock 10000s ahead of the lease issued_at
        let d = Deadline::accept_guest(&lease(6, now, 15), 5, skewed_guest).unwrap();
        assert_eq!(d.epoch, 1);
        // deadline is receipt-based in the guest's own clock, so expired() is self-consistent
        assert!(!d.expired(skewed_guest));
        assert!(d.expired(skewed_guest + MAX_LEASE_TTL_S));
        // ttl still capped
        assert_eq!(d.wall, skewed_guest + MAX_LEASE_TTL_S);
        // fencing still enforced: a token not above the high-water is rejected
        assert!(Deadline::accept_guest(&lease(5, now, 15), 5, skewed_guest).is_err());
    }

    #[test]
    fn atomic_state_roundtrip() {
        let dir = std::env::temp_dir().join(format!("ds-{}", random_hex(4)));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("run.json");
        assert!(read_json::<Lease>(&p).unwrap().is_none());
        atomic_write_json(&p, &lease(1, 2, 3)).unwrap();
        assert_eq!(read_json::<Lease>(&p).unwrap().unwrap().fencing_token, 1);
        std::fs::write(&p, b"{corrupt").unwrap();
        assert!(read_json::<Lease>(&p).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn signed_phase2_requests_reject_unknown_fields_and_cross_role_messages() {
        let key = SigningKey::generate(&mut OsRng);
        let request = ChallengeRequest {
            v: PROTO_V,
            kind: "challenge_request".into(),
            run_id: "r".into(),
            aud: AUD_CONTROLLER.into(),
            incarnation: "i".into(),
            issued_at: 100,
            request_id: random_hex(32),
        };
        let signed = Signed::sign(&key, "hostd", &request);
        assert!(signed
            .verify::<ChallengeRequest>(&key.verifying_key(), "challenge_request", AUD_CONTROLLER)
            .is_ok());
        assert!(signed
            .verify::<DefenderReport>(&key.verifying_key(), "defender_report", AUD_CONTROLLER)
            .is_err());
        let mut value = serde_json::to_value(request).unwrap();
        value["extra"] = serde_json::json!(true);
        assert!(Signed::sign(&key, "hostd", &value)
            .verify::<ChallengeRequest>(&key.verifying_key(), "challenge_request", AUD_CONTROLLER)
            .is_err());
        let report = DefenderReport {
            v: PROTO_V,
            kind: "defender_report".into(),
            run_id: "r".into(),
            aud: AUD_CONTROLLER.into(),
            incarnation: "i".into(),
            issued_at: 100,
            request_id: random_hex(32),
            action: DefenderAction::Pause {
                reason: "test".into(),
            },
        };
        let mut value = serde_json::to_value(report).unwrap();
        value["extra"] = serde_json::json!(true);
        assert!(Signed::sign(&key, "hostd", &value)
            .verify::<DefenderReport>(&key.verifying_key(), "defender_report", AUD_CONTROLLER)
            .is_err());
    }

    #[test]
    fn future_dated_lease_cannot_buy_more_than_its_ttl() {
        let now = 1_000_000;
        let d = Deadline::accept(&lease(6, now + CLOCK_SKEW_S, 15), 5, now).unwrap();
        assert!(d.mono <= Instant::now() + Duration::from_secs(15));
        assert!(Deadline::accept(&lease(6, u64::MAX, 15), 5, u64::MAX).is_err());
    }

    #[test]
    fn signing_key_is_private_from_creation_and_rejects_exposed_or_symlinked_keys() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        let dir = std::env::temp_dir().join(format!("ds-key-{}", random_hex(8)));
        std::fs::create_dir(&dir).unwrap();
        let path = dir.join("key");
        let k = load_or_create_signing_key(&path).unwrap();
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            pubkey_hex(&load_or_create_signing_key(&path).unwrap()),
            pubkey_hex(&k)
        );
        symlink(&path, dir.join("link")).unwrap();
        assert!(load_or_create_signing_key(&dir.join("link")).is_err());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load_or_create_signing_key(&path).is_err());
        std::fs::remove_dir_all(dir).unwrap();
    }
}
