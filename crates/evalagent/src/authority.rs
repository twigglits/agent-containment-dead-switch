//! One in-process authority for the lease loop, proxy dispatch, and response fence.
//! Gate transitions invalidate queued/in-flight work even if the gate is sealed again immediately.
//! Expiry and shutdown are terminal: a delayed renewal cannot resurrect a dead run.

use deadswitch_common::{now_unix, Deadline, GateObs, GateState, WatchdogObs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::watch;

struct Live {
    deadline: Option<Deadline>,
    evidence_deadline: Option<Instant>,
    gate: GateState,
    generation: u64,
    stop_reason: Option<String>,
}

pub struct Authority {
    live: Mutex<Live>,
    changed: watch::Sender<u64>,
    signal: &'static AtomicBool,
}

impl Authority {
    pub fn new(signal: &'static AtomicBool) -> Arc<Self> {
        Arc::new(Self {
            live: Mutex::new(Live {
                deadline: None,
                evidence_deadline: None,
                gate: GateState::Cut,
                generation: 0,
                stop_reason: None,
            }),
            changed: watch::channel(0).0,
            signal,
        })
    }

    fn invalidate(&self, live: &mut Live) {
        live.generation += 1;
        // Unlike send(), retain invalidation even when no request is subscribed yet.
        self.changed.send_replace(live.generation);
    }

    fn stop_locked(&self, live: &mut Live, reason: &str) {
        if live.stop_reason.is_none() {
            live.stop_reason = Some(reason.into());
            live.gate = GateState::Cut;
            live.deadline = None;
            self.invalidate(live);
            tracing::warn!(reason, "proxy authority revoked");
        }
    }

    fn refresh(&self, live: &mut Live) {
        if self.signal.load(Ordering::SeqCst) {
            self.stop_locked(live, "SIGTERM/SIGINT received");
        } else if live.evidence_deadline.is_some_and(|d| Instant::now() >= d) {
            self.stop_locked(
                live,
                "no acknowledged valid evidence before heartbeat deadline",
            );
        } else if live
            .deadline
            .as_ref()
            .is_some_and(|d| d.expired(now_unix()))
        {
            self.stop_locked(live, "lease expired (both-clock watchdog)");
        }
    }

    pub fn stop(&self, reason: &str) {
        self.stop_locked(&mut self.live.lock().unwrap(), reason);
    }

    pub fn stop_reason(&self) -> Option<String> {
        let mut live = self.live.lock().unwrap();
        self.refresh(&mut live);
        live.stop_reason.clone()
    }

    pub fn set_gate(&self, gate: GateState) {
        let mut live = self.live.lock().unwrap();
        self.refresh(&mut live);
        if live.stop_reason.is_none() && live.gate != gate {
            live.gate = gate;
            self.invalidate(&mut live);
        }
    }

    pub fn accept(&self, deadline: Deadline) -> anyhow::Result<()> {
        let mut live = self.live.lock().unwrap();
        // Check the OLD deadline before installing the new one. Missing a renewal bound is final.
        self.refresh(&mut live);
        anyhow::ensure!(live.stop_reason.is_none(), "run is terminating");
        anyhow::ensure!(
            !deadline.expired(now_unix()),
            "new lease is already expired"
        );
        live.deadline = Some(deadline);
        Ok(())
    }

    pub fn deadline(&self) -> Option<Deadline> {
        let mut live = self.live.lock().unwrap();
        self.refresh(&mut live);
        live.deadline.clone()
    }

    /// Arm at startup, then advance ONLY after a healthy evidence verdict. A lease renewal never
    /// extends this bound. The proxy observes it even while the controller/hook thread is blocked.
    pub fn expect_evidence_by(&self, deadline: Instant) -> anyhow::Result<()> {
        let mut live = self.live.lock().unwrap();
        self.refresh(&mut live);
        anyhow::ensure!(live.stop_reason.is_none(), "run is terminating");
        anyhow::ensure!(
            deadline > Instant::now(),
            "evidence acknowledgement arrived too late"
        );
        live.evidence_deadline = Some(deadline);
        Ok(())
    }

    pub fn observations(&self) -> (GateObs, WatchdogObs) {
        let mut live = self.live.lock().unwrap();
        self.refresh(&mut live);
        (
            GateObs {
                state: live.gate,
                bypass_packets: None,
            },
            WatchdogObs {
                lease_token: live.deadline.as_ref().map_or(0, |d| d.fencing_token),
                deadline_remaining_ms: live
                    .deadline
                    .as_ref()
                    .map_or(-1, |d| d.remaining_ms(now_unix())),
            },
        )
    }

    pub fn ticket(&self) -> Option<u64> {
        let mut live = self.live.lock().unwrap();
        self.refresh(&mut live);
        (live.stop_reason.is_none()
            && live.gate == GateState::Sealed
            && live.deadline.as_ref().is_some_and(|d| d.epoch >= 1))
        .then_some(live.generation)
    }

    pub fn active(&self, ticket: u64) -> bool {
        self.ticket() == Some(ticket)
    }

    /// Covers queued work and the ENTIRE upstream send/body read, as in Phase-1 hostd. Subscribe
    /// before checking state; a transition in that window cannot be lost. The tick also observes
    /// both clocks and the async-signal-safe stop flag while the controller/hook thread is blocked.
    pub async fn invalidated(&self, ticket: u64) {
        let mut changed = self.changed.subscribe();
        loop {
            if !self.active(ticket) {
                return;
            }
            tokio::select! {
                _ = changed.changed() => {},
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
    }

    pub async fn stopped(&self) {
        let mut changed = self.changed.subscribe();
        loop {
            if self.stop_reason().is_some() {
                return;
            }
            tokio::select! {
                _ = changed.changed() => {},
                _ = tokio::time::sleep(Duration::from_millis(10)) => {},
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    static NO_SIGNAL: AtomicBool = AtomicBool::new(false);

    pub fn authority() -> Arc<Authority> {
        Authority::new(&NO_SIGNAL)
    }

    pub fn fresh(epoch: u64) -> Deadline {
        Deadline {
            mono: Instant::now() + Duration::from_secs(15),
            wall: now_unix() + 15,
            fencing_token: 1,
            epoch,
        }
    }

    #[test]
    fn dispatch_requires_eval_lease_and_sealed_gate() {
        let a = authority();
        assert_eq!(a.ticket(), None);
        a.set_gate(GateState::Sealed);
        assert_eq!(a.ticket(), None);
        a.accept(fresh(0)).unwrap();
        assert_eq!(a.ticket(), None);
        a.accept(fresh(1)).unwrap();
        assert!(a.ticket().is_some());
        a.set_gate(GateState::Open);
        assert_eq!(a.ticket(), None);
        a.set_gate(GateState::Sealed);
        let before = a.ticket().unwrap();
        a.set_gate(GateState::Cut);
        assert!(!a.active(before));
        a.set_gate(GateState::Sealed);
        assert!(
            !a.active(before),
            "resealing must not resurrect queued/in-flight work"
        );
        assert!(a.ticket().is_some());
    }

    #[test]
    fn either_clock_expires_authority_permanently() {
        for wall in [false, true] {
            let a = authority();
            a.accept(fresh(1)).unwrap();
            a.set_gate(GateState::Sealed);
            let ticket = a.ticket().unwrap();
            {
                let mut live = a.live.lock().unwrap();
                let d = live.deadline.as_mut().unwrap();
                if wall {
                    d.wall = now_unix();
                } else {
                    d.mono = Instant::now();
                }
            }
            assert!(!a.active(ticket));
            assert!(a.accept(fresh(1)).is_err());
            assert!(a.stop_reason().is_some());
        }
    }

    #[tokio::test]
    async fn cut_and_denial_cancel_even_without_existing_subscribers() {
        let a = authority();
        a.accept(fresh(1)).unwrap();
        a.set_gate(GateState::Sealed);
        let ticket = a.ticket().unwrap();
        a.set_gate(GateState::Cut);
        a.set_gate(GateState::Sealed);
        tokio::time::timeout(Duration::from_secs(1), a.invalidated(ticket))
            .await
            .unwrap();
        a.stop("controller denied the lease");
        assert!(a.accept(fresh(1)).is_err());
        assert_eq!(a.ticket(), None);
    }

    #[tokio::test]
    async fn signal_flag_fences_dispatch_and_cancels_in_flight_work() {
        // A dedicated flag avoids sending signals to the test runner or racing other tests.
        let signal = Box::leak(Box::new(AtomicBool::new(false)));
        let a = Authority::new(signal);
        a.accept(fresh(1)).unwrap();
        a.set_gate(GateState::Sealed);
        let ticket = a.ticket().unwrap();
        signal.store(true, Ordering::SeqCst);
        assert!(!a.active(ticket));
        tokio::time::timeout(Duration::from_secs(1), a.invalidated(ticket))
            .await
            .unwrap();
        assert!(a.accept(fresh(1)).is_err());
    }

    #[tokio::test]
    async fn missing_evidence_stops_even_renewing_leases_and_cannot_be_resurrected() {
        let a = authority();
        a.expect_evidence_by(Instant::now() + crate::heartbeat::MAX_EVIDENCE_AGE)
            .unwrap();
        let evidence_deadline = a.live.lock().unwrap().evidence_deadline;
        a.accept(fresh(1)).unwrap();
        a.set_gate(GateState::Sealed);
        let ticket = a.ticket().unwrap();
        a.accept(fresh(1)).unwrap();
        assert_eq!(
            a.live.lock().unwrap().evidence_deadline,
            evidence_deadline,
            "leases must not acknowledge evidence"
        );
        a.live.lock().unwrap().evidence_deadline = Some(Instant::now());
        tokio::time::timeout(Duration::from_secs(1), a.invalidated(ticket))
            .await
            .unwrap();
        assert!(a.stop_reason().unwrap().contains("evidence"));
        assert!(a.accept(fresh(1)).is_err());
        assert!(a
            .expect_evidence_by(Instant::now() + crate::heartbeat::MAX_EVIDENCE_AGE)
            .is_err());
        assert_eq!(
            a.observations(),
            (
                GateObs {
                    state: GateState::Cut,
                    bypass_packets: None
                },
                WatchdogObs {
                    lease_token: 0,
                    deadline_remaining_ms: -1
                }
            )
        );
    }

    #[test]
    fn evidence_observes_the_actual_gate_and_current_lease_token() {
        let a = authority();
        let mut d = fresh(0);
        d.fencing_token = 42;
        a.accept(d).unwrap();
        for gate in [GateState::Cut, GateState::Unknown, GateState::Sealed] {
            a.set_gate(gate);
            let (observed_gate, watchdog) = a.observations();
            assert_eq!(
                observed_gate,
                GateObs {
                    state: gate,
                    bypass_packets: None
                }
            );
            assert_eq!(watchdog.lease_token, 42);
            assert!((1..=15_000).contains(&watchdog.deadline_remaining_ms));
        }
    }
}
