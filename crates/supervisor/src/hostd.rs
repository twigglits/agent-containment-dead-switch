//! VM2 → hostd client. Untrusted side of the channel: bearer token per incarnation, bounded log
//! queue (drop-oldest, counted), and the rung-1 lease copy verified against the controller key.

use deadswitch_common::*;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use tokio::sync::mpsc;

#[derive(Deserialize, Debug)]
pub struct LeaseView {
    pub run_id: String,
    pub epoch: u64,
    pub gate: GateState,
    pub lease: Option<Signed>,
    pub controller_pubkey: String,
}

pub struct Hostd {
    pub base: String,
    token: String,
    pub http: reqwest::Client,
    log_tx: mpsc::Sender<LogEvent>,
    log_seq: AtomicU64,
    pub log_dropped: std::sync::Arc<AtomicU64>,
}

impl Hostd {
    pub fn new(base: String, token: String) -> Arc<Self> {
        let (tx, mut rx) = mpsc::channel::<LogEvent>(1000);
        // Sealing the host gate deliberately flushes pf states. A keep-alive socket opened during
        // prestage is no longer a usable transport after that boundary: reusing it can lose the
        // first boot log or strand inference until its timeout. Each operation needs a fresh TCP
        // handshake under the CURRENT gate rules. Do not retry inference (it may have executed).
        let http = reqwest::Client::builder()
            .pool_max_idle_per_host(0)
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let h = Arc::new(Hostd {
            base,
            token,
            http,
            log_tx: tx,
            log_seq: AtomicU64::new(0),
            log_dropped: std::sync::Arc::new(AtomicU64::new(0)),
        });
        let hc = h.clone();
        tokio::spawn(async move {
            while let Some(ev) = rx.recv().await {
                let _ = hc
                    .http
                    .post(format!("{}/v1/log", hc.base))
                    .bearer_auth(&hc.token)
                    .json(&ev)
                    .send()
                    .await;
            }
        });
        h
    }

    pub fn log_dropped_handle(&self) -> std::sync::Arc<AtomicU64> {
        self.log_dropped.clone()
    }

    pub fn log(&self, kind: &str, msg: impl Into<String>, data: serde_json::Value) {
        let ev = LogEvent {
            seq: self.log_seq.fetch_add(1, Ordering::SeqCst),
            ts: now_unix(),
            kind: kind.into(),
            msg: msg.into(),
            data,
        };
        tracing::info!(kind, msg = %ev.msg, "event");
        if self.log_tx.try_send(ev).is_err() {
            self.log_dropped.fetch_add(1, Ordering::SeqCst);
        }
    }

    pub async fn lease(&self) -> anyhow::Result<LeaseView> {
        // Fetch the lease with a BLOCKING reqwest call on a spawn_blocking thread, NOT async reqwest
        // on the shared runtime: async reqwest here was intermittently starved/stalled under the
        // supervisor's tokio runtime (the same failure that moved the report path to a dedicated
        // thread), which left the eval-lease-wait loop hung so VM1 never booted. A dedicated blocking
        // thread cannot be starved by the async flow.
        let url = format!("{}/v1/lease", self.base);
        let token = self.token.clone();
        let v = tokio::task::spawn_blocking(move || -> anyhow::Result<LeaseView> {
            let c = reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()?;
            Ok(c.get(&url)
                .bearer_auth(&token)
                .send()?
                .error_for_status()?
                .json()?)
        })
        .await??;
        Ok(v)
    }

    /// Verified rung-1 lease: signature by the controller key, right run, replay-filtered by the
    /// caller's high-water mark.
    pub async fn verified_lease(
        &self,
        pk: &VerifyingKey,
        run_id: &str,
    ) -> anyhow::Result<Option<(Lease, GateState)>> {
        let v = self.lease().await?;
        match v.lease {
            None => Ok(None),
            Some(s) => {
                let l: Lease = s.verify(pk, "lease", AUD_HOSTD)?;
                anyhow::ensure!(l.run_id == run_id, "lease for another run");
                Ok(Some((l, v.gate)))
            }
        }
    }

    pub async fn report(&self, r: &Vm2Report) -> anyhow::Result<()> {
        self.http
            .post(format!("{}/v1/report", self.base))
            .bearer_auth(&self.token)
            .json(r)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn defender(&self, a: &DefenderAction) -> anyhow::Result<()> {
        self.http
            .post(format!("{}/v1/defender", self.base))
            .bearer_auth(&self.token)
            .json(a)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    pub async fn prestage_done(
        &self,
        manifest_digest: &str,
        image_digest: &str,
    ) -> anyhow::Result<()> {
        self.http
            .post(format!("{}/v1/prestage-done", self.base))
            .bearer_auth(&self.token)
            .json(&serde_json::json!({"manifest_digest": manifest_digest, "image_digest": image_digest}))
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    /// Forward exactly these bytes to the chokepoint.
    pub async fn chat(&self, body: bytes::Bytes) -> anyhow::Result<(u16, serde_json::Value)> {
        let r = self
            .http
            .post(format!("{}/v1/chat/completions", self.base))
            .bearer_auth(&self.token)
            .header("content-type", "application/json")
            .timeout(std::time::Duration::from_secs(90))
            .body(body)
            .send()
            .await?;
        let st = r.status().as_u16();
        let j = r
            .json::<serde_json::Value>()
            .await
            .unwrap_or(serde_json::json!({"error": "bad upstream body"}));
        Ok((st, j))
    }
}

#[cfg(test)]
mod tests {
    use super::Hostd;
    use std::time::Duration;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    #[tokio::test]
    async fn a_gate_transition_cannot_reuse_a_stranded_connection() {
        async fn reply(stream: &mut TcpStream) {
            let mut reader = BufReader::new(stream);
            loop {
                let mut line = String::new();
                assert!(reader.read_line(&mut line).await.unwrap() > 0);
                if line == "\r\n" {
                    break;
                }
            }
            reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .await
                .unwrap();
        }
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            // The first request works during prestage. Leave that TCP connection open but stop
            // replying on it, just as a state flush silently strands a pooled keep-alive socket.
            let (mut old, _) = listener.accept().await.unwrap();
            reply(&mut old).await;
            let (mut fresh, _) = listener.accept().await.unwrap();
            reply(&mut fresh).await;
            drop(old);
        });
        let h = Hostd::new(url.clone(), "test-token".into());
        for _ in 0..2 {
            tokio::time::timeout(Duration::from_secs(2), async {
                let r = h.http.get(&url).send().await.unwrap();
                assert!(r.status().is_success());
                assert_eq!(r.text().await.unwrap(), "{}");
            })
            .await
            .expect("request reused a connection stranded by the gate transition");
        }
        server.await.unwrap();
    }
}
