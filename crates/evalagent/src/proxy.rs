//! Linux port of hostd's inference chokepoint. The trusted evalagent owns this runtime and its
//! Authority; no guest-controlled IPC, lease file, or second process can grant dispatch authority.

use crate::authority::Authority;
use anyhow::Context;
use axum::{
    body::Bytes,
    extract::{rejection::BytesRejection, Request, State},
    http::{header, Method, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::any,
    Extension, Json, Router,
};
use deadswitch_common::{inference, sha256_hex, ChokepointObs, MAX_MSG_BYTES};
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[cfg(test)]
mod tests;

pub const PORT: u16 = 7001;
pub const BACKEND_PORT: u16 = 11434;
const ENDPOINT: &str = "/v1/chat/completions";

pub struct Proxy {
    authority: Arc<Authority>,
    model: String,
    backend: SocketAddr,
    http: reqwest::Client,
    obs: Mutex<ChokepointObs>,
    admission: tokio::sync::Semaphore,
    inference: tokio::sync::Semaphore,
}

impl Proxy {
    fn new(
        authority: Arc<Authority>,
        model: String,
        backend: SocketAddr,
    ) -> anyhow::Result<Arc<Self>> {
        Ok(Arc::new(Self {
            authority,
            model,
            backend,
            // Phase-1 fresh-connection fix: flushing gate conntrack must never strand a pooled
            // socket. HTTP/1 only also rules out multiplexed connection reuse. No redirects,
            // environment proxies, or retries (an inference may already have executed).
            http: reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .retry(reqwest::retry::never())
                .http1_only()
                .pool_max_idle_per_host(0)
                .connect_timeout(Duration::from_secs(5))
                .timeout(Duration::from_secs(60))
                .build()?,
            obs: Mutex::new(ChokepointObs::default()),
            admission: tokio::sync::Semaphore::new(8),
            inference: tokio::sync::Semaphore::new(1),
        }))
    }

    fn deny(&self, status: StatusCode, why: &str) -> Response {
        self.obs.lock().unwrap().denied += 1;
        tracing::debug!(why, "chokepoint_denied");
        (status, Json(serde_json::json!({"error": why}))).into_response()
    }

    pub fn observations(&self) -> ChokepointObs {
        self.obs.lock().unwrap().clone()
    }

    fn router(self: &Arc<Self>) -> Router {
        // Every method/path goes through the same exact-action admission check, including wrong
        // methods, queries, raw /api routes and percent-encoded aliases.
        Router::new()
            .fallback(any(chat))
            .layer(axum::extract::DefaultBodyLimit::max(MAX_MSG_BYTES))
            .layer(middleware::from_fn_with_state(self.clone(), admission))
            .with_state(self.clone())
    }
}

#[derive(Clone, Copy)]
struct DispatchTicket(u64);

async fn admission(State(proxy): State<Arc<Proxy>>, mut req: Request, next: Next) -> Response {
    let response = async {
        let Ok(_permit) = proxy.admission.try_acquire() else {
            return proxy.deny(StatusCode::SERVICE_UNAVAILABLE, "overloaded");
        };
        if req.method() != Method::POST
            || req.uri().scheme().is_some()
            || req.uri().authority().is_some()
            || req.uri().path_and_query().map(|p| p.as_str()) != Some(ENDPOINT)
        {
            return proxy.deny(
                StatusCode::FORBIDDEN,
                "only POST /v1/chat/completions is mediated",
            );
        }
        let Some(ticket) = proxy.authority.ticket() else {
            return proxy.deny(StatusCode::FORBIDDEN, "no active sealed eval lease");
        };
        req.extensions_mut().insert(DispatchTicket(ticket));
        match tokio::time::timeout(Duration::from_secs(75), next.run(req)).await {
            Ok(response) => response,
            Err(_) => proxy.deny(StatusCode::GATEWAY_TIMEOUT, "request timeout"),
        }
    }
    .await;
    let mut response = response;
    // Fresh guest connection per operation too: its state is also flushed on seal/cut.
    response.headers_mut().insert(
        header::CONNECTION,
        header::HeaderValue::from_static("close"),
    );
    response
}

async fn chat(
    State(proxy): State<Arc<Proxy>>,
    Extension(DispatchTicket(ticket)): Extension<DispatchTicket>,
    body: Result<Bytes, BytesRejection>,
) -> Response {
    let body = match body {
        Ok(body) => body,
        Err(_) => {
            return proxy.deny(
                StatusCode::PAYLOAD_TOO_LARGE,
                "unreadable or oversized body",
            )
        }
    };
    let backend = match inference::backend_request(&proxy.model, &body) {
        Ok(backend) => backend,
        Err(why) => return proxy.deny(StatusCode::FORBIDDEN, why),
    };
    // Retain the request's original generation while queued. Re-sealing cannot authorize old work.
    let permit = tokio::select! {
        biased;
        _ = proxy.authority.invalidated(ticket) => return proxy.deny(StatusCode::FORBIDDEN, "authority lost while queued"),
        p = proxy.inference.acquire() => p,
    };
    let Ok(_permit) = permit else {
        return proxy.deny(StatusCode::SERVICE_UNAVAILABLE, "inference closed");
    };
    if !proxy.authority.active(ticket) {
        return proxy.deny(StatusCode::FORBIDDEN, "authority lost before dispatch");
    }
    let fetch = async {
        // Final dispatch fence is inside the selected future, immediately before send, just as
        // Phase-1 hostd rechecks after acquiring its semaphore and subscribing to cancellation.
        anyhow::ensure!(proxy.authority.active(ticket), "authority lost before send");
        proxy.obs.lock().unwrap().inference_requests += 1;
        tracing::debug!(digest = %sha256_hex(&body), "chokepoint_forward");
        let mut response = proxy
            .http
            .post(format!("http://{}/api/chat", proxy.backend))
            .header(header::CONNECTION, "close")
            .json(&backend)
            .send()
            .await?;
        let status = response.status();
        // Bound the whole native response, including chunked bodies, before parsing or returning
        // any content. This remains within the cancellation select through the final body byte.
        let mut bytes = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            anyhow::ensure!(
                chunk.len() <= MAX_MSG_BYTES.saturating_sub(bytes.len()),
                "upstream body too large"
            );
            bytes.extend_from_slice(&chunk);
        }
        let native: serde_json::Value =
            serde_json::from_slice(&bytes).context("invalid upstream JSON")?;
        Ok::<_, anyhow::Error>((status, native))
    };
    let result = tokio::select! {
        biased;
        _ = proxy.authority.invalidated(ticket) => return proxy.deny(StatusCode::FORBIDDEN, "authority lost; in-flight inference cancelled"),
        result = fetch => result,
    };
    // Fence even a simultaneously ready response/cancellation. Nothing from upstream is returned
    // once the generation, either clock, gate, or shutdown state has invalidated this operation.
    if !proxy.authority.active(ticket) {
        return proxy.deny(
            StatusCode::FORBIDDEN,
            "authority lost during inference; response withheld",
        );
    }
    match result {
        Ok((status, native)) => (
            status,
            Json(inference::map_response(&proxy.model, &body, &native)),
        )
            .into_response(),
        Err(e) => {
            tracing::warn!(error = %e, "inference backend failed");
            (
                StatusCode::BAD_GATEWAY,
                Json(serde_json::json!({"error": "inference backend unavailable"})),
            )
                .into_response()
        }
    }
}

/// Keeps the proxy and its deadline monitor running independently of synchronous controller and
/// shell-hook calls. Dropping the owning evalagent scope revokes authority before stopping workers.
pub struct ProxyRuntime {
    runtime: Option<tokio::runtime::Runtime>,
    pub proxy: Arc<Proxy>,
}

impl ProxyRuntime {
    pub fn start(
        host: Ipv4Addr,
        peer: Ipv4Addr,
        backend: Ipv4Addr,
        model: String,
        authority: Arc<Authority>,
    ) -> anyhow::Result<Self> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()?;
        let proxy = Proxy::new(
            authority.clone(),
            model,
            SocketAddr::from((backend, BACKEND_PORT)),
        )?;
        let listener =
            runtime.block_on(CappedListener::bind(SocketAddr::from((host, PORT)), peer))?;
        let router = proxy.router();
        runtime.spawn(async move {
            tokio::select! {
                result = axum::serve(listener, router) => {
                    tracing::error!(?result, "proxy listener stopped");
                    authority.stop("proxy listener stopped");
                },
                _ = authority.stopped() => {},
            }
        });
        tracing::info!(%host, port = PORT, %peer, %backend, backend_port = BACKEND_PORT, "exact-action proxy listening");
        Ok(Self {
            runtime: Some(runtime),
            proxy,
        })
    }
}

impl Drop for ProxyRuntime {
    fn drop(&mut self) {
        self.proxy.authority.stop("proxy runtime stopping");
        tracing::info!(chokepoint = ?self.proxy.observations(), "proxy stopped");
        if let Some(runtime) = self.runtime.take() {
            runtime.shutdown_timeout(Duration::from_secs(1));
        }
    }
}

/// Ported from hostd's CappedListener/CappedStream: cap 64 live connections before HTTP admission.
/// Additionally check the VM2 source address on this dedicated L3 tap. The kernel gate provides
/// the interface binding/anti-bypass boundary; guest-supplied headers are never authentication.
struct CappedListener {
    inner: tokio::net::TcpListener,
    sem: Arc<tokio::sync::Semaphore>,
    peer: Ipv4Addr,
}

impl CappedListener {
    async fn bind(addr: SocketAddr, peer: Ipv4Addr) -> std::io::Result<Self> {
        Ok(Self {
            inner: tokio::net::TcpListener::bind(addr).await?,
            sem: Arc::new(tokio::sync::Semaphore::new(64)),
            peer,
        })
    }
}

impl axum::serve::Listener for CappedListener {
    type Io = CappedStream;
    type Addr = SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            let permit = self
                .sem
                .clone()
                .acquire_owned()
                .await
                .expect("connection semaphore never closed");
            match self.inner.accept().await {
                Ok((stream, addr)) if addr.ip() == self.peer => {
                    return (
                        CappedStream {
                            inner: stream,
                            _permit: permit,
                        },
                        addr,
                    )
                }
                Ok(_) => {}
                Err(_) => tokio::time::sleep(Duration::from_millis(10)).await,
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.inner.local_addr()
    }
}

struct CappedStream {
    inner: tokio::net::TcpStream,
    _permit: tokio::sync::OwnedSemaphorePermit,
}

impl AsyncRead for CappedStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for CappedStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }
    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}
