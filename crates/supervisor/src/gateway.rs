//! Exact-action gateway (docs §5). VM1's only reachable service. One permitted operation:
//! `POST /v1/chat/completions` with a pinned model. Approval is bound to the request digest and the
//! forwarded bytes are the reviewed bytes; a current rung-1 lease is re-checked at dispatch.

use crate::defender::{Decision, Defender};
use crate::hostd::Hostd;
use axum::{
    body::Bytes,
    extract::State,
    http::{Method, StatusCode, Uri},
    response::IntoResponse,
    routing::{any, post},
    Json, Router,
};
use deadswitch_common::*;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

pub struct Gateway {
    pub hostd: Arc<Hostd>,
    pub defender: Arc<Defender>,
    pub model: String,
    pub allowed: AtomicU64,
    pub denied: AtomicU64,
    /// set by the run loop from the verified rung-1 lease; false ⇒ nothing is forwarded
    pub lease_active: AtomicBool,
    /// bounded concurrency (docs §8)
    pub sem: tokio::sync::Semaphore,
}

pub fn validate(model: &str, body: &[u8]) -> Result<serde_json::Value, &'static str> {
    if body.len() > MAX_MSG_BYTES {
        return Err("body too large");
    }
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|_| "not json")?;
    let o = v.as_object().ok_or("not an object")?;
    if o.get("model").and_then(|m| m.as_str()) != Some(model) {
        return Err("model not pinned");
    }
    for k in ["tools", "functions", "tool_choice", "function_call", "response_format"] {
        if o.contains_key(k) {
            return Err("tool/function fields not allowed");
        }
    }
    if o.get("stream").and_then(|s| s.as_bool()).unwrap_or(false) {
        return Err("stream must be false");
    }
    if o.get("n").and_then(|n| n.as_u64()).unwrap_or(1) != 1 {
        return Err("n must be 1");
    }
    // max_tokens: must be a non-negative integer ≤ 1024 if present. `as_u64()` alone let -1 through
    // (it returns None → treated as 0 → passed → forwarded unchanged, and Ollama maps -1 to unlimited
    // generation). Reject any non-u64 or out-of-range value outright (Codex end-of-P1 #5).
    if let Some(mt) = o.get("max_tokens") {
        match mt.as_u64() {
            Some(n) if n <= 1024 => {}
            _ => return Err("max_tokens must be an integer in [0,1024]"),
        }
    }
    if o.get("messages").and_then(|m| m.as_array()).map(|a| a.is_empty()).unwrap_or(true) {
        return Err("messages required");
    }
    Ok(v)
}

async fn chat(State(g): State<Arc<Gateway>>, body: Bytes) -> impl IntoResponse {
    let digest = sha256_hex(&body);
    let deny = |g: &Gateway, why: &str, code: StatusCode| {
        g.denied.fetch_add(1, Ordering::SeqCst);
        g.hostd.log("gateway_denied", why, serde_json::json!({"digest": digest, "path": "/v1/chat/completions"}));
        (code, Json(serde_json::json!({"error": why}))).into_response()
    };
    if let Err(why) = validate(&g.model, &body) {
        if let Some(a) = g.defender.observe_forbidden(why) {
            let _ = g.hostd.defender(&a).await;
        }
        return deny(&g, why, StatusCode::FORBIDDEN);
    }
    let (decision, action) = g.defender.review_inference(&body, &digest);
    if let Some(a) = action {
        let _ = g.hostd.defender(&a).await;
    }
    if let Decision::Deny(why) = decision {
        return deny(&g, &why, StatusCode::FORBIDDEN);
    }
    let Ok(_permit) = g.sem.try_acquire() else { return deny(&g, "too many concurrent requests", StatusCode::TOO_MANY_REQUESTS) };
    // bind review to execution: the lease must still be active NOW, and we forward the reviewed bytes
    if !g.lease_active.load(Ordering::SeqCst) {
        return deny(&g, "no active lease at dispatch", StatusCode::FORBIDDEN);
    }
    g.allowed.fetch_add(1, Ordering::SeqCst);
    g.hostd.log("gateway_forward", "inference request approved", serde_json::json!({"digest": digest, "bytes": body.len()}));
    match g.hostd.chat(body).await {
        Ok((st, j)) => (StatusCode::from_u16(st).unwrap_or(StatusCode::BAD_GATEWAY), Json(j)).into_response(),
        Err(e) => (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": e.to_string()}))).into_response(),
    }
}

/// Every other method/path: denied, logged, and shown to the defender as a forbidden attempt.
async fn fallback(State(g): State<Arc<Gateway>>, method: Method, uri: Uri) -> impl IntoResponse {
    g.denied.fetch_add(1, Ordering::SeqCst);
    let what = format!("{method} {uri}");
    g.hostd.log("gateway_denied", "forbidden request", serde_json::json!({"request": what}));
    if let Some(a) = g.defender.observe_forbidden(&what) {
        let _ = g.hostd.defender(&a).await;
    }
    (StatusCode::FORBIDDEN, Json(serde_json::json!({"error": "forbidden: only POST /v1/chat/completions is mediated"})))
}

pub fn router(g: Arc<Gateway>) -> Router {
    Router::new()
        .route("/v1/chat/completions", post(chat))
        .fallback(any(fallback))
        .layer(axum::extract::DefaultBodyLimit::max(MAX_MSG_BYTES + 4096))
        .with_state(g)
}

#[cfg(test)]
mod tests {
    use super::validate;

    #[test]
    fn only_the_one_bounded_operation_validates() {
        let ok = br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;
        assert!(validate("m", ok).is_ok());
        assert_eq!(validate("other", ok).unwrap_err(), "model not pinned");
        assert_eq!(validate("m", br#"{"model":"m","messages":[],"tools":[]}"#).unwrap_err(), "tool/function fields not allowed");
        assert_eq!(validate("m", br#"{"model":"m","messages":[],"stream":true}"#).unwrap_err(), "stream must be false");
        assert_eq!(validate("m", br#"{"model":"m","messages":[{"role":"user","content":"h"}],"max_tokens":4096}"#).unwrap_err(), "max_tokens must be an integer in [0,1024]");
        // the -1 bypass: as_u64() is None → must be rejected, not silently forwarded
        assert_eq!(validate("m", br#"{"model":"m","messages":[{"role":"user","content":"h"}],"max_tokens":-1}"#).unwrap_err(), "max_tokens must be an integer in [0,1024]");
        assert_eq!(validate("m", br#"{"model":"m"}"#).unwrap_err(), "messages required");
        assert_eq!(validate("m", br#"{"model":"m","messages":[]}"#).unwrap_err(), "messages required");
        assert_eq!(validate("m", b"GET / HTTP/1.1").unwrap_err(), "not json");
    }
}
