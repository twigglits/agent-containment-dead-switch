use super::*;
use axum::http::{HeaderMap, Uri};
use deadswitch_common::{now_unix, Deadline, GateState};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, Notify, Semaphore};
use tokio::task::{JoinHandle, JoinSet};

const VALID: &[u8] = br#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#;
const WAIT: Duration = Duration::from_secs(3);
static NO_SIGNAL: AtomicBool = AtomicBool::new(false);

fn fresh_lease() -> Deadline {
    Deadline {
        mono: Instant::now() + Duration::from_secs(15),
        wall: now_unix() + 15,
        fencing_token: 1,
        epoch: 1,
    }
}

fn active_authority() -> Arc<Authority> {
    let authority = Authority::new(&NO_SIGNAL);
    authority.accept(fresh_lease()).unwrap();
    authority.set_gate(GateState::Sealed);
    authority
}

struct Server {
    addr: SocketAddr,
    task: JoinHandle<()>,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve(router: Router) -> Server {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    Server { addr, task }
}

async fn serve_proxy(authority: Arc<Authority>, backend: SocketAddr) -> (Arc<Proxy>, Server) {
    serve_proxy_for_peer(authority, backend, Ipv4Addr::LOCALHOST).await
}

async fn serve_proxy_for_peer(
    authority: Arc<Authority>,
    backend: SocketAddr,
    peer: Ipv4Addr,
) -> (Arc<Proxy>, Server) {
    let proxy = Proxy::new(authority, "m".into(), backend).unwrap();
    let listener = CappedListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)), peer)
        .await
        .unwrap();
    let addr = listener.inner.local_addr().unwrap();
    let router = proxy.router();
    let task = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (proxy, Server { addr, task })
}

fn guest_client() -> reqwest::Client {
    reqwest::Client::builder()
        .no_proxy()
        .http1_only()
        .retry(reqwest::retry::never())
        .timeout(WAIT)
        .build()
        .unwrap()
}

async fn request(
    addr: SocketAddr,
    method: Method,
    path: &str,
    body: &[u8],
) -> (StatusCode, HeaderMap, Vec<u8>) {
    let response = guest_client()
        .request(method, format!("http://{addr}{path}"))
        .body(body.to_vec())
        .send()
        .await
        .unwrap();
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await.unwrap().to_vec();
    (status, headers, body)
}

async fn chat_request(addr: SocketAddr) -> (StatusCode, HeaderMap, Vec<u8>) {
    request(addr, Method::POST, ENDPOINT, VALID).await
}

async fn wait_until(mut predicate: impl FnMut() -> bool) {
    tokio::time::timeout(WAIT, async {
        while !predicate() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("condition did not become true");
}

async fn no_connection(listener: &TcpListener) {
    assert!(
        tokio::time::timeout(Duration::from_millis(75), listener.accept())
            .await
            .is_err(),
        "forbidden request reached a backend listener"
    );
}

#[tokio::test]
async fn exact_wire_action_and_bounds_are_rejected_before_any_backend_connection() {
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (proxy, server) = serve_proxy(active_authority(), backend.local_addr().unwrap()).await;
    let mut denied = 0;
    let mut attempts = Vec::new();
    for method in [
        Method::GET,
        Method::PUT,
        Method::DELETE,
        Method::HEAD,
        Method::OPTIONS,
    ] {
        attempts.push((
            method,
            ENDPOINT.to_string(),
            VALID.to_vec(),
            StatusCode::FORBIDDEN,
        ));
    }
    for path in [
        "/api/chat",
        "/api/generate",
        "/v1/models",
        "/v1/chat/completions/",
        "/v1/chat/completions?model=other",
        "/v1/chat/%63ompletions",
        "/V1/chat/completions",
    ] {
        attempts.push((
            Method::POST,
            path.to_string(),
            VALID.to_vec(),
            StatusCode::FORBIDDEN,
        ));
    }
    for (key, value) in [
        ("model", json!("other")),
        ("stream", json!(true)),
        ("stream", json!("false")),
        ("n", json!(2)),
        ("n", json!(-1)),
        ("max_tokens", json!(-1)),
        ("max_tokens", json!(1025)),
        ("max_tokens", json!("512")),
        ("tools", json!([])),
        ("functions", json!([])),
        ("tool_choice", json!(null)),
        ("function_call", json!(null)),
        ("response_format", json!({})),
        ("messages", json!([])),
        ("messages", json!([{"role": "user", "content": []}])),
    ] {
        let mut body: Value = serde_json::from_slice(VALID).unwrap();
        body[key] = value;
        attempts.push((
            Method::POST,
            ENDPOINT.to_string(),
            serde_json::to_vec(&body).unwrap(),
            StatusCode::FORBIDDEN,
        ));
    }
    attempts.push((
        Method::POST,
        ENDPOINT.into(),
        b"not json".to_vec(),
        StatusCode::FORBIDDEN,
    ));
    attempts.push((
        Method::POST,
        ENDPOINT.into(),
        vec![b' '; MAX_MSG_BYTES + 1],
        StatusCode::PAYLOAD_TOO_LARGE,
    ));
    for (method, path, body, expected) in attempts {
        let (status, headers, _) = request(server.addr, method.clone(), &path, &body).await;
        assert_eq!(
            status,
            expected,
            "{method} {path}: {}",
            String::from_utf8_lossy(&body[..body.len().min(256)])
        );
        assert_eq!(headers.get(header::CONNECTION).unwrap(), "close");
        denied += 1;
        assert_eq!(
            proxy.observations(),
            ChokepointObs {
                inference_requests: 0,
                denied
            }
        );
    }
    // reqwest emits origin-form targets; exercise absolute-form admission using the raw wire.
    let mut absolute = TcpStream::connect(server.addr).await.unwrap();
    absolute.write_all(format!("POST http://{}/v1/chat/completions HTTP/1.1\r\nHost: {}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n", server.addr, server.addr).as_bytes()).await.unwrap();
    let mut response = String::new();
    tokio::time::timeout(WAIT, absolute.read_to_string(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with("HTTP/1.1 403"), "{response}");
    assert_eq!(
        proxy.observations(),
        ChokepointObs {
            inference_requests: 0,
            denied: denied + 1
        }
    );
    no_connection(&backend).await;
}

#[tokio::test]
async fn one_fresh_native_action_is_sent_and_response_is_mapped() {
    let (tx, mut received) = mpsc::unbounded_channel();
    let backend = serve(Router::new().fallback(any(move |method: Method, uri: Uri, headers: HeaderMap, body: Bytes| {
        let tx = tx.clone();
        async move {
            tx.send((method, uri.to_string(), headers, body)).unwrap();
            Json(json!({"model": "untrusted-model", "message": {"content": "bounded answer", "tool_calls": ["hidden"]}, "done_reason": "length", "prompt_eval_count": 5, "eval_count": 7}))
        }
    }))).await;
    let (proxy, server) = serve_proxy(active_authority(), backend.addr).await;
    let body = serde_json::to_vec(&json!({
        "model": "m", "messages": [{"role": "user", "content": "hi", "images": ["hidden"]}],
        "stream": false, "n": 1, "max_tokens": 16, "max_tokenſ": -1,
        "MODEL": "other", "options": {"num_ctx": -1, "num_predict": -1}, "keep_alive": -1,
    }))
    .unwrap();
    let (status, headers, mapped) = request(server.addr, Method::POST, ENDPOINT, &body).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers.get(header::CONNECTION).unwrap(), "close");
    let (method, uri, headers, native) = received.recv().await.unwrap();
    assert_eq!(method, Method::POST);
    assert_eq!(uri, "/api/chat");
    assert_eq!(headers.get(header::CONNECTION).unwrap(), "close");
    assert_eq!(
        serde_json::from_slice::<Value>(&native).unwrap(),
        json!({
            "model": "m", "messages": [{"role": "user", "content": "hi"}], "stream": false,
            "options": {"num_ctx": 4096, "num_predict": 16},
        })
    );
    assert_eq!(
        serde_json::from_slice::<Value>(&mapped).unwrap(),
        json!({
            "id": format!("chatcmpl-{}", &sha256_hex(&body)[..24]), "object": "chat.completion", "model": "m",
            "choices": [{"index": 0, "message": {"role": "assistant", "content": "bounded answer"}, "finish_reason": "length"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 7},
        })
    );
    assert_eq!(
        proxy.observations(),
        ChokepointObs {
            inference_requests: 1,
            denied: 0
        }
    );
    assert!(received.try_recv().is_err());
}

#[tokio::test]
async fn only_one_inference_dispatches_at_a_time() {
    let released = Arc::new(Semaphore::new(0));
    let active = Arc::new(AtomicUsize::new(0));
    let (started, mut starts) = mpsc::unbounded_channel();
    let backend = serve(Router::new().fallback(any({
        let released = released.clone();
        let active = active.clone();
        move || {
            let released = released.clone();
            let active = active.clone();
            let started = started.clone();
            async move {
                assert_eq!(
                    active.fetch_add(1, Ordering::SeqCst),
                    0,
                    "backend calls overlapped"
                );
                started.send(()).unwrap();
                released.acquire().await.unwrap().forget();
                active.fetch_sub(1, Ordering::SeqCst);
                Json(json!({"message": {"content": "ok"}}))
            }
        }
    })))
    .await;
    let (proxy, server) = serve_proxy(active_authority(), backend.addr).await;
    let first = tokio::spawn(chat_request(server.addr));
    tokio::time::timeout(WAIT, starts.recv())
        .await
        .unwrap()
        .unwrap();
    let second = tokio::spawn(chat_request(server.addr));
    wait_until(|| proxy.admission.available_permits() == 6).await;
    assert_eq!(proxy.observations().inference_requests, 1);
    assert!(starts.try_recv().is_err());
    released.add_permits(1);
    assert_eq!(
        tokio::time::timeout(WAIT, first).await.unwrap().unwrap().0,
        StatusCode::OK
    );
    tokio::time::timeout(WAIT, starts.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(proxy.observations().inference_requests, 2);
    released.add_permits(1);
    assert_eq!(
        tokio::time::timeout(WAIT, second).await.unwrap().unwrap().0,
        StatusCode::OK
    );
    assert_eq!(proxy.observations().denied, 0);
}

#[tokio::test]
async fn queued_and_in_flight_work_cannot_dispatch_across_cut_then_reseal() {
    let started = Arc::new(Notify::new());
    let blocked = Arc::new(Notify::new());
    let backend = serve(Router::new().fallback(any({
        let started = started.clone();
        move || {
            let started = started.clone();
            let blocked = blocked.clone();
            async move {
                started.notify_one();
                blocked.notified().await;
                Json(json!({"message": {"content": "must not escape"}}))
            }
        }
    })))
    .await;
    let authority = active_authority();
    let (proxy, server) = serve_proxy(authority.clone(), backend.addr).await;
    let first = tokio::spawn(chat_request(server.addr));
    tokio::time::timeout(WAIT, started.notified())
        .await
        .unwrap();
    let queued = tokio::spawn(chat_request(server.addr));
    wait_until(|| proxy.admission.available_permits() == 6).await;
    assert_eq!(proxy.observations().inference_requests, 1);
    authority.set_gate(GateState::Cut);
    authority.set_gate(GateState::Sealed);
    for task in [first, queued] {
        let (status, _, body) = tokio::time::timeout(WAIT, task).await.unwrap().unwrap();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(!String::from_utf8_lossy(&body).contains("must not escape"));
    }
    assert_eq!(
        proxy.observations(),
        ChokepointObs {
            inference_requests: 1,
            denied: 2
        }
    );
    assert!(
        authority.ticket().is_some(),
        "new work can have a new generation after reseal"
    );
}

// Minimal HTTP/1 reader lets the backend deliberately retain sockets and strand partial bodies.
// reqwest sends a Content-Length for the fresh JSON; a second request on the same socket is visible.
async fn read_request(stream: &mut BufReader<TcpStream>) -> std::io::Result<Option<String>> {
    let mut request_line = String::new();
    if stream.read_line(&mut request_line).await? == 0 {
        return Ok(None);
    }
    let mut length = 0;
    loop {
        let mut header = String::new();
        if stream.read_line(&mut header).await? == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "partial headers",
            ));
        }
        if header == "\r\n" {
            break;
        }
        if let Some((name, value)) = header.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                length = value.trim().parse::<usize>().unwrap();
            }
        }
    }
    assert!(length <= MAX_MSG_BYTES * 2);
    stream.read_exact(&mut vec![0; length]).await?;
    Ok(Some(request_line))
}

#[tokio::test]
async fn denial_signal_and_lease_expiry_cancel_partial_response_bodies() {
    for reason in ["denied", "signal", "expired"] {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let backend_addr = listener.local_addr().unwrap();
        let (sent, received) = tokio::sync::oneshot::channel();
        let (closed, was_closed) = tokio::sync::oneshot::channel();
        let backend = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            assert!(read_request(&mut stream).await.unwrap().is_some());
            stream.get_mut().write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 1000\r\n\r\n{\"message\":{\"content\":\"PRIVATE PARTIAL ANSWER").await.unwrap();
            sent.send(()).unwrap();
            let mut byte = [0];
            let result = stream.read(&mut byte).await;
            closed.send(matches!(result, Ok(0) | Err(_))).unwrap();
        });
        let _backend = Server {
            addr: backend_addr,
            task: backend,
        };
        let signal = Box::leak(Box::new(AtomicBool::new(false)));
        let authority = Authority::new(signal);
        authority.accept(fresh_lease()).unwrap();
        authority.set_gate(GateState::Sealed);
        let (proxy, server) = serve_proxy(authority.clone(), backend_addr).await;
        let request = tokio::spawn(chat_request(server.addr));
        tokio::time::timeout(WAIT, received).await.unwrap().unwrap();
        match reason {
            "denied" => authority.stop("controller Denied order"),
            "signal" => signal.store(true, Ordering::SeqCst),
            "expired" => {
                let mut short = fresh_lease();
                short.mono = Instant::now() + Duration::from_millis(30);
                authority.accept(short).unwrap();
            }
            _ => unreachable!(),
        }
        let (status, _, body) = tokio::time::timeout(WAIT, request).await.unwrap().unwrap();
        assert_eq!(status, StatusCode::FORBIDDEN, "{reason}");
        assert!(
            !String::from_utf8_lossy(&body).contains("PRIVATE"),
            "{reason}"
        );
        assert!(
            tokio::time::timeout(WAIT, was_closed)
                .await
                .unwrap()
                .unwrap(),
            "upstream socket remained open after {reason}"
        );
        assert!(
            authority.accept(fresh_lease()).is_err(),
            "{reason} must be terminal"
        );
        assert_eq!(chat_request(server.addr).await.0, StatusCode::FORBIDDEN);
        assert_eq!(
            proxy.observations(),
            ChokepointObs {
                inference_requests: 1,
                denied: 2
            }
        );
    }
}

#[tokio::test]
async fn completed_backend_content_is_withheld_when_authority_is_revoked() {
    let authority = active_authority();
    let backend = serve(Router::new().fallback(any({
        let authority = authority.clone();
        move || {
            let authority = authority.clone();
            async move {
                authority.stop("backend completes simultaneously with a Denied order");
                Json(json!({"message": {"content": "PRIVATE COMPLETED ANSWER"}}))
            }
        }
    })))
    .await;
    let (proxy, server) = serve_proxy(authority, backend.addr).await;
    let (status, _, body) = chat_request(server.addr).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!String::from_utf8_lossy(&body).contains("PRIVATE"));
    assert_eq!(
        proxy.observations(),
        ChokepointObs {
            inference_requests: 1,
            denied: 1
        }
    );
}

#[tokio::test]
async fn absent_lease_prestage_and_unsealed_gate_never_reach_backend() {
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let authority = Authority::new(&NO_SIGNAL);
    let (proxy, server) = serve_proxy(authority.clone(), backend.local_addr().unwrap()).await;
    assert_eq!(chat_request(server.addr).await.0, StatusCode::FORBIDDEN);
    authority.set_gate(GateState::Sealed);
    assert_eq!(chat_request(server.addr).await.0, StatusCode::FORBIDDEN);
    let mut prestage = fresh_lease();
    prestage.epoch = 0;
    authority.accept(prestage).unwrap();
    assert_eq!(chat_request(server.addr).await.0, StatusCode::FORBIDDEN);
    authority.accept(fresh_lease()).unwrap();
    for gate in [GateState::Open, GateState::Cut, GateState::Unknown] {
        authority.set_gate(gate);
        assert_eq!(chat_request(server.addr).await.0, StatusCode::FORBIDDEN);
    }
    assert_eq!(
        proxy.observations(),
        ChokepointObs {
            inference_requests: 0,
            denied: 6
        }
    );
    no_connection(&backend).await;
}

#[derive(Debug, PartialEq)]
enum ConnectionEvent {
    Accepted(usize),
    Request(usize),
    Closed(usize),
}

#[tokio::test]
async fn completed_calls_use_fresh_tcp_connections_across_seal() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (events, mut event) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        let mut id = 0;
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            id += 1;
            let id = id;
            let events = events.clone();
            events.send(ConnectionEvent::Accepted(id)).unwrap();
            connections.spawn(async move {
                let mut stream = BufReader::new(stream);
                while let Some(request) = read_request(&mut stream).await.unwrap() {
                    assert_eq!(request, "POST /api/chat HTTP/1.1\r\n");
                    events.send(ConnectionEvent::Request(id)).unwrap();
                    let body = br#"{"message":{"content":"ok"}}"#;
                    // Deliberately leave the server socket open and offer keep-alive, even though
                    // the proxy asks to close it. An idle pool regression would be observable here.
                    stream.get_mut().write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: keep-alive\r\n\r\n", body.len()).as_bytes()).await.unwrap();
                    stream.get_mut().write_all(body).await.unwrap();
                }
                events.send(ConnectionEvent::Closed(id)).unwrap();
            });
        }
    });
    let _backend = Server { addr, task };
    let authority = active_authority();
    let (proxy, server) = serve_proxy(authority.clone(), addr).await;
    for id in 1..=2 {
        if id == 2 {
            authority.set_gate(GateState::Cut);
            authority.set_gate(GateState::Sealed);
        }
        assert_eq!(chat_request(server.addr).await.0, StatusCode::OK);
        for expected in [
            ConnectionEvent::Accepted(id),
            ConnectionEvent::Request(id),
            ConnectionEvent::Closed(id),
        ] {
            assert_eq!(
                tokio::time::timeout(WAIT, event.recv())
                    .await
                    .unwrap()
                    .unwrap(),
                expected
            );
        }
    }
    assert_eq!(
        proxy.observations(),
        ChokepointObs {
            inference_requests: 2,
            denied: 0
        }
    );
}

#[tokio::test]
async fn upstream_redirects_are_not_followed() {
    let target = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let location = format!("http://{}/forbidden", target.local_addr().unwrap());
    let backend = serve(Router::new().fallback(any(move || {
        let location = location.clone();
        async move {
            (
                StatusCode::TEMPORARY_REDIRECT,
                [(header::LOCATION, location)],
                Json(json!({"message": {"content": "redirect refused"}})),
            )
        }
    })))
    .await;
    let (proxy, server) = serve_proxy(active_authority(), backend.addr).await;
    let (status, headers, _) = chat_request(server.addr).await;
    assert_eq!(status, StatusCode::TEMPORARY_REDIRECT);
    assert!(!headers.contains_key(header::LOCATION));
    assert_eq!(proxy.observations().inference_requests, 1);
    no_connection(&target).await;
}

#[tokio::test]
async fn oversized_chunked_backend_response_is_bounded_and_withheld() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = BufReader::new(stream);
        assert!(read_request(&mut stream).await.unwrap().is_some());
        stream.get_mut().write_all(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n").await.unwrap();
        // Valid native JSON would otherwise succeed, so BAD_GATEWAY must come from the bound,
        // rather than merely rejecting malformed JSON after collecting an unlimited body.
        let native =
            serde_json::to_vec(&json!({"message": {"content": "x".repeat(MAX_MSG_BYTES)}}))
                .unwrap();
        for chunk in native.chunks(MAX_MSG_BYTES / 2) {
            stream
                .get_mut()
                .write_all(format!("{:x}\r\n", chunk.len()).as_bytes())
                .await
                .unwrap();
            stream.get_mut().write_all(chunk).await.unwrap();
            stream.get_mut().write_all(b"\r\n").await.unwrap();
        }
        let _ = stream.get_mut().write_all(b"0\r\n\r\n").await;
    });
    let _backend = Server { addr, task };
    let (proxy, server) = serve_proxy(active_authority(), addr).await;
    let (status, _, body) = chat_request(server.addr).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(
        serde_json::from_slice::<Value>(&body).unwrap(),
        json!({"error": "inference backend unavailable"})
    );
    assert_eq!(proxy.observations().inference_requests, 1);
}

#[tokio::test]
async fn listener_refuses_a_peer_other_than_the_configured_vm2() {
    let backend = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let (proxy, server) = serve_proxy_for_peer(
        active_authority(),
        backend.local_addr().unwrap(),
        Ipv4Addr::new(127, 0, 0, 2),
    )
    .await;
    let response = guest_client()
        .post(format!("http://{}{ENDPOINT}", server.addr))
        .body(VALID)
        .send()
        .await;
    assert!(
        response.is_err(),
        "an unapproved source reached the HTTP router"
    );
    assert_eq!(proxy.observations(), ChokepointObs::default());
    no_connection(&backend).await;
}
