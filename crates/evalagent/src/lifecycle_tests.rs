//! Local-only wire and cleanup regressions. Hooks here touch temporary files; no VM, firewall,
//! interface or external controller is involved.

use super::*;
use std::io::{Read, Write};
use std::sync::atomic::AtomicU64;

static TEST_SEQUENCE: AtomicU64 = AtomicU64::new(0);
static NO_SIGNAL: AtomicBool = AtomicBool::new(false);

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        let sequence = TEST_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("ds-evalagent-{}-{sequence}", std::process::id()));
        std::fs::create_dir(&dir).unwrap();
        Self(dir)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn args(dir: &TempDir) -> RunArgs {
    RunArgs {
        controller_url: "http://127.0.0.1:1".into(),
        run_id: "r".into(),
        key_file: dir.0.join("key"),
        controller_pubkey: String::new(),
        incarnation: "inc".into(),
        vm2_template_digest: "template".into(),
        vm2_base_digest: "base".into(),
        lease_renew_interval_s: 5,
        boot_cmd: "exit 1".into(),
        seal_cmd: "true".into(),
        destroy_cmd: "true".into(),
        observe_cmd: r#"printf '{"running":true,"pid":7}'"#.into(),
        hostd_ip: Some(Ipv4Addr::new(10, 99, 0, 1)),
        vm2_ip: Ipv4Addr::new(10, 99, 0, 2),
        choke_wgip: Some(Ipv4Addr::new(10, 20, 0, 2)),
        model: "m".into(),
    }
}

fn grant(epoch: u64) -> Lease {
    Lease {
        v: PROTO_V,
        kind: "lease".into(),
        run_id: "r".into(),
        aud: AUD_HOSTD.into(),
        incarnation: "inc".into(),
        epoch,
        fencing_token: 7,
        issued_at: now_unix(),
        ttl_s: 15,
    }
}

/// Respond to exactly one real blocking controller request, after collecting the full body.
fn controller_response(response: LeaseResponse) -> (String, std::thread::JoinHandle<Signed>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut bytes = Vec::new();
        let end = loop {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            bytes.push(byte[0]);
            if bytes.ends_with(b"\r\n\r\n") {
                break bytes.len();
            }
        };
        let headers = String::from_utf8(bytes).unwrap();
        assert!(headers.starts_with("POST /lease HTTP/1.1\r\n"));
        let length = headers
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().unwrap())
            })
            .unwrap();
        assert!(end < 4096 && length < MAX_MSG_BYTES);
        let mut body = vec![0; length];
        stream.read_exact(&mut body).unwrap();
        let signed = serde_json::from_slice(&body).unwrap();
        let response = serde_json::to_vec(&response).unwrap();
        write!(stream, "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", response.len()).unwrap();
        stream.write_all(&response).unwrap();
        signed
    });
    (format!("http://{addr}"), handle)
}

#[test]
fn signed_lease_must_match_run_incarnation_epoch_and_high_water() {
    let dir = TempDir::new();
    let host_key = SigningKey::from_bytes(&[1; 32]);
    let controller = SigningKey::from_bytes(&[2; 32]);
    let wrong_key = SigningKey::from_bytes(&[3; 32]);
    let http = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    for case in [
        "valid",
        "wrong_run",
        "wrong_incarnation",
        "prestage_epoch",
        "stale",
        "bad_signature",
    ] {
        let mut a = args(&dir);
        let mut lease = grant(1);
        match case {
            "wrong_run" => lease.run_id = "other".into(),
            "wrong_incarnation" => lease.incarnation = "other".into(),
            "prestage_epoch" => lease.epoch = 0,
            _ => {}
        }
        let signer = if case == "bad_signature" {
            &wrong_key
        } else {
            &controller
        };
        let response = LeaseResponse::Granted {
            lease: Signed::sign(signer, "controller", &lease),
        };
        let (url, server) = controller_response(response);
        a.controller_url = url;
        let result = renew(
            &http,
            &a,
            &host_key,
            &controller.verifying_key(),
            1,
            GateState::Sealed,
            if case == "stale" { 7 } else { 0 },
        )
        .unwrap();
        assert_eq!(
            matches!(result, RenewOutcome::Granted(_)),
            case == "valid",
            "{case}"
        );
        let request: LeaseRequest = server
            .join()
            .unwrap()
            .verify(&host_key.verifying_key(), "lease_request", AUD_CONTROLLER)
            .unwrap();
        assert_eq!(
            (
                request.run_id.as_str(),
                request.incarnation.as_str(),
                request.epoch,
                request.gate
            ),
            ("r", "inc", 1, GateState::Sealed)
        );
    }
}

#[test]
fn even_an_unverifiable_denial_is_fail_closed() {
    let dir = TempDir::new();
    let mut a = args(&dir);
    let controller = SigningKey::from_bytes(&[2; 32]);
    let order = Order {
        v: PROTO_V,
        kind: "order".into(),
        run_id: "r".into(),
        aud: AUD_HOSTD.into(),
        incarnation: "inc".into(),
        issued_at: now_unix(),
        fencing_token: 9,
        order: OrderKind::Destroy,
        reason: "denied".into(),
    };
    let response = LeaseResponse::Denied {
        order: Signed::sign(&SigningKey::from_bytes(&[3; 32]), "controller", &order),
        reason: "denied".into(),
    };
    let (url, server) = controller_response(response);
    a.controller_url = url;
    let http = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let result = renew(
        &http,
        &a,
        &controller,
        &controller.verifying_key(),
        1,
        GateState::Sealed,
        0,
    )
    .unwrap();
    assert!(matches!(result, RenewOutcome::Denied));
    server.join().unwrap();
}

fn shell_quote(path: &Path) -> String {
    format!("'{}'", path.to_str().unwrap().replace('\'', "'\\''"))
}

#[test]
fn failing_seal_still_destroys_and_revokes_authority() {
    let dir = TempDir::new();
    let mut a = args(&dir);
    let events = dir.0.join("events");
    a.seal_cmd = format!("printf 'seal\\n' >> {}; exit 1", shell_quote(&events));
    a.destroy_cmd = format!("printf 'destroy\\n' >> {}", shell_quote(&events));
    let authority = Authority::new(&NO_SIGNAL);
    authority
        .accept(Deadline::accept(&grant(1), 0, now_unix()).unwrap())
        .unwrap();
    authority.set_gate(GateState::Sealed);
    assert!(authority.ticket().is_some());
    let key = SigningKey::from_bytes(&[1; 32]);
    let _ = fail_closed(&a, &authority, &key, "test denial");
    assert_eq!(authority.ticket(), None);
    assert!(authority
        .accept(Deadline::accept(&grant(1), 0, now_unix()).unwrap())
        .is_err());
    assert_eq!(std::fs::read_to_string(events).unwrap(), "seal\ndestroy\n");
}

#[test]
fn boot_failure_guard_cleans_up_even_before_listener_exists() {
    let dir = TempDir::new();
    let mut a = args(&dir);
    let events = dir.0.join("events");
    a.boot_cmd = format!("printf 'boot\\n' >> {}; exit 1", shell_quote(&events));
    a.seal_cmd = format!("printf 'seal\\n' >> {}", shell_quote(&events));
    a.destroy_cmd = format!("printf 'destroy\\n' >> {}", shell_quote(&events));
    let authority = Authority::new(&NO_SIGNAL);
    let http = reqwest::blocking::Client::builder()
        .no_proxy()
        .build()
        .unwrap();
    let key = SigningKey::from_bytes(&[2; 32]);
    {
        let _guard = RunGuard {
            args: &a,
            key: &key,
            authority: authority.clone(),
            armed: true,
        };
        assert!(run_workload(
            &a,
            &http,
            &key,
            &key.verifying_key(),
            &dir.0.join("state"),
            0,
            a.hostd_ip.unwrap(),
            a.choke_wgip.unwrap(),
            &authority
        )
        .is_err());
    }
    assert_eq!(
        std::fs::read_to_string(events).unwrap(),
        "boot\nseal\ndestroy\n"
    );
    assert!(authority.stop_reason().is_some());
}

#[test]
fn hook_network_configuration_matches_proxy_and_observation_is_conservative() {
    let dir = TempDir::new();
    let mut a = args(&dir);
    a.hostd_ip = Some(Ipv4Addr::new(10, 98, 0, 1));
    a.choke_wgip = Some(Ipv4Addr::new(10, 20, 0, 9));
    let out = hook_command(&a, "printf '%s %s %s %s %s %s' \"$HOSTD_IP\" \"$DS_WL_HOST_IP\" \"$DS_CHOKE_WGIP\" \"$CHOKE_WGIP\" \"$DS_VM2_IP\" \"$DS_MODEL\"").output().unwrap();
    assert_eq!(
        String::from_utf8(out.stdout).unwrap(),
        "10.98.0.1 10.98.0.1 10.20.0.9 10.20.0.9 10.99.0.2 m"
    );
    assert_eq!(observe_vm2(&a).running, Some(true));
    assert_eq!(
        observe_vm2(&a).nested_virt,
        None,
        "legacy observations must not invent healthy config"
    );
    a.observe_cmd = r#"printf '{"running":true,"pid":7,"nested_virt":true,"port_forwards":0,"writable_mounts":0}'"#.into();
    let observed = observe_vm2(&a);
    assert_eq!(
        (
            observed.nested_virt,
            observed.port_forwards,
            observed.writable_mounts
        ),
        (Some(true), Some(0), Some(0))
    );
    assert_eq!(
        (
            observed.instance,
            observed.template_digest,
            observed.base_image_digest
        ),
        (
            a.incarnation.clone(),
            a.vm2_template_digest.clone(),
            a.vm2_base_digest.clone()
        )
    );
    a.observe_cmd = "exit 1".into();
    assert_eq!(observe_vm2(&a).running, None);
    a.observe_cmd = "printf not-json".into();
    assert_eq!(observe_vm2(&a).running, None);
}

#[test]
fn conflicting_or_non_unicast_bind_addresses_are_rejected() {
    let host = Ipv4Addr::new(10, 99, 0, 1);
    let other = Ipv4Addr::new(10, 99, 0, 2);
    assert_eq!(resolve_address(None, None, host).unwrap(), host);
    assert_eq!(resolve_address(None, Some(other), host).unwrap(), other);
    assert_eq!(
        resolve_address(Some(host), Some(host), other).unwrap(),
        host
    );
    assert!(resolve_address(Some(host), Some(other), host).is_err());
    for ip in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(224, 0, 0, 1),
    ] {
        assert!(resolve_address(Some(ip), None, host).is_err());
    }
}

/// Local capture for the existing /terminated protocol. Never opens a mesh or public connection.
fn termination_response(status: &str) -> (String, std::thread::JoinHandle<Signed>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let status = status.to_string();
    let handle = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut header = Vec::new();
        loop {
            let mut byte = [0];
            stream.read_exact(&mut byte).unwrap();
            header.push(byte[0]);
            assert!(header.len() <= 4096);
            if header.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let header = String::from_utf8(header).unwrap();
        assert!(header.starts_with("POST /terminated HTTP/1.1\r\n"));
        let size: usize = header
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse().unwrap())
            })
            .unwrap();
        assert!(size <= 4096);
        let mut bytes = vec![0; size];
        stream.read_exact(&mut bytes).unwrap();
        write!(
            stream,
            "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        serde_json::from_slice(&bytes).unwrap()
    });
    (format!("http://{addr}"), handle)
}

#[test]
fn successful_destroy_and_independent_observation_notify_with_existing_host_key() {
    let dir = TempDir::new();
    let mut a = args(&dir);
    let events = dir.0.join("events");
    // Seal failure still cannot skip destruction; the deployed destroy hook independently cuts too.
    a.seal_cmd = format!("printf 'seal\\n' >> {}; exit 1", shell_quote(&events));
    a.destroy_cmd = format!("printf 'destroy\\n' >> {}", shell_quote(&events));
    a.observe_cmd = format!(
        "printf 'observe\\n' >> {}; printf '{{\"running\":false,\"pid\":null}}'",
        shell_quote(&events)
    );
    let (url, server) = termination_response("200 OK");
    a.controller_url = url;
    let key = SigningKey::from_bytes(&[19; 32]);
    let authority = Authority::new(&NO_SIGNAL);
    let _ = fail_closed(&a, &authority, &key, "test teardown");
    let envelope = server.join().unwrap();
    let message: termination::Terminated = envelope
        .verify(&key.verifying_key(), "terminated", AUD_CONTROLLER)
        .unwrap();
    assert_eq!(message.run_id, a.run_id);
    assert_eq!(message.incarnation, a.incarnation);
    assert!(now_unix().abs_diff(message.issued_at) <= CLOCK_SKEW_S);
    assert!(message.latency_ms < 5000);
    assert_eq!(
        std::fs::read_to_string(events).unwrap(),
        "seal\ndestroy\nobserve\n"
    );
    assert!(authority.stop_reason().is_some());
    assert!(authority
        .accept(Deadline::accept(&grant(1), 0, now_unix()).unwrap())
        .is_err());
    assert!(
        !a.key_file.exists(),
        "cleanup reuses the loaded signer and cannot generate credentials"
    );
}

#[test]
fn failed_destroy_or_absent_failed_running_or_contradictory_observation_never_notifies() {
    for case in [
        "destroy",
        "missing",
        "unknown",
        "failed",
        "running",
        "contradictory",
        "invalid",
        "oversize",
    ] {
        let dir = TempDir::new();
        let mut a = args(&dir);
        let events = dir.0.join("events");
        a.seal_cmd = format!("printf 'seal\\n' >> {}", shell_quote(&events));
        a.destroy_cmd = format!(
            "printf 'destroy\\n' >> {}{}",
            shell_quote(&events),
            if case == "destroy" { "; exit 1" } else { "" }
        );
        let observe = match case {
            "missing" => "true",
            "unknown" => "printf '{\"running\":null}'",
            "failed" => "printf '{\"running\":false}'; exit 1",
            "running" => "printf '{\"running\":true}'",
            "contradictory" => "printf '{\"running\":false,\"pid\":7}'",
            "invalid" => "printf not-json",
            "oversize" => "head -c 4097 /dev/zero",
            _ => "printf '{\"running\":false}'",
        };
        a.observe_cmd = format!("printf 'observe\\n' >> {}; {observe}", shell_quote(&events));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        a.controller_url = format!("http://{}", listener.local_addr().unwrap());
        let authority = Authority::new(&NO_SIGNAL);
        let key = SigningKey::from_bytes(&[19; 32]);
        let _ = fail_closed(&a, &authority, &key, "test uncertain teardown");
        assert_eq!(
            listener.accept().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock,
            "{case}"
        );
        assert!(authority.stop_reason().is_some());
        assert_eq!(
            std::fs::read_to_string(events).unwrap(),
            if case == "destroy" {
                "seal\ndestroy\n"
            } else {
                "seal\ndestroy\nobserve\n"
            },
            "{case}"
        );
    }
}

#[test]
fn hanging_observation_is_bounded_and_does_not_skip_destroy_or_notify() {
    let dir = TempDir::new();
    let mut a = args(&dir);
    let destroyed = dir.0.join("destroyed");
    a.destroy_cmd = format!("touch {}", shell_quote(&destroyed));
    a.observe_cmd = "sleep 30".into();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    a.controller_url = format!("http://{}", listener.local_addr().unwrap());
    let authority = Authority::new(&NO_SIGNAL);
    let start = Instant::now();
    let _ = fail_closed(
        &a,
        &authority,
        &SigningKey::from_bytes(&[19; 32]),
        "test observer hang",
    );
    assert!(start.elapsed() < Duration::from_secs(4));
    assert!(destroyed.exists());
    assert!(authority.stop_reason().is_some());
    assert_eq!(
        listener.accept().unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
}

#[test]
fn notification_errors_and_timeout_leave_the_run_destroyed_and_authority_revoked() {
    let dir = TempDir::new();
    let mut a = args(&dir);
    let destroyed = dir.0.join("destroyed");
    a.destroy_cmd = format!("touch {}", shell_quote(&destroyed));
    a.observe_cmd = "printf '{\"running\":false}'".into();
    let (url, server) = termination_response("500 Internal Server Error");
    a.controller_url = url;
    let key = SigningKey::from_bytes(&[19; 32]);
    let authority = Authority::new(&NO_SIGNAL);
    assert!(fail_closed(&a, &authority, &key, "test notify failure")
        .to_string()
        .contains("fail closed"));
    server.join().unwrap();
    assert!(destroyed.exists());
    assert!(authority.stop_reason().is_some());

    // Hold a local TCP connection open without an HTTP response; notification has a hard timeout.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    a.controller_url = format!("http://{}", listener.local_addr().unwrap());
    let (release, wait) = std::sync::mpsc::channel();
    let server = std::thread::spawn(move || {
        let (_stream, _) = listener.accept().unwrap();
        let _ = wait.recv_timeout(Duration::from_secs(5));
    });
    let started = Instant::now();
    let _ = fail_closed(&a, &authority, &key, "test notify timeout");
    release.send(()).unwrap();
    server.join().unwrap();
    assert!(started.elapsed() < Duration::from_secs(5));
    assert!(destroyed.exists());
    assert!(authority
        .accept(Deadline::accept(&grant(1), 0, now_unix()).unwrap())
        .is_err());
}
