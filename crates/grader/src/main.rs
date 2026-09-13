use anyhow::{ensure, Context};
use axum::body::{to_bytes, Body};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use clap::{Parser, Subcommand};
use deadswitch_common::grading::{
    decode_dispatch, verify_job, MAX_CAPTURED_OUTPUT_BYTES, MAX_DISPATCH_BYTES,
};
use deadswitch_common::{
    key_from_hex, load_or_create_signing_key, now_unix, pubkey_from_hex, pubkey_hex, sha256_hex,
};
use deadswitch_grader::hooks::{HookPaths, ShellHooks};
use deadswitch_grader::state::{read_private_file, Binding, PendingJob, StateLock, Store};
use deadswitch_grader::{
    HttpPublisher, Processor, SandboxHooks, DISPATCH_ADDR, FIXED_DISPATCH_ACK,
};
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::{mpsc, Semaphore};
use tracing::{error, info};

#[derive(Parser)]
#[command(name = "deadswitch-grader")]
struct Args {
    #[command(subcommand)]
    cmd: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Create the private scorer key. Public key is printed for controller enrollment.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Initialize a NEW state directory. Never use this to replace lost production authority.
    Init(IdentityArgs),
    /// Run only as root under deadswitch-grader.service on the isolated Linux grader host.
    Run(Box<RunArgs>),
}

#[derive(Parser, Clone)]
struct IdentityArgs {
    #[arg(
        long,
        env = "DS_GRADER_STATE_DIR",
        default_value = "/var/lib/deadswitch-grader"
    )]
    state_dir: PathBuf,
    #[arg(long, env = "DS_GRADER_KEY_FILE")]
    key_file: PathBuf,
    #[arg(long, env = "DS_CONTROLLER_PUBKEY")]
    controller_pubkey: String,
    #[arg(
        long,
        env = "DS_GRADER_EXPECTED_OUTPUT",
        default_value = "/etc/deadswitch-grader/expected-output.bin"
    )]
    expected_output: PathBuf,
}

#[derive(Parser)]
struct RunArgs {
    #[command(flatten)]
    identity: IdentityArgs,
    #[arg(long, env = "DS_GRADER_LAUNCH_HOOK")]
    launch_hook: PathBuf,
    #[arg(long, env = "DS_GRADER_OBSERVE_HOOK")]
    observe_hook: PathBuf,
    #[arg(long, env = "DS_GRADER_DESTROY_HOOK")]
    destroy_hook: PathBuf,
    #[arg(long, env = "DS_GRADER_DESTROY_ALL_HOOK")]
    destroy_all_hook: PathBuf,
}

fn identity(args: &IdentityArgs) -> anyhow::Result<(SigningKey, Vec<u8>, Binding)> {
    for path in [&args.state_dir, &args.key_file, &args.expected_output] {
        deadswitch_grader::state::check_trusted_ancestors(path)?;
    }
    let key_bytes = read_private_file(&args.key_file, 256, false)?;
    let key = key_from_hex(std::str::from_utf8(&key_bytes)?)?;
    let expected = read_private_file(&args.expected_output, MAX_CAPTURED_OUTPUT_BYTES, true)?;
    ensure!(!expected.is_empty(), "expected output cannot be empty");
    pubkey_from_hex(&args.controller_pubkey)?;
    let binding = Binding {
        controller_public_key: args.controller_pubkey.trim().to_ascii_lowercase(),
        scorer_public_key: pubkey_hex(&key),
        expected_output_digest: sha256_hex(&expected),
    };
    // Round-trip through the pinned verifying key rejects malformed key encodings; store a
    // canonical representation so formatting changes cannot implicitly rotate role identity.
    Ok((key, expected, binding))
}

#[derive(Clone)]
struct Intake {
    store: Arc<Mutex<Store>>,
    controller_key: VerifyingKey,
    pending: mpsc::Sender<PendingJob>,
    in_flight: Arc<AtomicBool>,
    stopping: Arc<AtomicBool>,
    request_slots: Arc<Semaphore>,
}

fn acknowledgement() -> Response {
    (
        StatusCode::ACCEPTED,
        [
            (header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "no-store"),
            (header::CONNECTION, "close"),
        ],
        FIXED_DISPATCH_ACK,
    )
        .into_response()
}

async fn dispatch(
    State(intake): State<Intake>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    request: Request<Body>,
) -> Response {
    // This response never reflects admission, execution, queue occupancy, scores or errors. It
    // is controller-only; the upload broker has already terminated its independent agent socket.
    if peer.ip() != IpAddr::V4(Ipv4Addr::new(10, 20, 0, 1))
        || intake.stopping.load(Ordering::SeqCst)
        || request
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|h| h.to_str().ok())
            != Some("application/octet-stream")
    {
        return acknowledgement();
    }
    let Ok(_slot) = intake.request_slots.try_acquire() else {
        return acknowledgement();
    };
    let body = match tokio::time::timeout(
        Duration::from_secs(2),
        to_bytes(request.into_body(), MAX_DISPATCH_BYTES),
    )
    .await
    {
        Ok(Ok(body)) => body,
        _ => return acknowledgement(),
    };
    let attempt = (|| {
        let (signed, submission) = decode_dispatch(&body)?;
        let job = verify_job(&signed, &intake.controller_key, now_unix())?;
        ensure!(!intake.stopping.load(Ordering::SeqCst), "stopping");
        ensure!(
            intake
                .in_flight
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok(),
            "one job already active"
        );
        let claimed = intake
            .store
            .lock()
            .map_err(|_| anyhow::anyhow!("poisoned state lock"))?
            .claim(job, &submission, now_unix());
        match claimed {
            Ok(pending) => {
                let job_id = pending.context.job.job_id.clone();
                if intake.pending.try_send(pending).is_err() {
                    let _ = intake.store.lock().map(|mut s| s.abort(&job_id, true));
                    intake.stopping.store(true, Ordering::SeqCst);
                    anyhow::bail!("grading worker unavailable");
                }
            }
            Err(error) => {
                intake.in_flight.store(false, Ordering::SeqCst);
                return Err(error);
            }
        }
        Ok::<_, anyhow::Error>(())
    })();
    if attempt.is_err() {
        // No guest-controlled error string, submission, output, score or hook stderr is logged.
        info!("dispatch not admitted");
    }
    acknowledgement()
}

async fn run(args: RunArgs) -> anyhow::Result<()> {
    ensure!(
        cfg!(target_os = "linux") && unsafe { libc::geteuid() } == 0,
        "production grader requires Linux root service"
    );
    let (key, expected_output, binding) = identity(&args.identity)?;
    let controller_key = pubkey_from_hex(&binding.controller_public_key)?;
    let paths = HookPaths {
        launch: args.launch_hook,
        observe: args.observe_hook,
        destroy: args.destroy_hook,
        destroy_all: args.destroy_all_hook,
    };
    paths.validate()?;
    let hooks = ShellHooks { paths };
    let lock = StateLock::acquire(&args.identity.state_dir)?;
    let cleanup_started_at = now_unix();
    // Run cleanup even when the ledger is missing/corrupt. The exclusive lock is already held.
    let cleanup = hooks.destroy_all().and_then(|observed| {
        ensure!(
            observed.processes_gone
                && observed.storage_gone
                && observed.teardown_confirmed_at >= cleanup_started_at
                && observed.teardown_confirmed_at <= now_unix(),
            "startup sandbox cleanup unconfirmed"
        );
        Ok(())
    });
    let mut store = Store::open(lock, &binding)?;
    if let Err(error) = cleanup {
        let _ = store.quarantine();
        return Err(error);
    }
    store.finish_recovery()?;
    ensure!(
        !store.quarantined(),
        "grader quarantined; off-host operator recovery required"
    );
    let stopping = Arc::new(AtomicBool::new(false));
    let signal_flag = stopping.clone();
    let signals = tokio::spawn(async move {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("SIGTERM handler");
        tokio::select! {
            _ = terminate.recv() => {},
            _ = tokio::signal::ctrl_c() => {},
        }
        signal_flag.store(true, Ordering::SeqCst);
    });
    let store = Arc::new(Mutex::new(store));
    let processor = Arc::new(Processor {
        hooks,
        publisher: HttpPublisher,
        store: store.clone(),
        scorer_key: key,
        expected_output,
        stopping: stopping.clone(),
    });
    let in_flight = Arc::new(AtomicBool::new(false));
    let (sender, mut receiver) = mpsc::channel::<PendingJob>(1);
    let worker_processor = processor.clone();
    let worker_stopping = stopping.clone();
    let worker_in_flight = in_flight.clone();
    let worker = tokio::spawn(async move {
        loop {
            let pending = tokio::select! {
                pending = receiver.recv() => pending,
                _ = tokio::time::sleep(Duration::from_millis(50)) => {
                    if worker_stopping.load(Ordering::SeqCst) && receiver.is_empty() { break; }
                    continue;
                }
            };
            let Some(pending) = pending else { break };
            let processor = worker_processor.clone();
            let outcome = tokio::task::spawn_blocking(move || processor.process(pending)).await;
            if !matches!(outcome, Ok(Ok(()))) {
                error!("grading job terminated without confirmed publication");
            }
            let quarantined = worker_processor
                .store
                .lock()
                .map(|s| s.quarantined())
                .unwrap_or(true);
            if outcome.is_err() || quarantined {
                worker_stopping.store(true, Ordering::SeqCst);
            }
            worker_in_flight.store(false, Ordering::SeqCst);
        }
    });
    let intake = Intake {
        store,
        controller_key,
        pending: sender,
        in_flight,
        stopping: stopping.clone(),
        request_slots: Arc::new(Semaphore::new(8)),
    };
    let app = Router::new()
        .route("/dispatch", post(dispatch))
        .with_state(intake);
    let listener = tokio::net::TcpListener::bind(DISPATCH_ADDR)
        .await
        .context("bind fixed grader dispatch address")?;
    info!(address = DISPATCH_ADDR, "grader dispatch ready");
    let shutdown = stopping.clone();
    let served = axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(async move {
        while !shutdown.load(Ordering::SeqCst) {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    stopping.store(true, Ordering::SeqCst);
    worker.await?;
    // Last independent check catches a processor panic or interrupted launch. Uncertainty is
    // persisted and must trigger the separate controller/operator off-host grader actuator.
    let final_cleanup = processor.hooks.destroy_all();
    if !matches!(final_cleanup, Ok(ref o) if o.processes_gone && o.storage_gone) {
        let _ = processor.store.lock().map(|mut s| s.quarantine());
        anyhow::bail!("shutdown teardown unconfirmed; off-host grader actuator required");
    }
    signals.abort();
    served?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "deadswitch_grader=debug".into()),
        )
        .with_writer(std::io::stderr)
        .init();
    match Args::parse().cmd {
        Command::Keygen { out } => {
            let key = load_or_create_signing_key(&out)?;
            println!("{}", pubkey_hex(&key));
        }
        Command::Init(args) => {
            let (_, _, binding) = identity(&args)?;
            Store::initialize(&args.state_dir, binding)?;
            info!("new grader authority store initialized");
        }
        Command::Run(args) => run(*args).await?,
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use deadswitch_common::grading::{
        encode_dispatch, GradingJob, AUD_GRADER, INPUT_VERSION, JOB_TYPE, SCORER_VERSION, TASK_ID,
    };
    use deadswitch_common::{random_hex, Signed, PROTO_V};

    struct Fixture {
        root: PathBuf,
        intake: Intake,
        receiver: mpsc::Receiver<PendingJob>,
        key: SigningKey,
    }

    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!("grader-intake-{}", random_hex(16)));
            let key = SigningKey::from_bytes(&[11; 32]);
            let binding = Binding {
                controller_public_key: pubkey_hex(&key),
                scorer_public_key: pubkey_hex(&SigningKey::from_bytes(&[12; 32])),
                expected_output_digest: sha256_hex(b"42\n"),
            };
            Store::initialize(&root, binding.clone()).unwrap();
            let store = Store::open(StateLock::acquire(&root).unwrap(), &binding).unwrap();
            let (sender, receiver) = mpsc::channel(1);
            Self {
                root,
                key: key.clone(),
                intake: Intake {
                    store: Arc::new(Mutex::new(store)),
                    controller_key: key.verifying_key(),
                    pending: sender,
                    in_flight: Arc::new(AtomicBool::new(false)),
                    stopping: Arc::new(AtomicBool::new(false)),
                    request_slots: Arc::new(Semaphore::new(8)),
                },
                receiver,
            }
        }

        fn frame(&self, token: u64, bytes: &[u8]) -> Vec<u8> {
            let job = GradingJob {
                v: PROTO_V,
                kind: JOB_TYPE.into(),
                aud: AUD_GRADER.into(),
                job_id: format!("j{token}"),
                run_id: "r1".into(),
                incarnation: "i1".into(),
                fencing_token: token,
                issued_at: now_unix(),
                expires_at: now_unix() + 120,
                submission_digest: sha256_hex(bytes),
                task_id: TASK_ID.into(),
                input_version: INPUT_VERSION.into(),
                scorer_version: SCORER_VERSION.into(),
            };
            encode_dispatch(&Signed::sign(&self.key, "controller", &job), bytes).unwrap()
        }

        async fn request(&self, frame: Vec<u8>, peer: [u8; 4]) -> (StatusCode, Vec<u8>) {
            let request = Request::builder()
                .method("POST")
                .uri("/dispatch")
                .header(header::CONTENT_TYPE, "application/octet-stream")
                .body(Body::from(frame))
                .unwrap();
            let response = dispatch(
                State(self.intake.clone()),
                ConnectInfo(SocketAddr::from((peer, 30000))),
                request,
            )
            .await;
            let status = response.status();
            assert_eq!(response.headers()[header::CONNECTION], "close");
            (
                status,
                to_bytes(response.into_body(), 100).await.unwrap().to_vec(),
            )
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[tokio::test]
    async fn dispatch_ack_is_identical_for_invalid_valid_duplicate_busy_and_stopped() {
        let mut fixture = Fixture::new();
        let expected = (StatusCode::ACCEPTED, FIXED_DISPATCH_ACK.as_bytes().to_vec());
        assert_eq!(
            fixture
                .request(b"not a signed dispatch".to_vec(), [10, 20, 0, 1])
                .await,
            expected
        );
        let frame = fixture.frame(1, b"candidate");
        assert_eq!(
            fixture.request(frame.clone(), [10, 20, 0, 2]).await,
            expected
        );
        assert!(fixture.receiver.try_recv().is_err());
        assert_eq!(
            fixture.request(frame.clone(), [10, 20, 0, 1]).await,
            expected
        );
        // Durable terminal claim is already on disk at acknowledgement, before any worker runs.
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture.root.join("ledger.json")).unwrap())
                .unwrap();
        assert_eq!(state["high_water"], 1);
        assert_eq!(state["claims"]["j1"]["status"], "execution_claimed");
        assert_eq!(fixture.request(frame, [10, 20, 0, 1]).await, expected);
        assert_eq!(
            fixture
                .request(fixture.frame(2, b"different"), [10, 20, 0, 1])
                .await,
            expected
        );
        assert_eq!(
            fixture
                .request(vec![0; MAX_DISPATCH_BYTES + 1], [10, 20, 0, 1])
                .await,
            expected
        );
        fixture.intake.stopping.store(true, Ordering::SeqCst);
        assert_eq!(
            fixture
                .request(fixture.frame(3, b"another"), [10, 20, 0, 1])
                .await,
            expected
        );
        assert!(fixture.receiver.try_recv().is_ok());
        assert!(fixture.receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn concurrent_dispatches_admit_exactly_one_job() {
        let mut fixture = Fixture::new();
        let one = fixture.frame(1, b"candidate A");
        let two = fixture.frame(2, b"candidate B");
        let (a, b) = tokio::join!(
            fixture.request(one, [10, 20, 0, 1]),
            fixture.request(two, [10, 20, 0, 1])
        );
        assert_eq!(a, b);
        assert!(fixture.receiver.try_recv().is_ok());
        assert!(fixture.receiver.try_recv().is_err());
        let state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(fixture.root.join("ledger.json")).unwrap())
                .unwrap();
        assert_eq!(state["claims"].as_object().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn valid_controller_signature_cannot_authorize_mismatched_submission_bytes() {
        let mut fixture = Fixture::new();
        let mut frame = fixture.frame(1, b"candidate A");
        *frame.last_mut().unwrap() = b'B';
        fixture.request(frame, [10, 20, 0, 1]).await;
        assert!(fixture.receiver.try_recv().is_err());
        assert_eq!(fixture.intake.store.lock().unwrap().high_water(), 0);
    }
}
