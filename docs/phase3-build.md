# Phase 3 local build and deployment contract

This implements `phase3-plan.md` v2. Live acceptance remains **BLOCKED** until the operator provisions
the grader and supplies the trusted observations required by G1–G5. Local unit tests exercise the
authorization, broker, scoring, lifecycle, firewall rendering, and provider-actuator decisions; they
do not establish that a deployed QEMU image or kernel enforces the configuration.

## Boundaries

1. The controller upload broker terminates the submission connection and stores at most **65,536
   raw bytes** under a recomputed SHA-256 digest. Its single opaque `202 {"status":"received"}`
   receipt has no dependency on grading, score, result delivery, queue availability, or remaining
   grading budget, and does not disclose admission or whether another run stored the digest.
2. The operator separately authorizes grading. The evaluation must already be terminal with a
   pinned-hostd termination confirmation. Grading never changes an execution lease or run state.
3. The controller consumes the one-submission claim, cumulative budget, and grading fencing token
   durably before the first dispatch attempt. Ambiguous dispatch cannot be retried as execution.
4. The grader recomputes the submission digest and consumes its own durable claim before launch.
   One disposable QEMU **TCG** guest executes at a time, with no NIC, credentials, or held-out answer.
5. The trusted scorer treats all captured guest output as untrusted bytes. Exact comparison with the
   scorer-private expected output determines `correct` or `incorrect`; guest `PASS`, exit codes, and
   reports have no grading authority.
6. The grader freezes the observed output and lifecycle, confirms process and disposable-storage
   teardown, and commits the signed result before attempting delivery. An uncertain lifecycle
   releases no result. Uncertain teardown quarantines the grader.
7. The result store has a scorer append path and authenticated operator reads. Agents have zero
   grading-dependent feedback and no result listing, callback, fetch, redirect, or evidence path.

## Wire format

The network identities are fixed: controller **10.20.0.1**, grader **10.20.0.4**. HTTP is carried only
over the authenticated, encrypted WireGuard link; HTTP endpoints do not accept redirects or URLs
from submissions. There is no generic artifact download service.

| Flow | Operation | Body |
| --- | --- | --- |
| Controller → grader | `POST http://10.20.0.4:7200/dispatch` | `application/octet-stream`, framing below |
| Scorer → controller | `POST http://10.20.0.1:7201/results` | JSON `Signed<GradingResult>` envelope |
| Agent → broker | Controller-only upload listener `:7202` | See [controller contract](phase3-controller.md) for token, path, and fixed admission vocabulary |
| Operator → controller | Loopback operator listener `127.0.0.1:7101`, accessed via SSH forwarding | Authenticated grading authorization and result reads; see controller contract |

`Signed` reuses `crates/common` unchanged: JSON with `payload` (a UTF-8 JSON **string**), `sig_hex`
(128 lowercase hex characters), and `signer` (`controller` or `scorer`). The Ed25519 signature covers
`SHA256(payload.as_bytes())`, not the outer envelope serialization. Verification uses a pinned role
public key, never the untrusted `signer` hint as key selection. Unknown job/result fields are rejected.
Each grading envelope is capped at **16,384 bytes** including JSON escaping and outer fields.

Dispatch framing is `u32_be(envelope_byte_length) || UTF8(Signed JSON) || submission_bytes`.
The complete HTTP body is capped at **81,924 bytes**. The submission is nonempty, at most 65,536
bytes, and everything after the envelope is submission data. Content addressing hashes those exact
bytes without decoding, normalizing, unpacking, or following any reference. The trusted broker and
grader independently recompute this digest. The controller does not receive grading results on
the dispatch connection.

The signed `GradingJob` payload contains exactly:

```json
{
  "v": 1,
  "type": "grading_job",
  "aud": "grader",
  "job_id": "controller-assigned-id",
  "run_id": "controller-assigned-run",
  "incarnation": "pinned-run-incarnation",
  "fencing_token": 1,
  "issued_at": 1800000000,
  "expires_at": 1800000120,
  "submission_digest": "<64 lowercase SHA-256 hex characters>",
  "task_id": "tiny-sum",
  "input_version": "1",
  "scorer_version": "1"
}
```

IDs contain 1–128 ASCII alphanumeric, `_`, or `-` characters. The task and versions are pinned to
the constants above for this fixture. Timestamps are unsigned Unix seconds, fencing tokens are
positive `u64` integers. The grading grant lasts at most **120 seconds**. Dispatch arriving more
than **5 seconds** from its signed issue time is rejected; an accepted delayed dispatch gets only
the remaining lifetime on the monotonic clock. The existing Phase 1/2 lease maximum stays 15 seconds.

`GradingResult` repeats the job's `job_id`, `run_id`, `incarnation`, `fencing_token`, `expires_at`,
`submission_digest`, `task_id`, `input_version`, and `scorer_version`. Its `v` is `1`, `type` is
`grading_result`, `aud` is `grading_results`, and `issued_at` is the scorer's publication time.
It adds exactly these fields:

```json
{
  "sandbox_id": "<32 lowercase hex characters>",
  "launched_artifact_digest": "<same SHA-256 digest as the authorized submission>",
  "captured_output_digest": "<SHA-256 of the exact frozen candidate output bytes>",
  "score": "correct",
  "status": "completed",
  "observations": {
    "started": true,
    "exited": true,
    "timed_out": false,
    "teardown_confirmed": true,
    "started_at": 1800000001,
    "exited_at": 1800000010,
    "frozen_at": 1800000011,
    "teardown_confirmed_at": 1800000012
  }
}
```

The only scores are `correct` and `incorrect`; the only releasable status is `completed`. Anomalies
remain private terminal records. There is no free-text evidence, score explanation, guest report,
URL, or candidate output in a result. Captured candidate output is capped at **4,096 bytes**.
Validation requires `started_at <= exited_at <= frozen_at <= teardown_confirmed_at <= issued_at`,
complete positive lifecycle observations, all job bindings, and unexpired authority at commit.

## Hooks, node configuration, and off-host kill

The [grader service contract](phase3-grader.md) specifies CLI arguments, initialization, exact hook
environment variables and JSON schemas. The [infrastructure contract](../infra/hetzner/grader/README.md)
specifies QEMU provisioning, fixture injection, scorer-private files, nft rules, WireGuard peers,
and the independent grader-node deletion actuator. Hook paths and fixed input/image configuration
are operator-installed. Submissions cannot choose host paths, hooks, network addresses, or arguments.

The grader's only WireGuard peer is the controller with `AllowedIPs = 10.20.0.1/32`; the controller
adds the grader peer with `AllowedIPs = 10.20.0.4/32`. Other peers must not list the grader. Grader
forwarding is dropped. The controller guard denies grader access to `:7100`, `:7101`, and the
upload broker. nft rules are a backstop for the trusted broker/scorer boundary, not a data diode.

Keep initialized controller, grader, and actuator state outside disposable guest storage. Lost,
corrupt, or inconsistent authority requires operator reconciliation; deleting state, restoring an
old snapshot, or reinitializing it is not a supported restart procedure or budget reset. Protect
state backups and scorer/controller keys as part of the trusted deployment.

## Local verification

```bash
export PATH="$HOME/.cargo/bin:$HOME/.rustup/toolchains/stable-aarch64-apple-darwin/bin:$PATH"
bash tests/phase3/offline.sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo zigbuild --release --target x86_64-unknown-linux-musl \
  -p deadswitch-grader -p deadswitch-controller --locked
```

The offline suite builds and tests the workspace, runs Phase 2/3 Python regressions and shell syntax
checks, and requires the live skeleton to return **77 / BLOCKED**. See `tests/phase3/acceptance.sh`
for the trusted-side G1–G5 observations still required. No live acceptance or Phase 3 deployment
approval is implied by a green local suite.
