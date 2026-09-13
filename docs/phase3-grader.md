# Phase 3 grader: wire, hooks and local recovery

`deadswitch-grader` is the trusted scorer/coordinator at **10.20.0.4**. It consumes separate
controller-signed grading authorization. It never enrolls, renews, or reactivates an evaluation
execution lease. The controller must terminate the submitting run before issuing that authorization.
See [phase3-plan.md](phase3-plan.md) for the information-flow and deployment acceptance criteria.

## Fixed application wire

The only listener is **TCP 10.20.0.4:7200**, accepting controller **10.20.0.1** requests to
`POST /dispatch` with `Content-Type: application/octet-stream`. Its body is:

```text
uint32_be envelope_byte_count
envelope_byte_count bytes: UTF-8 JSON Signed envelope
1..65536 bytes: exact raw submission, outside the envelope
```

The maximum envelope is 16,384 bytes; maximum complete body is 81,924 bytes. Body receipt is capped
at two seconds with eight simultaneous body readers. The exact `Signed` object has `payload`,
`sig_hex`, and `signer` fields. `payload` is the serialized JSON string; its signature is Ed25519
over SHA-256 of those exact UTF-8 bytes, following `common::Signed`. Jobs require `signer=controller`
**and** the pinned controller verification key. An evaluation/host/scorer signature is insufficient.

The job payload fields are exactly:

```text
v=1, type="grading_job", aud="grader",
job_id, run_id, incarnation, fencing_token,
issued_at, expires_at, submission_digest,
task_id="tiny-sum", input_version="1", scorer_version="1"
```

IDs are bounded ASCII identifiers; digests are 64 lowercase hexadecimal characters. Submission
digest is recomputed before admission and rechecked immediately before and after execution. The
private staged file is created with mode `0400` under a random sandbox directory. The payload
contains neither submission bytes nor caller-selected paths, URLs, arguments or environment values.

The `/dispatch` handler returns the same fixed HTTP `202`, `Content-Type: application/json`,
`Cache-Control: no-store`, `Connection: close`, and body **`{"status":"received"}`** for every
handled request: valid, invalid, duplicate, busy, oversized, unauthorized or stopped. This receipt
is not an admission or execution guarantee. The controller must neither consume it as grading
feedback nor relay it to the agent. Its independent upload broker terminates the agent connection
and issues its own fixed intake status before dispatch is possible. This is no claim of universal
timing non-interference.

Results use a new grader-initiated `POST http://10.20.0.1:7201/results` with
`Content-Type: application/json` and a `Signed` object, `signer=scorer`, signed by the distinct
root-only scorer key. This numeric destination cannot be overridden. HTTP proxies, redirects and
automatic retries are disabled. No response body is consumed. Only a success status confirms
delivery to the scorer; no downstream response is exposed through `/dispatch`.

The result payload fields are exactly:

```text
v=1, type="grading_result", aud="grading_results",
job_id, run_id, incarnation, fencing_token,
issued_at, expires_at, submission_digest,
task_id, input_version, scorer_version,
sandbox_id, launched_artifact_digest, captured_output_digest,
score="correct"|"incorrect", status="completed",
observations={started:true, exited:true, timed_out:false, teardown_confirmed:true,
              started_at, exited_at, frozen_at, teardown_confirmed_at}
```

All job bindings and the job expiry are repeated verbatim. `sandbox_id` is a random 32-character
lowercase hex identifier. Times are integer Unix seconds, ordered start ≤ exit ≤ freeze ≤ confirmed
teardown ≤ result issuance, all before expiry. Guest reports, PASS strings, exit codes, stdout and
free-text diagnostics are never result fields. The candidate answer is compared as **exact bytes**
against the root-only expected file; the tiny fixture expects `42\n`. Submitted code is never
imported, parsed as a scorer report, or executed by Rust.

## Hook contract

The four hook paths are absolute operator-installed executables with trusted, nonwritable
ancestors. They receive **no arguments**. There is no `sh -c` expansion. The grader clears the
environment and supplies only a fixed system `PATH`, `LANG=C`, `LC_ALL=C`,
`PYTHONDONTWRITEBYTECODE=1`, and these job values for launch/observe/destroy:

| Variable | Value |
| --- | --- |
| `DS_JOB_ID` | Validated controller job identifier |
| `DS_SANDBOX_ID` | Fresh 32-character lowercase hex identifier |
| `DS_JOB_DIR` | Grader-owned `0700` directory under its protected state directory |
| `DS_SUBMISSION_PATH` | `DS_JOB_DIR/submission.bin`, owned immutable `0400` regular file |
| `DS_SUBMISSION_DIGEST` | Recomputed SHA-256 bound by the signed job |
| `DS_CAPTURE_PATH` | Exactly `DS_JOB_DIR/capture.bin` |
| `DS_TASK_ID` | `tiny-sum` |
| `DS_INPUT_VERSION` | `1` |
| `DS_SCORER_VERSION` | `1` |
| `DS_JOB_EXPIRES_AT` | Signed absolute Unix expiry |
| `DS_WALL_TIMEOUT_SECS` | Positive integer ≤90, pinned once on admission; identical for all hooks |

Hook configuration is read by the trusted Python launcher from root-only
`/etc/deadswitch-grader/launcher.json`; service credentials are never inherited by hooks. QEMU
specifics remain in [infra/hetzner/grader](../infra/hetzner/grader/).

* **launch.sh** runs synchronously until execution has ended. It creates one fresh overlay of the
  immutable pinned base, attaches fixed read-only input, provides no NIC (`-net none`), and launches
  bounded QEMU TCG under the isolated QEMU uid. The independent systemd job cgroup uses hard runtime
  bounds and `BindsTo=deadswitch-grader.service`. Its successful stdout is one JSON object:
  `{"sandbox_id":"...","launched_artifact_digest":"...","started":true,"exited":true,"timed_out":false,"started_at":1,"exited_at":2}`.
  Normal host-observed QEMU termination is lifecycle evidence; guest exit/PASS claims do not assign
  the score. A crash, timeout, output flood, or missing observation fails the hook.
* **observe.sh** positively verifies launcher observations and freezes the launcher-owned candidate
  capture as a root-only, singly-linked, regular **0400** file of at most **4096** bytes. It returns
  the identical flat launch fields plus `"frozen":true`, `"captured_output_digest":"..."`, and
  `"capture_bytes":3`. No path is returned or accepted. Rust strictly decodes this schema, rejects
  unknown/missing fields and changed launch observations, and copies/re-hashes the capture into
  trusted memory.
* **destroy.sh** stops the independent sandbox cgroup, positively confirms no sandbox process
  remains, and removes the disposable storage. Its successful object is
  `{"sandbox_id":"...","processes_gone":true,"storage_gone":true,"teardown_confirmed_at":3}`.
  Destruction remains authorized after a job expires or shutdown begins.
* **destroy-all.sh** has no job environment and scans the launcher's durable claims/managed units
  for ambiguous leftovers. Its successful object is
  `{"processes_gone":true,"storage_gone":true,"teardown_confirmed_at":3}`. It is mandatory before
  readiness and again at shutdown. It must also work when the Rust ledger is unavailable.

Every hook stdout is capped at 4096 bytes; stderr is not copied to an API or unbounded log.
Hook process groups are killed on completion/error/deadline, including hanging descendants. QEMU
runs in its separate managed cgroup, so killing the hook alone is **not** teardown confirmation.
Rust caps launch at 95 seconds, observe at five seconds, and each destroy invocation at 15 seconds.
The independent guest execution timeout is at most 90 seconds. Launch/observe additionally obey
the shared `Deadline` monotonic and wall clocks and the shutdown flag; destruction uses its own
bounded authority. Publication cancels on either clock or shutdown with a 10 ms polling interval
and a maximum HTTP duration of five seconds.

## Admission, release and restart behavior

1. Verify the pinned controller signature, all signed bindings, fresh issuance (≤5 seconds skew),
   and maximum 120-second grading authority. This separate cap never changes Phase 1/2 lease caps.
2. Under the exclusive store lock, reject any previously claimed job/submission, non-increasing
   global fencing token, rollback behind the durable wall-clock floor, outstanding job or quarantine.
3. Durably stage the immutable content-addressed bytes. Atomically fsync the high-water and
   `execution_claimed` record **before ACK/launch**. This record consumes launch permission forever;
   `execution_claimed` means execution may already have happened after a crash.
4. Execute, observe, freeze the candidate bytes and lifecycle, and compare to the private expected
   bytes. A guest-written `PASS` is an incorrect candidate answer.
5. Always invoke destroy, including after a partial launch or failed validation. Confirm process
   **and** storage destruction. Remove the private per-job submission/capture files before signing.
6. Revalidate current authority and the exact bindings, sign once, and fsync the immutable
   `result_committed` envelope before the fixed append request. A delivery error retains exactly
   that signed result. There is no automatic execution or delivery retry.

An anomaly has no grading result. An unconfirmed destroy or failed local cleanup quarantines the
entire grader; no next job is admitted. The controller/operator must use the separate **off-host**
`ds-grader-kill.py` actuator to delete the grader Cloud server when local containment cannot be
confirmed. The grader holds no Cloud credentials and cannot call that API across its airlock.

`run` requires an already initialized private state directory and lock file. It obtains an exclusive
process-lifetime file lock before global cleanup, then strictly loads the ledger; a missing/corrupt
ledger or changed controller/scorer/expected-output binding refuses readiness. Startup cleanup
still runs if the ledger is missing/corrupt. Pending claims become `aborted` after positive global
cleanup, with tokens/digests permanently spent. A stored quarantine survives restarts. The grader
has a finite additional lifetime cap of 10,000 claims; it never prunes authority history.

The root operator must preserve the ledger and prohibit backup rollback. There is no TPM or external
monotonic counter to detect an operator restoring an old, otherwise valid full state snapshot.
Neither deleting a ledger nor changing the state directory is a supported recovery operation.

## Bootstrap and service arguments

Install scripts, pinned base, launcher config and the tiny guest runner according to the grader
infra README. Keep the expected output root-only and outside all guest images. Create the scorer
key and enroll only its public key in the controller's scorer allowlist:

```bash
deadswitch-grader keygen --out /etc/deadswitch-grader/scorer.key
deadswitch-grader init \
  --state-dir /var/lib/deadswitch-grader \
  --key-file /etc/deadswitch-grader/scorer.key \
  --controller-pubkey CONTROLLER_PUBLIC_HEX \
  --expected-output /etc/deadswitch-grader/expected-output.bin
```

`init` creates a **new** directory and fails if it already exists; run it before first starting
systemd. It never resets an existing store. Production `run` requires Linux root and the named
`deadswitch-grader.service` enforced by the launcher:

```bash
deadswitch-grader run \
  --state-dir /var/lib/deadswitch-grader \
  --key-file /etc/deadswitch-grader/scorer.key \
  --controller-pubkey CONTROLLER_PUBLIC_HEX \
  --expected-output /etc/deadswitch-grader/expected-output.bin \
  --launch-hook /opt/deadswitch/infra/hetzner/grader/launch.sh \
  --observe-hook /opt/deadswitch/infra/hetzner/grader/observe.sh \
  --destroy-hook /opt/deadswitch/infra/hetzner/grader/destroy.sh \
  --destroy-all-hook /opt/deadswitch/infra/hetzner/grader/destroy-all.sh
```

The corresponding environment aliases are `DS_GRADER_STATE_DIR`, `DS_GRADER_KEY_FILE`,
`DS_CONTROLLER_PUBKEY`, `DS_GRADER_EXPECTED_OUTPUT`, `DS_GRADER_LAUNCH_HOOK`,
`DS_GRADER_OBSERVE_HOOK`, `DS_GRADER_DESTROY_HOOK`, and `DS_GRADER_DESTROY_ALL_HOOK`. There are no
bind-address, result-URL, callback, output-fetch, agent-read or arbitrary command options.

Local Rust tests cover scoring positive/negative controls, forged PASS, mismatched submissions,
strict actual hook JSON, private-file protections, frozen capture mutation, execution/teardown/
publication ordering, timeout/crash/authority loss, durable replay/conflict/fencing, restart,
quarantine, no relaunch after ambiguous delivery, and concurrent dispatch with fixed receipts.
They do not prove the deployed QEMU image, Linux cgroup, nft or off-host actuator behavior.
Live G1–G5 must remain **BLOCKED** until that independent deployment evidence exists.
