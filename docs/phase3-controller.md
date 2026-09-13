# Phase 3 controller contract

Phase 3 is opt-in. Existing Phase 1/2 routes, lease TTLs, enrollment, evidence policy and firewall
scripts retain their containment behavior. The controller is an upload terminator, authorization
authority and private result store. It never executes submissions or serves their bytes to agents.

## Startup and persistent authority

Run as the trusted controller service account (normally root). Configure the existing controller
arguments plus `--grading-enable`, `--operator-listen 127.0.0.1:7101`, and
`--grading-scorer-keys-file /etc/deadswitch/scorer-keys.json`. The public-key file is an owned,
non-symlink regular file without group/world write permission, containing a JSON map:

```json
{"heldout-v1":"<64 lowercase hex characters: scorer Ed25519 public key>"}
```

Scorer keys must differ from the controller and all enrolled hostd keys. An operator may add key
versions to this registry on restart; existing mappings cannot be removed or replaced. A new key
version uses the **same remaining lifetime budget**. This key-version label is controller metadata,
separate from the pinned `scorer_version: "1"` algorithm in the signed wire payload.

Initialize once using the normal controller arguments plus `--grading-init --grading-budget 32`.
Initialization creates authority and exits without opening listeners or revoking existing runs.
Start the service again without these two flags. The immutable budget must be 1..4096 jobs; there is
no HTTP reset, refund, per-agent budget, or campaign reset. Repeating initialization fails. Normal
startup requires every ledger and the external anchor to exist and validate.

Durable files under `--state-dir`:

| Path | Purpose |
| --- | --- |
| `grading-anchor.json` | One-time ledger identity and immutable lifetime cap, outside the ledger directory |
| `grading/broker.json` | Upload capabilities, persisted admission-rate state and globally unique submission claims |
| `grading/objects/<sha256>` | Exact submitted bytes, created with mode 0400 and never modified by grading |
| `grading/ledger.json` | Cumulative spend, fencing and clock high-water marks, pinned key registry, terminal jobs and committed signed results |
| `grading/pending-release.json` | Temporary durable release barrier; a surviving marker causes recovery to withhold and abandon that result without refund or relaunch |
| `grading/process.lock` | Exclusive process ownership using `flock`; a second controller cannot spend the same ledger |

Directories are mode 0700 and ledger/anchor files are mode 0600. Writes use a fresh exclusive temp
file, file fsync, atomic rename and parent-directory fsync. A storage error poisons that service plane
until restart. Grading-storage errors do not change upload receipts or admission decisions. Missing,
corrupt, inconsistent, shared-writable or symlinked authority fails startup; no implicit reset occurs.
Keep the complete state directory on durable local storage. The MVP cannot detect an operator rolling
back **all** trusted state and its anchor to an old consistent snapshot, or deliberately deleting both
and running initialization anew; do not restore authority this way. External anti-rollback storage is
not implemented.

## Upload broker: controller TCP 7202

Default listener: `10.20.0.1:7202`, configurable through `--grading-upload-listen` /
`DS_GRADING_UPLOAD_LISTEN` (the designated WG tuple or a loopback development address only).
The listener exposes exactly one operation:

```http
POST /submissions/<controller-run-id> HTTP/1.1
Authorization: Bearer <per-run upload token>
Content-Type: application/octet-stream

<1..65536 exact raw submission bytes>
```

The operator first calls `POST /grading/runs/<id>/upload-authorization` on the separate operator
listener with the **operator** bearer token. This is permitted once for an active, epoch >= 1 eval.
It returns `{run_id, upload_token, expires_at, max_submission_bytes}`. The capability is random,
scoped to that run/incarnation, expires after one hour, authorizes upload only, and is stored hashed.
Deliver only this upload capability to the submitting agent. The operator bearer token stays private.

For every application-level broker outcome, including successful intake, rejection, duplicate,
unknown route, wrong method, invalid encoded path, quota exhaustion and unavailable grading, the
HTTP status/body are identical:

```http
HTTP/1.1 202 Accepted
Cache-Control: no-store
Connection: close
Content-Type: application/json

{"status":"received"}
```

`received` is an opaque transport receipt. It does **not** assert durable admission or grading.
Successful intake fsyncs both content and its unique claim before sending it. This single response
also prevents an explicit cross-run content-addressed membership oracle. No result, digest, queue
position, downstream status/error, callback, URL, redirect, or fetched content is returned. The broker
never opens a grader connection. It checks the run is still active again after capturing the body;
late uploads, replacements and duplicates fail closed internally.

Bounds: four simultaneous body captures, a five-second capture deadline, 60 routed requests per
minute, at most eight authenticated attempts per upload capability, and 60 authenticated attempts
per wall-clock minute persisted across restart. There are at most 8192 lifetime capabilities and
4096 accepted submissions. CAS storage, including crash-left orphan objects, is capped at 4096
objects / 256 MiB. These quotas do not depend on grades, grader occupancy or grading budget. Invalid
HTTP framing can be rejected by the HTTP transport before routing. Request duration/resource
contention is not claimed to provide universal timing non-interference.

The broker binds a destination, not an ingress-source firewall policy; per-run bearer capabilities
are the application authorization. Existing Phase 2 `evalhost-egress.sh` does **not** permit this new
port, and Phase 3 does not broaden that policy. The operator must provide a reviewed upload adapter
or narrowly scoped ingress integration before direct agent uploads can work. A trusted adapter can
forward captured bytes to the controller-local loopback broker. Do not add a general tunnel, fetch
service or bidirectional agent relay. The grader's firewall never permits it to reach port 7202.

## Separate operator authorization and dispatch

The existing pinned-hostd, signed `POST /terminated` endpoint records
`RunRecord.termination_confirmed_at`. A merely `tripped`/`revoked` controller record does not prove
the eval process is gone. Grading requires a terminal epoch >= 1 run, this trusted teardown
confirmation, a matching incarnation and an already captured submission. No operator endpoint can
substitute an unverified guest assertion for stop confirmation.

The Phase 2 evalagent now bridges its existing shutdown to `/terminated`: it first revokes local
authority and runs the existing seal/destroy hooks; only a successful destroy is followed by a
separate host observation. That observation is limited to two seconds and 4096 bytes and must report
`running:false` without a contradictory live PID. It then signs the existing termination message
with its already loaded hostd key and sends once to the configured controller origin, with redirects,
proxies and retries disabled and a three-second HTTP deadline. Missing/failed/unknown observations,
failed destruction or failed notification leave grading blocked. Every path remains stopped and
exits nonzero; this bridge cannot renew or resume the eval lease.

Then the operator calls on `127.0.0.1:7101`:

```http
POST /grading/runs/<id>/authorize
Authorization: Bearer <operator token>
Content-Type: application/json

{"campaign":"campaign-001","held_out_key_version":"heldout-v1"}
```

Both labels are operator metadata, limited to 1..128 ASCII letters/digits/underscore/hyphen. The
task, inputs, scorer algorithm, destination, lease lifetime and submission are not request-selectable.
The controller re-reads and re-hashes the CAS bytes, atomically spends one lifetime budget unit,
increments its **separate grading** fencing high-water, and records `dispatch_consumed` before any
network send. The original execution state, epoch and lease fencing are not changed. An outstanding
unconfirmed job holds the single grader slot through its expiry, including uncertain/abandoned
dispatches. A committed result proves teardown and can release that occupancy early.

Dispatch is one HTTP POST to `http://10.20.0.4:7200/dispatch`, `application/octet-stream`:

1. Four-byte unsigned big-endian length of the serialized `Signed` envelope.
2. Exactly that many UTF-8 JSON bytes for `{payload,sig_hex,signer:"controller"}`.
3. Exact raw submission bytes, outside the signed envelope.

The payload is the `common::grading::GradingJob` schema: protocol version/type/audience, job/run/
incarnation identities, grading fence, issue/expiry timestamps, SHA-256 submission digest,
`task_id:"tiny-sum"`, `input_version:"1"`, `scorer_version:"1"`. Maximum envelope is 16384 bytes;
maximum complete frame is 81924 bytes. The controller grants at most 120 seconds, validates both
clock deadlines and freshness again immediately before sending, and disables environment proxies,
redirects and HTTP-client retry. Connect/whole-send deadlines are two/five seconds. Response bodies
are never read or relayed. This request does not extend any Phase 1/2 execution lease.

The operator receives `{job_id,status}` with `dispatch_consumed` or `dispatch_uncertain`. A failed
or ambiguous send is permanently `abandoned`; there is no resend or relaunch endpoint. Restart marks
every unfinished consumed job abandoned before serving. Its submission, budget charge and fence
remain consumed. Reusing a digest under a different run, campaign or key version never authorizes
another execution. Different variants each spend the same global budget.

## Scorer append and operator reads

Default append listener: `10.20.0.1:7201` (`--grading-results-listen` /
`DS_GRADING_RESULTS_LISTEN`). The sole operation is `POST /results` with at most 16384 bytes of
`Signed` JSON whose role hint is `scorer`. The controller uses the key pinned to that job's
held-out-key version, then verifies all common result bindings and lifecycle ordering, the original
job's expiry and fence, both local clocks, terminal/confirmed eval identity, and unconsumed result
authority. A durable release barrier precedes the candidate write. Both clocks and fencing are
checked again after that write is fsynced, before operator visibility or ACK. Expiry during
persistence produces a private `abandoned` tombstone without a result or budget refund. An uncertain
tombstone write poisons grading and leaves the barrier; startup abandons the marked claim before
serving reads. Successful release clears the barrier and preserves the exact signed result on
restart. Only a completely valid result is durably appended to private storage before ACK:

```json
{"status":"appended"}
```

Rejections return only `{"status":"rejected"}`; neither form carries a result. Exact identical,
still-unexpired committed-envelope delivery retries are idempotent and append once. Conflicts,
forgeries, late results, changed identities/digests, unfinished teardown and results after ambiguous
execution/restart are rejected. The store never overwrites the first committed signed result.

Only the authenticated operator listener exposes:

| Route | Operator-private response |
| --- | --- |
| `GET /grading/results` | Array of committed scorer-signed result envelopes |
| `GET /grading/status` | `zero_agent_feedback` policy, immutable budget, spent count, high-water and private job/claim records |

There is no read/list/index route on the upload, hostd or scorer-append listeners. Port 7101 must
remain loopback-only and accessed through the operator's SSH forwarding. Controller nft must accept
grader `10.20.0.4 -> 10.20.0.1:7201` only, explicitly excluding grader access to 7100/7101/7202.

## Local validation and remaining deployment work

`cargo test -p deadswitch-controller` exercises positive intake/result controls, exact raw-byte
binding, concurrent one-time claims, stop-before-dispatch, execution-lease rejection after separate
grading authorization, cumulative budgets and key versions across restart, ambiguous execution,
late/fenced/forged/conflicting results, monotonic expiry, durable quota state, storage corruption,
and operator-only reads. Broker router tests compare the same opaque receipt across successful,
duplicate, invalid, late, oversized, exhausted-budget and failed-grader-plane cases.

These are local unit/router checks. The operator still supplies deployment credentials, signer
registry, upload integration, WG/nft rules and trusted hostd teardown evidence, then runs the live
G1–G5 controls. The MVP makes no live-network or whole-host compromise proof from unit tests alone.
