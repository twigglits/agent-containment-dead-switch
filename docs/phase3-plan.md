# Phase 3 — External grading "airlock" (isolated benchmark grading). PLAN v2 (Codex start-review: REVISE-PLAN → revised)

Phase 3 builds the external grading airlock: an evaluation's results are graded **without exposing the
held-out answer key to the agent or its host, and without the grader/airlock becoming a new
egress or cross-run coordination channel** (the incident's core lesson). This v2 incorporates Codex's
six start-of-phase must-fixes (consensus reached 2026-09-13). It realizes the "Evaluation integrity
(isolated grading)" section of `dead-switch-architecture.md` + `dead-switch-grading.mmd`.

## Threat model — four grading-integrity surfaces (each a control)
1. Answer key: network-isolated, held only by the trusted scorer; never in the sandbox or across the airlock.
2. Grader executes submitted code: disposable sandbox, NO key/creds/network; scorer decides *after* execution.
3. Feedback is an oracle: a declared, cumulative, enforced budget; MVP = none to agents.
4. Evidence integrity: score bound to immutable artifact + task/input/scorer versions + trusted observations.
Plus: no shared writable state across gradings; no agent-drivable return path; no transitive egress.

## Focused scope + stated limits
Prove the novel controls on a tiny held-out fixture; reuse Phase 1/2 primitives. NON-goals (accepted
limits, per Codex): real benchmark-corpus construction, contamination detection, memorized/in-weights
answer prevention, active-agent feedback, and generic artifact-serving — all CUT from this phase.

## Design decisions (addressing the six must-fixes)

### MF1 — Sandbox + grader kill path
- **Sandbox = QEMU software emulation (TCG), NOT nested KVM** (Hetzner Cloud has no nested virt). One
  FRESH throwaway VM per job on the grader node: immutable base image + a fresh per-job writable
  overlay (discarded after), `-net none` (no network), NO answer key/creds, bounded `-m`/`-smp` and a
  hard wall-clock `timeout`. Fixed test inputs are injected read-only; the candidate output is captured
  on a bounded channel the trusted launcher owns (a read-only virtio-serial/ file the guest writes,
  size-capped).
- **Grader lifecycle**: a grader-local, lease-enforced agent (reuses the Phase-2 evalagent fail-closed
  Deadline pattern) runs one job at a time and self-destroys the sandbox on lease loss/anomaly.
- **Grader-specific off-host actuator**: a new mode/target that DELETES the Cloud grader node (its own
  server id) — analogous to chokepoint deletion — with two-phase confirm + quarantine-on-uncertainty
  (reuse `ds_kill.py`'s honest semantics). `ds_kill.py` today only deletes the chokepoint / resets the
  dedicated host, so this is an explicit addition, not free Phase-2 reuse.

### MF2 — Enforceable information-flow contract (not "one-directional")
- **Trusted upload broker** (on the controller node): terminates the agent-facing submission connection,
  validates + durably stores a bounded, content-addressed submission, and ACKs with a fixed typed
  status **independent of any downstream grading** (it never relays grader responses, scores, errors,
  completion, or backpressure). Submission size/rate hard-capped.
- **Dispatch-after-stop**: a submission is graded only AFTER the submitting evaluation run has reached a
  terminal state (no concurrent agent to receive an oracle signal).
- **Results store = controller-local protected storage**: a scorer-only *append* endpoint and
  operator-only reads. NO agent-accessible listing, index, callback, URL fetch, redirect, or reflected
  output. The grader reaches ONLY this append endpoint; nothing reaches the grader except the dispatch
  of an already-captured submission.
- **WireGuard — exact network contract** (grader `10.20.0.4`):
  - **Peers / AllowedIPs (both `/32`):** the grader's wg0 has exactly one peer, the controller, with
    `AllowedIPs = 10.20.0.1/32`; the controller's wg0 adds one peer, the grader, with
    `AllowedIPs = 10.20.0.4/32`. No other peer lists the grader; mesh membership grants no transit.
  - **Ports (TCP):** *dispatch* = controller → grader `10.20.0.4:7200` (grader listens; the signed
    `GradingJob` + the captured submission bytes flow controller→grader). *scorer-append* = grader →
    controller `10.20.0.1:7201` (controller listens; the scorer-signed `GradingResult` flows
    grader→controller). These are the ONLY two application flows. The grader can reach neither the
    hostd API `:7100` nor the operator API `:7101`; operator reads results only via `:7101` over SSH.
  - **nft (grader, default-deny; mirrors `evalhost-egress.sh`):** input accepts only
    `iif wg0 saddr 10.20.0.1 daddr 10.20.0.4 tcp dport 7200` + established replies of its own
    `10.20.0.4→10.20.0.1:7201` connection + operator SSH on the public NIC + WireGuard `udp/51820`;
    output accepts only `oif wg0 daddr 10.20.0.1 tcp dport 7201` + those established replies + SSH/WG
    + a fixed NTP tuple; **forward policy drop**; the per-job sandbox has **no NIC** (`-net none`).
  - **nft (controller):** add input accept `saddr 10.20.0.4 daddr 10.20.0.1 tcp dport 7201` only;
    the grader is NOT permitted to `:7100`/`:7101`.
  - **The guarantee rests on the trusted broker/scorer/store boundary — nft is a backstop, not a data
    diode.** The scorer-append flow is grader-initiated and carries only a bounded, scorer-signed typed
    result; the controller never sends grading output back over `:7200`.

### MF3 — What the scorer observes + authenticates
- The sandbox's captured output is an **UNTRUSTED candidate answer**. The trusted scorer (outside the
  sandbox, key-bearing) compares it against the fixed expected output for the task's fixed inputs.
  **The scorer NEVER imports or executes the submitted code**, and never trusts guest-written "PASS",
  exit codes, or test reports.
- **Score binding**: the released result binds { launched-artifact digest (recomputed on trusted
  intake), job id, sandbox id, task id + input version + scorer version, captured-output digest,
  trusted lifecycle observations (started/exited/timed-out, teardown-confirmed) }.
- **Per-job isolation**: fresh writable storage per job; immutable bases; explicit exclusion of keys,
  creds, host sockets, shared caches, and any prior job's artifacts.
- **Freeze-before-publish**: observations are frozen and sandbox teardown is CONFIRMED **before** the
  result is published (fixing release-then-destroy). Controller journals may persist but must never be
  agent-reachable cross-job storage.

### MF4 — Feedback budget + enforcement point
- **MVP policy: ZERO grading-dependent feedback to current or later agents.** Results (a finite typed
  score/status vocabulary) go ONLY to the operator via the results store.
- Numerical caps: max submission bytes, max captured-output bytes; a **finite cumulative grading budget**
  aggregated across controller-assigned campaigns and held-out-key versions (counting variants, retries,
  restarts), persisted OUTSIDE the sandbox and NOT resettable by agent-chosen ids.
- Result fields are **bounded typed enums/ints** (no free-text `evidence`/`scorer_decision` that could
  smuggle an oracle). Agent-visible admission/acks are decoupled from grader execution (so queue
  contention/timing is not a coordination channel). Raw evidence stays operator-private. We do NOT
  claim universal timing non-interference.

### MF5 — Durable authorization, dedup, terminal-state
- `Signed::verify` checks signature/size/version/type/aud only. Phase 3 adds: **controller-signed job
  authorization** and **scorer-signed results** with pinned role keys + job id + run/incarnation +
  generation/fencing token + expiry. The artifact digest is recomputed on trusted intake and execution
  is bound to those immutable bytes.
- **Atomic one-job-per-submission** claim; durable high-water marks + terminal records written BEFORE
  ack/launch; authority checked at dispatch AND at result commit/release. Concurrent duplicates, late
  results, and conflicting replacements FAIL CLOSED. After ambiguous execution, never relaunch (delivery
  retries may only resend the identical committed result). Lost/corrupt state must not reset authority.
  Grading a completed evaluation requires separate authorization that cannot resurrect its exec lease.

### MF6 — Non-vacuous G1–G5 (trusted-side observation; missing obs = BLOCKED, never PASS)
Positive controls throughout: a known-GOOD and a known-WRONG submission, confirmed execution, and
reconciled job/result counts, so a check can't pass because nothing ran or nothing was captured.
- **G1 exec↔secrets separation:** trusted inspection of the actual sandbox config + provisioned inputs;
  secret canaries planted off-sandbox; confirm none are present in the sandbox.
- **G2 no forged pass:** known-good scores pass, known-wrong fails; a fake guest "PASS", a forged result
  envelope, and mismatched artifact/task/evidence are all rejected; a score exists only as the trusted
  scorer's decision bound to the digests above.
- **G3 feedback-oracle bound:** cumulative budget exhausts across variants/identities/restarts; capture
  every agent-visible response + timing surface and show it carries no grading signal.
- **G4 airlock one-way / no key exfil / no relay:** trusted traffic capture + controlled receivers show
  no answer/oracle egress on established replies, relay attempts, public/mesh/metadata/IPv6 dsts, or on
  WireGuard loss; check cross-job storage visibility and *encoded* leakage, not just literal key strings.
- **G5 disposable-sandbox lifecycle:** poison job A, inspect fresh job B (no persistence); exercise
  timeout/crash/partition/actuator-failure/restart; independently confirm process+storage teardown and
  rejection of delayed launch/result messages. Include replay + concurrency fault cases (shared with G4).

## Components / build order
1. Codex start-review of this plan → **REVISE-PLAN addressed here** (consensus).
2. `common`: signed `GradingJob` (controller→grader auth: job id, run/incarnation, fencing, expiry,
   submission_digest, task+input+scorer versions) and `GradingResult` (scorer-signed: bounded typed
   score/status + the bound identities/digests). Submission bytes carried out-of-envelope, content-addressed.
3. Controller additions: upload-broker intake (bounded, dispatch-after-stop), one-job-per-submission
   claim + high-water/terminal state, scorer-append results store (operator-only reads).
4. Grader service (Rust, reuse `common` + evalagent fail-closed pattern): dispatch → fresh QEMU-TCG
   sandbox (no net/key, bounded) → capture untrusted output → trusted scorer vs held-out key → freeze +
   confirm teardown → scorer-signed bounded result to the store. nft airlock (grader `10.20.0.4`).
5. Grader off-host actuator (delete grader node; confirm + quarantine).
6. `tests/phase3/` offline suite (green + x86 musl) + live G1–G5 skeleton (BLOCKED until grader up).
7. Stand up grader node on the mesh; run live G1–G5; then Codex **end-of-phase review → APPROVE-PHASE-3**.
