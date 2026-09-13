# Phase 3 — External grading "airlock" (isolated benchmark grading). PLAN (for Codex start-of-phase review)

Phase 3 builds the last piece of the reference architecture: the **external network airlock** through
which an evaluation's results are graded **without ever exposing the held-out answer key to the agent
or its host, and without letting the grader become a new egress/coordination channel.** It realizes
the "Evaluation integrity (isolated grading)" section of `dead-switch-architecture.md` and its
`dead-switch-grading.mmd` diagram.

## Why (threat model, from the incident + the architecture doc)
An agent that cannot read the answer key can still defeat grading four ways, so each is a control:
1. **Answer key** — network-isolate it; keep held-out tasks fresh (contamination is out of scope but stated).
2. **The grader executes submitted code** — separate execution from secrets: a disposable sandbox with
   NO key/creds; the trusted scorer decides *after* execution; the sandbox can never self-report "passed."
3. **Feedback is an oracle** — bound what is released across runs/variants (score only, to a trusted
   store; anything back to an active agent is explicit + bounded).
4. **Evidence integrity** — bind each score to task version + immutable submission + run identity +
   externally observed execution.
Additionally (the incident's core lesson): the airlock must not become the next Artifactory — no
shared writable state across gradings, no return path the agent can drive, no transitive egress.

## Focused scope (mirrors the approved Phase-2 focus)
Prove the NOVEL airlock/grading-integrity properties on the existing off-host topology; reuse Phase 1/2
primitives (signed envelopes in `common`, the off-host controller, fail-closed lease, evidence,
disposable-VM lifecycle, `ds_kill` actuator). Do NOT rebuild a real benchmark corpus — use a tiny
held-out task set to exercise the controls.

## Topology (adds one node to the Phase-2 mesh)
- **Grader node** — a new network-isolated Hetzner Cloud node (x86 `cpx`, ash; account is US/x86-only).
  It has NO general egress (nft default-deny, like the chokepoint): it can only (a) RECEIVE a validated
  immutable submission via the airlock and (b) EMIT a bounded score to the trusted results store. It
  holds the held-out answer key in a root-only store the exec sandbox cannot read.
- **Disposable execution sandbox** — one nested KVM guest (or a fresh throwaway namespace) per
  submission on the grader, created with NO key/creds and NO network, destroyed after grading. Reuses
  the Phase-2 nested-VM + gate machinery. The trusted scorer runs OUTSIDE it and observes it.
- **Airlock** — a strictly one-directional, bounded channel: submission IN (size/rate-capped, schema-
  validated, content-addressed/immutable), bounded score OUT to the results store. No answer key out;
  no channel the agent/eval side can use to pull data back or relay egress. Signed + fenced like the
  controller protocol; the results store is trusted and off the agent's path.
- Reuse the **controller** as the trusted control point that mints/authorizes a grading job and records
  the evidence-bound score; the **airlock** carries data, the controller carries authorization.

## Components to build
1. `common`: signed `GradingSubmission` (run_id, task_id, task_version, submission_digest, artifact) and
   `GradingResult` (run_id, task_id, task_version, submission_digest, score, scorer_decision, evidence)
   envelopes (v/type/aud/incarnation/issued_at, ed25519-signed) — same discipline as ChallengeRequest/etc.
2. A **grader service** (Rust, reuse `common`): accepts a signed submission over the airlock, validates
   + pins it immutable, launches the disposable sandbox with the submission (no key), collects the
   sandbox's externally-observed output, runs the trusted scorer (key compared here, never in the
   sandbox), releases only a bounded `GradingResult` to the results store, destroys the sandbox. Fail-
   closed: any anomaly → no score released, sandbox destroyed.
3. **Airlock enforcement** (nft/routing on the grader, mirroring `evalhost-egress.sh`): submission
   ingress only from the authorized airlock peer; score egress only to the results store; everything
   else (incl. the sandbox's egress) default-deny/blackhole; the sandbox has NO network.
4. A tiny **held-out task set** + trusted **scorer** (deterministic check), key stored root-only.
5. `tests/phase3/` offline suite (like phase2/offline.sh): unit-test the submission/immutability/
   scoring/feedback-bound logic without live cloud; a live G-series skeleton that reports BLOCKED until
   the grader node is up.

## Acceptance tests (observe from the trusted side)
- **G1 execution↔secrets separation:** a probing submission that tries to read the answer key or
  grading creds finds none in the sandbox; the key never enters the sandbox.
- **G2 no forged pass:** a submission that emits a fake "PASS" is scored by the trusted scorer against
  the real key and REJECTED; a score exists only as the scorer's decision bound to submission+task version.
- **G3 feedback-oracle bound:** many submissions/variants probing feedback get only the bounded score;
  no answer/timing/error leakage beyond the declared bound; feedback goes to the results store, not the agent.
- **G4 airlock one-way / no key exfil / no relay:** the answer key never crosses the airlock outward;
  the grader cannot be driven as an egress or cross-run coordination channel (no shared writable state;
  no agent-controllable return path); submission is immutable + schema-validated.
- **G5 disposable-sandbox lifecycle:** the sandbox is destroyed after each grading with no cross-
  submission persistence; the independent actuator can terminate it and prevent restart (reuse `ds_kill`).

## Reuse & non-goals
Reuse: `common` envelopes, controller authorization, fail-closed lease/evidence, nested-VM + gate,
`ds_kill`. Non-goals (stated limits): benchmark-corpus freshness/contamination detection; defeating
memorized/in-weights answers; a hardware root of trust — all consistent with the capability-gated
roadmap in `dead-switch-architecture.md`.

## Build order
1. Codex **start-of-phase review of THIS plan** (mandatory gate) → revise per feedback.
2. `common` grading envelopes + grader service + airlock nft + scorer + offline tests (green + x86 musl).
3. Stand up the grader node on the mesh; wire the airlock; live G1–G5.
4. Codex **end-of-phase review** → APPROVE-PHASE-3.
