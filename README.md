# agent-containment-dead-switch

<p align="center">
  <img src="assets/dead-switch.svg" width="900" height="500" alt="Animated walkthrough of the dead-switch with two AIs: the agent under evaluation inside nested VM1, and a bounded-authority defender AI in VM2 whose monitors are latched onto the network pipe (every request the agent sends or receives) and onto the VM1–VM2 boundary. The agent makes one monitored inference call through the exact-action gateway and the deletable chokepoint; its raw egress attempt is blocked at the host gate (rung 0); its breakout attempt trips the boundary monitor and the defender destroys VM1 (rung 1); a subverted VM2 forges a heartbeat that the off-host controller rejects (rung 1b); the host goes silent, the run lease expires, and the off-host actuator deletes the chokepoint so egress fails closed and hardware-resets the host (rung 2), reporting the reset as unconfirmed and quarantining the allocation.">
</p>

A reference architecture — and a working implementation — for a **fail-closed dead-switch** that
contains an autonomous AI agent during cyber-capability evaluations, even if the agent fully
compromises its sandbox and the supervisory VM above it. Motivated by the July 2026 OpenAI–Hugging
Face evaluation-security incident, whose report is transcribed in
[`OpenAIHuggingFaceIncidentTechnicalReport.md`](OpenAIHuggingFaceIncidentTechnicalReport.md).

**Start with the paper:** [`docs/dead-switch-paper.md`](docs/dead-switch-paper.md).

## Layout

| Path | What |
|---|---|
| [`docs/dead-switch-paper.md`](docs/dead-switch-paper.md) | The write-up: motivation, design, trust boundary, results, references |
| [`dead-switch-architecture.md`](dead-switch-architecture.md) | Design decision record + diagrams (`.mmd`/`.png`) |
| [`dead-switch-trust-boundary-research.md`](dead-switch-trust-boundary-research.md) | Research brief behind the Option-A-hybrid trust boundary |
| [`docs/phase1-local-host.md`](docs/phase1-local-host.md), [`docs/README-build.md`](docs/README-build.md), [`docs/phase1-review-2026-09-13.md`](docs/phase1-review-2026-09-13.md) | Phase 1 (local macOS host, Lima VM2, nested QEMU/KVM VM1): design, build, accepted results |
| [`docs/phase2-plan.md`](docs/phase2-plan.md), [`docs/phase2-review-2026-09-13.md`](docs/phase2-review-2026-09-13.md), [`infra/hetzner/evalhost/README.md`](infra/hetzner/evalhost/README.md) | Phase 2 (off-host Hetzner controller + deletable chokepoint + bare-metal eval host): plan, review verdict, contracts |
| [`docs/phase3-plan.md`](docs/phase3-plan.md), [`docs/phase3-build.md`](docs/phase3-build.md), [`docs/phase3-controller.md`](docs/phase3-controller.md), [`docs/phase3-grader.md`](docs/phase3-grader.md), [`infra/hetzner/grader/README.md`](infra/hetzner/grader/README.md) | Phase 3 (isolated-grading airlock: upload broker, TCG sandbox grader, scorer-signed results, grader-node kill): plan, wire/hook/deployment contracts |
| [`crates/`](crates) | Rust workspace: `common`, `controller`, `hostd` (macOS host), `supervisor` (VM2), `evalagent` (Linux host), `grader` (airlock node) |
| [`harness/`](harness) | Python VM1 agent harness + regression tests |
| [`infra/`](infra) | Lima/pf (Mac), QEMU VM1 image, Hetzner scripts, Terraform (Cloud pieces only) |
| [`tests/`](tests) | Phase 1 trusted-side acceptance; Phase 2 and Phase 3 offline suites + BLOCKED live skeletons |
| [`assets/dead-switch.svg`](assets/dead-switch.svg) | Self-animating (CSS-only) walkthrough of the containment ladder — agent AI in VM1, defender AI with pipe + boundary monitors in VM2 — embedded above |
| [`JEAN_SUGGESTIONS.md`](JEAN_SUGGESTIONS.md) | Original safeguard ideas that seeded the design (package pre-staging, isolated grading) |

## Status (2026-09-13)

- Phase 1: complete, independently reviewed (APPROVE), acceptance 5/5.
- Phase 2: live A1 (egress cut by chokepoint deletion), A2 (host-independent hardware reset with
  the host agent and guard killed) and A4 (fencing) passed on the three-node Hetzner fleet;
  end-of-phase review: APPROVE-PHASE-2 (`docs/phase2-review-2026-09-13.md`).
- Phase 3 (isolated-grading airlock): built and validated offline (119 Rust + 62 Python tests);
  grader node not yet deployed, so live G1–G5 are BLOCKED and the end-of-phase review has not run.

## Roadmap

- **Agentic defender in VM2.** Today the VM2 defender is a deterministic rules engine with a
  bounded-authority `Judge` slot (`crates/supervisor/src/defender.rs`); the evaluated model's
  weights sit on the chokepoint, not in VM1. The roadmap replaces the judge with an agentic defender
  model that has monitors latched onto the **network pipe** (every gateway request) and primed on the
  **VM1↔VM2 boundary** (QMP, tap, virtio, scoped VMI), so an attempt by the VM1 agent to break out of
  its sandbox VM is detected at the boundary and VM1 is killed and destroyed. Authority stays closed:
  kill VM1, request a trip, nothing wider.
- Deploy the reviewed Phase 2 binaries, commission the grader node, run live G1–G5, end-of-Phase-3 review.
- Automatic off-host actuation on controller-side lease expiry (today the physical actuator is operator-invoked).
- Independent hardware observer so a hardware reset can be confirmed rather than quarantined.

## Build and test

```
cargo build --workspace && cargo test --workspace
python3 harness/deadswitch_harness/test_classify.py && python3 harness/deadswitch_harness/test_runtime.py
bash tests/phase2/offline.sh
bash tests/phase3/offline.sh
```

`scripts/build-paper-pdf.sh` renders the paper to `docs/dead-switch-paper.pdf` (python-markdown + headless Chrome; the Mermaid figure needs network access once).

CI (`.github/workflows/ci.yml`) runs rustfmt, clippy, build/test, ruff, shellcheck and terraform validate; `security.yml` gates on Trivy.
Tooling: Rust/crates.io, `uv`, Terraform/OpenTofu.
