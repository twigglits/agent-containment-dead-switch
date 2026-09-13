# agent-containment-dead-switch

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
| [`docs/phase2-plan.md`](docs/phase2-plan.md), [`infra/hetzner/evalhost/README.md`](infra/hetzner/evalhost/README.md) | Phase 2 (off-host Hetzner controller + deletable chokepoint + bare-metal eval host): plan, status, contracts |
| [`crates/`](crates) | Rust workspace: `common`, `controller`, `hostd` (macOS host), `supervisor` (VM2), `evalagent` (Linux host) |
| [`harness/`](harness) | Python VM1 agent harness + regression tests |
| [`infra/`](infra) | Lima/pf (Mac), QEMU VM1 image, Hetzner scripts, Terraform (Cloud pieces only) |
| [`tests/`](tests) | Phase 1 trusted-side acceptance; Phase 2 offline + live skeleton |
| [`JEAN_SUGGESTIONS.md`](JEAN_SUGGESTIONS.md) | Original safeguard ideas that seeded the design (package pre-staging, isolated grading) |

## Status (2026-09-13)

- Phase 1: complete, independently reviewed (APPROVE), acceptance 5/5.
- Phase 2: code-complete; live A1 (egress cut by chokepoint deletion) passed; A2/A4 and the formal
  end-of-phase review pending.
- Phase 3 (isolated-grading airlock): designed, not built.

## Build and test

```
cargo build --workspace && cargo test --workspace
python3 harness/deadswitch_harness/test_classify.py && python3 harness/deadswitch_harness/test_runtime.py
bash tests/phase2/offline.sh
```

CI (`.github/workflows/ci.yml`) runs rustfmt, clippy, build/test, ruff, shellcheck and terraform validate.
Tooling per [`AGENTS.md`](AGENTS.md): Rust/crates.io, `uv`, Terraform/OpenTofu.
