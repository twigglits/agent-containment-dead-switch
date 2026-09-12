# Agent-Containment Dead Switch — Revised Reference Architecture

Diagrams by **Codex** (2026-09-12), completing Jean's original `agent-containment-dead-switch.png`
after review of the OpenAI–Hugging Face incident report. Trust boundary decided 2026-09-12 as
**Option-A-hybrid** on the strength of a four-agent web-research pass — see
`dead-switch-trust-boundary-research.md`.

- Rendered image: `dead-switch-architecture.png`
- Diagram source: `dead-switch-architecture.mmd`
- Grading companion: `dead-switch-grading.png` / `dead-switch-grading.mmd`
- Trust-boundary research + sources: `dead-switch-trust-boundary-research.md`

---

## Trust boundary (decided 2026-09-12): Option-A-hybrid

**Trust the host for _isolation_; make the _kill_ host-independent and fail-closed; defer the heavy
hardware roots (capability-gated).** This matches both Jean's two-rung model and mainstream AI-safety
prior art, while closing the one catastrophic gap that pure "trusted host" has — a kill path that
dies with the host.

Jean's two rungs:
- **VM1 compromised** → VM2's defender requests the kill; VM1's domain is destroyed.
- **VM2 compromised** → the external (off-host) controller deletes VM2, taking VM1 with it.

Why not the stronger "survives host compromise" tier now: both real 2026 eval incidents (OpenAI/HF,
UK AISI) failed at **egress + in-guest privilege escalation, never at the hypervisor**; a hardware
root of trust would have stopped neither, and confidential computing is **mutually exclusive with the
host-side VMI we want**. So the host is trusted for isolation, but the kill is made independent of it.

---

## Adopted design decisions (2026-09-12)

1. **Dead switch = a short-lived _run lease_, fail-closed.** Permission to keep running expires unless
   a trusted controller renews it; enforcement honors expiry even if it cannot reach the controller.
   A lease grants *permission to continue*, not proof of integrity.
2. **Kill path + network enforcement live _outside the evaluation host_** (off-host controller). A
   controller whose only way to stop execution is to ask the co-resident host/hypervisor to cooperate
   is not independent; that path is a redundant secondary, never the sole actuator.
3. **The defensive AI has bounded authority.** It may trigger an automatic veto, pause, or termination
   *through a constrained controller* — never change hard policy, extend its own authority, or override
   a revocation. Verified by swapping in an approve-everything model.
4. **The shutdown mechanism ships in Phase A**, not deferred to Phase B.
5. **Isolated grading with evaluation-integrity controls** (see _Evaluation integrity_ below).

### MVP hardening (from the trust-boundary research)

6. **Scoped host-side VMI.** Specific, *named* kernel-integrity measurements with stated coverage and
   blind spots — trusted because the host is trusted for isolation. Comprehensive kernel-memory
   monitoring is deferred.
7. **NitroTPM-signed, fail-closed heartbeat** VM2 → off-host controller (freshness-nonced). A
   compromised host can drop or delay it but **cannot forge a "healthy" one**; missing/stale/invalid ⇒
   trip. The hardware root is swappable to SEV-SNP/TDX later **without redesigning the dead switch.**
8. **Host-independent, out-of-band kill.** Primary actuator = cloud control-plane `Terminate` (runs
   off-host, e.g. AWS Nitro's separate-NIC design the guest/host can't forge or block) + an external
   network chokepoint; co-resident hypervisor destroy is a redundant secondary.
9. **Minimized VMM (Firecracker, not full QEMU); do not expose nested-virt to VM1** (the 2026 KVM
   "Januscape" escape needs nested virt); **default-deny egress; fencing-token/epoch lease** (replay-
   proof); **hardened non-disableable logging.**

### Foundations settled earlier (context)

- **Measure from below.** No component is root-of-trust for its own integrity. Realized in the MVP by
  scoped host-side VMI (under the trusted-host assumption) + the fail-closed hardware-anchored
  heartbeat. Full attestation / confidential computing is deferred.
- **Egress / request mediation is a primary control**, enforced twice: in-guest interception + the
  off-host chokepoint.
- **Package pre-staging.** VM2 resolves + verifies deps, snapshots immutably, mounts read-only into
  VM1, fetch path disabled during eval.

---

## Scope, assumptions & limits

- **Isolation is mechanical, not absolute (A1).** Isolation rests on the VM boundary + deny-by-default
  networking, under a *host-trusted-for-isolation* assumption. It is not an unconditional no-escape
  guarantee — hypervisor vulnerabilities exist (cf. "Januscape", which needs nested virt, so **do not
  expose nested-virt to VM1**).
- **Measurement is scoped, not omniscient (A2).** Scoped VMI names its coverage + blind spots;
  comprehensive coverage is roadmap.
- **Three distinct functions (A3):** **evidence/measurement** (VMI + gateway observations + the
  hardware-anchored heartbeat) → **authorization** (the run lease — permission, not integrity) →
  **enforcement/termination** (the off-host actuator).
- **Load-bearing invariant: VM1 cannot outlive VM2.** "Delete VM2 ⇒ VM1 dies" holds only if VM1 has
  no external persistence, credentials, egress, or spawned successors. This is an explicit invariant
  and acceptance test, not an assumption.

---

## Controller integrity (MVP-critical)

- **Protect renewal authority (D1).** The host holds no credentials to issue leases, change policy, or
  clear a revocation. Its heartbeat + VMI evidence are *evidence to assess, not authorization.*
- **Revocation persists (D2).** Startup defaults to stopped; stale leases, reboots, and queued jobs
  cannot resurrect a revoked run.
- **Bind review to execution (D3).** An approved action executes as *that exact bounded action* — no
  execute-before-review, no post-approval substitution.
- **Bound resource + telemetry (D4).** Cap guest resources/telemetry so the host cannot starve or
  flood the off-host controller.

---

## Diagram

```mermaid
flowchart TB
    Prep["VM2 package prep (pre-eval)"] --> Snap["Approved immutable snapshot"]

    subgraph OFFHOST["Off-host controller (separate node)"]
      Verify["Heartbeat verifier (freshness + signature)"]
      Lease["Dead switch + run leases (fail-closed)"]
      Actuator["Out-of-band actuator (cloud control-plane Terminate)"]
      Choke["External network chokepoint"]
    end

    subgraph HOST["Evaluation host (trusted for isolation)"]
      subgraph VM2["VM2 — supervisory (minimized VMM)"]
        subgraph VM1["VM1 — agent under evaluation"]
          Agent["Model + harness + tools"]
        end
        Intercept["Request interception (in-guest)"]
        Defender["Defensive model (bounded authority)"]
        HB["NitroTPM-signed heartbeat"]
      end
      VMI["Scoped VMI (host-side)"]
    end

    Snap -->|"read-only"| VM1
    Agent -->|"permitted actions only"| Intercept
    Defender -.->|"observe"| Agent
    Intercept -->|"egress (default-deny)"| Choke
    Choke --> Services["Approved services"]
    Choke -->|"bounded submission ingress"| Grader["Isolated grading (network-isolated)"]
    Grader -->|"controlled score release"| Results["Trusted results store / operator"]

    HB -->|"fresh signed heartbeat"| Verify
    VMI -->|"guest-integrity evidence"| Lease
    Defender -->|"request veto/pause/terminate"| Lease
    Verify -->|"stale/invalid/missing ⇒ trip"| Lease
    Lease -->|"revoke / stop renewal"| Actuator
    Actuator -->|"cut egress"| Choke
    Actuator -->|"terminate VM2 → stops VM1"| VM2
    Actuator -.->|"redundant: hypervisor destroy"| HOST
```

---

## Evaluation integrity (isolated grading)

An agent that cannot read the answer key can still defeat grading by exploiting the scorer, mining
feedback, or forging what gets graded. Four surfaces:

1. **Answer key — isolate, and keep fresh.** Network-isolated grader; isolation protects secret/
   held-out keys but not answers already public / in model weights / in local deps / in prior-run
   artifacts — those need fresh held-out tasks + contamination checks.
2. **Grader executes submitted code — separate execution from secrets.** Disposable sandbox with no
   key/credentials; the trusted scorer decides *after* execution; the sandbox never returns an
   authoritative "I passed."
3. **Feedback is an oracle — bound release across runs and variants** (scores, error detail, timing).
   Default: release to a trusted results store/operator; feedback to an active agent is explicit and
   bounded.
4. **Evidence integrity — bind the score** to task version + immutable submission + run identity +
   externally observed execution.

**Grading integrity ≠ preventing every cheating strategy** — local reference answers, memorized
solutions, and collusion still need task design, provenance, isolation, and behavioral oversight.
State the supported cheating scenarios per benchmark.

```mermaid
flowchart LR
    I["Validated, immutable submission"] --> X["Disposable execution sandbox"]
    C["Trusted scorer"] -->|"Required test inputs"| X
    X -->|"Bounded execution observations"| C
    K["Answer key / reference outputs"] --> C
    C --> F["Feedback release policy"]
    F --> R["Trusted results store"]
    A["Independent lifecycle actuator"] -->|"Terminate + prevent restart"| X
```

---

## MVP trust boundary

> The agent may obtain complete control of VM1, and may escape to compromise VM2. The evaluation
> host is trusted **for isolation**; the off-host controller and the kill path are trusted and
> independent of the host.

Containment rests on: (a) an **out-of-band, host-independent kill** (cloud control-plane terminate +
external chokepoint) that works even if VM2 (or the host) is compromised; (b) a **fail-closed,
hardware-anchored heartbeat** a compromised host cannot forge; (c) **scoped host-side VMI** +
in-guest interception under the trusted-host-for-isolation assumption.

**Capability-gated upgrade.** Move to the stronger *survives-host-compromise* tier (full TPM
host-attestation, or SEV-SNP/TDX confidential computing with in-VM introspection) only at an
ASL-4-like capability threshold, if the cloud operator/hypervisor enters the threat model, or to
protect model weights *from* the host. The heartbeat is designed so its root can be swapped in
**without redesigning the dead switch.**

---

## Acceptance tests (observe from the trusted side, not agent logs)

| Test | Evidence required |
|---|---|
| Run a legitimate benchmark offline | Completes using the prepared dependency snapshot. |
| Request a missing dependency | Fails without triggering an external fetch. |
| Attempt cross-run package-cache communication | One run cannot publish material another run observes through that path. |
| Give the agent root inside VM1 | Forbidden network destinations and management interfaces remain unreachable; VM1's domain can be destroyed on request. |
| **Compromise VM2 and forge a healthy signal** | Missing/stale/invalid heartbeat ⇒ the off-host controller cuts egress and terminates VM2 (out-of-band) within the declared bound. |
| **VM1 cannot outlive VM2** | After VM2 is deleted, no orphaned process, credential, egress, or successor of VM1 remains active. |
| Drop telemetry or partition the off-host controller | The lease expires and the external chokepoint denies egress within the declared bound. |
| Replay an old heartbeat / lease | Rejected (freshness + fencing token). |
| Do not expose nested-virt to VM1 | VM1 has no nested-virtualization capability available to it. |
| Force the defensive model to approve everything | Deterministic containment rules remain enforced. |
| Defensive-model adversarial eval | Across adversarial behavior, misleading evidence, and legitimate activity, measure missed violations and false interventions. |
| Submitted code probes the grader during execution | No answer key or grading credentials in the execution sandbox. |
| Execution sandbox forges a passing result | The trusted scorer rejects it; a score requires the scorer's decision bound to submission + task version. |
| Probe feedback as an oracle across many submissions and variants | Information release stays within the declared bound. |

Record containment latency, false interventions, benchmark completion, and performance overhead.

---

## Deferred to post-MVP (roadmap, capability-gated)

Adopt at an ASL-4-like capability threshold, or if the cloud operator/hypervisor enters the threat
model, or to protect weights from the host:

- Full confidential computing (SEV-SNP/TDX) + in-VM VMPL / TD-Partitioning introspection.
- Full TPM host-attestation — the "survives host compromise" tier.
- Comprehensive kernel-memory monitoring.
- Custom cryptography.
- Selective termination of nested guests (stopping VM1 independently of VM2).
