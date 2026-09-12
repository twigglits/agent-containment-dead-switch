# Dead-Switch Trust-Boundary — Research Brief

**Date:** 2026-09-12. **Status:** decided — adopted **Option-A-hybrid** (see below).
**Purpose:** choose the MVP trust boundary for the agent-containment dead switch, grounded in
external research rather than judgment alone.

## The decision

- **Option A — survives VM2 compromise (host trusted):** defend against the guest VMs being
  compromised; the host/hypervisor and the external process are trusted; an external process deletes
  VM2 (⇒ VM1).
- **Option B — survives host compromise:** assume the physical host/hypervisor itself can be
  subverted; requires a hardware root of trust (TPM / confidential computing) and a host-independent
  kill path.

Jean's two-rung model: VM1 compromised → VM2's defender kills VM1; VM2 compromised → external cloud
process deletes VM2 (⇒ VM1).

## Method

On 2026-09-12, four parallel web-research agents each investigated one pillar. Below are their
convergent conclusions and the decisive sources. (Codex to red-team this finished brief.)

## Pillar 1 — VM/hypervisor-escape reality

- Hypervisor escapes are real and recurring — Pwn2Own demonstrates guest→host escapes on hardened
  commercial hypervisors nearly every year. The **KVM core itself was shown escapable in 2026**
  ("Januscape", CVE-2026-53359 — a 16-year-old use-after-free, full host RCE) and it **requires
  nested virtualization — exactly our VM1-in-VM2 config.**
- Standards (NIST SP 800-125A) favor TCB minimization + defense-in-depth, never "trust the
  hypervisor absolutely."
- Minimized VMMs (Firecracker ≈ 83K LoC Rust) shrink the attack surface enormously vs full QEMU
  (cf. VENOM) or shared-kernel containers, but the hardware-virt boundary remains and is not immune.
- Sources: Januscape/CVE-2026-53359 (https://thehackernews.com/2026/07/16-year-old-linux-kvm-flaw-lets-guest.html);
  Google kvmCTF $250K (https://www.securityweek.com/google-offering-250000-for-full-vm-escape-in-new-kvm-bug-bounty-program/);
  ZDI CVE-2023-20869/70 (https://www.thezdi.com/blog/2023/5/17/cve-2023-2086920870-exploiting-vmware-workstation-at-pwn2own-vancouver);
  VMware Pwn2Own 2024 (https://blogs.vmware.com/security/2024/03/vmware-by-broadcom-and-pwn2own-vancouver-2024.html);
  Red Hat VENOM (https://access.redhat.com/articles/1444903);
  NIST SP 800-125A Rev.1 (https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-125Ar1.pdf).

## Pillar 2 — Confidential computing / hardware root of trust

- TPM measured boot + remote attestation (RFC 9334) prove **boot-time** state, not continuous runtime
  integrity; TOCTOU is a first-class weakness (attester clean at check, tampered at use).
- SEV-SNP / TDX give memory confidentiality+integrity against a malicious hypervisor — the real
  "measure from below the host" primitive — but they are **mutually exclusive with host-side VMI**
  (they encrypt guest memory *from* the hypervisor), **break classic nested virt** (need immature
  VMPL / TD-Partitioning), carry heavy I/O overhead (up to ~60%), and are themselves imperfect
  (Heckler, WeSee). **AWS sells no customer-attestable SEV-SNP CVM** — it is a "trust Nitro" model
  plus NitroTPM/Attestable-AMIs.
- Sources: AWS Confidential Computing (https://aws.amazon.com/confidential-computing/);
  Azure CVM (https://learn.microsoft.com/en-us/azure/confidential-computing/confidential-vm-overview);
  GCP CVM (https://docs.cloud.google.com/confidential-computing/confidential-vm/docs/confidential-vm-overview);
  USENIX Sec'24 in-VM introspection (https://www.usenix.org/system/files/usenixsecurity24-schwarz.pdf);
  Heckler (https://arxiv.org/pdf/2404.03387); RFC 9334 (https://www.rfc-editor.org/rfc/rfc9334);
  CCS'21 TOCTOU (https://dl.acm.org/doi/10.1145/3460120.3484532).

## Pillar 3 — AI-safety field prior art

- Mainstream eval-containment trusts the host/hypervisor and centers **egress control + nested
  isolation + an independent kill switch + monitoring** — not hardware roots of trust. UK AISI runs
  a "sandbox-in-a-sandbox" (container-in-VM = our nesting).
- Both 2026 incidents (OpenAI/HF, UK AISI) failed at **egress + in-guest privilege escalation, never
  the hypervisor**; a hardware RoT would have stopped neither.
- Anthropic (RSP) and DeepMind (FSF) reserve host/hardware-rooted assumptions for **weight security
  (ASL-4-like), not agent containment.** Redwood "AI control": assume the model may be egregiously
  misaligned, don't trust the monitor, keep a hardened "trusted core" the untrusted system cannot
  disable.
- Sources: OpenAI incident report (https://openai.com/index/hugging-face-model-evaluation-security-incident/);
  UK AISI incident (https://www.aisi.gov.uk/blog/incident-report-unsanctioned-agent-behaviour-during-cyber-testing) +
  Inspect (https://inspect.aisi.org.uk/); Anthropic RSP (https://www.anthropic.com/responsible-scaling-policy);
  DeepMind FSF (https://deepmind.google/blog/strengthening-our-frontier-safety-framework/);
  Redwood AI control (https://www.redwoodresearch.org/research/ai-control);
  METR common elements (https://metr.org/common-elements).

## Pillar 4 — Kill-switch / out-of-band control

- The independence principle is doctrine: reference-monitor **NEAT** (tamper-proof, always-invoked,
  non-bypassable); watchdog timers must be **external + non-disableable**; leases need **fencing
  tokens the resource itself rejects.**
- Fail-closed: a trusted controller renews permission; **absence ⇒ death.** Never self-reported
  "healthy" as the trigger. Replay/rollback resistance needs monotonic epochs/nonces.
- Host-independent actuators exist and are proven: **cloud control-plane Terminate is out-of-band**
  (AWS Nitro passive-comms — separate NIC, guest/host cannot forge or block it); external network
  chokepoint; BMC/PDU; data diodes.
- **The host under VM2 need NOT be trusted for the kill** if the primary actuator is the control
  plane / external chokepoint — but it IS in the kill TCB if the only kill is "ask the co-resident
  hypervisor to destroy the domain" (avoid that topology).
- **Critical:** "delete VM2 ⇒ VM1 dies" holds only if VM1 has no external persistence, credentials,
  egress, or spawned successors.
- Sources: Reference monitor / NIST AC-25 (https://csf.tools/reference/nist-sp-800-53/r5/ac/ac-25/);
  Ganssle watchdogs (https://www.ganssle.com/watchdogs.htm);
  Kleppmann fencing tokens (https://martin.kleppmann.com/2016/02/08/how-to-do-distributed-locking.html);
  AWS Nitro passive-comms (https://docs.aws.amazon.com/whitepapers/latest/security-design-of-aws-nitro-system/passive-communications-design.html);
  NIST SP 800-82 data diodes; KILLBENCH (https://arxiv.org/pdf/2511.13725).

## Decision: Option-A-hybrid

Trust the host **for isolation**; make the **kill host-independent and fail-closed**; defer the heavy
hardware roots (capability-gated). This matches both Jean's two-rung model and the field's prior art,
while closing the one catastrophic gap pure Option A has (a kill path that dies with the host).

**MVP-critical:**
1. Host-independent, fail-closed kill: cloud control-plane `Terminate` (out-of-band) + external
   network chokepoint; co-resident hypervisor destroy only a redundant secondary.
2. NitroTPM-signed, freshness-nonced fail-closed heartbeat VM2 → off-host controller (a compromised
   host can drop/delay it but cannot forge "healthy"); root swappable to SNP/TDX later without
   redesigning the dead switch.
3. Minimized VMM (Firecracker), do not expose nested-virt to VM1, default-deny egress,
   fencing-token/epoch lease, hardened non-disableable logging, scoped host-side VMI.
4. Invariant + test: **VM1 cannot outlive VM2** (no external persistence / credentials / egress /
   successors).

**Deferred / capability-gated** (adopt at an ASL-4-like capability threshold, or if the cloud
operator/hypervisor enters the threat model, or to protect weights from the host):
- Full confidential computing (SEV-SNP/TDX) + in-VM VMPL/TD-Partitioning introspection.
- Full TPM host-attestation (the "survives host compromise" tier).
- Comprehensive kernel-memory monitoring; custom cryptography; selective termination of nested guests.
