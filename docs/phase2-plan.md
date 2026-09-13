# Phase 2 — off-host controller + egress chokepoint (Hetzner). Plan (Codex start-review: REVISE-PLAN, 2026-09-13)

Two-node topology: a Hetzner **Cloud** controller (same `deadswitch-controller` binary) + a deletable
**egress chokepoint** Cloud VM, and a Hetzner **dedicated** (bare-metal) eval host (Robot API, nested
KVM) running `deadswitch-hostd` below VM2 → nested QEMU/KVM VM1 (REUSE the Phase-1 QEMU VM1 image +
harness; the old "Firecracker" note is stale). Host-independent fail-closed kill = controller DELETES
the chokepoint (egress fails closed) + Robot hardware reset of the eval host, confirmed via Robot.
Terraform manages only the Cloud pieces; the dedicated server is ordered out-of-band via Robot.

## Must-fix BEFORE building/apply (from Codex start-review)
1. **Independent termination proof.** The kill must work with hostd + its local guard DISABLED, and
   under controller partition/crash: exercise chokepoint-deletion egress-cut and Robot reset with API
   timeout/failure handling; confirm termination via Robot before reporting `terminated`.
2. **Chokepoint unavoidable.** Force the eval host's *workload* egress (VM2/VM1) through the deletable
   chokepoint via dedicated policy-routing/namespace + host nft covering forwarded AND proxy-originated
   traffic, default-deny at boot, with an UNREACHABLE fallback (no public IPv4/IPv6 fallback, no libvirt
   default NAT, no DNS/metadata bypass, no forwarding via the management channel). Seal/cut invalidates
   established flows. Keep host management traffic on a SEPARATE path. Preserve the exact-action
   inference proxy + model pinning + dispatch-time fencing + cancellation (do NOT degrade to generic
   NAT). Place the inference backend so agent requests traverse the deletable path.
3. **Network protocol hardening.** Signed envelopes stay, PLUS mTLS or tightly-scoped WireGuard with
   endpoint ACLs (signatures authenticate but do not encrypt; controller↔hostd now crosses a network,
   not loopback). SIGN `/challenge` and `/defender` (they currently accept unsigned requests). Operator
   ops behind SSH forwarding only. hostd key root-only at `/var/lib/deadswitch/keys/hostd.key`; pin the
   controller pubkey in root-owned config; provision the controller's hostd-key allowlist via the
   operator trust path. No private keys / operator tokens / provider creds in guest images, user-data, logs.
4. **Dedicated↔Cloud networking.** `type = "cloud"` subnet does NOT connect a dedicated server — use a
   Robot vSwitch + vSwitch-connected subnet (host VLAN config) OR explicit WireGuard tunnels.
5. **Physical-resource fencing/health/evidence.** Bind each run/incarnation to the dedicated server
   number + host boot/allocation generation + exact chokepoint server ID. Durable high-water + terminal
   revocation across every actuator restart; one active run per physical host; a delayed reset retry
   must never hit a later allocation. Terraform reconciliation must NOT silently recreate an authorized
   forwarding path after runtime deletion. Linux hostd observes real QEMU/nft digests; unknown = unhealthy.
   Signed host evidence + actuator outcomes stored durably OFF-host with bounded buffering.
6. **Scaffold exposure.** Attach a firewall to the (currently unprotected) chokepoint; restrict all SSH
   to operator CIDR/VPN; pin provider + image versions; protected recoverable Terraform state.

## Should-fix
- Correct the N9 note: established-connection survival on rule change is a **Cloud Firewall** property;
  **Robot** firewall is stateless per-packet. Keep chokepoint DELETION as the authoritative actuator;
  document Robot config delay, service exceptions, IPv6 limits.
- Reconcile stale Cloud-eval/Firecracker text; keep advisory-VMI as an accepted limit (bare metal does
  NOT auto-restore host-side VMI unless separately built + validated).
- Budget: hardware-qualification failures, image rebuild, inference capacity, setup/IP charges,
  teardown. Hetzner order latency ranges minutes→weeks; billing continues while powered off until
  cancellation. Robot limits: 50 reset requests/hr, 500 reset queries/hr → bounded backoff.

## Closeout gate (build toward this; Codex end-of-Phase-2 review)
1. **Hardware qualification** on the exact dedicated server: CPU/firmware/host+VM2 kernels/QEMU recorded;
   real nested KVM VM2→VM1 boot; browser + immutable deps verified; QMP pause/read/resume ×3 with
   identical same-instant reads; virt hidden from VM1; confirmed destruction; qualify the physical
   actuator + its observation mechanism on that server.
2. **Closed-infra commissioning**: management separation, peer authentication, actual routing/firewall
   state, external lease expiry, reboot quarantine, evidence persistence — before the adversarial harness.
3. **Acceptance vs declared bounds**: A1 egress-cut (delete chokepoint while eval host runs; new AND
   established traffic stops at external receivers; IPv4/IPv6, DNS, alt routes, mgmt bypass); A2
   independent kill (hostd + local guard disabled; controller partition/crash; API timeout handling);
   A4 fencing/recovery (race renew/revoke, replay/reorder, clock skew, restart controller/actuator,
   corrupt state, concurrent runs, delayed reset retries, Terraform recreation — no resurrection / false
   confirmation). Measure host-independent kill latency end-to-end into the containment bound.

## Blocking dependency (needs operator)
The dedicated bare-metal eval host requires **Hetzner Robot webservice credentials** (user/password),
which are SEPARATE from the Cloud API token and are NOT in `.env`. Without them the bare-metal
qualification + two-node acceptance cannot run. The Cloud controller + chokepoint + network + code can
proceed now on the Cloud API token.

## Status (2026-09-13): code-complete, live infrastructure up, A1 passed live; A2/A4 pending

Every Codex start-review must-fix has an implementation. Offline validation: `cargo test --workspace`
= 64 (common 15, controller 7, hostd 3, supervisor 5, evalagent 34); `tests/phase2/offline.sh` =
13 actuator + 13 eval-host hook + 5 observer tests, script syntax checks, and the live skeleton's
mandatory BLOCKED (77) status; `tests/phase2/network_ns.py` is the Linux-only netns egress-cut test.
The whole Phase-2 fleet is x86_64 (controller/evalagent cross-built to `x86_64-unknown-linux-musl`).

- Protocol hardening: `/challenge` + `/defender` SIGNED (common `ChallengeRequest`/`DefenderReport`);
  WireGuard mesh `10.20.0.0/24`, controller bound to the WireGuard interface only.
- Host-independent kill: `infra/hetzner/ds_kill.py` (`ds-kill.sh` wraps it). HONEST semantics after
  the Codex end-review: chokepoint deletion is confirmed via the provider API (`INCOMPLETE` →
  `EGRESS_CUT`); a Robot reset request / ping loss is NOT proof of termination, so `kill` reports
  "physical termination UNCONFIRMED" and quarantines the allocation until an independent hardware
  observer exists. Ambiguous resets are never auto-repeated; journals are fenced to the allocation.
- Chokepoint unavoidable: `infra/hetzner/evalhost-egress.sh` (policy routing + nft; blackhole
  fallback, never the public NIC; conntrack flush on seal) + `chokepoint-forward.sh` (inference only,
  forwarding/NAT disabled — deletion cuts egress AND inference).
- Linux eval host: Phase-1 `hostd` is macOS-only (Lima/pf/launchd), so the bare-metal side is the new
  `crates/evalagent` — fail-closed lease loop on both clocks, signed challenge/evidence heartbeat,
  embedded exact-action proxy, and operator hooks (`infra/hetzner/evalhost/`: boot, seal, destroy,
  observe). Contract: `infra/hetzner/evalhost/README.md`. Physical-resource fencing binds
  DS_SERVER_NUMBER + host boot_id + DS_CHOKEPOINT_ID.
- Scope decision (Jean, 2026-09-13): focused validation — a minimal scripted VM1 inference loop plus
  blocked canaries; Phase-1's accepted A5 (browser agent) is reused, not re-ported to x86.

**Live topology (provisioned 2026-09-13; billing until destroyed):** controller = Hetzner Cloud
`cpx11` (ash); chokepoint = Cloud `cpx31` (ash) hosting ollama `qwen2.5:3b` (DS_MODEL everywhere;
7b does not fit); eval host = dedicated Robot auction box (i7-7700, 64 GB, NVMe, FSN1), Ubuntu 24.04,
nested KVM. The account restriction that blocked EU Cloud locations is why the control plane is in
`ash`. Both earlier blockers (A: Cloud account; B: no dedicated host) are cleared.

**Live results:** full loop works end to end — enroll → epoch-0 lease → seal → epoch-1, signed
evidence heartbeats keep the run Active, nested VM2→VM1 inference is mediated by the host proxy (the
chokepoint logs the host, not the guest, as source). **A1 PASS** — `ds_kill.py cut` deleted the
chokepoint (two-phase, API-confirmed); the eval host lost its next hop with no fallback. Operator
record only until the end-of-phase review.

**Remaining:** A2 (SIGKILL evalagent + guard leaving VM2 up, then `ds_kill.py kill`: confirm
chokepoint gone + Robot hardware reset of the eval host), A4 (live fencing: replay, reorder, second
incarnation, restart), then re-request the formal end-of-Phase-2 Codex verdict (the first end-review
hardened the code but hit its usage cap before stamping APPROVE/REVISE). Recreate the chokepoint via
`terraform apply` if a live inference path is needed again. Phase 3 starts only after that APPROVE.
