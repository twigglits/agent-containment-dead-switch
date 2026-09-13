# Hetzner Robot (dedicated eval host) — out-of-band kill path

No official Terraform provider. Managed via the Robot webservice API (HTTP Basic, the Robot user/pw,
distinct from the Cloud API token). `infra/hetzner/ds_kill.py` uses:

- Power reset: `POST https://robot-ws.your-server.de/reset/<server-number>` with `type=hw`, after
  checking GET `/reset/<server-number>` against the pinned server number/IP and reset capability.
  The [Robot API](https://robot.hetzner.com/doc/webservice/en.html#reset) deprecates the IP form.
- Egress cut: deletion of the pinned Cloud chokepoint server. No Robot firewall mutation is part
  of this actuator. Robot limits are 50 reset requests/hour and 500 reset queries/hour; retry
  spacing and clock floors are persisted before I/O.

Kill sequence (controller-driven, host-independent):
1. Delete the chokepoint Cloud server → eval host egress fails closed. Confirmed only when the Cloud
   API reports the server gone (`INCOMPLETE` → `EGRESS_CUT`).
2. Robot hardware reset of the eval host → VM2 (and VM1 inside it) die with the host.
3. **Honest confirmation:** reset acceptance, ping loss, and API timeouts are NOT proof of physical
   termination. The actuator reports "physical termination UNCONFIRMED" and quarantines the
   allocation (fenced by server number + allocation id) until an independently qualified hardware
   observer exists. Link loss alone is not termination proof. An ambiguous reset is never
   auto-repeated, so a delayed retry cannot strike a later allocation of the same hardware.

The journal has no automatic unlock or reallocation path. Missing initialized state, malformed
JSON, wrong-typed fields, duplicate fields or inconsistent reset flags require reconciliation.
Provider actuation is operator-invoked in the focused Phase-2 profile; automated external expiry
and an independently qualified termination observer remain separate extensions.

Qualification gate before this host is a build baseline (mirrors Phase 1 §9):
- real nested KVM VM boot + vCPU init on the actual CPU,
- QEMU/KVM VM1 boot with no nested virt exposed, pause/`pmemsave`/resume ×3 with identical
  same-instant reads, confirmed kill,
- measured Robot reset latency folded into the containment bound.
