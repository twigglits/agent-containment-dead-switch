# Hetzner Robot (dedicated eval host) — out-of-band kill path

No official Terraform provider. Managed via the Robot webservice API (HTTP Basic, the Robot user/pw,
distinct from the Cloud API token). `hostd`/ops uses:

- Power reset (out-of-band kill): `POST https://robot-ws.your-server.de/reset/<server-ip>` `type=hw`.
- Stateless ingress firewall: `POST .../firewall/<server-ip>` with a deny-by-default ruleset.
  Note (Codex N9): Robot firewall changes do not tear down established connections and there are
  infrastructure-service exceptions; the *authoritative* egress cut is deleting the Cloud chokepoint
  server (fails closed when the controller cannot reach it), with the Robot firewall as a second layer.

Kill sequence (controller-driven, host-independent):
1. Delete the chokepoint Cloud server  -> eval host egress fails closed.
2. Robot hardware reset of the eval host -> VM2 (and VM1 inside it) die with the host.
3. Confirm: Robot `GET /reset/<ip>` + server no longer answering; only then report `terminated`.

Qualification gate before this host is a build baseline (mirrors Phase 1 §9):
- real nested KVM VM boot + vCPU init on the actual CPU,
- Firecracker VM1 boot + pause/snapshot/resume x3 + confirmed kill,
- measured Robot reset latency folded into the containment bound.
