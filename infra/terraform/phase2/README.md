# Phase 2 — Hetzner topology

Decided with Jean 2026-09-12 after Codex confirmed Hetzner **Cloud** has no nested virtualization.
Current status and live results: `../../../docs/phase2-plan.md`.

- **Controller**: Hetzner Cloud VM (`hcloud`). Runs `deadswitch-controller` bound to the WireGuard
  interface only. Holds the operator token and the actuator credentials. The trusted, independent node.
- **Chokepoint**: a small Cloud VM the eval host must route workload egress through. It hosts the
  pinned inference backend and does **no** forwarding/NAT, so deleting it fails both egress and
  inference closed.
- **Evaluation host**: Hetzner **dedicated** server (Robot), nested KVM. Runs `deadswitch-evalagent`
  below VM2 (KVM) → nested QEMU/KVM VM1 (`-cpu host,-vmx`, no nested virt to VM1). Phase-1 `hostd`
  is macOS-only and is not used here. Egress/gate contract: `../../hetzner/evalhost/README.md`.
- **Out-of-band kill** (host-independent because it runs from a different machine): delete the
  chokepoint, then Robot hardware reset of the dedicated server — `../../hetzner/ds_kill.py`, see
  `robot.md` for the honest-confirmation semantics.

## Why Terraform/OpenTofu split
Hetzner Cloud has a first-class provider (`hetznercloud/hcloud`). Hetzner **Robot** (dedicated) has
no official Terraform provider; dedicated servers are ordered out-of-band, then managed via the
Robot API. So Terraform provisions the Cloud pieces (controller, chokepoint, firewalls, network),
and `ds_kill.py` drives Robot for the physical kill. This file documents that boundary so we do not
pretend Terraform owns the bare-metal lifecycle. A Terraform replacement generates a fresh local
WireGuard key and installs no peers or inference service. Restoring an authorized path requires
explicit operator commissioning; `apply` alone must not restore one after a runtime deletion.

## Status
`main.tf` stands up the CONTROLLER + CHOKEPOINT + network + cloud firewall only. State is local and
gitignored (`*.tfstate*`); keep it private and backed up. Supply `TF_VAR_hcloud_token` for the
required `hcloud_token` variable and a verified immutable x86_64 image ID for the CPX fleet.

The controller ticker revokes lease authority. Provider cut/reset is a separate operator action
in the focused demonstration; an automatic external expiry daemon and a qualified hardware
termination observer remain outside this profile. See the [end-of-phase review](../../../docs/phase2-review-2026-09-13.md).
