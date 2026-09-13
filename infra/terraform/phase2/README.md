# Phase 2 — Hetzner topology (planned; not a build baseline until qualified)

Decided with Jean 2026-09-12 after Codex confirmed Hetzner **Cloud** has no nested virtualization.

- **Controller**: Hetzner Cloud VM (`hcloud`), location A. Runs `deadswitch-controller`. Holds the
  operator token and the Robot credential. This is the trusted, independent node.
- **Evaluation host**: Hetzner **dedicated** server (Robot API), location B, with nested KVM. Runs
  `deadswitch-hostd` below VM2; VM2 is a KVM guest; VM1 is Firecracker inside VM2. Real host-side VMI
  below VM2 lives here (bare metal we own) — restores spec decision 6/7.
- **Out-of-band kill** (host-independent, because it is a different machine from the controller):
  1. Robot API power-off / reset of the dedicated server.
  2. Robot stateless firewall (ingress) + an egress **chokepoint** the controller can *delete*.
- **Chokepoint**: a small Cloud VM the eval host must route egress through; deleting it fails closed.

## Why Terraform/OpenTofu split
Hetzner Cloud has a first-class provider (`hetznercloud/hcloud`). Hetzner **Robot** (dedicated) has
no official Terraform provider; dedicated servers are ordered out-of-band, then managed via the
Robot API. So Terraform provisions the Cloud pieces (controller, chokepoint, firewalls, network),
and `hostd`/an ops script drives Robot for the physical kill. This file documents that boundary so
we do not pretend Terraform owns the bare-metal lifecycle.

## Status
`main.tf` stands up the CONTROLLER + CHOKEPOINT + network + cloud firewall only. The dedicated
eval host and its Robot kill path are stubbed in `robot.md` and gated behind the qualification run
(nested KVM boot + Firecracker snapshot on that exact hardware) — same gate Phase 1 used locally.
