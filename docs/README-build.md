# Dead-switch reference architecture — build (Phase 1 local)

This directory implements the architecture in `../dead-switch-architecture.md` (Option-A-hybrid).
Phase 1 runs the whole loop locally on macOS; Phase 2 (`../infra/terraform/phase2`) moves the
controller and evaluation host to Hetzner. See `phase1-local-host.md` for the full design and the
two Codex reviews it answers.

## Components (Rust workspace, `../crates`)
- `deadswitch-common` — wire protocol v1: signed envelope (ed25519 over sha256, type+audience
  pinned), leases, challenges, host evidence, dual-clock `Deadline`, atomic durable state.
- `deadswitch-controller` — off-host authority: mints runs, issues fail-closed leases, challenges
  hostd for host-rooted evidence, applies the health policy, persists revocation, trips.
- `deadswitch-hostd` — trusted Mac component **below VM2**: lease watchdog (both clocks), pf
  user-gate, VM2 lifecycle (clone/start/destroy+delete, confirmed), host-rooted evidence signer,
  trusted evidence store, inference chokepoint.
- `deadswitch-supervisor` — runs **inside VM2** (untrusted): prestage, VM1 (QEMU) lifecycle,
  exact-action gateway, bounded-authority defender, scoped VMI, fail-closed rung-1 enforcer.

## Trust domains
```
Mac (trusted for isolation/signing/timing/termination)
 ├─ controller (Phase 2: Hetzner cloud VM)
 ├─ hostd (root, launchd) ── pf gate · watchdog · evidence signer · VM2 lifecycle · chokepoint
 │   └─ VM2 (Lima/vz, nested virt, UNTRUSTED) ── supervisor
 │        └─ VM1 (QEMU, ADVERSARY) ── harness + read-only deps, no nested virt, gateway-only net
 └─ ollama (pinned model, reachable only via chokepoint)
```

## One-time setup (needs your sudo password once)
```
sudo bash infra/mac/install-hostd.sh          # service user _deadswitch, pf anchor, sudoers, hostd
sudo /usr/local/sbin/deadswitch-hostd keygen   # prints hostd pubkey -> controller hostd_pubkeys.txt
```
Controller state lives in `~/.deadswitch/controller/` (key, operator token, hostd pubkeys).

## Build
```
cargo build -p deadswitch-controller -p deadswitch-hostd      # native (Mac)
cargo zigbuild --target aarch64-unknown-linux-musl -p deadswitch-supervisor   # for VM2 (Linux)
```

## Provision the base VM2 (once; re-run when the supervisor or VM1 assets change)
```
# assemble payload: supervisor binary + scripts + harness
sudo /usr/local/sbin/deadswitch-hostd provision-base \
     --template $PWD/infra/lima/vm2.yaml --payload /tmp/ds-payload
```

## Run one evaluation
```
# start the controller (background), note its pubkey from the log
deadswitch-controller ...      # env DS_LISTEN/DS_STATE_DIR/DS_KEY_FILE/DS_OPERATOR_TOKEN_FILE/DS_HOSTD_PUBKEYS_FILE
RUN=$(curl -sX POST :7100/runs -H "authorization: Bearer $OP" | jq -r .run_id)   # operator mints
sudo /usr/local/sbin/deadswitch-hostd run --run-id $RUN \
     --controller http://127.0.0.1:7100 --controller-pubkey $CTL_PUB \
     --model qwen2.5:7b --ollama http://127.0.0.1:11434 --template $PWD/infra/lima/vm2.yaml
```
`hostd run` clones the base, enrolls, gets a prestage lease (gate open), builds the immutable deps
image, seals the gate, gets the eval lease, boots VM1, runs the harness (adversarial replay by
default), takes a VMI baseline, and holds the run until the lease is revoked / evidence trips / it
finishes — then cuts egress and destroys VM2 (deleting its disks), confirmed.

## What the acceptance tests exercise
`docs/phase1-local-host.md` §14 (v2). The demonstration already validated on this Mac:
- pf user-gate seals VM2 egress (DNS, ICMP, TCP) while preserving the VM2→hostd path (§13);
- the full dead-switch loop fires and destroys VM2 in ~0.1 s once tripped;
- nested QEMU VM1 boots, is measured via pmemsave, and is killed cleanly (§9).
