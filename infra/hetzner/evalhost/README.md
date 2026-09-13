# Phase-2 Linux eval host: exact-action proxy and nested workload

`deadswitch-evalagent` embeds the inference proxy in its own process. The agent's lease loop owns
its dispatch authority; the proxy runs on an independent Tokio runtime so a blocked controller call
or shell hook cannot extend an expired lease. This avoids a second process, shared authorization
files, or guest-controlled IPC. The request validation and native request/response mapping are
shared with Phase-1's supervisor gateway and hostd in `deadswitch_common::inference`.

## Network and inference contract

```text
VM1 (nested QEMU usernet)
  -> VM2 10.99.0.2 (pure-L3 dstap0; default gateway 10.99.0.1)
  -> evalagent proxy 10.99.0.1:7001 POST /v1/chat/completions
  -> HOST-originated 10.20.0.3 -> wg0 -> 10.20.0.2:11434 POST /api/chat
```

VM2 cannot reach the raw backend, the controller, host management ports, public destinations, DNS,
or IPv6 destinations through the host. The host does **not** forward or NAT guest packets to the
chokepoint. VM1's QEMU usernet runs inside VM2, so its uplink traffic appears as `DS_VM2_IP` at the
eval host. The proxy admits only that peer IPv4 on `HOSTD_IP:7001`.

The one permitted action is an exact `POST /v1/chat/completions` without a query string or alternate
endpoint, with a JSON object of at most 65,536 bytes:

- `model` must equal `DS_MODEL` (default `qwen2.5:7b`).
- `messages` must be a nonempty array; every message has a known role (`system`, `user`, `assistant`,
  or `tool`) and string `content`.
- `stream` is absent or `false`; `n` is absent or integer `1`.
- `max_tokens` is an integer in `[1, 1024]`, defaulting to `512` when absent. Zero is refused
  because Ollama runners can interpret `num_predict:0` as unlimited generation.
- `tools`, `functions`, `tool_choice`, `function_call`, and `response_format` are rejected, including
  empty values. Other fields never reach the native backend: the proxy constructs fresh JSON with
  only the pinned model, sanitized messages, `stream:false`, and
  `options:{num_ctx:4096,num_predict:<bounded max_tokens>}`.

The proxy serializes backend inference and uses a fresh TCP connection per operation
(`pool_max_idle_per_host(0)`, HTTP/1, connection close). It does not use environment HTTP proxies,
DNS, redirects, or automatic retries. The backend destination and both ports are fixed by the
contract; the backend IP is configurable. Responses use the Phase-1 OpenAI `chat.completion` shape.
Dispatch and response delivery require a currently valid lease on both clocks, a sealed gate, and
an evaluation epoch of at least 1. Startup/prestage authority does not permit inference. Lease
loss, Denied, SIGINT/SIGTERM, or gate invalidation revokes dispatch and cancels active work; a late
backend response is withheld. Proxy `ChokepointObs` counters are logged by the agent.

The pre-staged VM1 loop submits this small action using a new curl process each time:

```json
{"model":"qwen2.5:7b","messages":[{"role":"user","content":"Reply with exactly OK."}],"stream":false,"n":1,"max_tokens":16}
```

It also attempts raw `10.20.0.2:11434/api/version` and public `1.1.1.1` canaries, which must remain
blocked. `proxy=200` requires a running backend with the pinned model installed. The live target is
`10.20.0.2:11434`; an absent backend produces a failed inference, with no fallback.

## Gate and lifecycle hooks

| Agent environment | Hook | Behavior |
|---|---|---|
| `DS_BOOT_CMD` | `bash /path/to/evalhost/vm2-boot.sh` | Install CUT first, configure the L3 tap, launch VM2; refuse an existing live VM2. The agent then binds its proxy to the tap. |
| `DS_SEAL_CMD` | `bash /path/to/evalhost/gate-seal.sh seal` | Canonical deny-before-allow seal; checked conntrack flush and policy routes. |
| `DS_DESTROY_CMD` | `bash /path/to/evalhost/vm2-destroy.sh` | Attempt CUT and SIGKILL VM2; report failure if either CUT or death is unconfirmed. VM1 dies with VM2. |
| `DS_OBSERVE_CMD` | `bash /path/to/evalhost/vm2-observe.sh` | Host process, QEMU configuration and KVM observations: `running`, `pid`, `nested_virt`, `port_forwards`, `writable_mounts`. Install `vm2-observe.py` alongside the shell wrapper. |

`gate-seal.sh` is a configuration adapter around `../evalhost-egress.sh`, the single source of the
nft/routing policy. Install that helper alongside the `evalhost/` directory. `network-config.sh`
normalizes legacy and canonical environment names and refuses conflicting values before any
mutation. A successful `seal` grants only guest→`HOSTD_IP:7001` and host→chokepoint TCP 11434,
in addition to explicit host management tuples. `cut` removes both inference allowances. Both
operations first atomically install CUT, disable IPv4/IPv6 forwarding, reject bridged workload
interfaces and flow offload, install the marked backend `/32` route with unreachable table and
terminal-rule fallbacks, and flush/check workload and backend conntrack entries. A fallible step
cannot install SEALED. There is no `open` operation.

The adapter does not remove a legacy `ds_gate` table. Its old forwarding/NAT allowances cannot
override the canonical `ds_egress` forward-drop policy. Host management is allowed only for the
specified SSH source CIDR, WireGuard peer endpoints, fixed NTP address, and controller TCP 7100.

## Configuration

Use the same settings when building the images and running evalagent. The agent passes its resolved
proxy addresses, peer address, and model to its hooks, including CLI overrides. Changing the pinned
model or runtime VM2 address requires rebuilding the baked workload/network configuration.

| Setting | Default | Meaning |
|---|---|---|
| `HOSTD_IP` / `DS_WL_HOST_IP` | `10.99.0.1` | Host tap address and proxy bind address; TCP **7001**. |
| `DS_VM2_IP` | `10.99.0.2` | Runtime VM2 address and sole admitted proxy peer. |
| `DS_MODEL` | `qwen2.5:7b` | Pinned model in the agent and baked VM1 request. |
| `DS_CHOKE_WGIP` / `CHOKE_WGIP` | `10.20.0.2` | Backend IPv4; TCP **11434**, native `/api/chat`. |
| `DS_TAP` / `WORKLOAD_IFACE` | `dstap0` | Dedicated unbridged host tap. |
| `DS_WL_SUBNET` / `WORKLOAD_SRC` | `10.99.0.0/24` | Workload network; both host and VM2 must be distinct host addresses in it. |
| `DS_WG_IF` / `WG_IF` | `wg0` | Host backend/management WireGuard interface. |
| `DS_EVAL_WGIP` / `EVAL_WGIP` | `10.20.0.3` | Eval host's WireGuard IPv4. |
| `DS_CTRL_WGIP` / `CTRL_WGIP` | `10.20.0.1` | Controller's WireGuard IPv4; TCP 7100. |
| `DS_VM2_DIR` | `/var/lib/deadswitch/vm2` | VM image, pidfile, serial logs. |

`DS_OLLAMA_PORT`, if present, must equal `11434`. Conflicting aliases, empty settings, invalid IPs,
and a backend inside the workload subnet are refused. Use `DS_CONTROLLER_URL=http://10.20.0.1:7100`
for this topology; the gate must match any configured controller address.

The following management values are **required** for gate render/apply and runtime boot/destroy;
there are no guessed public addresses or permissive defaults:

| Setting | Required value |
|---|---|
| `PUBLIC_IFACE` | Dedicated eval host's public management NIC. |
| `OPERATOR_CIDR` | Operator's IPv4 SSH source CIDR (not `0.0.0.0/0`). |
| `CTRL_PUBLIC_IP` | Controller's public WireGuard endpoint IPv4. |
| `CHOKE_PUBLIC_IP` | Chokepoint's public WireGuard endpoint IPv4. |
| `NTP_IP` | Fixed trusted NTP server IPv4. |

Keep the existing agent identity/lease settings: `DS_RUN_ID`, `DS_KEY_FILE`,
`DS_CONTROLLER_PUBKEY`, `DS_INCARNATION`, `DS_VM2_TEMPLATE_DIGEST`, `DS_VM2_BASE_DIGEST`, and optionally
`DS_LEASE_RENEW_INTERVAL_S` (default 5; accepted range 1–9 seconds). Digests and incarnation must describe the image/run being
launched. `deadswitch-evalagent run --help` lists the complete CLI.

After every accepted lease, including epoch 0, the agent requests a signed `/challenge`, verifies
the controller key, audience, run, incarnation, epoch and freshness, then sends signed
`HostEvidence` to `/evidence` with that nonce. Evidence includes the enrolled digests, current gate
(CUT before sealing), current lease token/time remaining, and proxy counters. Each heartbeat HTTP
request has a 2-second timeout. A nonce is never resent after an evidence POST attempt; a lost
reply could mean it was already consumed. HTTP 429 backs off for half a challenge TTL (5 seconds),
with attempts still driven by lease ticks and no rapid polling of a live nonce.

The controller trips after `CHALLENGE_TTL_S * MISSED_CHALLENGES_TO_TRIP` = 30 seconds without valid
evidence. A separate local evidence deadline expires after 20 seconds, measured from startup or
the send instant of the last acknowledged healthy evidence. Lease renewals and transient errors
cannot extend it. The independent proxy runtime observes that deadline even during blocked hooks
or HTTP calls, revokes authority and cancels inference. The lease loop uses the existing
seal/destroy cleanup on expiry, unhealthy/tripped verdicts, conflicts, or signed orders. Hook
completion still governs how soon shell cleanup finishes, as with lease expiry.

The observe hook recognizes `vm2-boot.sh`'s QEMU profile using the host's process command line and
KVM nested parameter. It pins the workload tap, disk, file-only serial output, disabled display,
and pidfile; TCP serial/monitor/display backends and foreign taps are unobservable. Unknown
configuration or unreadable fields remain null; the controller
requires positively observed `running=true`, `nested_virt=true`, `port_forwards=0`, and
`writable_mounts=0`. Custom observe hooks must supply these fields too. Enrollment digests remain
operator-supplied, and gate state follows successful hook transitions; these are not independent
measurements of disk contents or kernel firewall rules.

## Image preparation and local checks

`vm2-build.sh` is a one-time **operator-run** image build on an idle x86_64 Linux machine with nested
KVM and build-time internet. It requires QEMU, `qemu-img`, `cloud-localds`, curl, Python 3, GNU
`timeout`, and root; runtime additionally requires nftables, iproute2, conntrack, procps, and util-linux
(`setsid`). It does not open the runtime gate. Build both guest images before starting containment.

During preparation, VM2 uses QEMU usernet/DHCP to install dependencies and provision VM1 under
nested KVM. VM1 installs curl and enables its workload service for the next boot. After all fetches
and the nested build pass, VM2 stages static netplan for its fixed runtime MAC/address without
applying it to the provisioning connection. Both images disable subsequent cloud-init execution;
runtime needs neither a seed ISO nor package/image downloads. VM2 launches VM1 with `-cpu host,-vmx`,
so VM1 receives no further nested virtualization. Build QEMU failure, timeout, or missing success
markers fails the build.

Local checks require no root, networking changes, QEMU execution, or live access:

```bash
for hook in infra/hetzner/evalhost/*.sh infra/hetzner/evalhost-egress.sh; do bash -n "$hook"; done
python3 -m unittest discover -s tests/phase2 -p 'test_evalhost*.py' -v
```

The hook regressions compare canonical/adapter rules, verify config rejection, CUT-before-boot,
conntrack failure behavior, and teardown failure reporting, and inspect generated cloud-init and
workload scripts using harmless command stubs. Linux kernel packet enforcement, nested KVM/image
boot, WireGuard transport, and deletion of the live chokepoint still require operator validation.
Signed heartbeats and hook transitions do not establish complete kernel gate attestation. These
local checks do not claim Phase-2 acceptance or deployment.
