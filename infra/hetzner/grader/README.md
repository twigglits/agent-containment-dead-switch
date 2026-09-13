# Phase 3 grader deployment and hook contract

This directory is an operator-deployed reference backend. No images were fetched or built, no node
was provisioned, and no live containment claim is made by the offline suite. Deploy the Rust grader
on the separate `10.20.0.4` node. The submitting evaluation must already be terminal before the
controller dispatches; the submitting agent never receives downstream grading information.

## Host prerequisites and trust boundary

Use Linux with cgroup v2, systemd supporting transient `Type=exec` services, QEMU x86 TCG with seccomp,
`qemu-img`, GNU `timeout`, util-linux `setpriv`, Python 3, nftables, conntrack, iproute2 and WireGuard.
Hooks fail closed if these prerequisites or trusted observations are unavailable. They do not silently
fall back to KVM, a container, an unsupervised process or a network-enabled guest.

Install the hooks and `launcher.py` together under `/opt/deadswitch-grader/hooks`, root-owned with
no ancestor writable by another user. Shell hooks must be executable. Install the grader binary at
`/usr/local/bin/deadswitch-grader`. Its required service name is **`deadswitch-grader.service`**;
the supplied unit uses `Type=exec`, not `oneshot` or an unready `notify` service.

Create a dedicated **`deadswitch-qemu`** uid/gid with no login, memberships, credentials or other
services. Set its actual numeric IDs in the root-only mode0600
`/etc/deadswitch-grader/launcher.json`, starting from `launcher.example.json`.
Create the two separate launcher directories:

| Path (default example) | Ownership/mode | Contents |
| --- | --- | --- |
| `/var/lib/deadswitch-grader-launcher` | root:root 0700 | durable hook claims and lifecycle records |
| `/var/lib/deadswitch-grader-sandboxes` | root:root 0711 | root-owned per-job 0711 directories; QEMU-owned 0600 overlay and root-owned 0444 fixed input archive |
| `/var/lib/deadswitch-grader` | root:root 0700 | initialized Rust authority ledger and temporary root-only job files |
| `/etc/deadswitch-grader` | root:root 0700 | scorer key, controller public key configuration, expected output and launcher config |

The sandbox directory permits traversal so the dedicated QEMU uid can open its known overlay; it
cannot list other job directories or create/replace root-owned entries. The separate journal and
Rust job directory are inaccessible to that uid. The host root supervisor is trusted and key-capable;
its QEMU child drops uid/gid, supplementary groups and all capabilities, enables no-new-privileges,
and runs with QEMU seccomp. No submitted code is executed or imported by any host Python or Rust
process. The untrusted program executes only inside the VM. Protect all host logs as operator data.

Build/review a small bootable **raw x86_64 image offline** with BusyBox `sh`, `tar`, `mount`, `poweroff`,
virtio block/console drivers and the `fixture/guest-runner.sh` boot runner. It needs `/run/candidate`
and the virtio-port device path available before running. Install it root-owned and read-only (0444)
at `/opt/deadswitch-grader/base.raw`, with its SHA-256 in `launcher.json`. Never put the expected
output, scorer key, provider credentials, canaries, cloud-init credentials or host mounts in this
base. The guest's root disk is always a fresh qcow2 overlay backed by that pinned raw image. No
shared writable cache, seed with credentials, guest networking, host filesystem share, monitor or
QMP endpoint is exposed. Keep the base image's directory ancestry root-owned and traversable by
the dedicated QEMU uid (0711 or 0755); the private scorer/config directory remains 0700.

The tiny fixture uses task `tiny-sum`, input version `1`, scorer version `1`, input bytes `17 25\n`
and expected bytes `42\n`. Install `fixture/expected-output.bin` only on the trusted host as
`/etc/deadswitch-grader/expected-output.bin`, root-owned **0400**. It is a public toy fixture suitable
for proving separation and deterministic comparisons, not a secret real benchmark corpus. The good,
wrong and forged-PASS files are candidate examples; send their bytes through the upload broker.
The root scorer compares exact captured bytes with the host-only expectation and never interprets
guest PASS strings, JSON reports or candidate exit status as grading authority.

Generate the scorer key on the trusted host with `deadswitch-grader keygen --out
/etc/deadswitch-grader/scorer.key`, protect it as root-only 0400/0600 and enroll only its public key
on the controller. Install `grader.example.env` as the root-only `grader.env`, replace the controller
public key and initialize the fresh ledger with `deadswitch-grader init` using the same identity
arguments/environment. **Never reinitialize lost/corrupt production authority.** Do not place Cloud
API credentials on the grader; the separate deletion actuator runs on the controller.

## Exact application and WireGuard contract

| Direction | Endpoint | Payload |
| --- | --- | --- |
| Controller `10.20.0.1` → grader `10.20.0.4` | TCP7200 `POST /dispatch` | bounded framed controller-signed job JSON plus opaque submission bytes outside the signature envelope |
| Grader `10.20.0.4` → controller `10.20.0.1` | TCP7201 `POST /results` | bounded scorer-signed typed result JSON only |
| Operator over controller SSH | controller TCP7101 | protected result reads; unavailable to grader and agents |

The grader has exactly one WG peer: controller public key, controller public endpoint UDP51820,
`AllowedIPs = 10.20.0.1/32`. Controller adds the grader public key/endpoint with
`AllowedIPs = 10.20.0.4/32`. No other peer lists the grader. No `/24`, `0.0.0.0/0`, mesh transit or
IPv6 peer route is authorized. Keep both public WG endpoint ports at 51820 for the exact firewall
tuple. WG keys stay on the host, never in the guest.

On the grader set `PUBLIC_IFACE`, `OPERATOR_CIDR` (not `/0`), `CTRL_PUBLIC_IP`, `NTP_IP` (one fixed
IPv4) and optionally `WG_IF=wg0`, then use `airlock.sh render sealed` to review. Apply `airlock.sh
seal` **before** starting the grader service or any candidate. Application ports and mesh addresses
are fixed and cannot be overridden. The atomic apply installs CUT first, disables forwarding,
refuses flow offload, pins controller `/32` routing in table103 behind an unreachable default and
terminal RPDB rule, verifies conntrack deletion by a successful empty read, then seals.
Any fallible intermediate step leaves application traffic cut. Management SSH/WG/NTP tuples remain.

Input permits only controller→7200, established replies to the grader's own →controller7201,
public operator SSH, the pinned public WG tuple and established NTP replies. Output permits only
→controller7201, established replies for inbound controller7200, operator SSH replies, the pinned
WG tuple and fixed NTP. Forward is drop. There is no generic established/related allowance, DNS,
metadata, IPv6 or loopback exemption. WG disappearance cannot reroute application traffic publicly.
Do not add broad established rules during deployment.

On the controller review/apply `controller-guard.sh`. It adds a separate table with exact grader
result input and dispatch-reply input, exact dispatch output and result-reply output, and explicit
drops for every other grader-originated/destined flow and transit. It does not flush or replace
Phase-1/2 tables. Its accepts **do not override a later base-chain drop**: if the controller already
defaults to drop, add these same exact tuples to that existing policy. Never permit grader access
to hostd7100 or operator7101. Verify the installed kernel rules and `/32` peers during G4.

TCP is bidirectional; this is not a hardware data diode. The controller's trusted upload broker
terminates the agent socket independently, stores bounded bytes before a fixed typed ACK and does
not relay grader responses, status, errors or backpressure. Dispatch ACKs and the result endpoint's
reply are fixed transport acknowledgements. Signed typed results and private storage are the
information-flow enforcement boundary; nft is a backstop.

## Synchronous hook ABI

The Rust daemon executes the absolute hook paths without shell interpolation and with a cleared
environment. Job hooks receive these strings; neither candidate bytes nor any secret is in argv/env:

| Variable | Required value |
| --- | --- |
| `DS_JOB_ID` | bounded `[A-Za-z0-9_-]{1,128}` controller-assigned ID |
| `DS_SANDBOX_ID` | fresh 32 lowercase hex characters |
| `DS_SUBMISSION_DIGEST` | exact 64 lowercase hex SHA-256 |
| `DS_TASK_ID`, `DS_INPUT_VERSION`, `DS_SCORER_VERSION` | `tiny-sum`, `1`, `1` |
| `DS_JOB_DIR` | root-only absolute private Rust job directory |
| `DS_SUBMISSION_PATH` | root-owned read-only `${DS_JOB_DIR}/submission.bin`, 1–65536 bytes |
| `DS_CAPTURE_PATH` | exactly `${DS_JOB_DIR}/capture.bin`; created only by trusted supervisor, mode0400, ≤4096 bytes |
| `DS_JOB_EXPIRES_AT` | positive integer Unix seconds, immutable job expiry |
| `DS_WALL_TIMEOUT_SECS` | pinned per-job positive integer ≤90; identical for launch/observe |

All hooks load the fixed root-only `/etc/deadswitch-grader/launcher.json`; no config-path environment
override exists. JSON responses are bounded by the Rust caller to 4096 bytes. Booleans and integers
must be correctly typed. Any command error, missing observation, malformed response, timeout or
unconfirmed cleanup causes no result release and quarantine.

`launch.sh` is synchronous. Before side effects it durably creates an exclusive one-shot claim.
It checks the immutable base digest and recomputes the submitted byte digest; builds a fixed tar
block input containing only `submission.bin` and `input.txt`; creates a fresh overlay; then starts
`ds-grader-sandbox-<sandbox_id>.service` in `dsgrader.slice`. That service binds to and orders after
`deadswitch-grader.service`, has `RuntimeMaxSec`, `KillMode=control-group`, `Restart=no`, private
network/devices/tmp, read-only host/cgroup protection, memory/task bounds and an additional GNU
timeout. The root supervisor launches unprivileged QEMU with `q35,accel=tcg`, bounded `-m`/`-smp`,
`-net none`, read-only input block and a virtio-serial `stdio` backend. It owns the bounded read
pipe; QEMU stdin is `/dev/null`, and stderr is discarded. The guest can write candidate bytes only.

After host-observed normal QEMU termination and durable capture, launch returns:

```json
{"sandbox_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","launched_artifact_digest":"<64hex>","started":true,"exited":true,"timed_out":false,"started_at":123,"exited_at":124}
```

Timeout/crash/overflow returns nonzero, never a fabricated successful lifecycle. A guest's orderly
poweroff is just the end of execution; its output still has to match the trusted expectation.

`observe.sh` requires that same completed claim and positive inactive unit observation, verifies the
root-owned immutable captured file, durably freezes the trusted lifecycle record, and returns the
launch fields plus `"frozen":true`, `"captured_output_digest":"<64hex>"`, `"capture_bytes":3`.
It returns no path or free-text candidate field. Re-observation of an already frozen claim fails.

`destroy.sh` works independently of job expiry. It stops the exact pinned systemd unit, requires
complete manager observations and an absent/empty cgroup-v2 subtree, then removes disposable storage
with symlink-safe deletion and checks absence. It never kills a saved PID or mistakes a stopped
hook, timeout, `systemctl stop` acceptance or empty stdout for proof. It returns:

```json
{"sandbox_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","processes_gone":true,"storage_gone":true,"teardown_confirmed_at":125}
```

`storage_gone` covers the overlay and per-job input archive. The protected frozen capture/ledger are
trusted evidence, not a shared sandbox disk; Rust removes the temporary capture after freezing it
in memory and confirming destruction, before signing/publishing. Hook terminal records persist to
prevent reuse. No ambiguous claim is ever relaunched. Restart cleanup does not grade anything.

`destroy-all.sh` takes no job variables. Rust calls it under its durable service lock before
readiness, including after ambiguous startup. It reconciles matching systemd units, disposable
directories and private hook claims, attempts every known teardown even when one fails, and
returns only after positive cleanup:

```json
{"processes_gone":true,"storage_gone":true,"teardown_confirmed_at":125}
```

Already destroyed journal records are schema-checked without a per-record systemctl call. Missing,
corrupt or unknown state prevents service readiness. An abnormal backlog can exceed the 15-second
Rust cleanup bound; that remains quarantined for operator reconciliation. Never delete claims to
restore authority, and never reset a server allocation automatically.

## Independent grader-node deletion

Run `../ds-grader-kill.py kill` as root **on the controller**, with `ds_kill.py` beside it. It reuses
that transport's HTTPS-only, no-proxy/no-redirect, bounded curl requests and private fsync journals.
Required environment: `DS_RUN_ID`, `DS_INCARNATION`, `DS_ALLOCATION_ID`,
`DS_GRADER_SERVER_ID` (the grader's numeric Cloud ID, never the chokepoint ID), `DS_FENCING_TOKEN`
(positive u64). Cloud token comes from the existing private `DS_ENV_FILE`/`HETZNER_API_KEY` contract.
Its separate journal defaults to `/var/lib/deadswitch/grader-actuator` (override only by trusted
operator `DS_GRADER_ACTUATOR_STATE_DIR`).

The per-server lock pins the allocation and incarnation, advances durable fencing, and records
quarantine/deletion intent **before** DELETE. The first invocation does a target-matching GET and
at most one DELETE. A later invocation must positively observe HTTP404 for that exact Cloud server
ID. Accepted deletion/actions, timeouts, transport errors and ping loss remain INCOMPLETE. After
ambiguous DELETE, only confirmation GETs are attempted; no automatic second delete or reallocation.
Exit0 means provider absence confirmed, exit1 means unconfirmed/quarantined, exit3 means invalid or
unavailable authority/configuration. Even confirmed deleted allocations remain permanently retired.

## Verification and remaining live work

`tests/phase3/offline.sh` runs local Rust/Python regressions and shell syntax checks. Python tests use
actual bounded pipes and temporary state with mocked systemd/cgroup/provider operations. Firewall
tests evaluate rendered packet tuples and simulate failed apply steps; they are not Linux kernel
packet tests. The suite verifies separation of code/data, freeze/teardown ordering, durable claims,
timeout/overflow/crash rejection, packet restrictions and honest actuator uncertainty.

`tests/phase3/acceptance.sh [all|G1|G2|G3|G4|G5]` always exits **77 (BLOCKED)** until real trusted live
scenario drivers are implemented and the node is commissioned. Readiness flags or supplied PASS
strings cannot bypass that gate. The printed checklist explicitly requires good/wrong positive
controls, reconciled execution/result counts, actual sandbox/secret-canary inspection, encoded
leakage and all egress paths, complete agent response/timing captures, replay/concurrency, poison-A
and fresh-B, timeout/crash/partition/actuator failure/restart and independent teardown observations.
The current scaffold performs zero live assertions. QEMU/systemd/nft behavior, image device ordering
and real Cloud deletion confirmation must still be qualified on the operator-deployed Linux node.

Reference semantics were checked against the official [QEMU invocation manual](https://www.qemu.org/docs/master/system/qemu-manpage.html),
[systemd unit dependencies](https://github.com/systemd/systemd/blob/main/man/systemd.unit.xml),
[systemd service runtime limits](https://github.com/systemd/systemd/blob/main/man/systemd.service.xml),
[systemd cgroup ownership](https://systemd.io/CGROUP_DELEGATION/) and
[Hetzner Cloud API](https://docs.hetzner.cloud/reference/cloud). These docs explain primitives;
offline tests do not constitute proof of a deployed host's configuration.
