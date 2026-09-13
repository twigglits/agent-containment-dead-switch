# End-of-Phase-2 review — 2026-09-13

**VERDICT: APPROVE-PHASE-2** for Jean's operator-approved focused validation: A1, A2, A4 and
exact-action mediated inference, with Phase-1's accepted A5 reused. This verdict applies to the
reviewed working tree after the fixes below. There are no remaining must-fixes within that scope.

The live acceptance evidence is Jean's supplied 2026-09-13 operator record. This review inspected
the implementation and reran local verification; it did not repeat provider deletion/reset,
redeploy the fixes, or independently reproduce the live run. Earlier pending/blocker statements in
the Phase-2 plan are historical relative to this supplied acceptance record.

| Accepted property | Evidence and implementation assessment |
|---|---|
| Positive path and mediation | Nested VM2→VM1 executed; the workload used `10.99.0.1:7001`, and the chokepoint logged successful native inference sourced from the eval host `10.20.0.3`. The host drops all guest forwarding; only its exact-action proxy originates backend requests. |
| A1: deletion cuts egress | The off-host actuator first returned INCOMPLETE, then EGRESS_CUT after GET→404. The eval host lost `10.20.0.2` with no workload fallback. Marked backend routing has unreachable table/rule fallbacks, and nft requires the exact WireGuard interface, source, destination and backend port. |
| A2: host-independent kill | With evalagent SIGKILLed and VM2 orphaned, the off-host actuator requested a Robot hardware reset. The operator observed a fresh host boot and loss of VM2/VM1. The controller tripped on missing evidence; the actuator correctly retained physical termination UNCONFIRMED and quarantine. |
| A4: fencing | Rust regressions cover signed run/incarnation/epoch/token binding, replay and clock handling, terminal expiry and evidence loss, and queued/in-flight cancellation. Python regressions cover durable physical-allocation fencing, ambiguous resets, backoff, corrupt journals and provider response handling. |

The inspected fleet is the reported x86_64 CPX11 controller and CPX31 chokepoint in `ash`, with
the i7-7700 dedicated eval host in `fsn1`. WireGuard peers are pinned to individual `/32` addresses;
operator control stays behind SSH and a loopback operator API.

**Defects fixed during review**

1. **Zero disabled the generation bound on affected Ollama runners.** `max_tokens:0` previously
   became `options.num_predict:0`. Ollama runners that enforce the limit only when it is positive
   treat this as unbounded; see the [upstream runner condition](https://github.com/ollama/ollama/blob/v0.11.10/runner/llamarunner/runner.go#L361-L364).
   Shared validation now requires an integer in `[1,1024]` and retains the default of 512. Common
   and proxy regressions cover zero rejection before backend connection; the Phase-1 gateway's
   shared-validation expectations were updated. This tightens both profiles.
2. **Parseable corrupt actuator state could grant false authority.** For example, the string
   `"false"` in `egress_cut` was truthy. Journal loading now checks exact fields/types, bounded
   counters, duplicate keys, file size, allocation identity and reset consistency before any
   update or provider dispatch. The corruption regressions failed before this fix and now pass.
3. **The VM observer accepted alternate I/O backends as healthy.** It now requires the configured
   tap, expected disk/pidfile/file-only serial output and disabled display. TCP serial/monitor or
   display backends and foreign taps remain unknown and fail controller policy. The new drift
   regressions failed before the fix and pass afterward; configured custom taps remain supported.
4. **Teardown trusted stale PIDs and could confuse an observation error with absence.** It now
   signals the supported QEMU launch profile, never an unchecked pidfile target. A still-live or
   invalid pidfile and any failed process query produce UNCONFIRMED and retain quarantine. Tests
   verify that an unrelated process referenced by a recycled pidfile survives and that a failed
   query cannot produce a successful destruction claim.

The controller deployment default now matches the x86_64 fleet. Related Terraform/Robot notes
were corrected for image architecture, credentials, explicit peer commissioning and honest reset
semantics. Concurrent edits to other project documents were preserved and are not claimed as work
performed by this review.

**Containment assessment after fixes**

Inference admits only the exact POST path, with no query or alternate raw endpoint. Input is
bounded at 65,536 bytes; model equality, known message roles/string content, single nonstreamed
completion and positive generation limits are enforced. Fresh native JSON discards extension and
case-folding bypass fields and fixes `num_ctx` to 4096. Backend concurrency is one; admitted work
and connections are capped. Native responses, including chunked bodies, are byte-bounded. Neither
environment proxies, DNS endpoint resolution, redirects, automatic retries nor pooled HTTP
connections can introduce a second dispatch path.

The in-process authority fences admission, dispatch, queued work and response delivery. Gate
generation changes invalidate prior tickets, including across cut/reseal. Lease expiry on either
clock, received Denied, signal shutdown and missing acknowledged evidence revoke authority;
the independent proxy runtime cancels in-flight requests during blocked controller/hook calls.
The default five-second lease/heartbeat cadence, two-second heartbeat request timeouts, single-use
ten-second challenges and send-anchored twenty-second local evidence deadline leave margin before
the controller's thirty-second no-evidence trip window. Replay or delayed acknowledgements cannot
resurrect locally expired authority or a terminal controller run.

Gate installation starts with CUT, forbids forwarding/bridges/flow offload, checks conntrack
invalidation before SEALED, and has no OPEN operation. The workload has no raw inference, DNS,
metadata, management, NAT or IPv6 forwarding allowance. Cloud recreation produces fresh local
WireGuard keys without authorized peers, so Terraform alone cannot restore the deleted path.
Source inspection found no private keys/provider credentials inserted into guest images or
user-data, credential values in actuator argv, or automatic prompt/response-body logging. This
assessment relies on the documented trusted operator provisioning and private host files.

**Local verification**

| Check | Result |
|---|---|
| `cargo test --workspace --locked` | 64 passed: common 15, controller 7, evalagent 34, hostd 3, supervisor 5. |
| `cargo build --workspace --locked` | Passed. |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Passed. |
| `cargo fmt --all -- --check` | Passed. |
| `cargo zigbuild --release --locked --target x86_64-unknown-linux-musl -p deadswitch-evalagent -p deadswitch-controller` | Passed; both outputs verified as static x86_64 ELF executables. Zig emitted only its deprecated linker optimization-setting warning. |
| `python3 -B -m unittest discover -s tests/phase2 -p 'test_*.py' -v` | 31 passed: actuator 13, hooks 13, observer 5. |
| Bash syntax and `shellcheck -x -P SCRIPTDIR` for the Hetzner hooks | Passed. |
| `terraform validate -no-color` in `infra/terraform/phase2` | Passed. |
| Trivy dependency scan, refreshed database on the review date | No known vulnerabilities reported for `Cargo.lock`. |
| `git diff --check` | Passed; this review performed no git writes. |

Local command logs are in `target/phase2-review/`. Linux network-namespace/kernel and nested-KVM
tests were not rerun on this macOS workstation. The live acceptance shell remains an explicit
exit-77 placeholder for automated scenario drivers; it is not counted as a passing live test.

**Accepted reference-architecture limitations**

- Provider cut/reset is operator-invoked. The controller ticker revokes leases but does not invoke
  `ds_kill.py`; automatic off-host expiry/actuation during controller failure is not implemented
  or certified by this focused verdict. No production end-to-end kill-latency SLA is established.
- Robot acceptance is not hardware termination proof. The actuator remains nonzero/UNCONFIRMED
  and forbids automatic reuse or reset repetition after uncertainty. There is no qualified
  hardware observer or automatic allocator/unquarantine path.
- Host-root configuration and the operator hooks remain trusted. Gate state follows agent-owned
  hook transitions; arbitrary external nft changes are not continuously attested or notified to
  proxy authority. Image digests are operator-supplied, not independent disk measurements. This
  verdict does not claim containment after arbitrary host-kernel/configuration compromise.
- The accepted Phase-1 A5 evidence is reused. This run adds no browser re-port, independent
  host-side VMI proof, or complete supply-chain qualification of the one-time image build.
- The review fixes and rebuilt binaries are local. Deploy the reviewed artifacts before the next
  containment run; the supplied live evidence predates these stricter validation/observation fixes.
