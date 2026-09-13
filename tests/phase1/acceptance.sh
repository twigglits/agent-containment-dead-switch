#!/bin/bash
# Phase-1 acceptance suite — observed from the TRUSTED side (Mac: controller/hostd/pf/lima), never
# from guest logs. Drives the live pipeline and asserts the §14 VM-level guarantees. The protocol /
# health-policy cases (envelope replay, forged-health, digest binding, fencing, deadline) are covered
# by the crate unit tests (`cargo test`); this covers what needs the live nested stack.
#
# Prereqs: controller running on :7100; base provisioned; run as a user with the deadswitch sudoers.
# Usage: CTL_PUB=<hex> bash tests/phase1/acceptance.sh
set -uo pipefail
CTL=http://127.0.0.1:7100
OP=$(cat ~/.deadswitch/controller/operator.token)
CTL_PUB=${CTL_PUB:-$(cat /tmp/ds-ctl-pub)}
TEMPLATE="$(cd "$(dirname "$0")/../.." && pwd)/infra/lima/vm2.yaml"
MODEL=${DS_MODEL:-qwen2.5:7b}
SUDO=$(sed -n 's/^SUDO=//p' "$(cd "$(dirname "$0")/../.." && pwd)/.env" 2>/dev/null)
SUDOP(){ printf '%s\n' "$SUDO" | sudo -S -p '' "$@"; }  # password-sudo for ops outside the NOPASSWD allowlist
pass=0; fail=0
ok(){ echo "PASS: $1"; pass=$((pass+1)); }
no(){ echo "FAIL: $1"; fail=$((fail+1)); }
L(){ sudo -n -u _deadswitch -H /bin/bash -c "LIMA_HOME=/var/lib/deadswitch/lima exec /opt/homebrew/bin/limactl \"\$@\"" _ "$@"; }
mint(){ curl -s -X POST $CTL/runs -H "authorization: Bearer $OP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["run_id"])'; }
state(){ curl -s $CTL/runs/$1 -H "authorization: Bearer $OP" | python3 -c 'import sys,json;print(json.load(sys.stdin)["state"])'; }
inst_present(){ L list --json 2>/dev/null | grep -q "\"name\":\"vm2-$(echo "$1"|tr A-Z a-z)\""; }
# "gone" is asserted ONLY from a SUCCESSFUL trusted observation that shows the instance absent; a
# failed/empty limactl call is inconclusive and must NOT read as "gone" (Codex end-of-P1 #8).
inst_gone(){
  local name out
  name="vm2-$(echo "$1"|tr A-Z a-z)"
  out=$(L list --json 2>/dev/null) || return 1        # could not observe -> not "gone"
  printf '%s' "$out" | grep -q "\"name\":\"$name\"" && return 1 || return 0
}
lima_dir(){ echo "/var/lib/deadswitch/lima/vm2-$(echo "$1"|tr A-Z a-z)"; }
vz_pid_of(){ SUDOP cat "$(lima_dir "$1")/vz.pid" 2>/dev/null | tr -dc 0-9; }
# A missing/uncapturable pid is UNVERIFIED, not "dead": return non-zero so an assertion that relies
# on confirmed death fails rather than silently passing (Codex end-of-P1 #6).
pid_dead(){ [ -z "$1" ] && return 1; SUDOP kill -0 "$1" 2>/dev/null && return 1 || return 0; }
CONTAIN_BOUND_S=30   # §2 declared bound (25s) + margin for the suite's 1s polling
wait_eval(){ # wait until the run reaches eval (hostd logs a sealed-gate evidence entry), max ~300s
  local run=$1                       # prestage (uv sync + CPython fetch) can take a few minutes
  local E=/var/lib/deadswitch/evidence/$run.jsonl
  for _ in $(seq 1 150); do
    printf '%s\n' "$SUDO" | sudo -S -p '' grep -aq '"state":"sealed"\|vm1_booted' "$E" 2>/dev/null && return 0
    pgrep -f "deadswitch-hostd run --run-id $run" >/dev/null || return 1
    sleep 2
  done; return 1
}
teardown(){ # release the exclusive lock so the next test can run, even after a failure
  local run=$1
  SUDOP pkill -f "deadswitch-hostd run --run-id $run" 2>/dev/null || true
  sleep 3  # let the guard destroy the now-ownerless VM2
}
# shellcheck disable=SC2024  # log is intentionally owned by the invoking user, not root
launch(){ sudo -n /usr/local/sbin/deadswitch-hostd run --run-id "$1" --controller $CTL --controller-pubkey "$CTL_PUB" --model "$MODEL" --ollama http://127.0.0.1:11434 --max-run-s "${2:-400}" --template "$TEMPLATE" >/tmp/acc-$1.log 2>&1 & echo $!; }

echo "===== A1: sealed pf user-gate blocks VM2 egress, preserves the hostd path (trusted, no VM needed)"
sudo -n /sbin/pfctl -q -a deadswitch -f /etc/pf.anchors/deadswitch 2>/dev/null
(python3 -m http.server 7001 --bind 127.0.0.1 >/dev/null 2>&1 &) ; sleep 1
sudo -n -u _deadswitch /bin/bash -c 'curl -s -m4 -o /dev/null -w "%{http_code}" http://192.168.5.2:7001/ 2>/dev/null' >/dev/null 2>&1 || true
# start a probe VM2 (base) egress test is covered in §13; here assert the pf rule set is sealed+enabled
sudo -n /sbin/pfctl -s info 2>/dev/null | grep -q 'Status: Enabled' && sudo -n /sbin/pfctl -a deadswitch -sr 2>/dev/null | grep -q 'block drop out log quick all' && ok "A1 gate sealed and pf enabled" || no "A1 gate not effectively sealed"
pkill -f 'http.server 7001' 2>/dev/null

echo "===== A2: watchdog crash survival — SIGKILL the hostd run process, the guard destroys VM2"
R=$(mint); echo "run=$R"; launch "$R" 400 >/dev/null
if wait_eval "$R"; then
  vz=$(vz_pid_of "$R"); echo "captured VMM pid=$vz"
  # kill the REAL hostd run process (not the sudo wrapper): simulates a hostd crash. Its RunLock
  # Drop does not run under SIGKILL, so the guard (not this process) must destroy VM2.
  echo "reached eval; SIGKILL the hostd run process"; SUDOP pkill -9 -f "deadswitch-hostd run --run-id $R" 2>/dev/null
  t0=$(date +%s)
  for _ in $(seq 1 60); do inst_gone "$R" && break; sleep 1; done
  t1=$(date +%s)
  # Confirm a REAL teardown: instance observed gone, disk dir removed, captured VMM pid dead, AND
  # within the declared containment bound (Codex end-of-P1 #6 — A2 must assert timing too).
  a2dt=$((t1-t0))
  within=$([ "$a2dt" -le "$CONTAIN_BOUND_S" ] && echo yes || echo no)
  if inst_gone "$R" && [ ! -d "$(lima_dir "$R")" ] && pid_dead "$vz" && [ "$within" = yes ]; then
    ok "A2 guard destroyed VM2 ${a2dt}s after hostd crash (instance gone, dir removed, VMM pid $vz dead, within ${CONTAIN_BOUND_S}s)"
  else
    no "A2 guard did not fully+timely destroy VM2 (gone=$(inst_gone "$R" && echo y||echo n) dir=$([ -d "$(lima_dir "$R")" ]&&echo present||echo gone) vzdead=$(pid_dead "$vz" && echo y||echo n) dt=${a2dt}s within=$within)"
  fi
else no "A2 run did not reach eval"; tail -3 /tmp/acc-$R.log; teardown "$R"; fi
# run.lock is now a PERSISTENT flock inode (never deleted); the kernel released the crashed run's
# lock automatically when its fd closed, so nothing to clean up here (Codex end-of-P1 #2).

echo "===== A3: operator revoke → dead switch destroys VM2, VM1 cannot outlive it"
R=$(mint); echo "run=$R"
# Launch as a DIRECT child of this shell (not via $(launch ...), whose command-substitution subshell
# reparents the background process so `wait` would return 127) — so we can read hostd's real exit code.
# shellcheck disable=SC2024  # log is intentionally owned by the invoking user, not root
sudo -n /usr/local/sbin/deadswitch-hostd run --run-id "$R" --controller $CTL --controller-pubkey "$CTL_PUB" --model "$MODEL" --ollama http://127.0.0.1:11434 --max-run-s 400 --template "$TEMPLATE" >/tmp/acc-$R.log 2>&1 &
PID=$!
if wait_eval "$R"; then
  vz=$(vz_pid_of "$R"); echo "captured VMM pid=$vz"
  t0=$(date +%s)
  curl -s -X POST $CTL/runs/$R/revoke -H "authorization: Bearer $OP" -H 'content-type: application/json' -d '{"reason":"acceptance A3"}' >/dev/null
  for _ in $(seq 1 60); do inst_gone "$R" && break; sleep 1; done
  t1=$(date +%s); dt=$((t1-t0))
  st=$(state "$R")
  # VM1 cannot outlive VM2: instance observed gone, disk dir deleted, captured VMM pid dead, run
  # terminal, AND within the declared containment bound (Codex end-of-P1 #6 — assert the bound).
  gone=$(inst_gone "$R" && echo yes || echo no)
  dir_gone=$([ ! -d "$(lima_dir "$R")" ] && echo yes || echo no)
  vzdead=$(pid_dead "$vz" && echo yes || echo no)
  within=$([ "$dt" -le "$CONTAIN_BOUND_S" ] && echo yes || echo no)
  # Propagate hostd's own exit status: a containment-bound bailout (hostd exits non-zero) must NOT
  # coexist with an A3 pass (Codex end-of-P1 #6).
  wait "$PID" 2>/dev/null; hostd_rc=$?
  if [ "$gone" = yes ] && [ "$dir_gone" = yes ] && [ "$vzdead" = yes ] && { [ "$st" = revoked ] || [ "$st" = terminated ]; } && [ "$within" = yes ] && [ "$hostd_rc" = 0 ]; then
    ok "A3 revoke destroyed VM2 in ${dt}s (state=$st, instance+dir gone, VMM pid $vz dead, within ${CONTAIN_BOUND_S}s, hostd rc=0)"
  else
    no "A3 revoke incomplete (state=$st gone=$gone dir_gone=$dir_gone vzdead=$vzdead dt=${dt}s within=$within hostd_rc=$hostd_rc)"
  fi
else no "A3 run did not reach eval"; tail -3 /tmp/acc-$R.log; teardown "$R"; fi

echo "===== A4: exclusive host-gate lock — two SIMULTANEOUS runs, exactly one refused (kernel flock)"
# No deliberate serialization: both race on the OS-level flock in RunLock::acquire, taken atomically
# in the kernel, so exactly one must win and the other must be refused (Codex end-of-P1 #2 — the old
# check-then-write could admit two owners; A4 previously side-stepped the race).
R1=$(mint); R2=$(mint)
launch "$R1" 120 >/dev/null
launch "$R2" 120 >/dev/null
sleep 6
refused=0
grep -q 'another run holds the host gate' /tmp/acc-$R1.log && refused=$((refused+1))
grep -q 'another run holds the host gate' /tmp/acc-$R2.log && refused=$((refused+1))
[ "$refused" -eq 1 ] && ok "A4 exactly one of two simultaneous runs refused (kernel flock)" || no "A4 expected exactly 1 refusal, got $refused"
teardown "$R1"; teardown "$R2"

echo "===== A5: positive — VM1 boots, harness RUNS from the prestaged image to completion, containment holds"
# The full pipeline (prestage → seal → VM1 QEMU boot → obscura/harness → HARNESS_DONE), with NO early
# kill: proves the harness actually executes from the verified deps image and that egress is contained
# (Codex end-of-P1 #6 — a mandatory positive harness-execution test, not just seal-and-kill).
R=$(mint); echo "run=$R"
# shellcheck disable=SC2024  # log is intentionally owned by the invoking user, not root
sudo -n /usr/local/sbin/deadswitch-hostd run --run-id "$R" --controller $CTL --controller-pubkey "$CTL_PUB" --model "$MODEL" --ollama http://127.0.0.1:11434 --max-run-s 900 --template "$TEMPLATE" >/tmp/acc-$R.log 2>&1 &
PID=$!
E=/var/lib/deadswitch/evidence/$R.jsonl
harness_seen=no
for _ in $(seq 1 420); do   # up to ~14 min: prestage (uv sync) + VM1 boot + agentic inference
  SUDOP grep -aq '"kind":"harness_done"' "$E" 2>/dev/null && { harness_seen=yes; break; }
  pgrep -f "deadswitch-hostd run --run-id $R" >/dev/null || break
  sleep 2
done
if [ "$harness_seen" = yes ]; then
  # A5 passes ONLY on a VALID successful harness completion (Codex end-of-P1): the HARNESS_DONE
  # summary must have NO error/fatal field, must have ACTUALLY exercised an external navigation
  # (external_nav_attempts >= 1), and must report AFFIRMATIVE containment (contained == true). A
  # completion marker that is an abort/timeout/fatal, or that never navigated, or contained != true,
  # is NOT a pass.
  verdict=$(SUDOP cat "$E" 2>/dev/null | python3 -c '
import sys, json
res = {"found": False}
for line in sys.stdin:
    try: e = json.loads(line)
    except Exception: continue
    d = e.get("data", {})
    if isinstance(d, dict) and d.get("kind") == "harness_done":
        s = d.get("data", {}) or {}
        res = {"found": True, "error": ("error" in s or "fatal" in s),
               "contained": s.get("contained", "absent"),
               "navs": s.get("external_nav_attempts", 0), "mode": s.get("mode", "?")}
print(json.dumps(res))')
  booted=$(SUDOP grep -aq '"kind":"vm1_booted"' "$E" && echo yes || echo no)
  err=$(echo "$verdict" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("error"))')
  contained=$(echo "$verdict" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("contained"))')
  navs=$(echo "$verdict" | python3 -c 'import sys,json;print(json.load(sys.stdin).get("navs"))')
  if [ "$booted" = yes ] && [ "$err" = "False" ] && [ "$contained" = "True" ] && [ "${navs:-0}" -ge 1 ] 2>/dev/null; then
    ok "A5 VM1 booted + harness completed validly (navs=$navs, contained=true, no error) — egress contained"
  else
    no "A5 not a valid contained completion (booted=$booted error=$err contained=$contained navs=$navs)"
  fi
else
  no "A5 harness did not reach HARNESS_DONE"; tail -8 /tmp/acc-$R.log
fi
# revoke to tear the run down and release the lock
curl -s -X POST $CTL/runs/$R/revoke -H "authorization: Bearer $OP" -H 'content-type: application/json' -d '{"reason":"acceptance A5 cleanup"}' >/dev/null
for _ in $(seq 1 60); do inst_gone "$R" && break; sleep 1; done
wait "$PID" 2>/dev/null

echo "===== summary: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
