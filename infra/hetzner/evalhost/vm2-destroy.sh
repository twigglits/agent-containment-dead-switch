#!/bin/bash
# DS_DESTROY_CMD: CUT the gate, then destroy VM2 (SIGKILL its QEMU), which takes nested VM1 with it.
# Both steps are attempted even if one fails. Never report success if CUT or death is unconfirmed.
set -uo pipefail
DIR="${DS_VM2_DIR:-/var/lib/deadswitch/vm2}"
PIDFILE="$DIR/vm2.pid"
HERE="$(cd "$(dirname "$0")" && pwd)"
cut_ok=true
bash "$HERE/gate-seal.sh" cut || cut_ok=false

# A pidfile can refer to a recycled PID after a crash/reboot. Never signal that PID blindly
# (zero/negative values are process-group targets). Match the supported launch profile instead.
profile='^([^ ]*/)?qemu-system-x86_64 -name deadswitch-vm2([[:space:]]|$)'
pkill -KILL -f "$profile" 2>/dev/null || true
for _ in 1 2 3 4 5 6 7 8 9 10; do
  pgrep -f "$profile" >/dev/null 2>&1
  observed=$?
  [ "$observed" -eq 1 ] && break
  [ "$observed" -eq 0 ] || { echo 'DESTROY UNCONFIRMED: process observation failed' >&2; exit 1; }
  sleep 0.3
done
[ "$observed" -eq 1 ] || { echo 'DESTROY FAILED: VM2 qemu still present' >&2; exit 1; }
if [ -f "$PIDFILE" ]; then
  pid="$(cat "$PIDFILE" 2>/dev/null)" || exit 1
  [[ "$pid" =~ ^[1-9][0-9]*$ && "$pid" != 1 ]] || { echo 'DESTROY UNCONFIRMED: invalid pidfile' >&2; exit 1; }
  # A still-live PID could be an unfamiliar QEMU launch or an unrelated process. Quarantine
  # either case for reconciliation without killing an unrelated host process or claiming death.
  if kill -0 "$pid" 2>/dev/null; then
    echo 'DESTROY UNCONFIRMED: pidfile still refers to a live process' >&2; exit 1
  fi
fi
rm -f "$PIDFILE"
[ "$cut_ok" = true ] || { echo 'VM2 destroyed, but gate CUT failed' >&2; exit 1; }
echo "VM2 destroyed; gate cut"
