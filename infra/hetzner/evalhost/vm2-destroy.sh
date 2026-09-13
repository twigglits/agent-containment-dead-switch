#!/bin/bash
# DS_DESTROY_CMD: CUT the gate, then destroy VM2 (SIGKILL its QEMU), which takes nested VM1 with it.
# Both steps are attempted even if one fails. Never report success if CUT or death is unconfirmed.
set -uo pipefail
DIR="${DS_VM2_DIR:-/var/lib/deadswitch/vm2}"
PIDFILE="$DIR/vm2.pid"
HERE="$(cd "$(dirname "$0")" && pwd)"
cut_ok=true
bash "$HERE/gate-seal.sh" cut || cut_ok=false

if [ -f "$PIDFILE" ]; then
  pid="$(cat "$PIDFILE" 2>/dev/null || true)"
  if [ -n "${pid:-}" ] && kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do kill -0 "$pid" 2>/dev/null || break; sleep 0.3; done
  fi
fi
# belt & braces: any stray VM2 qemu by name
pkill -KILL -f 'qemu-system-x86_64 -name deadswitch-vm2' 2>/dev/null || true
# verify nothing named deadswitch-vm2 survives
if pgrep -f 'qemu-system-x86_64 -name deadswitch-vm2' >/dev/null 2>&1; then
  echo "DESTROY FAILED: VM2 qemu still present" >&2; exit 1
fi
rm -f "$PIDFILE"
[ "$cut_ok" = true ] || { echo 'VM2 destroyed, but gate CUT failed' >&2; exit 1; }
echo "VM2 destroyed; gate cut"
