#!/bin/bash
# DS_OBSERVE_CMD: host process + QEMU configuration + host KVM observations for signed evidence.
# No guest report supplies positive health; missing observations remain JSON null.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/network-config.sh"
exec python3 "$HERE/vm2-observe.py"
