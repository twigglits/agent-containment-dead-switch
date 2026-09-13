#!/bin/bash
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
exec /usr/bin/python3 -I "$HERE/launcher.py" destroy
