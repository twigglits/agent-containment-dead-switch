#!/bin/bash
# Non-cloud regressions. Linux network-namespace tests are a separate command (see review).
set -euo pipefail
cd "$(dirname "$0")/../.."
python3 -B -m unittest discover -s tests/phase2 -p 'test_actuator.py' -v
for script in infra/hetzner/*.sh tests/phase2/*.sh; do bash -n "$script"; done
# A placeholder live gate must never silently become a passing CI job.
set +e
bash tests/phase2/acceptance.sh
rc=$?
set -e
[ "$rc" = 77 ] || { echo "live skeleton returned unexpected status $rc" >&2; exit 1; }
