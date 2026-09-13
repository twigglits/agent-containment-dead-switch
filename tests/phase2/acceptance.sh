#!/bin/bash
# Live closeout requires a commissioned Linux backend and independent actuator/observer. The old
# skeleton returned success with zero assertions. Until those scenario drivers exist, CI MUST NOT
# count this as a pass. See docs/phase2-plan.md (closeout gate + live status) for the observers and pass conditions.
set -euo pipefail
printf '%s\n' 'BLOCKED: Phase 2 live A1/A2/A4 drivers are not implemented; no assertions ran.' >&2
printf '%s\n' 'Run tests/phase2/offline.sh for implementation regressions; these do not establish live containment.' >&2
exit 77
