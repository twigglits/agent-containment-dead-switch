#!/bin/bash
# Controller-side actuator. cut confirms only chokepoint deletion; kill also dispatches a Robot
# reset. Reset acceptance is NOT termination proof. See infra/terraform/phase2/robot.md.
set -euo pipefail
exec python3 "$(cd "$(dirname "$0")" && pwd)/ds_kill.py" "${1:-kill}"
