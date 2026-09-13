#!/bin/bash
# Live G1-G5 SKELETON. No remote connection or provider action is performed by this scaffold.
# Readiness flags, empty captures, guest reports, ping loss, and operator-supplied PASS strings
# cannot substitute for independent trusted scenario drivers and reconciled observations.
set -euo pipefail
case "${1:-all}" in
  all|G1|G2|G3|G4|G5) ;;
  *) echo 'usage: acceptance.sh [all|G1|G2|G3|G4|G5]' >&2; exit 2 ;;
esac
while IFS='|' read -r gate requirement; do
  if [ "${1:-all}" = all ] || [ "$1" = "$gate" ]; then
    printf '%s\n' "BLOCKED $gate: $requirement" >&2
  fi
done <<'GATES'
G1|actual QEMU config/input inspection, off-sandbox secret canaries and positive guest execution require the provisioned grader
G2|good/wrong/forged-PASS/forged-envelope/mismatched-artifact-task-evidence controls and reconciled trusted signed result counts missing
G3|cumulative variants/identities/campaigns/key versions/restarts exhaustion plus complete agent response/timing capture missing
G4|trusted packet capture and receivers for established replies/relay/public/mesh/metadata/IPv6/WG loss/encoded leakage/cross-job storage/replay/concurrency missing
G5|poison-A/fresh-B, timeout/crash/partition/actuator-failure/restart, independent process+storage teardown, delayed launch/result rejection observations missing
GATES
printf '%s\n' 'BLOCKED: grader deployment and trusted live scenario drivers are required; zero live assertions ran. Offline tests establish implementation regressions only.' >&2
exit 77
