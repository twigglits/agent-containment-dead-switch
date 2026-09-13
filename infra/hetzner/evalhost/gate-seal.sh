#!/bin/bash
# Focused evalagent hook for the canonical pure-L3 host policy. SEALED admits guest -> local exact-
# action proxy only; backend connections originate on the host. CUT removes both allowances.
# The canonical helper owns atomic deny-before-allow nft replacement, route fencing, and checked
# conntrack invalidation. Keep it the single implementation of these containment rules.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/network-config.sh"

# PUBLIC_IFACE, OPERATOR_CIDR, CTRL_PUBLIC_IP, CHOKE_PUBLIC_IP and NTP_IP are deliberately REQUIRED
# by evalhost-egress.sh. The operator must supply the management tuples; never infer public IPs.
exec bash "$HERE/../evalhost-egress.sh" "$@"
