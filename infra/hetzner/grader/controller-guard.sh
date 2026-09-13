#!/bin/bash
# Additive controller guard: leave Phase-1/2 rules untouched, constrain every grader flow.
# Existing controller filters must also allow the two exact tuples; accept cannot bypass later drop.
set -euo pipefail
WG_IF="${WG_IF:-wg0}"
[[ "$WG_IF" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]] || exit 2
rules() {
  cat <<NFT
add table inet ds_grader_guard
flush table inet ds_grader_guard
table inet ds_grader_guard {
  chain input {
    type filter hook input priority -20; policy accept;
    iifname "$WG_IF" ip saddr 10.20.0.4 ip daddr 10.20.0.1 tcp dport 7201 ct direction original ct state { new, established } accept
    iifname "$WG_IF" ip saddr 10.20.0.4 ip daddr 10.20.0.1 tcp sport 7200 ct direction reply ct state established accept
    ip saddr 10.20.0.4 counter drop
  }
  chain output {
    type filter hook output priority -20; policy accept;
    oifname "$WG_IF" ip saddr 10.20.0.1 ip daddr 10.20.0.4 tcp dport 7200 ct direction original ct state { new, established } accept
    oifname "$WG_IF" ip saddr 10.20.0.1 ip daddr 10.20.0.4 tcp sport 7201 ct direction reply ct state established accept
    ip daddr 10.20.0.4 counter drop
  }
  chain forward {
    type filter hook forward priority -20; policy accept;
    ip saddr 10.20.0.4 counter drop
    ip daddr 10.20.0.4 counter drop
  }
}
NFT
}
case "${1:-render}" in
  render) rules ;;
  apply) [ "$(id -u)" = 0 ]; rules | nft -f - ;;
  *) echo 'usage: controller-guard.sh render|apply' >&2; exit 2 ;;
esac
