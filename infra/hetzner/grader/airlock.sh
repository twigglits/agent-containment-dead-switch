#!/bin/bash
# Exact Phase-3 grader tuples; no generic established/related or mesh transit allowance.
set -euo pipefail
WG_IF="${WG_IF:-wg0}"
: "${PUBLIC_IFACE:?set the public management interface}"
: "${OPERATOR_CIDR:?set an operator IPv4 CIDR}"
: "${CTRL_PUBLIC_IP:?set the controller WireGuard endpoint IPv4}"
: "${NTP_IP:?set one fixed NTP server IPv4}"
python3 - "$WG_IF" "$PUBLIC_IFACE" "$OPERATOR_CIDR" "$CTRL_PUBLIC_IP" "$NTP_IP" <<'PY'
import ipaddress as ip, re, sys
wg, public, operator, endpoint, ntp = sys.argv[1:]
assert wg != public and all(re.fullmatch(r'[A-Za-z0-9_.-]{1,15}', x) for x in (wg, public))
assert ip.IPv4Network(operator).prefixlen > 0
for address in (endpoint, ntp):
    value = ip.IPv4Address(address)
    assert not value.is_unspecified and not value.is_multicast and not value.is_loopback and not value.is_link_local
    assert value not in ip.IPv4Network('10.20.0.0/24')
PY
rules() {
  local incoming='' outgoing='' state="$1"
  if [ "$state" = sealed ]; then
    incoming="iifname \"$WG_IF\" ip saddr 10.20.0.1 ip daddr 10.20.0.4 tcp dport 7200 ct direction original ct state { new, established } accept
    iifname \"$WG_IF\" ip saddr 10.20.0.1 ip daddr 10.20.0.4 tcp sport 7201 ct direction reply ct state established accept"
    outgoing="oifname \"$WG_IF\" ip saddr 10.20.0.4 ip daddr 10.20.0.1 tcp dport 7201 ct direction original ct state { new, established } accept
    oifname \"$WG_IF\" ip saddr 10.20.0.4 ip daddr 10.20.0.1 tcp sport 7200 ct direction reply ct state established accept"
  fi
  cat <<NFT
add table inet ds_grader_airlock
flush table inet ds_grader_airlock
table inet ds_grader_airlock {
  chain input {
    type filter hook input priority -10; policy drop;
    $incoming
    iifname "$PUBLIC_IFACE" ip saddr $OPERATOR_CIDR tcp dport 22 ct direction original ct state { new, established } accept
    iifname "$PUBLIC_IFACE" ip saddr $CTRL_PUBLIC_IP udp sport 51820 udp dport 51820 accept
    iifname "$PUBLIC_IFACE" ip saddr $NTP_IP udp sport 123 ct direction reply ct state established accept
    counter drop
  }
  chain forward {
    type filter hook forward priority -10; policy drop;
    counter drop
  }
  chain route_output {
    type route hook output priority mangle; policy accept;
    ip daddr 10.20.0.1 meta mark set 0x0d6
  }
  chain output {
    type filter hook output priority -10; policy drop;
    ip daddr 169.254.0.0/16 counter drop
    udp dport { 53, 853 } counter drop
    tcp dport { 53, 853 } counter drop
    $outgoing
    oifname "$PUBLIC_IFACE" ip daddr $OPERATOR_CIDR tcp sport 22 ct direction reply ct state established accept
    oifname "$PUBLIC_IFACE" ip daddr $CTRL_PUBLIC_IP udp sport 51820 udp dport 51820 accept
    oifname "$PUBLIC_IFACE" ip daddr $NTP_IP udp dport 123 ct direction original ct state { new, established } accept
    counter drop
  }
}
NFT
}
routes() {
  ip route replace unreachable default table 103 metric 1000
  if ip link show "$WG_IF" >/dev/null 2>&1; then
    ip route replace 10.20.0.1/32 dev "$WG_IF" src 10.20.0.4 table 103
  fi
  while ip rule del priority 103 2>/dev/null; do :; done
  while ip rule del priority 104 2>/dev/null; do :; done
  ip rule add priority 103 fwmark 0x0d6 lookup 103
  ip rule add priority 104 fwmark 0x0d6 unreachable
}
flush_flows() {
  local selector remaining
  for selector in --orig-src --orig-dst; do
    conntrack -D -f ipv4 "$selector" 10.20.0.4 >/dev/null 2>&1 || true
    remaining=$(conntrack -L -f ipv4 "$selector" 10.20.0.4 2>/dev/null)
    [ -z "$remaining" ] || return 1
  done
}
case "${1:-status}" in
  render) case "${2:-}" in sealed|cut) rules "$2";; *) exit 2;; esac ;;
  seal|cut)
    [ "$(id -u)" = 0 ] || { echo 'must run as root' >&2; exit 1; }
    rules cut | nft -f -
    sysctl -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0 >/dev/null
    nft -j list ruleset | python3 -c 'import json,sys; s=json.load(sys.stdin); assert "flowtable" not in str(s) and "flow add" not in str(s)'
    routes
    flush_flows
    if [ "$1" = seal ]; then rules sealed | nft -f -; fi
    echo "grader airlock: $1 applied; live kernel/traffic checks required"
    ;;
  status) nft list table inet ds_grader_airlock; ip rule show; ip route show table 103 ;;
  *) echo 'usage: airlock.sh seal|cut|status|render sealed|render cut' >&2; exit 2 ;;
esac
