#!/bin/bash
# Dedicated host containment for a PURE L3 tap (never a public bridge or userspace/NAT NIC).
# VM2 reaches only the local exact-action hostd API. Only HOST-originated backend traffic reaches
# the chokepoint; VM2 cannot bypass hostd and speak the raw inference API. Host output is also denied
# by default, with explicit management/WG/NTP tuples. Configuration is required, never guessed.
# evalhost/gate-seal.sh integrates these rules with evalagent's embedded exact-action proxy.
# Hook success is not a complete kernel-health attestation; richer observations remain separate.
set -euo pipefail
WG_IF="${WG_IF:-wg0}"
EVAL_WGIP="${EVAL_WGIP:-10.20.0.3}"
CHOKE_WGIP="${CHOKE_WGIP:-10.20.0.2}"
CTRL_WGIP="${CTRL_WGIP:-10.20.0.1}"
: "${WORKLOAD_IFACE:?set the dedicated L3 tap name}"
: "${WORKLOAD_SRC:?set the VM2 IPv4 subnet}"
: "${HOSTD_IP:?set the host address on that tap}"
: "${PUBLIC_IFACE:?set the management NIC}"
: "${OPERATOR_CIDR:?set the operator IPv4 CIDR}"
: "${CTRL_PUBLIC_IP:?set the controller WG endpoint IPv4}"
: "${CHOKE_PUBLIC_IP:?set the chokepoint WG endpoint IPv4}"
: "${NTP_IP:?set a fixed trusted NTP server IPv4}"
TABLE=100
MARK=0x0d5

validate() {
  python3 - "$WG_IF" "$WORKLOAD_IFACE" "$PUBLIC_IFACE" "$EVAL_WGIP" "$CHOKE_WGIP" "$CTRL_WGIP" "$WORKLOAD_SRC" "$HOSTD_IP" "$OPERATOR_CIDR" "$CTRL_PUBLIC_IP" "$CHOKE_PUBLIC_IP" "$NTP_IP" <<'PY'
import ipaddress as ip, re, sys
wg, tap, public, own, choke, ctrl, src, local, operator, cep, gep, ntp = sys.argv[1:]
assert len({wg, tap, public}) == 3
assert all(re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', x) for x in (wg, tap, public))
net = ip.IPv4Network(src)
assert ip.IPv4Address(local) in net
assert ip.IPv4Network(operator).prefixlen > 0
assert len({own, choke, ctrl}) == 3
for addr in (own, choke, ctrl, cep, gep, ntp):
    assert ip.IPv4Address(addr) not in net
PY
}

rules() {
  local state="$1" backend_in='' backend_out='' guest_in='' guest_out=''
  if [ "$state" = sealed ]; then
    guest_in="iifname \"$WORKLOAD_IFACE\" ip saddr $WORKLOAD_SRC ip daddr $HOSTD_IP tcp dport 7001 accept"
    guest_out="oifname \"$WORKLOAD_IFACE\" ip saddr $HOSTD_IP ip daddr $WORKLOAD_SRC tcp sport 7001 ct direction reply ct state established accept"
    backend_out="oifname \"$WG_IF\" ip saddr $EVAL_WGIP ip daddr $CHOKE_WGIP tcp dport 11434 accept"
    backend_in="iifname \"$WG_IF\" ip saddr $CHOKE_WGIP ip daddr $EVAL_WGIP tcp sport 11434 ct direction reply ct state established accept"
  fi
  # One atomic transaction, replacing rules rather than appending another copy on every seal/cut.
  cat <<NFT
add table inet ds_egress
flush table inet ds_egress
table inet ds_egress {
  chain input {
    type filter hook input priority -10; policy drop;
    $guest_in
    iifname "$WORKLOAD_IFACE" counter drop
    iifname "lo" accept
    iifname "$PUBLIC_IFACE" ip saddr $OPERATOR_CIDR tcp dport 22 accept
    iifname "$PUBLIC_IFACE" ip saddr { $CTRL_PUBLIC_IP, $CHOKE_PUBLIC_IP } udp dport 51820 accept
    iifname "$PUBLIC_IFACE" ip saddr $NTP_IP udp sport 123 ct direction reply ct state established accept
    iifname "$WG_IF" ip saddr $CTRL_WGIP ip daddr $EVAL_WGIP tcp sport 7100 ct direction reply ct state established accept
    $backend_in
  }
  chain forward {
    type filter hook forward priority -10; policy drop;
    counter drop
  }
  chain route_output {
    type route hook output priority mangle; policy accept;
    ip daddr $CHOKE_WGIP meta mark set $MARK
  }
  chain output {
    type filter hook output priority -10; policy drop;
    $guest_out
    oifname "$WORKLOAD_IFACE" counter drop
    ip daddr 169.254.0.0/16 counter drop
    udp dport { 53, 853 } counter drop
    tcp dport { 53, 853 } counter drop
    oifname "lo" accept
    oifname "$PUBLIC_IFACE" ip daddr $OPERATOR_CIDR tcp sport 22 ct direction reply ct state established accept
    oifname "$PUBLIC_IFACE" ip daddr { $CTRL_PUBLIC_IP, $CHOKE_PUBLIC_IP } udp dport 51820 accept
    oifname "$PUBLIC_IFACE" ip daddr $NTP_IP udp dport 123 accept
    oifname "$WG_IF" ip saddr $EVAL_WGIP ip daddr $CTRL_WGIP tcp dport 7100 accept
    $backend_out
  }
}
NFT
}

policy_routes() {
  # No default next-hop over the whole mesh. Only the backend /32 can route over wg0. Both an
  # unreachable table default and a terminal RPDB rule prevent main-table fallback if wg0 disappears
  # or the dedicated table is emptied. OUTPUT also requires the exact destination AND interface.
  ip route replace unreachable default table "$TABLE" metric 1000
  if ip link show "$WG_IF" >/dev/null 2>&1; then
    ip route replace "$CHOKE_WGIP/32" dev "$WG_IF" src "$EVAL_WGIP" table "$TABLE"
  fi
  # Own these priorities; remove duplicates while CUT, then install exactly one of each.
  while ip rule del priority 100 2>/dev/null; do :; done
  while ip rule del priority 101 2>/dev/null; do :; done
  ip rule add priority 100 fwmark "$MARK" lookup "$TABLE"
  ip rule add priority 101 fwmark "$MARK" unreachable
}

flush_flows() {
  # DELETE can return 1 for zero matches. The authoritative check is a successful EMPTY listing
  # afterward; permission/netlink/command failures cannot be mistaken for an empty state table.
  local selector remaining
  for selector in '--orig-src' '--orig-dst'; do
    conntrack -D -f ipv4 "$selector" "$WORKLOAD_SRC" >/dev/null 2>&1 || true
    remaining=$(conntrack -L -f ipv4 "$selector" "$WORKLOAD_SRC" 2>/dev/null)
    [ -z "$remaining" ] || return 1
  done
  conntrack -D -f ipv4 --orig-dst "$CHOKE_WGIP" >/dev/null 2>&1 || true
  remaining=$(conntrack -L -f ipv4 --orig-dst "$CHOKE_WGIP" 2>/dev/null)
  [ -z "$remaining" ]
}

validate
case "${1:-status}" in
  render) case "${2:-}" in sealed|cut) rules "$2";; *) exit 2;; esac ;;
  seal|cut)
    [ "$(id -u)" = 0 ] || { echo 'must run as root' >&2; exit 1; }
    # Install deny-all workload rules BEFORE any fallible routing or conntrack operation. A failed
    # seal leaves CUT installed; no open fallback. The apply must precede VM creation at boot.
    rules cut | nft -f -
    sysctl -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0 >/dev/null
    [ ! -e "/sys/class/net/$WORKLOAD_IFACE/master" ] || { echo 'bridged workload interface refused' >&2; exit 1; }
    nft -j list ruleset | python3 -c 'import json,sys; s=json.load(sys.stdin); assert "flowtable" not in str(s) and "flow add" not in str(s), "flow offload must be disabled"'
    policy_routes
    flush_flows
    if [ "$1" = seal ]; then rules sealed | nft -f -; fi
    echo "evalhost-egress: $1 applied (kernel readback still required for health)"
    ;;
  open) echo 'OPEN refused: provision offline, before any untrusted workload exists' >&2; exit 2 ;;
  status) nft list table inet ds_egress; ip rule show; ip route show table "$TABLE" ;;
  *) echo "usage: $0 seal|cut|status|render sealed|render cut" >&2; exit 2 ;;
esac
