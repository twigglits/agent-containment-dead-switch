#!/bin/bash
# Inference endpoint only. The eval-host exact-action proxy is the ONLY permitted client.
# Neither direct guest forwarding/NAT nor SSH through the WireGuard management mesh is permitted.
set -euo pipefail
WG_IF="${WG_IF:-wg0}"
WG_IP="${WG_IP:-10.20.0.2}"
EVAL_WGIP="${EVAL_WGIP:-10.20.0.3}"
OLLAMA_PORT="${OLLAMA_PORT:-11434}"
: "${PUBLIC_IFACE:?set the public NIC}"
: "${OPERATOR_CIDR:?set the operator IPv4 CIDR}"
python3 - "$WG_IF" "$PUBLIC_IFACE" "$WG_IP" "$EVAL_WGIP" "$OLLAMA_PORT" "$OPERATOR_CIDR" <<'PY'
import ipaddress as ip, re, sys
wg, public, local, peer, port, operator = sys.argv[1:]
assert wg != public and all(re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', x) for x in (wg, public))
assert ip.IPv4Address(local) != ip.IPv4Address(peer)
assert port.isdecimal() and 0 < int(port) <= 65535
assert ip.IPv4Network(operator).prefixlen > 0
PY
rules() {
  cat <<NFT
add table inet ds_choke
flush table inet ds_choke
table inet ds_choke {
  chain input {
    type filter hook input priority -10; policy drop;
    iifname "lo" accept
    iifname "$WG_IF" ip saddr $EVAL_WGIP ip daddr $WG_IP tcp dport $OLLAMA_PORT accept
    iifname "$WG_IF" counter drop
    iifname "$PUBLIC_IFACE" udp dport 51820 accept
    iifname "$PUBLIC_IFACE" ip saddr $OPERATOR_CIDR tcp dport 22 accept
    iifname "$PUBLIC_IFACE" ct direction reply ct state established,related accept
  }
  chain forward {
    type filter hook forward priority -10; policy drop;
    counter drop
  }
}
NFT
}
case "${1:-status}" in
  render) rules ;;
  apply)
    [ "$(id -u)" = 0 ] || { echo 'must run as root' >&2; exit 1; }
    sysctl -w net.ipv4.ip_forward=0 net.ipv6.conf.all.forwarding=0 >/dev/null
    rules | nft -f -
    nft -j list ruleset | python3 -c 'import json,sys; s=json.load(sys.stdin); assert "flowtable" not in str(s), "flow offload must be disabled"'
    echo 'chokepoint: inference only; forwarding disabled'
    ;;
  status) nft list table inet ds_choke; sysctl net.ipv4.ip_forward net.ipv6.conf.all.forwarding ;;
  *) echo "usage: $0 apply|status|render" >&2; exit 2 ;;
esac
