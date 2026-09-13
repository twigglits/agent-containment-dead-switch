#!/bin/bash
# Sourced by the focused Linux hooks. Keep legacy DS_* settings and the canonical egress helper
# settings identical: silently using different tap/backend addresses would break containment.

ds_same_setting() {
  local canonical="$1" legacy="$2" fallback="$3" value
  if [ "${!canonical+x}" = x ] && [ "${!legacy+x}" = x ] && [ "${!canonical}" != "${!legacy}" ]; then
    echo "conflicting $canonical and $legacy" >&2
    return 1
  fi
  value="${!canonical-${!legacy-$fallback}}"
  [ -n "$value" ] || { echo "$canonical must not be empty" >&2; return 1; }
  printf -v "$canonical" '%s' "$value"
  printf -v "$legacy" '%s' "$value"
  export "$canonical" "$legacy"
}

ds_same_setting WORKLOAD_IFACE DS_TAP dstap0
ds_same_setting WORKLOAD_SRC DS_WL_SUBNET 10.99.0.0/24
ds_same_setting HOSTD_IP DS_WL_HOST_IP 10.99.0.1
ds_same_setting WG_IF DS_WG_IF wg0
ds_same_setting EVAL_WGIP DS_EVAL_WGIP 10.20.0.3
ds_same_setting CHOKE_WGIP DS_CHOKE_WGIP 10.20.0.2
ds_same_setting CTRL_WGIP DS_CTRL_WGIP 10.20.0.1
export DS_VM2_IP="${DS_VM2_IP-10.99.0.2}"
[ "${DS_OLLAMA_PORT-11434}" = 11434 ] || { echo 'DS_OLLAMA_PORT must be 11434 (fixed proxy backend contract)' >&2; exit 1; }

# Validate before interpolating into shell-generated nft, netplan, or cloud-init data.
DS_WL_PREFIXLEN=$(python3 - "$WORKLOAD_IFACE" "$WORKLOAD_SRC" "$HOSTD_IP" "$DS_VM2_IP" "$CHOKE_WGIP" <<'PY'
import ipaddress as ip, re, sys
tap, subnet, local, guest, choke = sys.argv[1:]
assert re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}', tap), 'invalid workload tap'
net = ip.IPv4Network(subnet)
local, guest, choke = map(ip.IPv4Address, (local, guest, choke))
assert local != guest and local in net and guest in net, 'HOSTD_IP and DS_VM2_IP must be distinct addresses in WORKLOAD_SRC'
assert not any(addr.is_multicast or addr.is_unspecified or addr.is_loopback for addr in (local, guest, choke)), 'unicast non-loopback IPv4 addresses required'
if net.prefixlen < 31:
    assert all(addr not in (net.network_address, net.broadcast_address) for addr in (local, guest)), 'network/broadcast host address refused'
assert choke not in net, 'backend must be off the workload subnet'
print(net.prefixlen)
PY
)
export DS_WL_PREFIXLEN
