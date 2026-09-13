#!/bin/bash
# Run on EACH of controller/chokepoint/eval after verifying public keys via the operator SSH path.
# All inputs below are PUBLIC. Each node's private key remains local. No mesh peer gets a default
# route or transit authority. The Cloud-only subnet is not involved. Use pinned SSH host keys.
set -euo pipefail
umask 077
[ "$(id -u)" = 0 ] || { echo 'must run as root' >&2; exit 1; }
role="${1:?controller|chokepoint|eval}"
: "${CONTROLLER_PUBLIC_IP:?} ${CHOKEPOINT_PUBLIC_IP:?} ${EVAL_PUBLIC_IP:?}"
: "${CONTROLLER_WG_KEY:?} ${CHOKEPOINT_WG_KEY:?} ${EVAL_WG_KEY:?}"
python3 - "$role" "$CONTROLLER_PUBLIC_IP" "$CHOKEPOINT_PUBLIC_IP" "$EVAL_PUBLIC_IP" "$CONTROLLER_WG_KEY" "$CHOKEPOINT_WG_KEY" "$EVAL_WG_KEY" <<'PY'
import base64, ipaddress, sys
assert sys.argv[1] in ('controller', 'chokepoint', 'eval')
for addr in sys.argv[2:5]: ipaddress.IPv4Address(addr)
assert len(set(sys.argv[5:])) == 3
for key in sys.argv[5:]: assert len(base64.b64decode(key, validate=True)) == 32
PY
install -d -m0700 /etc/wireguard
if [ ! -e /etc/wireguard/privatekey ]; then
  wg genkey > /etc/wireguard/privatekey
  wg pubkey < /etc/wireguard/privatekey > /etc/wireguard/publickey
fi
python3 - <<'PY'
import os, stat
p = '/etc/wireguard/privatekey'
m = os.lstat(p)
assert stat.S_ISREG(m.st_mode) and m.st_uid == 0 and m.st_mode & 0o077 == 0, 'WireGuard key must be a private root-owned regular file'
PY
case "$role" in
  controller) own=10.20.0.1; expected="$CONTROLLER_WG_KEY" ;;
  chokepoint) own=10.20.0.2; expected="$CHOKEPOINT_WG_KEY" ;;
  eval) own=10.20.0.3; expected="$EVAL_WG_KEY" ;;
esac
[ "$(wg pubkey < /etc/wireguard/privatekey)" = "$expected" ] || { echo 'local public key does not match operator-pinned identity' >&2; exit 1; }
peer() {
  printf '\n[Peer]\nPublicKey = %s\nAllowedIPs = %s/32\nEndpoint = %s:51820\nPersistentKeepalive = 25\n' "$1" "$2" "$3"
}
tmp=$(mktemp /etc/wireguard/.wg0.XXXXXX)
trap 'rm -f "$tmp"' EXIT
{
  printf '[Interface]\nAddress = %s/32\nListenPort = 51820\nPrivateKey = ' "$own"
  cat /etc/wireguard/privatekey
  printf '\n'
  if [ "$role" = eval ]; then
    peer "$CONTROLLER_WG_KEY" 10.20.0.1 "$CONTROLLER_PUBLIC_IP"
    peer "$CHOKEPOINT_WG_KEY" 10.20.0.2 "$CHOKEPOINT_PUBLIC_IP"
  else
    peer "$EVAL_WG_KEY" 10.20.0.3 "$EVAL_PUBLIC_IP"
  fi
} > "$tmp"
# Never mutate an active peer mapping: stop/quarantine runs first. New keys require explicit
# commissioning; neither Terraform nor this script may silently replace a live allocation's peer.
if systemctl is-active --quiet wg-quick@wg0; then
  cmp -s "$tmp" /etc/wireguard/wg0.conf || { echo 'active WireGuard config differs; quarantine before reconfiguration' >&2; exit 1; }
else
  mv "$tmp" /etc/wireguard/wg0.conf
  chmod 0600 /etc/wireguard/wg0.conf
  systemctl enable --now wg-quick@wg0
fi
printf 'WireGuard configured for %s; /32 peers only\n' "$role"
