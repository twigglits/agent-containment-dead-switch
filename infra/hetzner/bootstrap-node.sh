#!/bin/bash
# Non-secret cloud-init payload. No peer authorization is installed by Terraform.
set -euo pipefail
umask 077
role="${1:?controller or chokepoint}"
operator="${2:?operator IPv4 CIDR}"
python3 - "$operator" <<'PY'
import ipaddress, sys
assert ipaddress.IPv4Network(sys.argv[1]).prefixlen > 0
PY
public=$(ip -o -4 route show to default | awk 'NR == 1 {print $5}')
[[ "$public" =~ ^[a-zA-Z0-9_.-]{1,15}$ ]]
install -d -m0700 /etc/wireguard /etc/deadswitch
# Fresh node => fresh transport identity; a Terraform replacement cannot inherit an authorized path.
# This script runs ONCE from cloud-init. Peer changes use configure-wireguard.sh, never a second apply.
wg genkey > /etc/wireguard/privatekey
wg pubkey < /etc/wireguard/privatekey > /etc/wireguard/publickey
cat > /etc/sysctl.d/90-deadswitch.conf <<'CONF'
net.ipv4.ip_forward=0
net.ipv6.conf.all.forwarding=0
CONF
sysctl -p /etc/sysctl.d/90-deadswitch.conf >/dev/null
if [ "$role" = controller ]; then
  cat > /etc/nftables.conf <<NFT
#!/usr/sbin/nft -f
flush ruleset
table inet ds_controller {
  chain input {
    type filter hook input priority -10; policy drop;
    iifname "lo" accept
    iifname "wg0" ip saddr 10.20.0.3 ip daddr 10.20.0.1 tcp dport 7100 accept
    iifname "wg0" drop
    iifname "$public" ip saddr $operator tcp dport 22 accept
    iifname "$public" udp dport 51820 accept
    iifname "$public" ct direction reply ct state established,related accept
  }
  chain forward { type filter hook forward priority -10; policy drop; }
}
NFT
elif [ "$role" = chokepoint ]; then
  PUBLIC_IFACE="$public" OPERATOR_CIDR="$operator" /usr/local/sbin/chokepoint-forward.sh render > /etc/nftables.conf
else
  exit 2
fi
nft -f /etc/nftables.conf
systemctl enable nftables.service
# This output is public enrollment material only. No private key is printed or stored in Terraform.
printf '%s node initialized in quarantine; WireGuard public key: ' "$role"
cat /etc/wireguard/publickey
