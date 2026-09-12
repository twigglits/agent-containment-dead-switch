#!/bin/bash
# Runs INSIDE VM2 as root. Builds VM1's only network path: tap0 <-> VM2, default-deny.
# VM1 = 172.16.0.2/30, VM2 side = 172.16.0.1. The ONLY allowed flow is VM1 -> 172.16.0.1:3128
# (the supervisor's interceptor). No forwarding, no NAT, no DNS, no route to the host or beyond.
set -euo pipefail
TAP=${TAP:-tap0}
PROXY_PORT=${PROXY_PORT:-3128}
ip link show "$TAP" >/dev/null 2>&1 || ip tuntap add dev "$TAP" mode tap
ip addr replace 172.16.0.1/30 dev "$TAP"
ip link set "$TAP" up
sysctl -qw net.ipv4.ip_forward=0
sysctl -qw net.ipv6.conf.all.forwarding=0
sysctl -qw "net.ipv6.conf.$TAP.disable_ipv6=1"
nft -f - <<NFT
table inet vm1 { }
delete table inet vm1
table inet vm1 {
  chain input {
    type filter hook input priority 0; policy drop;
    iifname != "$TAP" accept
    # (ARP is not seen by the inet family; the kernel answers ARP for 172.16.0.1 itself. IPv4
    # fragments and all IPv6 from the guest are dropped here.)
    iifname "$TAP" ip frag-off & 0x1fff != 0 counter drop
    iifname "$TAP" meta nfproto ipv6 counter drop
    # the single permitted service, from VM1's fixed address, and only its established replies
    iifname "$TAP" ip saddr 172.16.0.2 ip daddr 172.16.0.1 tcp dport $PROXY_PORT ct state new,established counter accept
    iifname "$TAP" ip saddr 172.16.0.2 ip daddr 172.16.0.1 ct state established,related counter accept
    iifname "$TAP" counter drop
  }
  chain forward {
    type filter hook forward priority 0; policy drop;
    iifname "$TAP" counter drop
    oifname "$TAP" counter drop
  }
  chain output {
    type filter hook output priority 0; policy accept;
    oifname "$TAP" ip daddr 172.16.0.2 tcp sport $PROXY_PORT ct state established,related counter accept
    oifname "$TAP" counter drop
  }
}
NFT
echo "vm1 net ready: $TAP 172.16.0.1/30, only VM1->172.16.0.1:$PROXY_PORT accepted"
