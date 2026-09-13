#!/bin/bash
# DS_BOOT_CMD: launch VM2 (which boots a nested VM1) on a pure-L3 tap. Idempotent-ish: refuses to
# double-launch if a live pid is present. The VM2 image (vm2.qcow2) must already be BUILT (vm2-build.sh)
# with qemu + the nested VM1 payload baked in — no run-time fetch. Nested KVM is real (i7-7700 VT-x).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/network-config.sh"
DIR="${DS_VM2_DIR:-/var/lib/deadswitch/vm2}"
PIDFILE="$DIR/vm2.pid"
IMG="$DIR/vm2.qcow2"
[ -f "$IMG" ] || { echo "VM2 image missing: $IMG (run vm2-build.sh first)" >&2; exit 1; }

# CUT precedes all tap setup and VM creation. Missing management config, nft failure, bad routes,
# or unflushable conntrack state aborts boot; no untrusted guest receives a build-time open network.
bash "$HERE/gate-seal.sh" cut

# refuse a second live VM2 (one run per physical host)
if [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; then
  echo "VM2 already running pid $(cat "$PIDFILE"); refusing reuse of a live run" >&2; exit 1
fi

# tap up (host side of the pure-L3 workload network). Replace the configured address even when the
# tap already exists, and reject a bridge. The same HOSTD_IP is the embedded proxy's bind address.
if ! ip link show "$WORKLOAD_IFACE" >/dev/null 2>&1; then
  ip tuntap add dev "$WORKLOAD_IFACE" mode tap
fi
[ ! -e "/sys/class/net/$WORKLOAD_IFACE/master" ] || { echo 'bridged workload interface refused' >&2; exit 1; }
ip addr replace "$HOSTD_IP/$DS_WL_PREFIXLEN" dev "$WORKLOAD_IFACE"
ip link set "$WORKLOAD_IFACE" up

# -cpu host WITHOUT nested-virt passthrough to VM1 is handled INSIDE VM2 (it launches VM1 with
# -cpu host,-vmx). VM2 itself needs vmx to run nested KVM, so VM2 gets full -cpu host here.
setsid qemu-system-x86_64 \
  -name deadswitch-vm2 -machine q35,accel=kvm -cpu host -smp 4 -m 16384 \
  -nographic -nodefaults -no-user-config \
  -drive if=virtio,format=qcow2,file="$IMG" \
  -netdev tap,id=n0,ifname="$WORKLOAD_IFACE",script=no,downscript=no \
  -device virtio-net-pci,netdev=n0,mac=52:54:00:99:00:02,romfile= \
  -device virtio-rng-pci \
  -serial file:"$DIR/vm2-serial.log" -display none \
  -pidfile "$PIDFILE" </dev/null >/dev/null 2>&1 &
disown 2>/dev/null || true
sleep 1
[ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null || { echo "VM2 failed to start" >&2; exit 1; }
echo "VM2 launched pid $(cat "$PIDFILE") on tap $WORKLOAD_IFACE; proxy=$HOSTD_IP:7001; gate remains cut"
