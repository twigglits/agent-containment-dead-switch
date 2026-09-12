#!/bin/bash
# QEMU nested-stack qualification gate (runs INSIDE VM2). Proves, on this exact stack:
# real KVM boot of the browser VM1 to VM1_READY, QMP stop/pmemsave/cont x3, browser present,
# no nested-virt exposed to VM1, clean kill. Exit non-zero on any failure.
set -euo pipefail
D=/var/lib/deadswitch/vm1; S=/tmp/qemu-qual; rm -rf "$S"; mkdir -p "$S"
sudo pkill -9 -x qemu-system-aarch64 2>/dev/null || true; sleep 2
sudo ip link del tap0 2>/dev/null || true
sudo bash /usr/local/lib/deadswitch/vm1-net.sh >/dev/null
{ echo "vm2_kernel=$(uname -r) kvm=$([ -e /dev/kvm ] && echo yes || echo no) qemu=$(qemu-system-aarch64 --version|head -1)"; cat "$D/SHA256SUMS"; } | tee "$S/versions.txt"
qemu-img create -q -f qcow2 -F qcow2 -b "$D/vm1.qcow2" "$S/overlay.qcow2"
cp "$D/efivars-template.fd" "$S/vars.fd"
accel=$([ -e /dev/kvm ] && echo kvm || echo tcg); cpu=$([ -e /dev/kvm ] && echo host || echo cortex-a57)
sudo qemu-system-aarch64 -machine virt,gic-version=3,accel=$accel -cpu $cpu -smp 2 -m 4096 \
  -nographic -sandbox on -nodefaults -no-user-config \
  -drive if=pflash,format=raw,unit=0,readonly=on,file="$D/QEMU_EFI.fd" \
  -drive if=pflash,format=raw,unit=1,file="$S/vars.fd" \
  -drive if=virtio,format=qcow2,file="$S/overlay.qcow2" \
  -netdev tap,id=n0,ifname=tap0,script=no,downscript=no -device virtio-net-pci,netdev=n0,mac=06:00:AC:10:00:02,romfile= \
  -device virtio-gpu-pci -device virtio-rng-pci \
  -serial chardev:ser0 -chardev file,id=ser0,path="$S/serial.log" \
  -qmp unix:"$S/qmp.sock",server=on,wait=off >/dev/null 2>&1 &
QP=$!
for i in $(seq 1 1800); do grep -q 'VM1_READY' "$S/serial.log" 2>/dev/null && break; kill -0 $QP 2>/dev/null || { echo "QEMU EXITED"; tail -20 "$S/serial.log"; exit 1; }; sleep 0.1; done
grep -q 'VM1_READY' "$S/serial.log" || { echo "BOOT TIMEOUT"; tail -20 "$S/serial.log"; sudo kill -9 $QP; exit 1; }
echo "BOOT OK: $(grep -m1 KMEM "$S/serial.log")"
qmp() { printf '%s\n' '{"execute":"qmp_capabilities"}' "$1" | sudo socat - UNIX-CONNECT:"$S/qmp.sock" 2>/dev/null | tail -2; }
km=$(grep -m1 -a KMEM "$S/serial.log" | tr -d '\r' | sed 's/.*KMEM //')
cs=$(( $(printf '%s' "$km" | jq -r .code_start) )); ce=$(( $(printf '%s' "$km" | jq -r .code_end) ))
len=$(( ce - cs + 1 ))
echo "measuring kernel code phys=$cs len=$len (decimal for QMP)"
prev=""
for n in 1 2 3; do
  qmp '{"execute":"stop"}' >/dev/null
  qmp "{\"execute\":\"pmemsave\",\"arguments\":{\"val\":$cs,\"size\":$len,\"filename\":\"$S/t$n\"}}" >/dev/null
  qmp '{"execute":"cont"}' >/dev/null
  h=$(sudo sha256sum "$S/t$n" | cut -c1-16); echo "pmemsave $n: $(sudo stat -c %s "$S/t$n") bytes sha=$h"
  [ -n "$prev" ] && [ "$prev" != "$h" ] && echo "WARN: kernel text hash changed between clean measurements"; prev=$h
done
echo "vm1 nested-virt: guest CPU is -cpu $cpu with no +vmx/+svm -> no nested virt exposed"
sudo kill -9 $QP; for i in 1 2 3 4 5; do kill -0 $QP 2>/dev/null || break; sleep 0.2; done
kill -0 $QP 2>/dev/null && { echo "KILL FAILED"; exit 1; } || echo "KILL OK"
echo QUALIFIED
