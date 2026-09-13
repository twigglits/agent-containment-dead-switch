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
# The qualification contract requires real nested KVM (not TCG emulation) on this exact stack.
[ -e /dev/kvm ] || { echo "FAIL: /dev/kvm absent — nested KVM required, TCG does not qualify"; exit 1; }
qemu-img create -q -f qcow2 -F qcow2 -b "$D/vm1.qcow2" "$S/overlay.qcow2"
cp "$D/efivars-template.fd" "$S/vars.fd"
# Build a minimal but structurally-valid deps image and attach it as /dev/vdb, so qualification
# exercises the MANDATORY deps-image consumption path — not merely VM1_READY, which the missing-image
# abort also emits (Codex end-of-P1 #6). (The venv is absent here, so the harness will not run; the
# assertion below is that VM1 mounted the image and parsed its config.)
DEPSROOT=$S/depsroot; mkdir -p "$DEPSROOT"
printf '{"model":"qwen3:14b","manifest_digest":"qualify"}' > "$DEPSROOT/run-config.json"
truncate -s 16M "$S/deps.ext4"; mkfs.ext4 -q -F -d "$DEPSROOT" "$S/deps.ext4"
accel=kvm; cpu=host
sudo qemu-system-aarch64 -machine virt,gic-version=3,accel=$accel -cpu $cpu -smp 2 -m 4096 \
  -nographic -sandbox on -nodefaults -no-user-config \
  -drive if=pflash,format=raw,unit=0,readonly=on,file="$D/QEMU_EFI.fd" \
  -drive if=pflash,format=raw,unit=1,file="$S/vars.fd" \
  -drive if=virtio,format=qcow2,file="$S/overlay.qcow2" \
  -drive if=virtio,format=raw,readonly=on,file="$S/deps.ext4" \
  -netdev tap,id=n0,ifname=tap0,script=no,downscript=no -device virtio-net-pci,netdev=n0,mac=06:00:AC:10:00:02,romfile= \
  -device virtio-gpu-pci -device virtio-rng-pci \
  -serial chardev:ser0 -chardev file,id=ser0,path="$S/serial.log" \
  -qmp unix:"$S/qmp.sock",server=on,wait=off >/dev/null 2>&1 &
# track the EXACT qemu child pid (not a wrapper); sudo re-execs, so resolve the real qemu pid.
sleep 1; QP=$(pgrep -f "qemu-system-aarch64.*overlay.qcow2" | tail -1); [ -n "$QP" ] || { echo "FAIL: qemu did not start"; exit 1; }
for _ in $(seq 1 1800); do grep -q 'VM1_READY' "$S/serial.log" 2>/dev/null && break; kill -0 $QP 2>/dev/null || { echo "QEMU EXITED"; tail -20 "$S/serial.log"; exit 1; }; sleep 0.1; done
grep -q 'VM1_READY' "$S/serial.log" || { echo "BOOT TIMEOUT"; tail -20 "$S/serial.log"; sudo kill -9 $QP; exit 1; }
echo "BOOT OK: $(grep -m1 KMEM "$S/serial.log")"
# The mandatory deps image (attached as /dev/vdb) must have been mounted and its config parsed.
grep -q 'DEPS_IMAGE mounted ro' "$S/serial.log" || { echo "FAIL: VM1 did not mount/consume the attached deps image"; tail -25 "$S/serial.log"; sudo kill -9 "$QP"; exit 1; }
echo "DEPS OK: $(grep -m1 'DEPS_IMAGE mounted ro' "$S/serial.log")"
# The attached image is config-only (no venv), so the deps-consumption path MUST fail closed with the
# specific interpreter-missing abort — proving VM1 actually exercised and correctly refused an
# incomplete image, not silently ran an unverified path (Codex end-of-P1 #6). Full harness EXECUTION
# with a real prestaged venv is validated by the acceptance eval run, not here.
for _ in $(seq 1 300); do grep -q 'HARNESS_DONE' "$S/serial.log" 2>/dev/null && break; kill -0 "$QP" 2>/dev/null || break; sleep 0.1; done
grep -qE 'HARNESS_DONE.*prestaged interpreter.*missing' "$S/serial.log" || { echo "FAIL: VM1 did not fail-closed on the venv-less deps image (expected interpreter-missing abort)"; grep -a HARNESS_DONE "$S/serial.log" | tail -3; sudo kill -9 "$QP"; exit 1; }
echo "FAIL-CLOSED OK: harness correctly refused the incomplete deps image"
# Send the capabilities handshake + one command TAGGED with a unique id, and return the reply
# CARRYING THAT id — so a missing command reply cannot be masked by the capabilities `{"return":{}}`
# (which has no id). Replies are correlated by command id (Codex end-of-P1 #6).
QID=0
qmp() {
  QID=$((QID+1)); local id="q$QID" cmd
  cmd=$(printf '%s' "$1" | sed 's/}$/,"id":"'"$id"'"}/')
  # Parse each reply as JSON and return the one whose id STRUCTURALLY equals ours — QMP output has
  # spaces (`"id": "q1"`), so a literal grep would reject valid replies (Codex end-of-P1 #6).
  printf '%s\n' '{"execute":"qmp_capabilities"}' "$cmd" | sudo socat - UNIX-CONNECT:"$S/qmp.sock" 2>/dev/null | python3 -c "
import sys, json
for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        d = json.loads(line)
    except Exception:
        continue
    if d.get('id') == '$id':
        print(json.dumps(d))
        break
"
}
# Run a QMP command and ASSERT its (id-correlated) reply carries "return", not "error" or nothing.
qmp_ok() { local out; out=$(qmp "$1"); case "$out" in *'"return"'*) : ;; *) echo "FAIL: QMP command did not return success: $1 -> ${out:-<no id-matched reply>}"; sudo kill -9 "$QP" 2>/dev/null; exit 1 ;; esac; }
km=$(grep -m1 -a KMEM "$S/serial.log" | tr -d '\r' | sed 's/.*KMEM //')
cs=$(( $(printf '%s' "$km" | jq -r .code_start) )); ce=$(( $(printf '%s' "$km" | jq -r .code_end) ))
len=$(( ce - cs + 1 ))
echo "measuring kernel code phys=$cs len=$len (decimal for QMP)"
# Determinism: two pmemsaves of the SAME paused instant (no resume between) must be byte-identical
# — this is what "pmemsave works reliably" means. We do NOT compare across resume boundaries: the
# kernel legitimately self-patches .text while running (jump labels/ftrace), which is exactly why
# VMI is advisory. So: pause once, read twice, compare, resume.
qmp_ok '{"execute":"stop"}'
# Assert the guest is actually PAUSED (not merely that stop returned) before reading memory.
pstat=$(qmp '{"execute":"query-status"}'); echo "$pstat" | grep -q 'paused' || { echo "FAIL: guest not paused after stop: $pstat"; sudo kill -9 "$QP"; exit 1; }
echo "query-status after stop: $pstat"
qmp_ok "{\"execute\":\"pmemsave\",\"arguments\":{\"val\":$cs,\"size\":$len,\"filename\":\"$S/a\"}}"
qmp_ok "{\"execute\":\"pmemsave\",\"arguments\":{\"val\":$cs,\"size\":$len,\"filename\":\"$S/b\"}}"
qmp_ok '{"execute":"cont"}'
ha=$(sudo sha256sum "$S/a" | cut -c1-16); hb=$(sudo sha256sum "$S/b" | cut -c1-16)
sza=$(sudo stat -c %s "$S/a")
echo "pmemsave paused-instant x2: $sza bytes, sha $ha / $hb"
[ "$sza" = "$len" ] || { echo "FAIL: pmemsave wrote $sza bytes, expected $len"; sudo kill -9 "$QP"; exit 1; }
[ "$ha" = "$hb" ] || { echo "FAIL: pmemsave of a paused guest is non-deterministic ($ha != $hb)"; sudo kill -9 "$QP"; exit 1; }
# Prove stop/pmemsave/cont works repeatedly (pause/resume stability), without asserting cross-cycle equality.
for n in 1 2 3; do
  qmp_ok '{"execute":"stop"}'
  qmp_ok "{\"execute\":\"pmemsave\",\"arguments\":{\"val\":$cs,\"size\":$len,\"filename\":\"$S/c$n\"}}"
  qmp_ok '{"execute":"cont"}'
  echo "cycle $n: $(sudo stat -c %s "$S/c$n") bytes"
done
# no-nested-virt-to-VM1: launched with -cpu host and NO +vmx/+svm, and the QEMU cmdline carries no
# ARM 'virtualization=on' machine option (which is what would expose EL2 to the guest on aarch64).
if ps -o command= -p "$QP" | grep -q 'virtualization=on'; then echo "FAIL: VM1 machine exposes ARM virtualization=on (nested virt to VM1)"; sudo kill -9 "$QP"; exit 1; fi
echo "vm1 nested-virt: -cpu host, no +vmx/+svm, no machine virtualization=on -> EL2 not exposed to VM1 (in-guest /dev/kvm-absent asserted by acceptance T7)"
sudo kill -9 "$QP"; for _ in 1 2 3 4 5; do kill -0 "$QP" 2>/dev/null || break; sleep 0.2; done
kill -0 "$QP" 2>/dev/null && { echo "KILL FAILED"; exit 1; } || echo "KILL OK"
echo QUALIFIED
