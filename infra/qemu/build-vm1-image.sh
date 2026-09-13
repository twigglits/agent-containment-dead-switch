#!/bin/bash
# Runs INSIDE VM2 (gate OPEN) during base provisioning. Builds the browser VM1 image by BOOTING the
# Ubuntu cloud image under QEMU/KVM (the same nested path VM1 uses at runtime) with a cloud-init
# NoCloud seed that installs Playwright Chromium + Xvfb + the harness + the init unit, then powers
# off. Output: /var/lib/deadswitch/vm1/{vm1.qcow2,QEMU_EFI.fd,efivars-template.fd,SHA256SUMS}
set -euxo pipefail
OUT=/var/lib/deadswitch/vm1; P=/tmp/payload
mkdir -p "$OUT"; cd "$OUT"
IMG_URL="https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img"
# Prefer a base cloud image STAGED in the payload (copied into VM2 locally) so provisioning does not
# re-download ~348MB over the guest's usernet every time — that download stalled for >1h once. Fall
# back to a bounded, resuming download only if no staged image is present.
if [ -f /tmp/payload/base-cloud.img ]; then
  cp /tmp/payload/base-cloud.img base-cloud.img; echo "using staged base-cloud.img from payload ($(du -h base-cloud.img | cut -f1))"
elif [ ! -f base-cloud.img ]; then
  curl -fsSL --retry 5 --retry-delay 3 -C - --max-time 1800 "$IMG_URL" -o base-cloud.img; echo "$IMG_URL" > vm1.qcow2.source
fi
rm -f vm1.qcow2
qemu-img convert -O qcow2 base-cloud.img vm1.qcow2
qemu-img resize vm1.qcow2 12G
cp /usr/share/AAVMF/AAVMF_CODE.fd  "$OUT/QEMU_EFI.fd"
cp /usr/share/AAVMF/AAVMF_VARS.fd  "$OUT/efivars-template.fd"
cp "$OUT/efivars-template.fd" "$OUT/build-vars.fd"

# ---- cloud-init seed: install everything, then power off
HARNESS_B64=$(tar czf - -C "$P/harness" . | base64 -w0)
NETPLAN_B64=$(base64 -w0 < "$P/50-deadswitch.yaml")
INIT_B64=$(base64 -w0 < "$P/vm1-init.sh")
UNIT_B64=$(base64 -w0 < "$P/deadswitch-vm1-init.service")
# Build-verification script written into the guest and run there — kept as a base64 blob so the
# unquoted user-data heredoc below cannot expand its $(...) / $VAR on the HOST (which broke the old
# inline runcmd) (Codex end-of-P1 #5). It actually EXECUTES obscura and a Playwright browser binary,
# not just tests directory existence, and only then emits the DEADSWITCH_BUILD_OK marker.
VERIFY_B64=$(base64 -w0 <<'VERIFY'
#!/bin/bash
set -e
test -x /opt/obscura/obscura
(/opt/obscura/obscura --version || /opt/obscura/obscura --help) >/dev/null 2>&1
test -x /opt/harness/venv/bin/python
ok=
for c in /opt/ms-playwright/chromium-*/chrome-linux/chrome /opt/ms-playwright/chromium_headless_shell-*/chrome-linux/headless_shell; do
  [ -x "$c" ] || continue
  if "$c" --version >/dev/null 2>&1 || "$c" --headless --version >/dev/null 2>&1 || "$c" --no-sandbox --version >/dev/null 2>&1; then ok=1; break; fi
done
test -n "$ok"
command -v python3 >/dev/null
# ttyAMA0 carries the harness protocol. A login getty must never reset/hang up its open writers.
test "$(systemctl is-enabled serial-getty@ttyAMA0.service)" = masked
touch /var/lib/deadswitch-build-ok
echo DEADSWITCH_BUILD_OK > /dev/console
VERIFY
)
cat > user-data <<YAML
#cloud-config
package_update: true
packages: [python3, python3-venv, python3-pip, xvfb, ca-certificates, fonts-liberation, x11-utils]
write_files:
  - path: /tmp/harness.tgz.b64
    content: ${HARNESS_B64}
  - path: /etc/netplan/50-deadswitch.yaml
    permissions: '0600'
    encoding: b64
    content: ${NETPLAN_B64}
  - path: /usr/local/bin/deadswitch-vm1-init
    permissions: '0755'
    encoding: b64
    content: ${INIT_B64}
  - path: /etc/systemd/system/deadswitch-vm1-init.service
    encoding: b64
    content: ${UNIT_B64}
  - path: /usr/local/bin/deadswitch-verify-build
    permissions: '0755'
    encoding: b64
    content: ${VERIFY_B64}
runcmd:
  - [ bash, -c, "mkdir -p /opt/harness && base64 -d /tmp/harness.tgz.b64 | tar xz -C /opt/harness" ]
  - [ bash, -c, "python3 -m venv /opt/harness/venv" ]
  - [ bash, -c, "/opt/harness/venv/bin/pip install --no-input playwright" ]
  - [ bash, -c, "/opt/harness/venv/bin/pip install --no-input -e /opt/harness || true" ]
  - [ bash, -c, "/opt/harness/venv/bin/python -m playwright install-deps chromium" ]
  - [ bash, -c, "PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright /opt/harness/venv/bin/python -m playwright install chromium" ]
  - [ bash, -c, "echo PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright >> /etc/environment" ]
  - [ bash, -c, "systemctl enable deadswitch-vm1-init.service" ]
  - [ bash, -c, "systemctl mask serial-getty@ttyAMA0.service" ]
  - [ bash, -c, "systemctl disable systemd-networkd-wait-online.service ssh.service snapd.service unattended-upgrades.service || true" ]
  - [ bash, -c, "systemctl mask apt-daily.timer apt-daily-upgrade.timer motd-news.timer || true" ]
  - [ bash, -c, "rm -f /etc/netplan/50-cloud-init.yaml /etc/netplan/*.yaml.bak" ]
  - [ bash, -c, "cp /etc/netplan/50-deadswitch.yaml /root/50-deadswitch.yaml.keep" ]
  - [ bash, -c, "printf 'network: {config: disabled}\n' > /etc/cloud/cloud.cfg.d/99-disable-network.cfg" ]
  - [ bash, -c, "touch /etc/cloud/cloud-init.disabled" ]
  - [ bash, -c, "cp /root/50-deadswitch.yaml.keep /etc/netplan/50-deadswitch.yaml && chmod 600 /etc/netplan/50-deadswitch.yaml" ]
  - [ bash, -c, "passwd -l root || true" ]
  - [ bash, -c, "set -euo pipefail; mkdir -p /opt/obscura; curl -fsSL https://github.com/h4ckf0r0day/obscura/releases/download/v0.2.2/obscura-aarch64-linux-stealth.tar.gz -o /tmp/obscura.tgz; echo '5fc7e90393e38dc60288381a523eaf8dddb9a1e2925874844c8433a69bdf75c1  /tmp/obscura.tgz' | sha256sum -c -; tar xzf /tmp/obscura.tgz -C /opt/obscura; test -x /opt/obscura/obscura || mv /opt/obscura/*/obscura /opt/obscura/obscura; chmod +x /opt/obscura/obscura; if [ -f /opt/obscura/obscura-worker ]; then chmod +x /opt/obscura/obscura-worker; fi; sha256sum /tmp/obscura.tgz > /opt/obscura/SHA256SUM; test -x /opt/obscura/obscura" ]
  - [ bash, -c, "bash /usr/local/bin/deadswitch-verify-build" ]
power_state: { mode: poweroff, timeout: 60, condition: true }
YAML
printf 'instance-id: build\nlocal-hostname: vm1-build\n' > meta-data
cloud-localds seed.iso user-data meta-data

# ---- boot the build VM with internet via user-mode NIC (NOT tap0); wait for cloud-init poweroff
accel=$([ -e /dev/kvm ] && echo kvm || echo tcg); cpu=$([ -e /dev/kvm ] && echo host || echo cortex-a57)
timeout 2400 qemu-system-aarch64 -machine virt,gic-version=3,accel=$accel -cpu $cpu -smp 2 -m 4096 \
  -nographic -nodefaults -no-user-config \
  -drive if=pflash,format=raw,unit=0,readonly=on,file="$OUT/QEMU_EFI.fd" \
  -drive if=pflash,format=raw,unit=1,file="$OUT/build-vars.fd" \
  -drive if=virtio,format=qcow2,file="$OUT/vm1.qcow2" \
  -drive if=virtio,format=raw,readonly=on,file="$OUT/seed.iso" \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0,romfile= \
  -device virtio-rng-pci \
  -serial file:"$OUT/build-serial.log" -display none || true

grep -qE 'reboot: Power down|Reached target.*[Pp]oweroff|Power down' "$OUT/build-serial.log" || { echo "BUILD FAILED: VM did not power off cleanly"; tail -60 "$OUT/build-serial.log"; exit 1; }
# The build is only usable if obscura + Playwright browsers + the venv all verified inside the guest.
# cloud-init runcmds do NOT fail the build on their own (it powers off regardless), so we require the
# guest to have emitted the verification marker to the console (Codex end-of-P1 #5). A checksum
# mismatch, a failed obscura extract, or a missing browser aborts that runcmd => marker absent => fail.
grep -q 'DEADSWITCH_BUILD_OK' "$OUT/build-serial.log" || { echo "BUILD FAILED: verification marker absent (obscura/playwright/venv install failed inside VM1 build)"; tail -80 "$OUT/build-serial.log"; exit 1; }
rm -f "$OUT/seed.iso" "$OUT/build-vars.fd" user-data meta-data
sha256sum vm1.qcow2 QEMU_EFI.fd efivars-template.fd > SHA256SUMS
cat SHA256SUMS
echo "VM1 image build verified (DEADSWITCH_BUILD_OK)"
