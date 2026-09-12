#!/bin/bash
# Runs INSIDE VM2 (gate OPEN) during base provisioning. Builds the browser VM1 image by BOOTING the
# Ubuntu cloud image under QEMU/KVM (the same nested path VM1 uses at runtime) with a cloud-init
# NoCloud seed that installs Playwright Chromium + Xvfb + the harness + the init unit, then powers
# off. Output: /var/lib/deadswitch/vm1/{vm1.qcow2,QEMU_EFI.fd,efivars-template.fd,SHA256SUMS}
set -euxo pipefail
OUT=/var/lib/deadswitch/vm1; P=/tmp/payload
mkdir -p "$OUT"; cd "$OUT"
IMG_URL="https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-arm64.img"
[ -f base-cloud.img ] || { curl -fsSL "$IMG_URL" -o base-cloud.img; echo "$IMG_URL" > vm1.qcow2.source; }
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
runcmd:
  - [ bash, -c, "mkdir -p /opt/harness && base64 -d /tmp/harness.tgz.b64 | tar xz -C /opt/harness" ]
  - [ bash, -c, "python3 -m venv /opt/harness/venv" ]
  - [ bash, -c, "/opt/harness/venv/bin/pip install --no-input playwright" ]
  - [ bash, -c, "/opt/harness/venv/bin/pip install --no-input -e /opt/harness || true" ]
  - [ bash, -c, "/opt/harness/venv/bin/python -m playwright install-deps chromium" ]
  - [ bash, -c, "PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright /opt/harness/venv/bin/python -m playwright install chromium" ]
  - [ bash, -c, "echo PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright >> /etc/environment" ]
  - [ bash, -c, "systemctl enable deadswitch-vm1-init.service" ]
  - [ bash, -c, "systemctl disable systemd-networkd-wait-online.service ssh.service snapd.service unattended-upgrades.service || true" ]
  - [ bash, -c, "systemctl mask apt-daily.timer apt-daily-upgrade.timer motd-news.timer || true" ]
  - [ bash, -c, "rm -f /etc/netplan/50-cloud-init.yaml /etc/netplan/*.yaml.bak" ]
  - [ bash, -c, "cp /etc/netplan/50-deadswitch.yaml /root/50-deadswitch.yaml.keep" ]
  - [ bash, -c, "printf 'network: {config: disabled}\n' > /etc/cloud/cloud.cfg.d/99-disable-network.cfg" ]
  - [ bash, -c, "touch /etc/cloud/cloud-init.disabled" ]
  - [ bash, -c, "cp /root/50-deadswitch.yaml.keep /etc/netplan/50-deadswitch.yaml && chmod 600 /etc/netplan/50-deadswitch.yaml" ]
  - [ bash, -c, "passwd -l root || true" ]
  - [ bash, -c, "mkdir -p /opt/obscura && curl -fsSL https://github.com/h4ckf0r0day/obscura/releases/download/v0.2.2/obscura-aarch64-linux-stealth.tar.gz -o /tmp/obscura.tgz && tar xzf /tmp/obscura.tgz -C /opt/obscura && (test -x /opt/obscura/obscura || mv /opt/obscura/*/obscura /opt/obscura/obscura 2>/dev/null || true) && chmod +x /opt/obscura/obscura && sha256sum /tmp/obscura.tgz > /opt/obscura/SHA256SUM" ]
  - [ bash, -c, "touch /var/lib/deadswitch-build-ok" ]
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

grep -qE 'reboot: Power down|Reached target.*[Pp]oweroff|Power down' "$OUT/build-serial.log" || { echo "BUILD VM did not power off cleanly"; tail -40 "$OUT/build-serial.log"; }
rm -f "$OUT/seed.iso" "$OUT/build-vars.fd" user-data meta-data
sha256sum vm1.qcow2 QEMU_EFI.fd efivars-template.fd > SHA256SUMS
cat SHA256SUMS
