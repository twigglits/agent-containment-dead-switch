#!/bin/bash
# ONE-TIME offline-image preparation, on an idle x86_64 eval host with nested KVM and build-time
# internet. Both VM2 and VM1 are provisioned here; runtime boot attaches only VM2's pure-L3 tap.
# Do not run alongside evalagent or an untrusted workload. This script never opens the sealed gate.
set -euxo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/network-config.sh"
[ "$(id -u)" = 0 ] || { echo 'must run as root on the build host' >&2; exit 1; }
DIR="${DS_VM2_DIR:-/var/lib/deadswitch/vm2}"
if pgrep -f 'qemu-system-x86_64 -name deadswitch-vm2' >/dev/null 2>&1; then
  echo 'stop evalagent and destroy the runtime workload before rebuilding' >&2; exit 1
fi
mkdir -p "$DIR"
cd "$DIR"
IMG_URL="https://cloud-images.ubuntu.com/releases/noble/release/ubuntu-24.04-server-cloudimg-amd64.img"
export DS_MODEL="${DS_MODEL-qwen2.5:7b}"
# Encode configurable text instead of interpolating it into JSON, YAML, or shell source.
REQUEST_B64=$(python3 - <<'PY'
import base64, json, os
model = os.environ['DS_MODEL']
assert model and len(model) <= 256 and all(ord(c) >= 32 for c in model), 'invalid pinned DS_MODEL'
request = {'model': model, 'messages': [{'role': 'user', 'content': 'Reply with exactly OK.'}],
           'stream': False, 'n': 1, 'max_tokens': 16}
print(base64.b64encode(json.dumps(request, separators=(',', ':')).encode()).decode())
PY
)
[ -f base.img ] || curl -fsSL --retry 5 -C - --max-time 1800 "$IMG_URL" -o base.img
rm -f vm2.qcow2
qemu-img convert -O qcow2 base.img vm2.qcow2
qemu-img resize vm2.qcow2 20G

# VM1 is provisioned during VM2's build (nested usernet has internet only during this stage).
# The workload unit is enabled but not started until VM1's NEXT boot, behind the host gate.
VM1_USERDATA_B64=$(base64 <<VM1 | tr -d '\n'
#cloud-config
package_update: true
packages: [curl, ca-certificates]
write_files:
  - path: /etc/deadswitch/request.json
    encoding: b64
    content: $REQUEST_B64
  - path: /usr/local/bin/ds-workload
    permissions: '0755'
    content: |
      #!/bin/bash
      # Nested QEMU usernet makes this traffic originate from VM2 (DS_VM2_IP) at the host tap.
      # Every loop performs one bounded exact-action POST using a fresh curl process.
      while true; do
        c=\$(curl --noproxy '*' --http1.1 -s -m 10 -o /dev/null -w '%{http_code}' \\
          -H 'Content-Type: application/json' -X POST --data-binary @/etc/deadswitch/request.json \\
          http://$HOSTD_IP:7001/v1/chat/completions 2>/dev/null || printf FAIL)
        r=\$(curl --noproxy '*' -s -m 2 -o /dev/null -w '%{http_code}' http://$CHOKE_WGIP:11434/api/version 2>/dev/null || printf BLOCKED)
        x=\$(curl --noproxy '*' -s -m 2 -o /dev/null -w '%{http_code}' http://1.1.1.1/ 2>/dev/null || printf BLOCKED)
        echo "DS_WORKLOAD proxy=\$c raw_backend_canary=\$r external_canary=\$x \$(date -u +%H:%M:%S)" > /dev/ttyS0
        sleep 5
      done
  - path: /etc/systemd/system/deadswitch-workload.service
    content: |
      [Unit]
      Description=deadswitch bounded inference workload
      Wants=network-online.target
      After=network-online.target
      [Service]
      ExecStart=/usr/local/bin/ds-workload
      Restart=no
      [Install]
      WantedBy=multi-user.target
  - path: /usr/local/sbin/finish-deadswitch-vm1-build
    permissions: '0755'
    content: |
      #!/bin/bash
      set -euo pipefail
      command -v curl
      test -s /etc/deadswitch/request.json
      systemctl enable deadswitch-workload.service
      systemctl mask serial-getty@ttyS0.service
      touch /etc/cloud/cloud-init.disabled
      echo DEADSWITCH_VM1_BUILD_OK > /dev/ttyS0
runcmd:
  - [bash, /usr/local/sbin/finish-deadswitch-vm1-build]
power_state: {mode: poweroff, timeout: 120, condition: true}
VM1
)

# VM2 provisions with DHCP on QEMU usernet. Only after every fetch and nested build succeeds do we
# stage runtime netplan (without applying it during this build) and disable further cloud-init runs.
cat > user-data <<YAML
#cloud-config
package_update: true
packages: [qemu-system-x86, qemu-utils, cloud-image-utils, curl, ca-certificates]
write_files:
  - path: /var/lib/vm1/user-data.b64
    content: $VM1_USERDATA_B64
  - path: /var/lib/deadswitch/runtime-netplan.yaml
    permissions: '0600'
    content: |
      network:
        version: 2
        renderer: networkd
        ethernets:
          workload:
            match: {macaddress: '52:54:00:99:00:02'}
            set-name: ds0
            dhcp4: false
            dhcp6: false
            accept-ra: false
            link-local: []
            addresses: [$DS_VM2_IP/$DS_WL_PREFIXLEN]
            routes:
              - to: default
                via: $HOSTD_IP
  - path: /usr/local/bin/boot-vm1
    permissions: '0755'
    content: |
      #!/bin/bash
      set -euo pipefail
      exec qemu-system-x86_64 -machine q35,accel=kvm -cpu host,-vmx -smp 2 -m 4096 \\
        -nographic -nodefaults -no-user-config \\
        -drive if=virtio,format=qcow2,file=/var/lib/vm1/vm1.qcow2 \\
        -netdev user,id=n0 -device virtio-net-pci,netdev=n0,mac=52:54:00:99:01:02,romfile= \\
        -device virtio-rng-pci -serial file:/var/log/vm1-serial.log -display none
  - path: /etc/systemd/system/deadswitch-vm1.service
    content: |
      [Unit]
      Description=deadswitch nested VM1 workload
      Wants=network-online.target
      After=network-online.target
      [Service]
      ExecStart=/usr/local/bin/boot-vm1
      Restart=no
      [Install]
      WantedBy=multi-user.target
  - path: /usr/local/sbin/finish-deadswitch-vm2-build
    permissions: '0755'
    content: |
      #!/bin/bash
      set -euo pipefail
      command -v qemu-system-x86_64
      command -v cloud-localds
      curl -fsSL --retry 5 --max-time 1800 $IMG_URL -o /var/lib/vm1/base.img
      qemu-img convert -O qcow2 /var/lib/vm1/base.img /var/lib/vm1/vm1.qcow2
      qemu-img resize /var/lib/vm1/vm1.qcow2 8G
      base64 -d /var/lib/vm1/user-data.b64 > /var/lib/vm1/user-data
      printf 'instance-id: vm1\nlocal-hostname: vm1\n' > /var/lib/vm1/meta-data
      cloud-localds /var/lib/vm1/seed.iso /var/lib/vm1/user-data /var/lib/vm1/meta-data
      timeout 1800 qemu-system-x86_64 -machine q35,accel=kvm -cpu host,-vmx -smp 2 -m 4096 \\
        -nographic -nodefaults -no-user-config \\
        -drive if=virtio,format=qcow2,file=/var/lib/vm1/vm1.qcow2 \\
        -drive if=virtio,format=raw,readonly=on,file=/var/lib/vm1/seed.iso \\
        -netdev user,id=n0 -device virtio-net-pci,netdev=n0,mac=52:54:00:99:01:02,romfile= \\
        -device virtio-rng-pci -serial file:/var/log/vm1-build-serial.log -display none
      grep -q DEADSWITCH_VM1_BUILD_OK /var/log/vm1-build-serial.log
      rm -f /var/lib/vm1/seed.iso /var/lib/vm1/user-data /var/lib/vm1/user-data.b64 /var/lib/vm1/meta-data /var/lib/vm1/base.img
      # Cloud-init's build-time DHCP netplan must not survive as a second runtime network definition.
      rm -f /etc/netplan/*.yaml /etc/netplan/*.yml
      install -m 600 /var/lib/deadswitch/runtime-netplan.yaml /etc/netplan/50-deadswitch.yaml
      netplan generate
      systemctl enable systemd-networkd.service
      systemctl enable deadswitch-vm1.service
      systemctl mask serial-getty@ttyS0.service
      touch /etc/cloud/cloud-init.disabled
      echo DEADSWITCH_VM2_BUILD_OK > /dev/ttyS0
runcmd:
  - [bash, /usr/local/sbin/finish-deadswitch-vm2-build]
power_state: {mode: poweroff, timeout: 120, condition: true}
YAML
printf 'instance-id: vm2\nlocal-hostname: vm2-build\n' > meta-data
cloud-localds seed.iso user-data meta-data

# A timeout or failed QEMU is a build failure even if a success marker appeared earlier.
if ! timeout 3600 qemu-system-x86_64 -machine q35,accel=kvm -cpu host -smp 4 -m 16384 \
  -nographic -nodefaults -no-user-config \
  -drive if=virtio,format=qcow2,file=vm2.qcow2 \
  -drive if=virtio,format=raw,readonly=on,file=seed.iso \
  -netdev user,id=n0 -device virtio-net-pci,netdev=n0,mac=52:54:00:99:00:02,romfile= \
  -device virtio-rng-pci -serial file:vm2-build-serial.log -display none; then
  echo 'VM2 BUILD FAILED (QEMU failed or timed out)' >&2; exit 1
fi

grep -q DEADSWITCH_VM2_BUILD_OK vm2-build-serial.log || { echo 'VM2 BUILD FAILED' >&2; tail -60 vm2-build-serial.log; exit 1; }
rm -f seed.iso user-data meta-data
echo "VM2 image built: $DIR/vm2.qcow2 (offline nested VM1; proxy=$HOSTD_IP:7001; model=$DS_MODEL)"
