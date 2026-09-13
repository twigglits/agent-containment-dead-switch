#!/bin/bash
# Runs INSIDE the base VM2 as root during hostd provision-base (gate OPEN). Installs QEMU + tooling,
# the supervisor, the harness source, vm1-net, and builds the browser-capable VM1 image.
set -euxo pipefail
P=/tmp/payload
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  qemu-system-arm qemu-utils qemu-efi-aarch64 cloud-image-utils genisoimage \
  nftables conntrack ca-certificates curl jq socat
install -m 0755 "$P/deadswitch-supervisor" /usr/local/bin/deadswitch-supervisor
install -d -m 0755 /usr/local/lib/deadswitch
install -m 0755 "$P/vm1-net.sh" /usr/local/lib/deadswitch/vm1-net.sh
install -m 0755 "$P/qualify-vm1.sh" /usr/local/lib/deadswitch/qualify-vm1.sh
install -d -m 0700 /etc/deadswitch
install -d -m 0755 /var/lib/deadswitch/vm1 /var/lib/deadswitch/harness /var/lib/deadswitch/run
cp -r "$P/harness/." /var/lib/deadswitch/harness/
# lock the harness deps against the running uv so prestage can run --frozen --no-build
cd /var/lib/deadswitch/harness && /usr/local/bin/uv lock
id prestage >/dev/null 2>&1 || useradd -r -m -d /var/lib/deadswitch/prestage -s /usr/sbin/nologin prestage
install -d -m 0755 -o prestage -g prestage /var/lib/deadswitch/prestage
# build the VM1 browser image (heavy; downloads Ubuntu cloud image + Playwright Chromium)
bash "$P/build-vm1-image.sh"
# Qualify the exact image just built, inside this VM2, before it can become the stopped base.
# pipefail preserves the gate's failure through tee; retain the result beside the image digests.
bash /usr/local/lib/deadswitch/qualify-vm1.sh | tee /var/lib/deadswitch/vm1/qualification.log
echo "supervisor $(/usr/local/bin/deadswitch-supervisor --help >/dev/null 2>&1 && echo ok); qemu $(qemu-system-aarch64 --version | head -1)"
