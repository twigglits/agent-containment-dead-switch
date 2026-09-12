#!/bin/bash
# One-time (and after each hostd rebuild) install of the Mac-side trusted components. Run with sudo.
#  - creates the hidden service user _deadswitch that runs Lima (so pf can gate VM2 by user)
#  - installs hostd to /usr/local/sbin/deadswitch-hostd (root-owned)
#  - loads the "deadswitch" pf anchor (sealed by default) and enables pf
#  - sudoers: jean may run hostd, pfctl and limactl-as-_deadswitch without a password
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run with sudo"; exit 1; }
REPO=$(cd "$(dirname "$0")/../.." && pwd)
OWNER=${SUDO_USER:-jean}
STATE=/var/lib/deadswitch
SVC=_deadswitch

if ! id "$SVC" >/dev/null 2>&1; then
  uid=450; while dscl . -search /Users UniqueID "$uid" | grep -q UniqueID; do uid=$((uid+1)); done
  dscl . -create /Users/$SVC UniqueID "$uid"
  dscl . -create /Users/$SVC Password '*'
  dscl . -create /Users/$SVC PrimaryGroupID 20
  dscl . -create /Users/$SVC UserShell /bin/bash
  dscl . -create /Users/$SVC NFSHomeDirectory $STATE/home
  dscl . -create /Users/$SVC RealName "deadswitch Lima runner"
  dscl . -create /Users/$SVC IsHidden 1
fi
mkdir -p $STATE/home $STATE/lima $STATE/evidence $STATE/keys
chown -R $SVC:staff $STATE/home $STATE/lima
chmod 700 $STATE/keys $STATE/evidence

if [ -f "$REPO/target/release/deadswitch-hostd" ]; then
  install -o root -g wheel -m 0755 "$REPO/target/release/deadswitch-hostd" /usr/local/sbin/deadswitch-hostd
fi
install -o root -g wheel -m 0644 "$REPO/infra/mac/pf-deadswitch.conf" /etc/pf.anchors/deadswitch
grep -q 'anchor "deadswitch"' /etc/pf.conf || printf '\nanchor "deadswitch"\nload anchor "deadswitch" from "/etc/pf.anchors/deadswitch"\n' >> /etc/pf.conf
pfctl -q -f /etc/pf.conf 2>/dev/null || true
pfctl -q -e 2>/dev/null || true

cat > /etc/sudoers.d/deadswitch <<SUDO
$OWNER ALL=(root) NOPASSWD: /usr/local/sbin/deadswitch-hostd, /sbin/pfctl, /usr/bin/install -o root -g wheel -m 0755 $REPO/target/release/deadswitch-hostd /usr/local/sbin/deadswitch-hostd
$OWNER ALL=($SVC) NOPASSWD: /opt/homebrew/bin/limactl, /bin/bash
SUDO
chmod 0440 /etc/sudoers.d/deadswitch
visudo -cf /etc/sudoers.d/deadswitch
echo "installed: user $SVC, state $STATE, pf anchor deadswitch (sealed), sudoers for $OWNER"
pfctl -a deadswitch -sr
