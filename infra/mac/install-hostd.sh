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
# pf MUST load and be enabled — a silent failure here would leave the gate ineffective (Codex #3).
pfctl -f /etc/pf.conf
pfctl -e 2>&1 | grep -qiE 'enabled|already enabled' || { pfctl -s info | grep -q 'Status: Enabled' || { echo "FATAL: pf not enabled"; exit 1; }; }
pfctl -s info | grep -q 'Status: Enabled' || { echo "FATAL: pf not enabled after enable"; exit 1; }

# Always-on independent watchdog daemon (KeepAlive): destroys any eval VM2 that loses its live lease
# handoff, so `kill -9` of a run process cannot leave VM2 alive (Codex end-of-P1 #1).
cat > /Library/LaunchDaemons/co.overdrive.deadswitch.guard.plist <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>Label</key><string>co.overdrive.deadswitch.guard</string>
  <key>ProgramArguments</key><array>
    <string>/usr/local/sbin/deadswitch-hostd</string><string>guard</string>
  </array>
  <key>KeepAlive</key><true/>
  <key>RunAtLoad</key><true/>
  <key>StandardOutPath</key><string>$STATE/guard.log</string>
  <key>StandardErrorPath</key><string>$STATE/guard.log</string>
</dict></plist>
PLIST
launchctl bootout system/co.overdrive.deadswitch.guard 2>/dev/null || true
launchctl bootstrap system /Library/LaunchDaemons/co.overdrive.deadswitch.guard.plist 2>/dev/null || launchctl load -w /Library/LaunchDaemons/co.overdrive.deadswitch.guard.plist
echo "guard daemon loaded (KeepAlive)"

cat > /etc/sudoers.d/deadswitch <<SUDO
$OWNER ALL=(root) NOPASSWD: /usr/local/sbin/deadswitch-hostd, /sbin/pfctl, /usr/bin/install -o root -g wheel -m 0755 $REPO/target/release/deadswitch-hostd /usr/local/sbin/deadswitch-hostd
$OWNER ALL=($SVC) NOPASSWD: /opt/homebrew/bin/limactl, /bin/bash
SUDO
chmod 0440 /etc/sudoers.d/deadswitch
visudo -cf /etc/sudoers.d/deadswitch
echo "installed: user $SVC, state $STATE, pf anchor deadswitch (sealed), sudoers for $OWNER"
pfctl -a deadswitch -sr
