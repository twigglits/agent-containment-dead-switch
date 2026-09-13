#!/bin/bash
# Phase 2 — deploy the SAME deadswitch-controller binary (Phase 1 ran it on the Mac) to the Hetzner
# Cloud controller node, bound to the WireGuard interface only (never the public NIC). Run from the
# ops workstation after `terraform apply` and after the WireGuard mesh is wired.
#
# Ships: the cross-compiled x86_64-musl controller binary, a systemd unit, and reuses the controller
# keypair/operator-token from Phase 1 (~/.deadswitch/controller) so the same pubkey stays authoritative
# — OR generates fresh ones on the node (choose per deployment; here we upload the existing ones so the
# enrolled hostd keys and CTL_PUB carry over). Secrets are scp'd over SSH, never baked into images.
#
# Env:
#   CONTROLLER_IP    public IPv4 of the Cloud controller (terraform output controller_ip)
#   CONTROLLER_WGIP  controller WireGuard IP            (default 10.20.0.1)
#   SSH_KEY          ops private key                    (default ~/.deadswitch/phase2/ops_ed25519)
#   BIN              controller binary                  (default target/x86_64-unknown-linux-musl/release/deadswitch-controller)
set -euo pipefail
CONTROLLER_IP="${CONTROLLER_IP:?set CONTROLLER_IP (terraform output controller_ip)}"
CONTROLLER_WGIP="${CONTROLLER_WGIP:-10.20.0.1}"
SSH_KEY="${SSH_KEY:-$HOME/.deadswitch/phase2/ops_ed25519}"
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
BIN="${BIN:-$REPO/target/x86_64-unknown-linux-musl/release/deadswitch-controller}"
CDIR="${CDIR:-$HOME/.deadswitch/controller}"
SSH=(ssh -i "$SSH_KEY" -o StrictHostKeyChecking=yes "root@$CONTROLLER_IP")
SCP=(scp -i "$SSH_KEY" -o StrictHostKeyChecking=yes)

[ -x "$BIN" ] || { echo "controller binary missing: $BIN (cargo zigbuild --release --target x86_64-unknown-linux-musl -p deadswitch-controller)"; exit 1; }
for f in controller.key operator.token hostd_pubkeys.txt; do [ -f "$CDIR/$f" ] || { echo "missing $CDIR/$f (run Phase 1 keygen/enroll first)"; exit 1; }; done

python3 - "$CONTROLLER_IP" "$CONTROLLER_WGIP" <<'PYCFG'
import ipaddress, sys
for address in sys.argv[1:]: ipaddress.IPv4Address(address)
PYCFG
echo "==> uploading binary + configuration to $CONTROLLER_IP (SSH host key must already be pinned)"
"${SSH[@]}" 'install -d -m0700 /etc/deadswitch/controller /var/lib/deadswitch/controller/state'
"${SCP[@]}" "$BIN" "root@$CONTROLLER_IP:/usr/local/sbin/deadswitch-controller"
"${SCP[@]}" "$CDIR/controller.key" "$CDIR/operator.token" "$CDIR/hostd_pubkeys.txt" "root@$CONTROLLER_IP:/etc/deadswitch/controller/"
"${SSH[@]}" 'chmod 0755 /usr/local/sbin/deadswitch-controller; chmod 0600 /etc/deadswitch/controller/*'

echo "==> installing systemd unit (bind :7100 to the WireGuard IP only)"
"${SSH[@]}" "cat > /etc/systemd/system/deadswitch-controller.service" <<UNIT
[Unit]
Description=deadswitch controller (Phase 2, off-host)
After=network-online.target wg-quick@wg0.service nftables.service
Requires=wg-quick@wg0.service nftables.service
Wants=network-online.target
[Service]
Environment=DS_LISTEN=${CONTROLLER_WGIP}:7100
Environment=DS_OPERATOR_LISTEN=127.0.0.1:7101
Environment=DS_STATE_DIR=/var/lib/deadswitch/controller/state
Environment=DS_KEY_FILE=/etc/deadswitch/controller/controller.key
Environment=DS_OPERATOR_TOKEN_FILE=/etc/deadswitch/controller/operator.token
Environment=DS_HOSTD_PUBKEYS_FILE=/etc/deadswitch/controller/hostd_pubkeys.txt
ExecStart=/usr/local/sbin/deadswitch-controller
Restart=always
RestartSec=2
User=root
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/deadswitch/controller
[Install]
WantedBy=multi-user.target
UNIT
"${SSH[@]}" 'systemctl daemon-reload && systemctl enable deadswitch-controller && systemctl restart deadswitch-controller && systemctl is-active deadswitch-controller'
echo "==> health check over WireGuard"
"${SSH[@]}" "curl -fsS http://${CONTROLLER_WGIP}:7100/health && echo"
echo "controller deployed at ${CONTROLLER_WGIP}:7100; operator API via SSH to 127.0.0.1:7101"
echo "Controller deployed; off-host cut/kill is operator-invoked via ds_kill.py. Automatic external expiry and a hardware termination observer are separate extensions."
