#!/usr/bin/env bash
# uninstall-relay.sh — stop and remove the porthub-relay service, unit file,
# data directory and runtime user. Does NOT touch core/netd/agent binaries.
set -euo pipefail

RELAY_USER="porthub-relay"
DATA_DIR="/var/lib/porthub/relay"
UNIT_DST="/etc/systemd/system/porthub-relay.service"
BIN_DST="/opt/porthub/bin/porthub-relay"

if [[ $EUID -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

systemctl disable --now porthub-relay 2>/dev/null || true
rm -f "$UNIT_DST"
systemctl daemon-reload
rm -rf "$DATA_DIR"
rm -f "$BIN_DST"
if id "$RELAY_USER" &>/dev/null; then
  userdel "$RELAY_USER"
  echo "removed user $RELAY_USER"
fi
echo "porthub-relay removed."
