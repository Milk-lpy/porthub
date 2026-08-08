#!/usr/bin/env bash
# install-relay.sh — create the porthub-relay runtime user, data directory,
# install the systemd unit and start the relay service. Safe to re-run.
set -euo pipefail

# Derive the repo root from this script's location so the script works from
# any checkout directory (no hard-coded project path).
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

RELAY_USER="porthub-relay"
RELAY_GROUP="porthub"          # read access for netd-written config
DATA_DIR="/var/lib/porthub/relay"
UNIT_SRC="$REPO_DIR/deploy/porthub-relay.service"
UNIT_DST="/etc/systemd/system/porthub-relay.service"
BIN_SRC="$REPO_DIR/bin/porthub-relay"
BIN_DST="/opt/porthub/bin/porthub-relay"
CONFIG_FILE="$DATA_DIR/config.json"

if [[ $EUID -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

# 1. Runtime user (system, no login, no home).
if ! id "$RELAY_USER" &>/dev/null; then
  useradd --system --no-create-home --shell /usr/sbin/nologin "$RELAY_USER"
  echo "created user $RELAY_USER"
fi
# The relay must be in the porthub group so it can read the config file
# netd writes (root:porthub 0640) and the runtime directory.
usermod -aG "$RELAY_GROUP" "$RELAY_USER" 2>/dev/null || true

# 2. Data directory owned by the relay user, with an initial empty config so
#    the unit's ConditionPathExists passes on a fresh install.
mkdir -p "$DATA_DIR"
chown "$RELAY_USER":"$RELAY_GROUP" "$DATA_DIR"
chmod 0750 "$DATA_DIR"
if [[ ! -f "$CONFIG_FILE" ]]; then
  printf '{"rules":[]}\n' > "$CONFIG_FILE"
  chown "$RELAY_USER":"$RELAY_GROUP" "$CONFIG_FILE"
  chmod 0640 "$CONFIG_FILE"
  echo "created initial $CONFIG_FILE"
fi

# 3. Binary.
if [[ -f "$BIN_SRC" ]]; then
  install -o root -g root -m 0755 "$BIN_SRC" "$BIN_DST"
  echo "installed $BIN_DST"
else
  echo "WARNING: $BIN_SRC missing; building..." >&2
  (cd "$REPO_DIR" && make build)
  install -o root -g root -m 0755 "$BIN_SRC" "$BIN_DST"
fi

# 4. systemd unit (from the repo deploy dir when present).
if [[ -f "$UNIT_SRC" ]]; then
  install -o root -g root -m 0644 "$UNIT_SRC" "$UNIT_DST"
else
  cat > "$UNIT_DST" <<'EOF'
[Unit]
Description=PortHub Relay (cross-family port forwarding)
After=network.target
Wants=network.target

[Service]
Type=simple
User=porthub-relay
Group=porthub
ExecStart=/opt/porthub/bin/porthub-relay -config /var/lib/porthub/relay/config.json -status /var/lib/porthub/relay/status.json -poll 5
Restart=always
RestartSec=3
# Sandbox: no privilege escalation, no new privileges, read-only root.
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
ReadWritePaths=/var/lib/porthub/relay

[Install]
WantedBy=multi-user.target
EOF
  echo "wrote default unit to $UNIT_DST"
fi

systemctl daemon-reload
systemctl enable porthub-relay
systemctl restart porthub-relay
systemctl --no-pager --full status porthub-relay | head -12
echo "porthub-relay installed and started."
