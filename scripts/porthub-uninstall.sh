#!/usr/bin/env bash
set -euo pipefail

mode="dry-run"
root=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --execute)
      mode="execute"
      shift
      ;;
    --root)
      root="${2:-}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -n "$root" ]]; then
  root="$(cd "$root" && pwd)"
  if [[ "$root" == "/" ]]; then
    echo "--root must not be /" >&2
    exit 2
  fi
fi

services=(
  "porthub-core.service"
  "porthub-edge.service"
  "porthub-agent.service"
  "porthub-netd.service"
  "porthub-relay.service"
  "wg-quick@wg-porthub.service"
)

paths=(
  "/opt/porthub"
  "/etc/porthub"
  "/var/lib/porthub"
  "/var/log/porthub"
  "/var/backups/porthub"
  "/etc/wireguard/wg-porthub.conf"
  "/etc/sysctl.d/99-porthub.conf"
)

units=(
  "/etc/systemd/system/porthub-core.service"
  "/etc/systemd/system/porthub-edge.service"
  "/etc/systemd/system/porthub-agent.service"
  "/etc/systemd/system/porthub-netd.service"
  "/etc/systemd/system/porthub-relay.service"
)

run() {
  if [[ "$mode" == "dry-run" ]]; then
    printf '[dry-run]'
    for arg in "$@"; do
      printf ' %q' "$arg"
    done
    printf '\n'
  else
    "$@"
  fi
}

target_path() {
  local path="$1"
  if [[ -z "$root" ]]; then
    printf '%s\n' "$path"
    return
  fi
  printf '%s/%s\n' "$root" "${path#/}"
}

echo "PortHub uninstall mode: $mode"
echo "This script only targets PortHub-owned resources."

if [[ -z "$root" ]]; then
  for svc in "${services[@]}"; do
    if systemctl list-unit-files "$svc" >/dev/null 2>&1 || systemctl status "$svc" >/dev/null 2>&1; then
      run systemctl disable --now "$svc"
    fi
  done

  if command -v nft >/dev/null 2>&1 && nft list table inet porthub >/dev/null 2>&1; then
    run nft delete table inet porthub
  fi

  if command -v nft >/dev/null 2>&1 && nft list table inet porthub_core >/dev/null 2>&1; then
    run nft delete table inet porthub_core
  fi

  if command -v wg >/dev/null 2>&1 && wg show wg-porthub >/dev/null 2>&1; then
    run wg-quick down wg-porthub
  fi
else
  echo "Test root active: $root"
  echo "Skipping systemctl, nft and wg operations in test-root mode."
fi

for unit in "${units[@]}"; do
  target="$(target_path "$unit")"
  [[ -e "$target" ]] && run rm -f "$target"
done

if [[ -z "$root" ]] && systemctl >/dev/null 2>&1; then
  run systemctl daemon-reload
fi

for path in "${paths[@]}"; do
  target="$(target_path "$path")"
  [[ -e "$target" ]] && run rm -rf "$target"
done

echo "PortHub uninstall $mode complete."
