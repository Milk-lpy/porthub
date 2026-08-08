#!/usr/bin/env bash
set -euo pipefail

root="$(mktemp -d)"
cleanup() {
  chmod -R u+w "$root" 2>/dev/null || true
  rm -r "$root" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$root"/{opt,etc,var/lib,var/log,var/backups,etc/wireguard,etc/sysctl.d,etc/systemd/system}
mkdir -p "$root/opt/porthub" "$root/etc/porthub" "$root/var/lib/porthub" "$root/var/log/porthub" "$root/var/backups/porthub"
touch "$root/etc/wireguard/wg-porthub.conf"
touch "$root/etc/wireguard/wg-existing.conf"
touch "$root/etc/sysctl.d/99-porthub.conf"
touch "$root/etc/sysctl.d/99-existing.conf"
touch "$root/etc/systemd/system/porthub-core.service"
touch "$root/etc/systemd/system/existing.service"

scripts/porthub-uninstall.sh --execute --root "$root" >/tmp/porthub-uninstall-test.out

for removed in \
  "$root/opt/porthub" \
  "$root/etc/porthub" \
  "$root/var/lib/porthub" \
  "$root/var/log/porthub" \
  "$root/var/backups/porthub" \
  "$root/etc/wireguard/wg-porthub.conf" \
  "$root/etc/sysctl.d/99-porthub.conf" \
  "$root/etc/systemd/system/porthub-core.service"; do
  if [[ -e "$removed" ]]; then
    echo "expected removed: $removed" >&2
    exit 1
  fi
done

for preserved in \
  "$root/etc/wireguard/wg-existing.conf" \
  "$root/etc/sysctl.d/99-existing.conf" \
  "$root/etc/systemd/system/existing.service"; do
  if [[ ! -e "$preserved" ]]; then
    echo "expected preserved: $preserved" >&2
    exit 1
  fi
done

grep -q "Skipping systemctl, nft and wg operations in test-root mode" /tmp/porthub-uninstall-test.out
echo "uninstall_execute_test=passed"
