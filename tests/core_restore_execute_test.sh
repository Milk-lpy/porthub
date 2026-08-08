#!/usr/bin/env bash
set -euo pipefail

root="$(mktemp -d)"
cleanup() {
  chmod -R u+w "$root" 2>/dev/null || true
  rm -r "$root" 2>/dev/null || true
}
trap cleanup EXIT

mkdir -p "$root/var/backups/porthub" "$root/var/lib/porthub/core" "$root/tmp/backup/core"
printf old > "$root/var/lib/porthub/core/core.db"
printf keep > "$root/var/lib/porthub/core/existing-extra"
printf restored > "$root/tmp/backup/core/core.db"
printf pub > "$root/tmp/backup/core/ed25519.pub"
printf key > "$root/tmp/backup/core/ed25519.key"
printf cert > "$root/tmp/backup/core/tls.crt"
printf tkey > "$root/tmp/backup/core/tls.key"
printf '{}' > "$root/tmp/backup/manifest.json"
tar -czf "$root/var/backups/porthub/core-test.tar.gz" -C "$root/tmp/backup" manifest.json core

scripts/porthub-core-restore.sh --execute --root "$root" --backup core-test.tar.gz >/tmp/porthub-core-restore-test.out

if [[ "$(cat "$root/var/lib/porthub/core/core.db")" != "restored" ]]; then
  echo "core.db was not restored" >&2
  exit 1
fi
if [[ -e "$root/var/lib/porthub/core/existing-extra" ]]; then
  echo "unexpected non-backup file survived restore target replacement" >&2
  exit 1
fi
if ! find "$root/var/backups/porthub" -maxdepth 1 -type d -name 'pre-restore-*' | grep -q .; then
  echo "missing pre-restore copy" >&2
  exit 1
fi
grep -q "Skipping systemctl operations in test-root mode" /tmp/porthub-core-restore-test.out
echo "core_restore_execute_test=passed"
