#!/usr/bin/env bash
set -euo pipefail

mode="dry-run"
root=""
backup=""
backup_dir="/var/backups/porthub"
data_dir="/var/lib/porthub/core"

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
    --backup)
      backup="${2:-}"
      shift 2
      ;;
    --backup-dir)
      backup_dir="${2:-}"
      shift 2
      ;;
    --data-dir)
      data_dir="${2:-}"
      shift 2
      ;;
    *)
      echo "unknown argument: $1" >&2
      exit 2
      ;;
  esac
done

if [[ -z "$backup" ]]; then
  echo "--backup is required" >&2
  exit 2
fi

if [[ -n "$root" ]]; then
  root="$(cd "$root" && pwd)"
  if [[ "$root" == "/" ]]; then
    echo "--root must not be /" >&2
    exit 2
  fi
fi

target_path() {
  local path="$1"
  if [[ -z "$root" ]]; then
    printf '%s\n' "$path"
    return
  fi
  printf '%s/%s\n' "$root" "${path#/}"
}

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

backup_dir_target="$(target_path "$backup_dir")"
data_dir_target="$(target_path "$data_dir")"
backup_path="$backup_dir_target/$backup"

if [[ "$backup" == */* || "$backup" == *..* || "$backup" != *.tar.gz ]]; then
  echo "invalid backup name" >&2
  exit 2
fi
if [[ ! -f "$backup_path" ]]; then
  echo "backup not found: $backup_path" >&2
  exit 1
fi

allowed_entries=(
  "manifest.json"
  "core/"
  "core/core.db"
  "core/core.db-wal"
  "core/core.db-shm"
  "core/ed25519.key"
  "core/ed25519.pub"
  "core/tls.crt"
  "core/tls.key"
)

is_allowed_entry() {
  local entry="$1"
  for allowed in "${allowed_entries[@]}"; do
    [[ "$entry" == "$allowed" ]] && return 0
  done
  return 1
}

while IFS= read -r entry; do
  [[ -z "$entry" ]] && continue
  if [[ "$entry" == /* || "$entry" == *".."* || "$entry" == "."* ]]; then
    echo "unsafe archive entry: $entry" >&2
    exit 1
  fi
  if ! is_allowed_entry "$entry"; then
    echo "unexpected archive entry: $entry" >&2
    exit 1
  fi
done < <(tar -tzf "$backup_path")

echo "PortHub Core restore mode: $mode"
echo "Backup: $backup_path"
echo "Target data dir: $data_dir_target"

restore_parent="$(dirname "$data_dir_target")"
restore_stage="$restore_parent/.porthub-restore-stage"
pre_restore="$backup_dir_target/pre-restore-$(date -u +%Y%m%d-%H%M%S)"

if [[ -z "$root" ]]; then
  run systemctl stop porthub-core.service
else
  echo "Test root active: $root"
  echo "Skipping systemctl operations in test-root mode."
fi

run mkdir -p "$restore_parent" "$backup_dir_target"
if [[ -d "$data_dir_target" ]]; then
  run cp -a "$data_dir_target" "$pre_restore"
fi
run rm -rf "$restore_stage"
run mkdir -p "$restore_stage"
run tar -xzf "$backup_path" -C "$restore_stage"
run rm -rf "$data_dir_target"
run mkdir -p "$data_dir_target"
if [[ "$mode" == "dry-run" ]]; then
  echo "[dry-run] copy restored core files into $data_dir_target"
else
  shopt -s nullglob
  for file in "$restore_stage"/core/*; do
    cp -a "$file" "$data_dir_target/"
  done
  shopt -u nullglob
fi
run chmod 0700 "$data_dir_target"
for private in core.db core.db-wal core.db-shm ed25519.key tls.key; do
  target="$data_dir_target/$private"
  [[ -e "$target" ]] && run chmod 0600 "$target"
done
for public in ed25519.pub tls.crt; do
  target="$data_dir_target/$public"
  [[ -e "$target" ]] && run chmod 0644 "$target"
done
run rm -rf "$restore_stage"

if [[ -z "$root" ]]; then
  run chown -R porthub:porthub "$data_dir_target"
  run systemctl start porthub-core.service
else
  echo "Skipping chown and systemctl start in test-root mode."
fi

echo "PortHub Core restore $mode complete."
echo "Pre-restore copy: $pre_restore"
