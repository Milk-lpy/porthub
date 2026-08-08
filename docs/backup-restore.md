# Backup Restore

Core exposes a controlled backup API:

- `GET /api/backups`
- `POST /api/backups`
- `POST /api/backups/restore/plan`

Backups are written to `/var/backups/porthub` with mode `0600`. The archive contains the Core SQLite database and PortHub-owned Core key/certificate files required for a functional Core restore. API responses return only metadata and paths, never archive contents.

Restore planning is available through `/api/backups/restore/plan`. Restore execution is handled by `/opt/porthub/bin/porthub-core-restore` so replacement of the running Core data directory is explicit and auditable.

Dry-run:

```bash
/opt/porthub/bin/porthub-core-restore --backup core-YYYYMMDD-HHMMSS.tar.gz
```

Execute during a maintenance window:

```bash
/opt/porthub/bin/porthub-core-restore --execute --backup core-YYYYMMDD-HHMMSS.tar.gz
```

The helper validates that the archive is under `/var/backups/porthub`, rejects unsafe archive entries, stops only `porthub-core.service`, creates a pre-restore copy under `/var/backups/porthub/pre-restore-*`, restores only known Core files, fixes permissions, and starts only `porthub-core.service`.

Automated tests use `--root` to execute the restore flow in a fake root directory without touching the real host.
