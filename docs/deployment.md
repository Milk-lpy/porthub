# Deployment

## Prerequisites

Use a supported Linux host with Go-built binaries, systemd, SQLite, nftables,
WireGuard tools and a C compiler available at build time. Perform a read-only
environment audit and create a private backup before installing anything.

## Installation shape

- binaries: `/opt/porthub/bin`
- configuration: `/etc/porthub`
- state: `/var/lib/porthub`
- logs: `/var/log/porthub`
- backups: `/var/backups/porthub`
- service user: `porthub`

Install the Edge/Core units from `deploy/`, but replace all example addresses
with audited values in a root-only environment file. Start the restricted
network helper before the process that requests it. Use independent
`wg-porthub`; do not edit an existing WireGuard profile.

## Frontend

Build with `cd apps/frontend && npm run build`, copy the resulting `dist` to a
versioned release directory readable by `porthub`, atomically update the
`current` symlink, and restart only `porthub-core.service`. Verify that the
returned document is the Vue SPA and that `/api/health` responds locally.

## Operations

Core persists snapshots and history; Edge keeps the current and previous valid
configuration and continues serving the last valid snapshot while Core is
offline. Every apply requires validation, signature verification, syntax check,
health check and an auditable result. Cloud security groups and DNS providers
must be verified separately; this project cannot claim to have changed them.
