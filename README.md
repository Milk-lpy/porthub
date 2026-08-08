# PortHub

PortHub is a control-plane/data-plane platform for publishing private TCP, UDP
and HTTP services through an independent WireGuard tunnel. It combines a Go
Core, a lightweight Go Edge, a capability-bounded network helper, Linux and
Windows Agent support, and a Vue 3 management console.

## Repository

- `apps/core`: control API, authentication, snapshots, monitoring and integrations
- `apps/edge`: signed public data plane and lightweight reverse proxy
- `apps/netd`: restricted nftables/WireGuard helper
- `apps/agent`: Linux/Windows node discovery and signed task validation
- `apps/frontend`: Vue 3, TypeScript, Naive UI, Pinia and ECharts console
- `internal`: shared authentication, snapshots, nftables and updater packages
- `deploy`: systemd units and Agent installation templates
- `docs`: architecture, operations, security and test documentation

## Development

Requirements are Go, Node.js/npm, a C compiler for SQLite CGO, and Playwright
Chromium for browser tests.

```bash
make build
go test ./...
go test -race ./apps/core ./apps/edge ./apps/agent ./apps/netd ./internal/...
cd apps/frontend
npm install
npm run build
npm run test:e2e
```

The repository contains only example values. Configure real addresses, domain
names, credentials, certificates and signing keys through files outside Git.
Never commit production certificates, private keys, TOTP secrets, API tokens,
database credentials, SSH credentials, backups or logs.

## Example deployment

The example units use these documentation ranges:

- Edge public address: `203.0.113.10`
- Core/LAN example: `192.0.2.0/24`
- PortHub tunnel: `10.255.0.0/24`
- Management API example: `9443/tcp`
- WireGuard example: `51830/udp`

Replace them with values discovered during a read-only audit. PortHub must use
an independent `wg-porthub` interface and its own nftables tables. It must not
flush an existing firewall, alter unrelated WireGuard interfaces, stop an
existing proxy, or modify a host-managed site.

Read these documents before changing a live host:

- [Architecture](docs/architecture.md)
- [Environment audit template](docs/environment-audit.md)
- [Security design](docs/security-design.md)
- [Deployment](docs/deployment.md)
- [Backup and restore](docs/backup-restore.md)
- [Rollback](docs/rollback.md)
- [Troubleshooting](docs/troubleshooting.md)
- [Uninstall](docs/uninstall.md)
- [Test report](docs/test-report.md)
- [Example deployment report](docs/final-deployment-report.md)

## Security boundary

Edge accepts only signed snapshots from Core. The normal management path uses
TLS/mTLS, Ed25519 signatures, timestamp and nonce replay protection, Argon2id
password hashes, TOTP, secure sessions, trusted-device cookies and RBAC.
Network mutations are delegated to the restricted `porthub-netd` helper; the
web process is not an arbitrary root shell.

## Project status

The source tree includes the working Core, Edge, Agent, relay, frontend,
snapshot, forwarding, DDNS, certificate, audit and update components. Hardware,
cloud firewall, DNS and service-specific values are intentionally deployment
inputs rather than repository defaults.
