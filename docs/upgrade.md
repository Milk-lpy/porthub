# Upgrade

PortHub uses signed, two-stage updates. The Core Web process runs without root privileges and never replaces its own executable.

## Check And Stage

1. Configure `-update-manifest-url` and the Ed25519 public key at the `-update-public-key` path.
2. Use the Upgrade page to check the signed manifest.
3. Stage `core` or `agent`. Core verifies the manifest signature, platform, artifact size and SHA-256 before an atomic write under `/var/lib/porthub/updates/VERSION/COMPONENT`.
4. Review `stage.meta`, `manifest.json`, release notes and the maintenance impact.

## Install During A Maintenance Window

Run the command shown by the Upgrade page, for example:

```bash
sudo /opt/porthub/bin/porthub-update-helper --execute --version 0.5.0 --component core
```

Without `--execute`, the helper is a dry-run. Execute mode re-verifies the signed manifest and artifact, creates `/var/backups/porthub/update-TIMESTAMP-COMPONENT`, atomically installs only `porthub-core` or `porthub-agent`, restarts only the matching service, and waits up to 30 seconds for its local health endpoint. A failed restart or health check restores the previous binary and restarts the same service again.

After success, verify WireGuard handshake, nft table ownership, existing published TCP/UDP paths and protected-service listener counts. Do not restart networking, Lucky, old WireGuard interfaces, BaoTa or unrelated containers.

Core and Agent versions may be staged independently. Edge updates are deliberately not installed through the Core Web API because Edge has a separate trust and availability boundary.
