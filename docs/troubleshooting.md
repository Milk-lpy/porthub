# Troubleshooting

## Panel is unreachable

Check the Core unit, its local listener and `/api/health` on the audited host.
Verify the certificate path and that the frontend release is readable by the
`porthub` user. Keep the management API on TLS; do not enable plaintext as a
diagnostic shortcut.

## Mapping does not work

Check the mapping's enabled state, conflict check, snapshot version and Edge
apply result. Inspect only `nft list table inet porthub` and the PortHub-owned
Core table. Confirm the target listener, WireGuard handshake and return path.
If local listening is correct but external access fails, check the cloud
security group and upstream routing.

## Core is offline

Existing Edge rules should continue using the last valid snapshot. Do not
delete that snapshot. Restore Core connectivity, inspect the mTLS and signature
errors, and re-run deployment only after the configuration has passed checks.

## Protect existing services

Compare their process/listener/config hashes before and after a PortHub change.
Never flush a firewall, restart host networking, stop another proxy or change
an unrelated WireGuard interface to diagnose PortHub.
