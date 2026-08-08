# Example Deployment Report

This document is a redacted report template. It contains no real host names,
addresses, credentials, certificates, backups or cloud account information.
Copy it to a private operator report and fill in the values only after a live
deployment has been audited and verified.

## Deployment identity

- Core host: `<CORE_HOST>`
- Edge host: `<EDGE_HOST>`
- Core directory: `/opt/porthub`
- State directory: `/var/lib/porthub`
- Service names: `porthub-core.service`, `porthub-edge.service`, `porthub-netd.service`
- WireGuard interface: `wg-porthub`
- WireGuard port: `<FREE_UDP_PORT>`
- Tunnel network: `<PORTHUB_TUNNEL_CIDR>`
- Management URL: `https://<CORE_HOST>:<MANAGEMENT_PORT>`

## Credentials

Record only the administrator username in an operator password manager. Never
place an initial password, TOTP secret, private key, API token or database
password in this report or Git.

## Verification checklist

- [ ] Core and Edge use the intended certificates and mutual authentication.
- [ ] Snapshot signature, timestamp and nonce checks reject invalid/replayed data.
- [ ] TCP, UDP and range mappings pass isolated test traffic.
- [ ] Disabled mappings do not claim listeners and enabled mappings pass conflict checks.
- [ ] Failed apply restores the previous valid snapshot.
- [ ] Core outage leaves the last Edge snapshot serving traffic.
- [ ] Core and Edge restart recovery works.
- [ ] Authentication, TOTP, trusted-device login, RBAC, CSRF and audit logging work.
- [ ] Existing host services and unrelated firewall/WireGuard resources are unchanged.
- [ ] Mobile and desktop frontend smoke tests pass.

## Cloud firewall

The cloud security group is outside this repository. Record only the protocol
and port that must be allowed, and state whether reachability was tested from an
external network. Do not claim that a provider console was changed unless it
was actually changed.

## Rollback

Use the PortHub snapshot rollback path and restore only PortHub-owned units,
files, nftables tables and `wg-porthub`. Keep the private backup location in an
operator-only system, not in the public repository.
