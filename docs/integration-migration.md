# Integration Migration Guide

PortHub can take ownership of forwarding and DDNS workflows after a separate
inventory of the existing service. The migration is deliberately generic: the
existing service name, addresses, credentials and port list must be recorded in
a private change plan, never in Git.

## Safe sequence

1. Audit the current listeners, configuration owner, routes, firewall rules and
   startup units without changing them.
2. Back up the old service configuration and generate a manifest privately.
3. Create equivalent PortHub rules disabled and run conflict checks.
4. Verify the target service through the independent PortHub tunnel.
5. During a maintenance window, stop the old owner only after explicit approval.
6. Enable PortHub rules, test both address families and confirm return traffic.
7. Keep the old backup unavailable to the API and document the exact rollback.

PortHub must never parse or expose opaque credentials from another service.
Disable/delete operations must be scoped to PortHub-owned resources and must not
flush firewall state or change unrelated WireGuard interfaces.
