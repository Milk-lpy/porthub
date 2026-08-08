# WireGuard Compatibility

PortHub uses an independent interface named `wg-porthub`. The interface name,
UDP port, tunnel network and peer AllowedIPs must be selected after an audit.
The example tunnel is `10.255.0.0/24`; it is not a production requirement.

PortHub never deletes, downs or overwrites an existing WireGuard interface or
configuration. Peer updates are restricted to PortHub-managed peers, validate
unique public keys and addresses, and restore the previous peer set when a
health check fails. Private keys never enter list APIs, snapshots sent to the
UI or routine logs.

Uninstall removes only `wg-porthub` and PortHub-owned firewall state after an
explicit confirmation. Existing WireGuard interfaces and their routes remain
untouched.
