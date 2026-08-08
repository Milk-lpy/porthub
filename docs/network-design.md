# Network Design

PortHub separates the public Edge from the Core control plane. Edge receives
public TCP/UDP traffic and applies only signed rules in `table inet porthub`.
Core manages users, resources, mappings, policies, history and configuration.
The two sides communicate through an independent `wg-porthub` tunnel and a
mutually authenticated TLS channel.

## Example address plan

- Edge tunnel: `10.255.0.1/24`
- Core tunnel: `10.255.0.2/24`
- Agent pool: `10.255.0.10/24` onward
- Example managed LAN: `192.0.2.0/24`

These are documentation values. A deployment must discover unused interfaces,
ports, routes and AllowedIPs before choosing real values.

## Forwarding modes

Compatibility mode uses controlled Core SNAT so replies return through the
tunnel. Source-preserving mode is opt-in and requires an externally managed
return route; PortHub must not replace the LAN default route to enable it.

The restricted `porthub-netd` helper owns the narrow capability needed for
nftables/WireGuard changes. It validates structured requests, accepts only the
PortHub table/interface and applies candidates atomically after `nft -c`.
