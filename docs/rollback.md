# Rollback

## Configuration rollback

Use Core immutable snapshot history. Core loads the selected payload, creates a
new signed version, revalidates nft syntax and conflicts, applies it to Edge
over mTLS, and records the result. Edge keeps the last valid snapshot so a Core
outage does not erase active forwarding.

## Binary or frontend rollback

Restore only the affected PortHub binary or previous frontend release from a
private, host-local backup. Restart only the affected PortHub unit and verify
health, tunnel handshake, owned nftables state and published paths.

## External service rollback

Disable all PortHub rules that claim the migrated ports, confirm their owned
listeners/rules are gone, then restore the previous service according to its
operator documentation. Do not flush firewall state, restart host networking,
alter unrelated WireGuard interfaces, or modify host-managed sites.
