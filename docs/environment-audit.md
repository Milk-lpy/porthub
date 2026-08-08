# Environment Audit Template

Run a read-only audit on every host before installation. Save the result in a
private operator-controlled location, not in this repository. The command
output may contain addresses, host names, process arguments and service
metadata.

## Required checks

- OS release, kernel, architecture, CPU, memory and disk
- Listening TCP/UDP sockets, interfaces, addresses and default route
- Policy rules and all route tables
- Existing WireGuard interfaces, peers, addresses and listening ports
- Existing nftables and iptables state, including NAT
- firewalld/ufw status
- Nginx, Apache, Caddy, Docker, Podman and database services
- Existing proxy/service processes and their configuration owners
- IP forwarding, reverse-path filtering, conntrack, DNS and time sync

## Safety decision

Choose values only after comparing the audit with the proposed configuration.
The example values in this repository are documentation ranges, not automatic
production defaults:

| Item | Example only |
| --- | --- |
| Edge management API | `9443/tcp` |
| WireGuard | `51830/udp` |
| Tunnel | `10.255.0.0/24` |
| Example LAN | `192.0.2.0/24` |

The audit must explicitly record occupied ports, overlapping routes and
AllowedIPs, the selected free values, the rollback point and the owner of every
existing firewall/proxy resource. Never use a firewall flush or a host network
restart to resolve a conflict.
