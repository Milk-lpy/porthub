# PortHub Architecture

PortHub separates the control plane, public data plane and node telemetry plane.

## Core

Core runs as the unprivileged `porthub` user on `192.0.2.12`. It owns authentication, RBAC, resources, services, mappings, proxy routes, ACLs, domains, DDNS, certificates, immutable snapshots, audit/history, Agent enrollment, backups, local AI drafts and signed update staging. SQLite WAL is the production control database. The Vue SPA calls same-origin REST and WebSocket APIs over HTTPS.

Core operations that require network administration are compiled into strict data and sent to `porthub-netd` over a group-restricted Unix socket. The Core helper runs with bounded capabilities and only accepts the `porthub_core` nft candidate path/table. Both netd units use `Type=notify`, so dependent services are not considered started before their Unix sockets are ready. Signed update installation is kept outside the Web process in the explicit root-only `porthub-update-helper` maintenance command.

## Edge

Edge is the lightweight public data plane on `203.0.113.10`. It validates Core's mTLS identity and Ed25519 signature, timestamp and nonce before accepting snapshots. The Web/proxy process runs as the unprivileged `porthub` user with an empty effective capability set. Candidate nft, fixed-interface WireGuard peer operations and conntrack inspection go through a separate `porthub-netd` process over `/run/porthub/edge-netd.sock`.

Edge netd owns only `table inet porthub` and `wg-porthub`. Its request model has no command, executable or interface-name field: nft candidates must be regular `0640` files below `/var/lib/porthub/edge/netd`, runtime nft reads are fixed to the owned table, WireGuard reads use a field allowlist, peer updates validate public keys/CIDRs/keepalive, and conntrack uses one fixed read command. `Type=notify` prevents Edge from starting before the helper socket is bound and permissioned.

Edge stores the current signed snapshot and current compiled nft file, so forwarding and startup restoration do not require Core. If netd is temporarily unavailable, the already-applied kernel data plane remains active; only configuration updates and privileged status collection pause until the helper returns.

The Edge process also serves lightweight Host/Path reverse proxy traffic, exact HTTP-01 challenges, traffic counters and safe status APIs. Its management listener requires a client certificate and has no public recovery UI.

## Agent

Agents generate their private key locally, enroll once, then heartbeat to Core using a dedicated mTLS identity. Linux discovery reads bounded host, interface and listener state and can query the Docker Unix socket read-only for container identity/port state. No environment variables, labels, packet payloads or arbitrary shell endpoint are collected or exposed.

Controlled task envelopes are signed, timestamped, nonced, timeout-bounded and allowlisted. The current implementation validates envelopes but intentionally does not execute tasks.

## Traffic Path

Public TCP/UDP traffic enters Edge, is DNATed through `wg-porthub`, then passes exact Core `porthub_core` forwarding rules to the selected LAN target. Compatibility mode SNATs on Core so replies reliably return through the tunnel. Source-preserving mode is opt-in and requires an externally managed LAN return route.

HTTP traffic enters Edge's lightweight proxy listeners and is selected by normalized Host and longest matching Path. Backend health and retry state stay on Edge; route definitions remain signed Core snapshot data.

## Failure Boundaries

- Core offline: existing Edge nft and proxy configuration continues to serve traffic.
- New snapshot failure: candidate validation fails without modifying the active table; Core history records the result.
- Edge restart: `current.nft` is ownership-checked, atomically staged as a group-readable candidate, syntax-checked by netd and restored only inside the owned table.
- Core restart: SQLite WAL, certificates and snapshots remain under `/var/lib/porthub/core`.
- Existing services: Lucky, old WireGuard, SSH, Docker and unrelated firewall tables are outside PortHub ownership.
