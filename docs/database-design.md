# Database Design

The first production build uses SQLite WAL on Core at /var/lib/porthub/core/core.db. Edge keeps only current and previous signed snapshots under /var/lib/porthub/edge.

Core tables currently deployed:

- users: username, Argon2id password hash, TOTP secret, role, first-login password-change flag.
- trusted_devices: username, SHA-256 token hash, user-agent metadata, created time, expiry, last-used time and revoked flag for 30-day remembered browser login.
- sessions: opaque session id, username, CSRF token, expiry.
- mappings: TCP/UDP public mapping records compiled into signed snapshots.
- resources, services, mapping_groups, acls, templates, webhooks: generic enabled metadata objects with JSON data payloads.
- api_tokens: token name, hash, prefix, role and revocation state. Raw token values are returned only once.
- audit: timestamp, actor, action and detail. The API uses SQLite's immutable rowid as a display-only record number and derives readable labels, category, risk, result, target and summary at query time, so existing audit rows and webhook payloads remain compatible without a destructive table migration.
- traffic_samples: timestamp, Edge snapshot version, packets, bytes and bounded raw Edge metrics JSON.
- traffic_rule_samples: one row per Edge nft DNAT rule per sample, storing protocol, public port, target, packets and bytes.
- domains: domain zone inventory with provider and ownership marker.
- ddns_providers: provider metadata and redacted configuration. Real secrets should live in external secret files referenced by secret_ref.
- ddns_records: desired A/AAAA DDNS records, IP source and sync state. The historical `managed_by_lucky` column is retained only for SQLite schema compatibility, is forced to zero on write, and is not exposed as a management option.
- certificates: certificate metadata, SAN/domain list, issue mode, optional DNS Provider reference, status, expiry and key reference only.
- ip_sets: named CIDR collections for custom, GeoIP-derived or ASN-derived policy inputs. Core stores CIDRs and Edge receives only compiled lightweight nft sets.
- acl_rules: normalized source networks, action, protocol/port scope, node/service/group binding and optional schedule.
- http_proxies: Host/Path routes and their signed backend configuration.
- snapshot_history: immutable signed payload, digest, operator, application result and rollback source version.
- agent_enrollments: one-time token hashes and expiry/consumption state.
- agent_nodes: mTLS node identity, bounded heartbeat/discovery JSON, certificate expiry and last-seen state.
- wireguard_peers: PortHub-managed public keys, tunnel addresses, AllowedIPs, keepalive and enabled state. No private key column exists.
- system_alerts: deduplicated alert fingerprints, severity, source, lifecycle and acknowledgement state.
- ip_feeds: public HTTPS feed URL, kind/action, optional SHA-256 pin, refresh interval, managed IP-set reference and last result.
- update_events: signed-manifest check and artifact-stage history; artifact data remains on disk, not in SQLite.
- acme_config: singleton ACME contact email. Account private keys remain protected files.
- acme_orders: bounded issuance/renewal/deploy result history without challenge tokens or private keys.

SQLite uses WAL and a busy timeout and is included in scheduled protected backups. PostgreSQL remains the preferred future option for substantially larger multi-user/history-heavy deployments; production currently uses only the isolated SQLite database and does not modify any existing database server.
