# Test Report Template

The repository keeps automated tests for the shared packages, Core, Edge,
Agent, restricted network helper, relay and frontend. This file describes how
to reproduce the checks; it is not a claim about a particular production host.

## Unit and compile checks

```bash
go test ./...
go test -race ./apps/core ./apps/edge ./apps/agent ./apps/netd ./internal/...
make build
cd apps/frontend && npm run build
```

## Functional coverage

- snapshot Ed25519 signing, validation and replay protection
- WireGuard peer validation and allowed-network boundaries
- nftables TCP, UDP, dual-protocol and port-range compilation
- duplicate-port and invalid-target rejection
- ACL, rate and connection-limit compilation
- Core rollback and Edge last-known-good recovery
- authentication, TOTP, trusted devices, CSRF, RBAC and login rate limiting
- DDNS dry-run/provider validation and certificate planning
- Agent enrollment and signed allowlisted tasks
- resource scanning, managed service boundaries and public-source audit parsing
- frontend route rendering, mapping forms and responsive visual smoke tests

## Production acceptance template

Run production acceptance in an isolated maintenance window with temporary
unused ports. Record the host-specific evidence privately:

1. capture a pre-change audit and PortHub-owned backup;
2. verify old service process/listener/config hashes;
3. apply a test snapshot and test TCP, UDP and range traffic;
4. stop Core and confirm the last Edge snapshot still serves traffic;
5. restart Edge/Core independently and verify recovery;
6. compare unrelated nftables tables, routes, interfaces and containers;
7. remove the test mapping and confirm only PortHub resources changed.

Do not run these tests against production ports if another service owns them.
