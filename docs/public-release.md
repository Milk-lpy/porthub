# Public Release Notes

This GitHub snapshot is intentionally separated from any live deployment.

## Redaction rules

- Production audit output, backup manifests and host-specific deployment reports
  are excluded.
- Production IP addresses, tunnel addresses, real domains and host names are
  replaced with RFC 5737/RFC 3849 documentation values or configurable examples.
- The Git history is recreated as one clean snapshot; no previous deployment
  commits are included.
- No private key, certificate, TOTP secret, API credential, database, log,
  backup or SSH credential is part of the release.
- The deployment units and scripts require an operator to provide real values
  outside Git.

## Before using on a live host

Run a read-only audit, select unused ports and networks, create a private
backup, review the security boundary, and verify the rollback plan. Do not
copy the example addresses into a live network without checking for conflicts.
