# Existing Service Compatibility

PortHub is designed to coexist with an existing forwarding or DDNS service.
The service owner must be audited and its ports must be treated as occupied
until a planned migration is approved. PortHub does not read opaque credentials
or silently import another service's configuration.

For migration, create disabled PortHub drafts, verify target reachability and
port conflicts, then switch ownership during a maintenance window. Rollback is
to disable only the PortHub rules and restore the old service from a private
operator backup. Never run two owners on the same listener.
