# BaoTa Compatibility

PortHub never writes BaoTa site definitions, reverse-proxy snippets, panel configuration or managed certificates. It uses independent systemd units, directories, WireGuard interface and nftables tables.

The installer does not assume whether BaoTa or Nginx exists. Run the audit
template on the target host, record the owner of each HTTP/HTTPS listener in a
private change plan, and choose unused PortHub proxy ports. This repository
does not contain a production availability claim.

If BaoTa is installed later, keep its HTTP/HTTPS listeners and sites unchanged. Choose non-conflicting PortHub proxy ports or add an explicit administrator-managed route for `/.well-known/acme-challenge/`; PortHub must not overwrite an existing site to obtain a certificate.
