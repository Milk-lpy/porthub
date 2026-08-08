# Uninstall

Remove only PortHub-owned services, directories, wg-porthub, and table inet porthub. Preserve Lucky, Baota, Docker, old WireGuard, SSH and existing firewall tables.

The installed helper is `/opt/porthub/bin/porthub-uninstall`.

Preview only:

```bash
/opt/porthub/bin/porthub-uninstall
```

Execute removal:

```bash
/opt/porthub/bin/porthub-uninstall --execute
```

Test execute mode against a fake root directory:

```bash
scripts/porthub-uninstall.sh --execute --root /tmp/porthub-uninstall-root
```

When `--root` is set, the helper maps file paths into that directory and skips `systemctl`, `nft`, and `wg` operations. This is used by automated tests to prove the delete scope without changing the real host.

The helper only targets:

- `porthub-core.service`
- `porthub-edge.service`
- `porthub-agent.service`
- `porthub-netd.service`
- `wg-quick@wg-porthub.service`
- `table inet porthub`
- `table inet porthub_core`
- `wg-porthub`
- `/opt/porthub`
- `/etc/porthub`
- `/var/lib/porthub`
- `/var/log/porthub`
- `/var/backups/porthub`
- `/etc/wireguard/wg-porthub.conf`
- `/etc/sysctl.d/99-porthub.conf`

It does not target non-PortHub WireGuard configs, existing systemd units, Lucky, Baota, Docker, SSH, or non-PortHub firewall tables.
