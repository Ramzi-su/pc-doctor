# PC Doctor

Local web dashboard to monitor and diagnose a Linux PC, **as a normal user (no root)**:

| Tab | Content |
|---|---|
| Tableau de bord | live CPU / RAM / temperatures / GPU / network / top processes (Server-Sent Events, every 2 s) and a prioritized diagnosis |
| Matériel | machine, BIOS, CPU, disks, partitions, battery health, GPUs (with NVIDIA details), USB devices |
| Réseau | interfaces with their physical card (vendor, driver, firmware, PCI slot), MAC, IPs, traffic |
| Ports | listening TCP/UDP sockets, local vs. network-exposed, owning process when visible |
| Utilisateurs & groupes | accounts, admins, sensitive groups, login history |
| Droits & SUID | permission audit of sensitive files, world-writable files, SUID/SGID scan |
| Journal | systemd journal with filters (software, priority, time range, crashes) |
| Fichiers /var/log | readable text/gzip log files, filtered and followed live |

## Install and run

```bash
uv sync
uv tool install --editable .   # once: installs the `pc-doctor` command
pc-doctor                      # starts the server and opens the browser
pc-doctor --port 9000 --no-browser
```

## What needs root (shown as "nécessite root")

- serial numbers / UUID of the machine (DMI);
- the name of a process that owns a port when it belongs to another user (e.g. `sshd`);
- failed logins (`/var/log/btmp`), password hashes (`/etc/shadow`);
- full SMART disk data.

Reading the system logs requires membership of the `adm` or `systemd-journal` group.
Hardware **manufacturing dates are not exposed by Linux** for GPUs or network cards;
the BIOS date is the firmware date. Some batteries report their own.

## Security

- Bound to `127.0.0.1` only, with a Host header check (DNS rebinding), a strict CSP,
  and a CSRF guard on the only action (SUID scan). Never bind to `0.0.0.0`: this page
  is a full map of the machine.
- `pc-doctor` refuses to run as root.
- External tools are called with argument lists (no shell) and timeouts.
- Log file paths are resolved and confined to `/var/log` (path traversal).

Tests: `uv run pytest`
