"""Turn raw facts into findings ("diagnosis"), sorted by severity."""

import re

import psutil

from app.system import runner
from app.system.runner import CommandError
from app.system.models import (
    Accounts,
    Finding,
    Hardware,
    Permissions,
    Port,
    Severity,
    SuidScan,
)

_ORDER = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2, Severity.OK: 3}


def _hardware(hw: Hardware) -> list[Finding]:
    out = []
    for part in hw.partitions:
        if part.percent >= 90:
            out.append(Finding(severity=Severity.WARNING if part.percent < 97 else Severity.CRITICAL,
                               area="Disque", message=f"{part.mountpoint} est plein à {part.percent:.0f} %"))
    for bat in hw.batteries:
        if bat.health_percent is not None:
            sev = Severity.OK if bat.health_percent >= 80 else (
                Severity.INFO if bat.health_percent >= 60 else Severity.WARNING)
            out.append(Finding(severity=sev, area="Batterie",
                               message=f"{bat.name} : {bat.health_percent:.0f} % de sa capacité d'origine"))
    mem = psutil.virtual_memory()
    if mem.percent >= 90:
        out.append(Finding(severity=Severity.WARNING, area="Mémoire",
                           message=f"RAM utilisée à {mem.percent:.0f} %"))
    for sensor, entries in psutil.sensors_temperatures().items():
        for t in entries:
            limit = t.critical or t.high or 95
            if 0 < t.current < 150 and t.current >= limit - 5:
                out.append(Finding(severity=Severity.WARNING, area="Température",
                                   message=f"{t.label or sensor} : {t.current:.0f} °C (limite {limit:.0f} °C)"))
    return out


def _ports(ports: list[Port]) -> list[Finding]:
    exposed = [p for p in ports if p.exposed]
    if not exposed:
        return [Finding(severity=Severity.OK, area="Ports",
                        message="aucun port accessible depuis le réseau")]
    out = []
    seen: set[tuple[str, int]] = set()
    for p in exposed:
        key = (p.protocol.rstrip("6"), p.port)  # tcp + tcp6 on the same port = one finding
        if key in seen:
            continue
        seen.add(key)
        who = p.process or (f"probablement {p.service}" if p.service
                            else "processus d'un autre utilisateur (root nécessaire pour le nom)")
        # UDP 5353 (mDNS) and DHCP client are normal on desktops.
        sev = Severity.INFO if (p.protocol.startswith("udp") and p.port in (68, 5353, 1900)) \
            else Severity.WARNING
        out.append(Finding(severity=sev, area="Ports",
                           message=f"{key[0].upper()} {p.port} ouvert sur le réseau — {who}"))
    return out


def _accounts(acc: Accounts) -> list[Finding]:
    out = []
    for user in acc.users:
        if user.uid == 0 and user.name != "root":
            out.append(Finding(severity=Severity.CRITICAL, area="Comptes",
                               message=f"le compte « {user.name} » a l'UID 0 : c'est un second root"))
    admins = [u.name for u in acc.users if u.admin and u.name != "root"]
    if admins:
        out.append(Finding(severity=Severity.INFO, area="Comptes",
                           message=f"administrateurs (sudo) : {', '.join(admins)}"))
    for group in acc.groups:
        if group.name in {"docker", "lxd", "disk"} and group.members:
            out.append(Finding(severity=Severity.WARNING, area="Groupes",
                               message=f"groupe {group.name} ({', '.join(group.members)}) : {group.why}"))
    service_shells = [u.name for u in acc.users if not u.human and u.can_login and u.uid != 0
                      and u.name not in {"sync"}]
    if service_shells:
        out.append(Finding(severity=Severity.INFO, area="Comptes",
                           message=f"comptes système avec un shell : {', '.join(service_shells)}"))
    return out


def _permissions(perms: Permissions) -> list[Finding]:
    out = [
        Finding(severity=Severity.CRITICAL if f.path.startswith("/etc") else Severity.WARNING,
                area="Droits", message=f"{f.path} en {f.octal} (attendu {f.expected})"
                + (f" — {f.note}" if f.note else ""))
        for f in perms.files if not f.ok
    ]
    for path in perms.world_writable[:20]:
        out.append(Finding(severity=Severity.CRITICAL, area="Droits",
                           message=f"{path} est modifiable par tout le monde"))
    if not out:
        out.append(Finding(severity=Severity.OK, area="Droits",
                           message="droits des fichiers sensibles corrects"))
    return out


def _suid(scan: SuidScan | None) -> list[Finding]:
    if scan is None:
        return [Finding(severity=Severity.INFO, area="SUID",
                        message="scan SUID pas encore lancé (onglet Sécurité)")]
    out = [Finding(severity=Severity.CRITICAL, area="SUID",
                   message=f"{f.path} est SUID root : n'importe qui peut obtenir un shell root")
           for f in scan.files if f.dangerous]
    unknown = [f.path for f in scan.files if not f.known and not f.dangerous]
    if unknown:
        out.append(Finding(severity=Severity.WARNING, area="SUID",
                           message=f"{len(unknown)} fichier(s) SUID/SGID inhabituel(s) à vérifier"))
    if not out:
        out.append(Finding(severity=Severity.OK, area="SUID",
                           message=f"{len(scan.files)} fichiers SUID/SGID, tous connus"))
    return out


# Kernel messages that mean failing hardware or a damaged filesystem.
KERNEL_PATTERNS: list[tuple[str, Severity, str]] = [
    (r"EXT4-fs error|BTRFS (error|critical)|XFS.*corrupt", Severity.CRITICAL,
     "système de fichiers corrompu : sauvegarde puis fsck"),
    (r"I/O error|Buffer I/O|blk_update_request", Severity.CRITICAL,
     "erreur de lecture/écriture disque : vérifier l'état SMART du disque"),
    (r"nvme.*(timeout|reset controller)", Severity.WARNING, "le SSD NVMe ne répond pas toujours"),
    (r"NVRM: Xid|GPU has fallen off", Severity.WARNING, "erreur du GPU NVIDIA"),
    (r"Hardware Error|Machine check|mce:", Severity.CRITICAL, "erreur matérielle CPU/RAM signalée"),
]
KERNEL_GREP = "|".join(p for p, _, _ in KERNEL_PATTERNS)


def kernel_errors(days: int = 7, run: runner.Runner | None = None) -> list[Finding]:
    """Scan the kernel log (needs group adm or systemd-journal, not root)."""
    try:
        out = runner.run(["journalctl", "-k", "--no-pager", "-q", "-o", "cat",
                          f"--since=-{days}d", "--priority=0..4", f"--grep={KERNEL_GREP}"],
                         timeout=20, runner=run)
    except CommandError:
        return []  # no match (journalctl exits 1) or journal not readable
    counts: dict[str, int] = {}
    for line in out.splitlines():
        counts[line] = counts.get(line, 0) + 1
    findings = []
    for message, count in list(counts.items())[:10]:
        for pattern, severity, advice in KERNEL_PATTERNS:
            if re.search(pattern, message, re.I):
                findings.append(Finding(
                    severity=severity, area="Noyau",
                    message=f"{advice} — « {message[:160]} » ({count}× en {days} j)"))
                break
    return findings


def diagnose(hw: Hardware, ports: list[Port], acc: Accounts, perms: Permissions,
             suid: SuidScan | None, kernel: list[Finding] | None = None) -> list[Finding]:
    findings = (_hardware(hw) + _ports(ports) + _accounts(acc)
                + _permissions(perms) + _suid(suid) + (kernel or []))
    return sorted(findings, key=lambda f: _ORDER[f.severity])
