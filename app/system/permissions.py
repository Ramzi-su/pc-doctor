"""Permission audit of sensitive files, world-writable files, SUID/SGID scan.

A SUID file runs with its *owner's* rights (usually root) whatever user starts
it. That is how `passwd` can write /etc/shadow. A SUID copy of `bash` or `find`
would hand a root shell to anyone: that is what the scan looks for.
"""

import getpass
import grp
import os
import pwd
import re
import stat
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from app.system import runner
from app.system.models import FileAudit, Permissions, SuidFile, SuidScan


@dataclass(frozen=True)
class Rule:
    path: str
    forbidden: int  # mode bits that must NOT be set
    expected: str  # human description shown in the UI
    required: int = 0  # mode bits that MUST be set
    note: str | None = None


_G_W = stat.S_IWGRP
_O_ALL = stat.S_IRWXO
_O_W = stat.S_IWOTH
_GO_ALL = stat.S_IRWXG | stat.S_IRWXO

SYSTEM_RULES = [
    Rule("/etc/passwd", _G_W | _O_W, "644, root", note="modifiable = création d'un compte root"),
    Rule("/etc/group", _G_W | _O_W, "644, root"),
    Rule("/etc/shadow", _O_ALL | _G_W, "640 ou moins", note="contient les empreintes des mots de passe"),
    Rule("/etc/gshadow", _O_ALL | _G_W, "640 ou moins"),
    Rule("/etc/sudoers", _O_ALL | _G_W | stat.S_IWUSR, "440", note="règles d'accès root"),
    Rule("/etc/sudoers.d", _O_W | _G_W, "750/755"),
    Rule("/etc/crontab", _O_W | _G_W, "644", note="modifiable = commande lancée en root"),
    Rule("/etc/ssh/sshd_config", _O_W | _G_W, "644"),
    Rule("/root", _O_ALL, "700", note="dossier personnel de root"),
    Rule("/tmp", 0, "1777 (sticky)", required=stat.S_ISVTX,
         note="sans sticky bit, chacun peut supprimer les fichiers des autres"),
    Rule("/var/tmp", 0, "1777 (sticky)", required=stat.S_ISVTX),
]


def home_rules(home: Path) -> list[Rule]:
    return [
        Rule(str(home), _O_ALL, "750 ou 700", note="les autres comptes ne doivent pas lire ton dossier"),
        Rule(str(home / ".ssh"), _GO_ALL, "700"),
        Rule(str(home / ".ssh/authorized_keys"), _G_W | _O_W, "600/644",
             note="modifiable = quelqu'un peut ajouter sa clé et se connecter"),
        *[Rule(str(key), _GO_ALL, "600", note="clé privée SSH")
          for key in sorted((home / ".ssh").glob("id_*")) if key.suffix != ".pub"],
    ]


def _owner(uid: int) -> str:
    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def _group(gid: int) -> str:
    try:
        return grp.getgrgid(gid).gr_name
    except KeyError:
        return str(gid)


def audit_file(rule: Rule) -> FileAudit | None:
    try:
        st = os.lstat(rule.path)  # lstat: judge a symlink itself, do not follow it
    except FileNotFoundError:
        return None
    except PermissionError:
        return FileAudit(path=rule.path, mode="?", octal="?", owner="?", group="?",
                         expected=rule.expected, ok=True, note="illisible (normal sans root)")
    mode = st.st_mode
    ok = not (mode & rule.forbidden) and (mode & rule.required) == rule.required
    return FileAudit(
        path=rule.path, mode=stat.filemode(mode), octal=oct(stat.S_IMODE(mode))[2:].zfill(3),
        owner=_owner(st.st_uid), group=_group(st.st_gid), expected=rule.expected,
        ok=ok, note=rule.note,
    )


WORLD_WRITABLE_DIRS = ["/etc", "/usr/bin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin",
                       "/usr/lib/systemd/system", "/etc/systemd/system"]


def world_writable(dirs: list[str] = WORLD_WRITABLE_DIRS, limit: int = 200) -> list[str]:
    """Regular files anyone can modify in system directories (should be none)."""
    found = []
    for top in dirs:
        for root, _dirs, files in os.walk(top, onerror=lambda _e: None):
            for name in files:
                path = os.path.join(root, name)
                try:
                    st = os.lstat(path)
                except OSError:
                    continue
                if stat.S_ISREG(st.st_mode) and st.st_mode & stat.S_IWOTH:
                    found.append(path)
                    if len(found) >= limit:
                        return found
    return found


def permissions(home: Path | None = None) -> Permissions:
    rules = SYSTEM_RULES + home_rules(home or Path.home())
    audits = [a for a in map(audit_file, rules) if a is not None]
    return Permissions(files=audits, world_writable=world_writable())


# ---------- SUID / SGID ----------

# Usual SUID/SGID binaries on Debian/Ubuntu/Fedora/Arch base systems.
KNOWN_SUID = {
    "su", "sudo", "sudoedit", "passwd", "chsh", "chfn", "gpasswd", "newgrp", "sg",
    "mount", "umount", "fusermount", "fusermount3", "pkexec", "polkit-agent-helper-1",
    "ping", "ping6", "traceroute6.iputils", "ssh-keysign", "ssh-agent",
    "dbus-daemon-launch-helper", "snap-confine", "chrome-sandbox", "Xorg.wrap",
    "pppd", "ntfs-3g", "unix_chkpwd", "pam_extrausers_chkpwd", "crontab", "at",
    "expiry", "chage", "wall", "write", "bsd-write", "dotlockfile", "plocate",
    "mlocate", "locate", "newuidmap", "newgidmap", "lxc-user-nic", "vmware-user-suid-wrapper",
    "mount.nfs", "mount.cifs", "mount.ecryptfs_private", "uuidd", "utempter",
    "Xorg", "kismet_cap_linux_wifi", "VBoxHeadless", "VBoxNetAdpCtl", "VBoxNetDHCP",
    "VBoxNetNAT", "VBoxSDL", "VirtualBoxVM", "VBoxVolInfo", "suexec", "staprun",
    "mail-lock", "mail-touchlock", "mail-unlock", "screen", "procmail", "exim4",
    "postdrop", "postqueue", "sendmail", "gnome-pty-helper", "spice-client-glib-usb-acl-helper",
    "qemu-bridge-helper", "ksu", "userhelper", "usernetctl", "cockpit-session",
    "krb5_child", "ldap_child", "selinux_child", "proxy_child", "p11_child", "gpo_child",
    "camel-lock-helper-1.2", "pam_timestamp_check", "dmcrypt-get-device", "bwrap",
    "chromium-sandbox", "nvidia-modprobe", "ksysguardprocesslist_helper", "kcheckpass",
}

# Container image layers hold copies of passwd, su... owned by the user
# (rootless Podman/Docker): legitimate, huge, and slow to walk.
PRUNE_PATHS = ["*/.local/share/containers", "/var/lib/docker", "/var/lib/containers",
               "*/.local/share/docker"]

# Binaries that give a root shell when SUID root (see https://gtfobins.github.io).
_DANGEROUS = re.compile(
    r"^(ba|da|z|k|c|tc|a|fi)?sh$|^(python|perl|ruby|lua|php|node|tclsh)[\d.]*$|"
    r"^(find|vim?|nano|less|more|awk|gawk|mawk|nmap|cp|mv|tar|zip|env|tee|dd|cat|base64|"
    r"xxd|sed|git|wget|curl|rsync|openssl|gdb|strace|busybox|nc|ncat|socat|expect|make|"
    r"taskset|nice|timeout|stdbuf|xargs|time|ionice|run-parts|start-stop-daemon|flock|"
    r"setarch|unshare|docker|systemctl|chmod|chown|install|ed|emacs|journalctl|man|"
    r"screen|tmux|watch|ssh|scp|ftp|bc|jq|diff|head|tail|sort|uniq|od|hexdump|file)$"
)

SCAN_TIMEOUT = 180
CACHE_SECONDS = 600


def parse_find(output: str, ignore_owner: str | None = None) -> list[SuidFile]:
    """Parse `find -printf '%m\\t%u\\t%p\\n'` (octal mode, owner, path).

    Files owned by `ignore_owner` are dropped: a SUID file owned by the
    current user runs with that user's own rights, so it grants nothing.
    """
    files = []
    for line in output.splitlines():
        parts = line.split("\t", 2)
        if len(parts) != 3 or not parts[0].isdigit():
            continue
        octal, owner, path = parts
        if owner == ignore_owner:
            continue
        mode = int(octal, 8)
        suid, sgid = bool(mode & stat.S_ISUID), bool(mode & stat.S_ISGID)
        name = os.path.basename(path)
        files.append(SuidFile(
            path=path, mode=octal, owner=owner,
            kind="suid+sgid" if suid and sgid else "suid" if suid else "sgid",
            known=name in KNOWN_SUID,
            dangerous=suid and owner == "root" and bool(_DANGEROUS.match(name)),
        ))
    return sorted(files, key=lambda f: (not f.dangerous, f.known, f.path))


class SuidScanner:
    """Runs the slow full-disk scan at most once at a time and caches the result."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cache: SuidScan | None = None

    @property
    def cached(self) -> SuidScan | None:
        """Last result without scanning (None if never scanned)."""
        return self._cache

    def get(self, refresh: bool = False, run: runner.Runner | None = None) -> SuidScan:
        with self._lock:  # a second caller waits for the running scan, no double scan
            fresh = self._cache and (
                datetime.now(timezone.utc) - self._cache.scanned_at
            ).total_seconds() < CACHE_SECONDS
            if fresh and not refresh:
                return self._cache
            start = time.monotonic()
            # -xdev: stay on the root filesystem (skips /proc, /sys, snap images).
            # find exits 1 on "Permission denied" dirs: runner keeps stdout anyway.
            prune: list[str] = []
            for pattern in PRUNE_PATHS:
                prune += ["-o" if prune else "(", "-path", pattern]
            out = runner.run(
                ["find", "/", "-xdev", *prune, ")", "-prune", "-o",
                 "-type", "f", "-perm", "/6000", "-printf", r"%m\t%u\t%p\n"],
                timeout=SCAN_TIMEOUT, runner=run,
            )
            self._cache = SuidScan(
                files=parse_find(out, ignore_owner=getpass.getuser()),
                scanned_at=datetime.now(timezone.utc),
                duration_seconds=round(time.monotonic() - start, 2),
            )
            return self._cache


suid_scanner = SuidScanner()
