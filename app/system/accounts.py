"""Users, groups and login history.

/etc/passwd and /etc/group are world-readable by design (they hold no
passwords). Password hashes live in /etc/shadow, which needs root: we never
try to read it.
"""

import getpass
import grp
import pwd
import re
from pathlib import Path

from app.system import runner
from app.system.models import Accounts, Group, Login, User
from app.system.runner import CommandError

NO_LOGIN_SHELLS = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false", "/usr/bin/false", ""}
ADMIN_GROUPS = {"sudo", "wheel", "admin"}

# Groups that grant powerful rights; membership deserves attention.
SENSITIVE_GROUPS = {
    "sudo": "administrateur : peut lancer n'importe quelle commande en root",
    "wheel": "administrateur : peut lancer n'importe quelle commande en root",
    "admin": "administrateur : peut lancer n'importe quelle commande en root",
    "root": "groupe de root : accès à des fichiers système",
    "docker": "équivalent root : un conteneur peut monter / en écriture",
    "lxd": "équivalent root : un conteneur peut monter / en écriture",
    "disk": "équivalent root : lecture/écriture brute des disques",
    "shadow": "peut lire les empreintes des mots de passe (/etc/shadow)",
    "adm": "peut lire tous les logs système",
    "systemd-journal": "peut lire tous les logs du journal",
    "input": "peut lire le clavier et la souris (keylogger possible)",
    "video": "accès direct à l'écran et à la caméra",
    "libvirt": "peut créer des machines virtuelles (proche de root)",
    "kvm": "accès à la virtualisation matérielle",
}


def uid_min(login_defs: Path = Path("/etc/login.defs")) -> int:
    """First UID of human accounts (1000 on most distributions)."""
    try:
        match = re.search(r"^\s*UID_MIN\s+(\d+)", login_defs.read_text(), re.M)
    except OSError:
        match = None
    return int(match.group(1)) if match else 1000


def users_and_groups() -> tuple[list[User], list[Group]]:
    first_uid = uid_min()
    all_groups = grp.getgrall()
    gid_to_name = {g.gr_gid: g.gr_name for g in all_groups}
    members: dict[str, set[str]] = {g.gr_name: set(g.gr_mem) for g in all_groups}

    users = []
    for entry in sorted(pwd.getpwall(), key=lambda p: p.pw_uid):
        primary = gid_to_name.get(entry.pw_gid)
        if primary:
            members.setdefault(primary, set()).add(entry.pw_name)
        user_groups = sorted(g for g, m in members.items() if entry.pw_name in m)
        users.append(User(
            name=entry.pw_name, uid=entry.pw_uid, gid=entry.pw_gid,
            home=entry.pw_dir, shell=entry.pw_shell,
            human=first_uid <= entry.pw_uid < 65534,  # 65534 = nobody
            can_login=entry.pw_shell not in NO_LOGIN_SHELLS,
            groups=user_groups,
            admin=entry.pw_uid == 0 or bool(ADMIN_GROUPS & set(user_groups)),
        ))

    groups = [
        Group(
            name=g.gr_name, gid=g.gr_gid, members=sorted(members.get(g.gr_name, ())),
            sensitive=g.gr_name in SENSITIVE_GROUPS, why=SENSITIVE_GROUPS.get(g.gr_name),
        )
        for g in sorted(all_groups, key=lambda g: g.gr_gid)
    ]
    return users, groups


_LAST_LINE = re.compile(
    r"^(?P<user>\S+)\s+(?P<tty>\S+)\s+(?P<source>.*?)\s+"
    r"(?P<start>\d{4}-\d\d-\d\dT\S+)\s+(?P<end>.+?)\s*$"
)


def parse_last(output: str) -> list[Login]:
    logins = []
    for line in output.splitlines():
        match = _LAST_LINE.match(line)
        if match:
            end = match["end"].lstrip("- ").strip()
            logins.append(Login(user=match["user"], terminal=match["tty"],
                                source=match["source"].strip(), start=match["start"], end=end))
    return logins


def login_history(limit: int = 50, run: runner.Runner | None = None) -> list[Login]:
    """Successful logins from /var/log/wtmp (world-readable). Failed ones need root."""
    try:
        out = runner.run(["last", "-n", str(limit), "--time-format", "iso", "-w"], runner=run)
    except CommandError:
        return []
    return parse_last(out)


def accounts(run: runner.Runner | None = None) -> Accounts:
    users, groups = users_and_groups()
    return Accounts(users=users, groups=groups, logins=login_history(run=run),
                    current_user=getpass.getuser())
