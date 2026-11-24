"""Actions that change the system: kill a process, close a port, firewall.

The web server always runs as the normal user. Root is obtained for one
command at a time through polkit:
- `pkexec <absolute path> <args>` opens the system password dialog
  (see root_helpers.py for the small programs we run that way);
- `systemctl stop` asks polkit by itself (same dialog).
The password never goes through PC Doctor: polkit's agent (gnome-shell)
handles it.

Security rules:
- every argument is validated (by Pydantic at the API, and again here);
- argument lists only, never a shell, so a value cannot become a command;
- absolute paths for the programs, so a modified $PATH cannot swap them;
- what to stop is recomputed here from the live system, never taken from
  the page (the page sends a port number, not a unit name).
"""

import json
import os
import signal
from datetime import datetime
from pathlib import Path
from typing import Literal

import psutil

from app.system import network, procnet, root_helpers, runner
from app.system.models import ActionResult, FirewallStatus
from app.system.processes import is_protected
from app.system.runner import CommandError

PKEXEC = "/usr/bin/pkexec"
SYSTEMCTL = "/usr/bin/systemctl"
UFW = "/usr/sbin/ufw"
UFW_CONF = Path("/etc/ufw/ufw.conf")

AUTH_TIMEOUT = 120  # seconds left to type the password
PKEXEC_DISMISSED = 126  # dialog closed / cancelled
PKEXEC_NOT_AUTHORIZED = 127  # wrong password or no polkit agent

Signal = Literal["TERM", "KILL"]
Protocol = Literal["tcp", "udp"]
SIGNALS = {"TERM": signal.SIGTERM, "KILL": signal.SIGKILL}


class ActionError(RuntimeError):
    """Refused or failed action; the message is shown to the user as is."""

    def __init__(self, message: str, returncode: int | None = None) -> None:
        super().__init__(message)
        self.returncode = returncode


def run_privileged(cmd: list[str], run: runner.Runner | None = None) -> str:
    """Run `cmd` as root after the system password dialog."""
    try:
        proc = runner.run_full([PKEXEC, *cmd], timeout=AUTH_TIMEOUT, runner=run)
    except CommandError as exc:
        raise ActionError(f"pkexec indisponible ou délai dépassé : {exc}") from exc
    if proc.returncode == PKEXEC_DISMISSED:
        raise ActionError("Authentification annulée.")
    if proc.returncode == PKEXEC_NOT_AUTHORIZED:
        raise ActionError("Authentification refusée (mauvais mot de passe ou pas d'agent polkit).")
    if proc.returncode != 0:
        raise ActionError(proc.stderr.strip()[:300] or f"{cmd[0]} a échoué", proc.returncode)
    return proc.stdout


# ---------- processes ----------

KILL_OTHER_PROCESS = 3  # exit codes of root_helpers.KILL_IF_SAME
KILL_GONE = 4


def start_ticks(pid: int, proc_root: Path = Path("/proc")) -> str:
    """Start time of `pid` in clock ticks since boot (/proc/<pid>/stat, field 22).

    The command name (field 2) is in parentheses and may contain spaces or
    ")" itself, so we split after the *last* ")".
    """
    stat = (proc_root / str(pid) / "stat").read_text()
    return stat.rsplit(")", 1)[1].split()[19]


def kill_process(pid: int, started: datetime, sig: Signal,
                 run: runner.Runner | None = None) -> ActionResult:
    """Send SIGTERM (ask to quit) or SIGKILL (force) to `pid`.

    PIDs are recycled: if the process the page showed has exited and another
    one got its number, we must not kill the newcomer. So:
    1. pidfd_open() gives a handle on *this* process: as long as it is open,
       a signal sent through it can only reach this process;
    2. we check its start time against the one the page displayed;
    3. we signal through the pidfd. Another user's process needs root: the
       same open-check-signal sequence then runs in one root process.
    """
    if sig not in SIGNALS:
        raise ActionError("Signal non autorisé.")
    try:
        pidfd = os.pidfd_open(pid)
    except ProcessLookupError as exc:
        raise ActionError("Ce processus est déjà terminé.") from exc
    try:
        try:
            proc = psutil.Process(pid)
            created, ppid, name = proc.create_time(), proc.ppid(), proc.name()
            ticks = start_ticks(pid)
        except (psutil.NoSuchProcess, FileNotFoundError) as exc:
            raise ActionError("Ce processus est déjà terminé.") from exc
        if abs(created - started.timestamp()) > 0.01:
            raise ActionError("Ce PID appartient maintenant à un autre programme : rafraîchis la liste.")
        if is_protected(pid, ppid):
            raise ActionError(f"{name} ({pid}) est protégé : le tuer bloquerait la machine ou PC Doctor.")
        try:
            signal.pidfd_send_signal(pidfd, SIGNALS[sig])  # own process: no root needed
            return ActionResult(message=f"Signal {sig} envoyé à {name} ({pid}).", privileged=False)
        except ProcessLookupError as exc:
            raise ActionError("Ce processus est déjà terminé.") from exc
        except PermissionError:
            pass  # another user's process: retry as root
    finally:
        os.close(pidfd)

    try:
        run_privileged(root_helpers.command(root_helpers.KILL_IF_SAME, str(pid), ticks, sig), run)
    except ActionError as exc:
        code = getattr(exc, "returncode", None)
        if code == KILL_OTHER_PROCESS:
            raise ActionError("Ce PID appartient maintenant à un autre programme : rien n'a été tué.") from exc
        if code == KILL_GONE:
            raise ActionError("Ce processus s'est terminé pendant la saisie du mot de passe.") from exc
        raise
    return ActionResult(message=f"Signal {sig} envoyé à {name} ({pid}) en root.", privileged=True)


# ---------- ports ----------

def listening_inodes(entries: list[procnet.SocketEntry]) -> dict[tuple[str, int, str], int]:
    """(proto, port, address) -> socket inode, for listening sockets only."""
    inodes = {}
    for e in entries:
        listening = e.state == procnet.TCP_LISTEN if e.proto == "tcp" else e.remote_port == 0
        if listening and e.inode:
            inodes[(e.proto, e.local_port, network.normalize_address(e.local_ip))] = e.inode
    return inodes


def reveal_port_owners(run: runner.Runner | None = None) -> ActionResult:
    """Find the program behind every port with one root call.

    Root lists the socket inodes each process holds (kernel-written links);
    we match them with the inodes of /proc/net/* (readable without root).
    """
    raw = run_privileged(root_helpers.command(root_helpers.SOCKET_OWNERS), run)
    try:
        by_inode = {int(k): int(v) for k, v in json.loads(raw).items()}
    except (ValueError, AttributeError) as exc:
        raise ActionError("Réponse inattendue de l'outil root.") from exc
    owners = {key: by_inode[inode] for key, inode in listening_inodes(procnet.sockets()).items()
              if inode in by_inode}
    network.revealed_owners.update(owners)
    return ActionResult(message=f"{len(owners)} ports associés à leur programme.", privileged=True)


def units_for_port(protocol: Protocol, port: int) -> list[str]:
    """Units holding `port`, looked up on the live system (never from the page)."""
    units: list[str] = []
    for p in network.listening_ports():
        if p.protocol.rstrip("6") == protocol and p.port == port:
            units += [u for u in p.units if u not in units]
    return units


def stop_port_service(protocol: Protocol, port: int, disable: bool,
                      run: runner.Runner | None = None) -> ActionResult:
    """Stop (and optionally disable at boot) the systemd units behind a port.

    systemctl talks to systemd over D-Bus; systemd asks polkit, which shows
    the password dialog. No pkexec needed.
    """
    units = units_for_port(protocol, port)
    if not units:
        raise ActionError("Aucun service systemd trouvé pour ce port : arrête plutôt le processus.")
    cmd = [SYSTEMCTL, "disable", "--now", "--", *units] if disable else [SYSTEMCTL, "stop", "--", *units]
    try:
        proc = runner.run_full(cmd, timeout=AUTH_TIMEOUT, runner=run)
    except CommandError as exc:
        raise ActionError(str(exc)) from exc
    if proc.returncode != 0:
        raise ActionError(proc.stderr.strip()[:300] or "systemctl a échoué")
    what = "arrêté et désactivé au démarrage" if disable else "arrêté (jusqu'au prochain redémarrage)"
    return ActionResult(message=f"{', '.join(units)} : {what}.", privileged=True)


# ---------- firewall ----------

def firewall_status(conf: Path = UFW_CONF) -> FirewallStatus:
    """ufw.conf is world-readable: no root needed to know if ufw is on."""
    text = runner.read_text(conf) or ""
    enabled = any(line.strip().lower() == "enabled=yes" for line in text.splitlines())
    return FirewallStatus(installed=Path(UFW).exists(), enabled=enabled)


def firewall_rule(protocol: Protocol, port: int, block: bool,
                  run: runner.Runner | None = None) -> ActionResult:
    """Add (`ufw deny 22/tcp`) or remove (`ufw delete deny 22/tcp`) a block rule."""
    if not 1 <= port <= 65535 or protocol not in ("tcp", "udp"):
        raise ActionError("Port ou protocole invalide.")
    rule = f"{port}/{protocol}"
    run_privileged([UFW, "deny", rule] if block else [UFW, "delete", "deny", rule], run)
    if block and not firewall_status().enabled:
        return ActionResult(privileged=True, message=(
            f"Règle ajoutée pour {rule}, mais le pare-feu est désactivé : "
            "elle ne s'appliquera qu'une fois ufw activé."))
    return ActionResult(privileged=True,
                        message=f"{rule} {'bloqué' if block else 'débloqué'} dans le pare-feu.")


def firewall_enable(enabled: bool, run: runner.Runner | None = None) -> ActionResult:
    # --force: ufw normally asks "Proceed? (y|n)" on a terminal we do not have.
    run_privileged([UFW, "--force", "enable"] if enabled else [UFW, "disable"], run)
    return ActionResult(privileged=True,
                        message="Pare-feu activé." if enabled else "Pare-feu désactivé.")
