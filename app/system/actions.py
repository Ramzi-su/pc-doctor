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

import hashlib
import ipaddress
import json
import os
import re
import signal
import threading
from datetime import datetime
from pathlib import Path
from typing import Literal

import psutil

from app.system import network, procnet, root_helpers, runner
from app.system.models import ActionResult, FirewallPolicies, FirewallRule, FirewallStatus
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
#
# Every ufw command runs through root_helpers.UFW_THEN_RULES: one password
# changes the firewall *and* reads the rules back (their files are root-only),
# so the list on the page is always the one ufw just wrote.

UFW_DEFAULTS = Path("/etc/default/ufw")
POLICY_NAMES = {"ACCEPT": "allow", "DROP": "deny", "REJECT": "reject"}
POLICY_KEYS = {"incoming": "DEFAULT_INPUT_POLICY", "outgoing": "DEFAULT_OUTPUT_POLICY",
               "routed": "DEFAULT_FORWARD_POLICY"}

Policy = Literal["allow", "deny", "reject"]
PolicyDirection = Literal["incoming", "outgoing", "routed"]
LogLevel = Literal["off", "low", "medium", "high", "full"]
RuleAction = Literal["allow", "deny", "reject", "limit"]
Direction = Literal["in", "out"]
RuleProtocol = Literal["tcp", "udp", "any"]

ANY_ADDRESSES = {"0.0.0.0/0", "::/0", "any"}
MAX_PORTS = 15  # iptables multiport limit (a range counts as two)
PORTS_RE = re.compile(r"\d{1,5}(:\d{1,5})?(,\d{1,5}(:\d{1,5})?)*")
# Letters (accents included), digits, space, . _ - ; not starting with "-"
# so ufw can never read it as an option.
COMMENT_RE = re.compile(r"[^\W_][\w .-]{0,59}")


def read_key_values(path: Path) -> dict[str, str]:
    """KEY=value lines of a shell-style config file (quotes removed)."""
    values = {}
    for line in (runner.read_text(path) or "").splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and not key.startswith("#"):
            values[key.strip()] = value.strip().strip("\"'")
    return values


class FirewallRules:
    """Last rules read as root (shared by all requests, so locked)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.rules: list[FirewallRule] | None = None
        self.read_at: datetime | None = None

    def update(self, rules: list[FirewallRule]) -> None:
        with self._lock:
            self.rules, self.read_at = rules, datetime.now().astimezone()

    def get(self) -> tuple[list[FirewallRule] | None, datetime | None]:
        with self._lock:
            return self.rules, self.read_at

    def find(self, rule_id: str) -> FirewallRule | None:
        with self._lock:
            return next((r for r in self.rules or [] if r.id == rule_id), None)


firewall_rules = FirewallRules()


def firewall_status(conf: Path = UFW_CONF, defaults: Path = UFW_DEFAULTS) -> FirewallStatus:
    """ufw.conf and /etc/default/ufw are world-readable: no root needed."""
    main = read_key_values(conf)
    policies = read_key_values(defaults)
    level = main.get("LOGLEVEL", "").lower() or None
    rules, read_at = firewall_rules.get()
    return FirewallStatus(
        installed=Path(UFW).exists(),
        enabled=main.get("ENABLED", "").lower() == "yes",
        policies=FirewallPolicies(**{
            name: POLICY_NAMES.get(policies.get(key, "").upper()) for name, key in POLICY_KEYS.items()}),
        logging="low" if level == "on" else level,
        rules=rules, rules_read_at=read_at,
    )


def parse_tuple(line: str, ipv6: bool) -> FirewallRule | None:
    """Parse one "### tuple ###" line (the format of ufw's _read_rules()).

    action proto dport dst sport src [dapp sapp] direction [comment=<hex>]
    e.g. "allow_log tcp 22 0.0.0.0/0 any 192.168.1.0/24 in_wlp2s0 comment=737368"
    """
    body, _, comment_hex = line.partition(" comment=")
    fields = body.split()
    if len(fields) not in (7, 9):
        return None
    action, proto, dport, dst, sport, src = fields[:6]
    dapp, sapp = (fields[6], fields[7]) if len(fields) == 9 else ("-", "-")
    route, _, action = action.rpartition(":")
    action, _, log = action.partition("_")
    direction, iface_in, iface_out = "in", "", ""
    for part in fields[-1].split("!"):
        name, _, iface = part.partition("_")
        if name not in ("in", "out"):
            return None
        direction = name if not iface_in and not iface_out else direction
        if name == "in":
            iface_in = iface
        else:
            iface_out = iface
    try:
        comment = bytes.fromhex(comment_hex.strip()).decode("utf-8", "replace")
    except ValueError:
        comment = ""
    unspace = lambda app: "" if app == "-" else app.replace("%20", " ")  # noqa: E731
    return FirewallRule(
        id=hashlib.sha256(f"{int(ipv6)}|{line}".encode()).hexdigest()[:16],
        action=action, direction=direction, route=route == "route", log=log, protocol=proto,
        to_address=dst, to_port="" if dport == "any" else dport, to_app=unspace(dapp),
        from_address=src, from_port="" if sport == "any" else sport, from_app=unspace(sapp),
        interface_in=iface_in, interface_out=iface_out, ipv6=ipv6, comment=comment,
    )


def parse_rules(dump: dict[str, list[str]]) -> list[FirewallRule]:
    rules = []
    for name, ipv6 in (("user.rules", False), ("user6.rules", True)):
        for line in dump.get(name, []):
            rule = parse_tuple(line, ipv6)
            if rule:
                rules.append(rule)
    return rules


def run_ufw(args: list[str], run: runner.Runner | None = None) -> str:
    """`ufw <args>` as root, then refresh the rules cache. Returns ufw's output."""
    raw = run_privileged(root_helpers.command(root_helpers.UFW_THEN_RULES, *args), run)
    try:
        data = json.loads(raw)
        rules = parse_rules(data["rules"])
        code, out, err = int(data["returncode"]), str(data["stdout"]).strip(), str(data["stderr"]).strip()
    except (ValueError, KeyError, TypeError, AttributeError) as exc:
        raise ActionError("Réponse inattendue de l'outil root.") from exc
    firewall_rules.update(rules)
    if code != 0:
        raise ActionError(f"ufw a refusé : {(err or out)[:300]}", code)
    if "non-existent rule" in out:
        raise ActionError("Cette règle n'existe plus (déjà supprimée ?) : la liste a été relue.")
    return out


def reveal_firewall_rules(run: runner.Runner | None = None) -> ActionResult:
    run_ufw([], run)
    rules, _ = firewall_rules.get()
    return ActionResult(privileged=True, message=f"{len(rules or [])} règles lues.")


def firewall_rule(protocol: Protocol, port: int, block: bool,
                  run: runner.Runner | None = None) -> ActionResult:
    """Add (`ufw deny 22/tcp`) or remove (`ufw delete deny 22/tcp`) a block rule."""
    if not 1 <= port <= 65535 or protocol not in ("tcp", "udp"):
        raise ActionError("Port ou protocole invalide.")
    rule = f"{port}/{protocol}"
    run_ufw(["deny", rule] if block else ["delete", "deny", rule], run)
    if block and not firewall_status().enabled:
        return ActionResult(privileged=True, message=(
            f"Règle ajoutée pour {rule}, mais le pare-feu est désactivé : "
            "elle ne s'appliquera qu'une fois ufw activé."))
    return ActionResult(privileged=True,
                        message=f"{rule} {'bloqué' if block else 'débloqué'} dans le pare-feu.")


def firewall_enable(enabled: bool, run: runner.Runner | None = None) -> ActionResult:
    # --force: ufw normally asks "Proceed? (y|n)" on a terminal we do not have.
    run_ufw(["--force", "enable"] if enabled else ["disable"], run)
    return ActionResult(privileged=True,
                        message="Pare-feu activé." if enabled else "Pare-feu désactivé.")


def firewall_default(direction: PolicyDirection, policy: Policy,
                     run: runner.Runner | None = None) -> ActionResult:
    """`ufw default deny incoming`: what happens to traffic no rule matches."""
    if direction not in POLICY_KEYS or policy not in ("allow", "deny", "reject"):
        raise ActionError("Politique invalide.")
    run_ufw(["default", policy, direction], run)
    return ActionResult(privileged=True, message=f"Politique par défaut {direction} : {policy}.")


def firewall_logging(level: LogLevel, run: runner.Runner | None = None) -> ActionResult:
    """`ufw logging low`: blocked packets go to the kernel log ([UFW BLOCK])."""
    if level not in ("off", "low", "medium", "high", "full"):
        raise ActionError("Niveau de journalisation invalide.")
    run_ufw(["logging", level], run)
    return ActionResult(privileged=True, message=f"Journalisation du pare-feu : {level}.")


# ----- user rules: validation -----

def check_ports(value: str) -> str:
    """"" (no port), "22", "8000:8100" or "80,443"; raises ValueError otherwise."""
    value = value.strip()
    if not value:
        return ""
    if not PORTS_RE.fullmatch(value):
        raise ValueError("port : un nombre, une plage 8000:8100 ou une liste 80,443")
    count = 0
    for part in value.split(","):
        bounds = [int(b) for b in part.split(":")]
        if not all(1 <= b <= 65535 for b in bounds) or bounds != sorted(set(bounds)):
            raise ValueError(f"port invalide : {part}")
        count += len(bounds)
    if count > MAX_PORTS:
        raise ValueError(f"au plus {MAX_PORTS} ports (une plage compte pour deux)")
    return value


def check_address(value: str) -> str:
    """"any" or an IPv4/IPv6 address or network, normalized ("10.0.0.5/8" -> "10.0.0.0/8")."""
    value = value.strip() or "any"
    if value.lower() == "any":
        return "any"
    if "%" in value:  # Python accepts IPv6 scope ids ("fe80::1%eth0"), ufw does not
        raise ValueError(f"adresse invalide : {value}")
    try:
        return str(ipaddress.ip_network(value, strict=False))
    except ValueError as exc:
        raise ValueError(f"adresse invalide : {value}") from exc


def check_comment(value: str) -> str:
    value = value.strip()
    if value and not COMMENT_RE.fullmatch(value):
        raise ValueError("commentaire : lettres, chiffres, espaces et . _ - seulement (60 max)")
    return value


def _version(address: str) -> int | None:
    return None if address == "any" else ipaddress.ip_network(address).version


def add_firewall_rule(action: RuleAction, direction: Direction, protocol: RuleProtocol,
                      from_address: str, from_port: str, to_address: str, to_port: str,
                      log: bool, comment: str,
                      run: runner.Runner | None = None) -> ActionResult:
    """`ufw allow in proto tcp from any to any port 22 comment ssh`, field by field."""
    if action not in ("allow", "deny", "reject", "limit") or direction not in ("in", "out") \
            or protocol not in ("tcp", "udp", "any"):
        raise ActionError("Action, direction ou protocole invalide.")
    try:  # checked by Pydantic already; again here so no caller can skip it
        src, dst = check_address(from_address), check_address(to_address)
        sport, dport, comment = check_ports(from_port), check_ports(to_port), check_comment(comment)
    except ValueError as exc:
        raise ActionError(str(exc)) from exc
    if None not in (_version(src), _version(dst)) and _version(src) != _version(dst):
        raise ActionError("Source et destination doivent être toutes deux IPv4 ou IPv6.")
    if protocol == "any" and any(c in sport + dport for c in ":,"):
        raise ActionError("Une plage ou une liste de ports demande tcp ou udp.")
    args = [action, direction]
    if log:
        args.append("log")
    if protocol != "any":
        args += ["proto", protocol]
    args += ["from", src] + (["port", sport] if sport else [])
    args += ["to", dst] + (["port", dport] if dport else [])
    if comment:
        args += ["comment", comment]
    out = run_ufw(args, run)
    if "Skipping" in out:
        return ActionResult(privileged=True, message="Cette règle existe déjà : rien n'a changé.")
    return ActionResult(privileged=True, message=f"Règle ajoutée : ufw {' '.join(args)}")


def delete_args(rule: FirewallRule) -> list[str]:
    """The `ufw delete …` arguments that match `rule` (rebuilt from the parsed file)."""
    args = (["route", "delete"] if rule.route else ["delete"]) + [rule.action]
    if rule.route and (rule.interface_in or rule.interface_out):
        if rule.interface_in:
            args += ["in", "on", rule.interface_in]
        if rule.interface_out:
            args += ["out", "on", rule.interface_out]
    else:
        args.append(rule.direction)
        iface = rule.interface_in or rule.interface_out
        if iface:
            args += ["on", iface]
    if rule.log:
        args.append(rule.log)
    if rule.protocol != "any" and not (rule.from_app or rule.to_app):
        args += ["proto", rule.protocol]
    for word, address, port, app in (("from", rule.from_address, rule.from_port, rule.from_app),
                                     ("to", rule.to_address, rule.to_port, rule.to_app)):
        args += [word, "any" if address in ANY_ADDRESSES else address]
        if app:
            args += ["app", app]
        elif port:
            args += ["port", port]
    return args


def delete_firewall_rule(rule_id: str, run: runner.Runner | None = None) -> ActionResult:
    """Delete a rule by the id the page got from the last root read.

    The page never sends the rule's text: we rebuild the command from the
    rules root read, and ufw only deletes a rule that matches exactly.
    """
    rule = firewall_rules.find(rule_id)
    if rule is None:
        raise ActionError("Règle inconnue : relis les règles d'abord.")
    args = delete_args(rule)
    run_ufw(args, run)
    both = rule.from_address in ANY_ADDRESSES and rule.to_address in ANY_ADDRESSES
    return ActionResult(privileged=True, message=f"Règle supprimée : ufw {' '.join(args)}"
                        + (" (IPv4 et IPv6)" if both else ""))
