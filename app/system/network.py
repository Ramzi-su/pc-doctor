"""Network interfaces (with their physical card) and listening ports."""

import ipaddress
import re
import socket
import threading
from datetime import datetime, timezone
from pathlib import Path

import psutil

from app.system import runner
from app.system.models import Interface, PciDevice, Port
from app.system.runner import CommandError, read_text

SYS = Path("/sys")


def _kind(name: str, net_dir: Path) -> str:
    if name == "lo":
        return "loopback"
    if (net_dir / "wireless").exists() or (net_dir / "phy80211").exists():
        return "wifi"
    if not (net_dir / "device").exists():
        return "virtual"  # docker0, veth, VPN tunnels...
    return "ethernet"


def parse_ethtool(output: str) -> dict[str, str]:
    fields = {}
    for line in output.splitlines():
        key, _, value = line.partition(":")
        fields[key.strip()] = value.strip()
    return fields


def interfaces(pci: list[PciDevice], sys_root: Path = SYS,
               run: runner.Runner | None = None) -> list[Interface]:
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()
    counters = psutil.net_io_counters(pernic=True)
    by_slot = {d.slot: d for d in pci}
    result = []
    for name in sorted(addrs.keys() | stats.keys()):
        net_dir = sys_root / "class/net" / name
        kind = _kind(name, net_dir)
        mac = next((a.address for a in addrs.get(name, []) if a.family == psutil.AF_LINK), None)
        ips = [_with_prefix(a.address, a.netmask)
               for a in addrs.get(name, []) if a.family in (socket.AF_INET, socket.AF_INET6)]
        hardware, driver, firmware = None, None, None
        if kind in ("ethernet", "wifi"):
            # /sys/class/net/<if>/device -> .../0000:09:00.0 (the PCI slot)
            slot = (net_dir / "device").resolve().name
            hardware = by_slot.get(slot.removeprefix("0000:"))
            try:
                info = parse_ethtool(runner.run(["ethtool", "-i", name], runner=run))
                driver = info.get("driver") or None
                fw = info.get("firmware-version")
                firmware = fw if fw and fw != "N/A" else None
            except CommandError:
                driver = hardware.driver if hardware else None
        stat = stats.get(name)
        io = counters.get(name)
        result.append(Interface(
            name=name, kind=kind, mac=mac if mac != "00:00:00:00:00:00" else None,
            state=read_text(net_dir / "operstate") or ("up" if stat and stat.isup else "down"),
            mtu=stat.mtu if stat else None,
            speed_mbps=(stat.speed or None) if stat else None,  # 0 = unknown (Wi-Fi)
            addresses=ips, driver=driver, firmware=firmware, hardware=hardware,
            rx_bytes=io.bytes_recv if io else 0, tx_bytes=io.bytes_sent if io else 0,
            rx_errors=io.errin if io else 0, tx_errors=io.errout if io else 0,
        ))
    return result


def _with_prefix(address: str, netmask: str | None) -> str:
    """'10.0.0.3' + '255.255.255.0' -> '10.0.0.3/24' (also for IPv6)."""
    address = address.split("%")[0]  # drop IPv6 zone ("%wlo1")
    if not netmask:
        return address
    try:
        # Prefix length = number of 1 bits in the mask. ip_network() would
        # reject IPv6 masks written as "ffff:ffff::", so count bits directly.
        prefix = int(ipaddress.ip_address(netmask)).bit_count()
    except ValueError:
        return address
    return f"{address}/{prefix}"


# Usual service behind a port: a hint when the owning process is hidden
# (sockets of other users, e.g. root's sshd, need root to be attributed).
WELL_KNOWN_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 67: "DHCP serveur",
    68: "DHCP client", 80: "HTTP", 111: "rpcbind", 123: "NTP", 137: "NetBIOS",
    139: "Samba", 443: "HTTPS", 445: "Samba", 631: "CUPS (impression)", 1900: "SSDP/UPnP",
    3000: "dev server", 3306: "MySQL", 3389: "RDP", 5000: "dev server", 5173: "Vite",
    5353: "mDNS (Avahi)", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8000: "dev server", 8080: "HTTP alt", 8765: "PC Doctor", 11434: "Ollama",
    27017: "MongoDB",
}


def is_exposed(address: str) -> bool:
    """True if a socket bound to `address` is reachable from other machines."""
    try:
        ip = ipaddress.ip_address(address.split("%")[0])  # drop "%lo" zone
    except ValueError:
        return True  # unknown: assume the worst
    if ip.is_loopback:
        return False
    # IPv4-mapped loopback (::ffff:127.0.0.1)
    mapped = getattr(ip, "ipv4_mapped", None)
    return not (mapped and mapped.is_loopback)


def _process(pid: int | None) -> tuple[str | None, str | None, datetime | None]:
    if pid is None:
        return None, None, None
    try:
        p = psutil.Process(pid)
        return p.name(), p.username(), datetime.fromtimestamp(p.create_time(), timezone.utc)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None, None, None


def normalize_address(address: str) -> str:
    """Same spelling for psutil and ss/systemctl: no brackets, no %zone,
    and "*" (ss: every address) folded with the IPv4/IPv6 wildcards."""
    address = address.strip("[]").split("%")[0]
    return "*" if address in ("*", "0.0.0.0", "::") else address


def split_endpoint(endpoint: str) -> tuple[str, int] | None:
    """"[::]:22" -> ("*", 22); "127.0.0.53%lo:53" -> ("127.0.0.53", 53)."""
    address, _, port = endpoint.rpartition(":")
    if not address or not port.isdigit():
        return None
    return normalize_address(address), int(port)


def parse_list_sockets(output: str) -> dict[tuple[str, int, str], list[str]]:
    """`systemctl list-sockets --show-types` -> {(proto, port, address): [units]}.

    A socket-activated service (e.g. ssh on Ubuntu) is listened on by
    systemd itself (PID 1): closing the port means stopping the .socket
    unit *and* the .service it starts. No root needed to list them.
    """
    units: dict[tuple[str, int, str], list[str]] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[1] not in ("Stream", "Datagram"):
            continue  # unix sockets, netlink, FIFOs...
        endpoint = split_endpoint(parts[0])
        if endpoint is None:
            continue
        proto = "tcp" if parts[1] == "Stream" else "udp"
        names = [u for u in parts[2:] if UNIT_RE.fullmatch(u)]
        units[(proto, endpoint[1], endpoint[0])] = names
    return units


UNIT_RE = re.compile(r"[A-Za-z0-9@_.:\\-]+\.(service|socket)")


def unit_of_pid(pid: int, proc_root: Path = Path("/proc")) -> str | None:
    """System service a process belongs to, from its cgroup (world-readable):
    "0::/system.slice/mysql.service" -> "mysql.service". None for user apps."""
    cgroup = read_text(proc_root / str(pid) / "cgroup") or ""
    match = re.search(r"^0::/system\.slice/(?:.*/)?([^/]+\.service)$", cgroup, re.M)
    return match.group(1) if match else None


class RevealedOwners:
    """Port owners found once with root, kept to fill later listings.

    A PID can be reused by an unrelated program after the owner exits, so we
    remember its start time and drop the entry when it no longer matches.
    """

    def __init__(self) -> None:
        self._owners: dict[tuple[str, int, str], tuple[int, float]] = {}
        self._lock = threading.Lock()

    def update(self, owners: dict[tuple[str, int, str], int]) -> None:
        found = {}
        for key, pid in owners.items():
            try:
                found[key] = (pid, psutil.Process(pid).create_time())
            except psutil.NoSuchProcess:
                continue
        with self._lock:
            self._owners = found

    def get(self, proto: str, port: int, address: str) -> int | None:
        with self._lock:
            entry = self._owners.get((proto, port, address))
        if entry is None:
            return None
        pid, started = entry
        try:
            return pid if psutil.Process(pid).create_time() == started else None
        except psutil.NoSuchProcess:
            return None


revealed_owners = RevealedOwners()


def _socket_units() -> dict[tuple[str, int, str], list[str]]:
    try:
        return parse_list_sockets(runner.run(
            ["systemctl", "list-sockets", "--all", "--no-legend", "--no-pager", "--show-types"],
            timeout=5))
    except CommandError:
        return {}


def listening_ports() -> list[Port]:
    """TCP sockets in LISTEN state and bound UDP sockets.

    psutil reads /proc/net/*: the ports are visible to everyone, but the
    owning process is only known for our own processes (root sees all).
    """
    seen: set[tuple] = set()
    ports = []
    socket_units = _socket_units()
    for conn in psutil.net_connections(kind="inet"):
        is_tcp = conn.type == socket.SOCK_STREAM
        if is_tcp and conn.status != psutil.CONN_LISTEN:
            continue
        if not is_tcp and conn.raddr:
            continue  # connected UDP socket, not a server
        base = "tcp" if is_tcp else "udp"
        proto = base + ("6" if conn.family == socket.AF_INET6 else "")
        key = (proto, conn.laddr.ip, conn.laddr.port, conn.pid)
        if key in seen:
            continue
        seen.add(key)
        endpoint = (base, conn.laddr.port, normalize_address(conn.laddr.ip))
        pid, revealed = conn.pid, False
        if pid is None:
            pid = revealed_owners.get(*endpoint)
            revealed = pid is not None
        name, user, started = _process(pid)
        units = socket_units.get(endpoint, [])
        if not units and pid and pid > 1 and (unit := unit_of_pid(pid)):
            units = [unit]
        ports.append(Port(
            protocol=proto, address=conn.laddr.ip, port=conn.laddr.port,
            exposed=is_exposed(conn.laddr.ip), pid=pid, process=name, user=user, started=started,
            service=WELL_KNOWN_PORTS.get(conn.laddr.port), units=units, revealed=revealed,
        ))
    return sorted(ports, key=lambda p: (not p.exposed, p.port, p.protocol))
