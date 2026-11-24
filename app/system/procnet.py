"""Parser for /proc/net/{tcp,tcp6,udp,udp6} (world-readable, no root needed).

Each line gives a socket's addresses, state, owner UID and inode. We use it to:
- find the UID of the program connecting to PC Doctor (refuse other users);
- match listening ports with the socket inodes found by the root helper.
"""

import socket
from dataclasses import dataclass
from pathlib import Path

PROC_NET = Path("/proc/net")
TCP_LISTEN = "0A"
TCP_ESTABLISHED = "01"


@dataclass(frozen=True)
class SocketEntry:
    proto: str  # "tcp" or "udp" (family folded)
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str  # hex kernel state, e.g. "0A" = LISTEN
    uid: int
    inode: int


def decode_address(hex_addr: str) -> tuple[str, int]:
    """"0100007F:1F90" -> ("127.0.0.1", 8080).

    The kernel prints the address as 32-bit words in host byte order
    (little-endian on x86): each 4-byte word must be reversed.
    """
    ip_hex, port_hex = hex_addr.split(":")
    raw = bytes.fromhex(ip_hex)
    raw = b"".join(raw[i:i + 4][::-1] for i in range(0, len(raw), 4))
    family = socket.AF_INET if len(raw) == 4 else socket.AF_INET6
    return socket.inet_ntop(family, raw), int(port_hex, 16)


def parse_table(text: str, proto: str) -> list[SocketEntry]:
    entries = []
    for line in text.splitlines()[1:]:  # first line is the header
        parts = line.split()
        if len(parts) < 10:
            continue
        try:
            local_ip, local_port = decode_address(parts[1])
            remote_ip, remote_port = decode_address(parts[2])
            entries.append(SocketEntry(proto, local_ip, local_port, remote_ip, remote_port,
                                       parts[3], int(parts[7]), int(parts[9])))
        except ValueError:
            continue
    return entries


def sockets(root: Path = PROC_NET) -> list[SocketEntry]:
    entries = []
    for name in ("tcp", "tcp6", "udp", "udp6"):
        try:
            entries += parse_table((root / name).read_text(), name.rstrip("6"))
        except OSError:
            continue
    return entries


def peer_uid(client_ip: str, client_port: int, server_port: int,
             entries: list[SocketEntry] | None = None) -> int | None:
    """UID owning the client end of a TCP connection to our server, or None."""
    for e in sockets() if entries is None else entries:
        if (e.proto == "tcp" and e.state == TCP_ESTABLISHED and e.local_port == client_port
                and e.remote_port == server_port and _same_ip(e.local_ip, client_ip)):
            return e.uid
    return None


def _same_ip(a: str, b: str) -> bool:
    # IPv4-mapped IPv6 ("::ffff:127.0.0.1") is the same address as "127.0.0.1".
    return a.removeprefix("::ffff:") == b.removeprefix("::ffff:")
