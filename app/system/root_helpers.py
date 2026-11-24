"""Tiny programs run as root through `pkexec /usr/bin/python3 -I -S -c CODE args`.

Why code run as root instead of `pkexec kill <pid>` or parsing `pkexec ss`:
- the check and the action happen in the same root process, so nothing can
  change between them while the password dialog is open (TOCTOU);
- they only read values written by the kernel (/proc), never text that a
  program controls (a process can name itself `x",pid=1`).

Safety of the call itself:
- CODE is a constant of this file: the page never sends code;
- arguments are separate argv entries, already validated as integers or a
  fixed signal name: no shell, so nothing can be injected;
- `-I` (isolated) ignores PYTHON* variables, the current directory and the
  user's site-packages; `-S` skips `site`: only the standard library runs.
"""

PYTHON = "/usr/bin/python3"

# argv: pid, expected start time (clock ticks since boot, /proc/<pid>/stat
# field 22), signal name. Exit 0: sent; 3: other process; 4: already gone.
KILL_IF_SAME = r"""
import os, signal, sys
pid, start, sig = int(sys.argv[1]), sys.argv[2], {"TERM": 15, "KILL": 9}[sys.argv[3]]
try:
    fd = os.pidfd_open(pid)  # pins this exact process: the PID cannot be reused under us
    with open(f"/proc/{pid}/stat") as f:
        fields = f.read().rsplit(")", 1)[1].split()
    if fields[19] != start:
        sys.exit(3)
    signal.pidfd_send_signal(fd, sig)
except ProcessLookupError:
    sys.exit(4)
"""

# Prints {"<socket inode>": pid} for every socket of every process.
# readlink() of /proc/<pid>/fd/<n> gives "socket:[12345]", written by the kernel.
SOCKET_OWNERS = r"""
import json, os
owners = {}
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        fds = os.listdir(f"/proc/{pid}/fd")
    except OSError:
        continue
    for fd in fds:
        try:
            link = os.readlink(f"/proc/{pid}/fd/{fd}")
        except OSError:
            continue
        if link.startswith("socket:["):
            owners.setdefault(link[8:-1], int(pid))
print(json.dumps(owners))
"""


def command(code: str, *args: str) -> list[str]:
    return [PYTHON, "-I", "-S", "-c", code, *args]
