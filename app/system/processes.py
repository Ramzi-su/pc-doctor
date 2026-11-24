"""Full process list for the Processus tab (no root needed).

Without root, Linux still shows every process (no `hidepid` mount option on
this machine); only a few fields of other users' processes can be refused.
Those fields become None: a process is never hidden because one field failed.
"""

import getpass
import os
import threading
from datetime import datetime, timezone

import psutil

from app.system.models import ProcessDetail, ProcessList

KTHREADD_PID = 2  # parent of every kernel thread

# Killing one of these ends the graphical session or cuts the network/sound:
# allowed, but the UI asks for an explicit confirmation.
CRITICAL_NAMES = frozenset({
    "gnome-shell", "Xorg", "Xwayland", "gdm", "gdm3", "gdm-wayland-session", "gdm-x-session",
    "gnome-session-binary", "dbus-daemon", "dbus-broker", "NetworkManager", "wpa_supplicant",
    "pipewire", "wireplumber", "pulseaudio", "polkitd", "sddm", "lightdm", "kwin_x11", "kwin_wayland",
})


def is_critical(name: str) -> bool:
    return name in CRITICAL_NAMES or name.startswith("systemd")


def is_protected(pid: int, ppid: int | None, own_pid: int | None = None) -> bool:
    """Processes the UI must never offer to kill.

    PID 1 (systemd) and kernel threads: killing them crashes or freezes the
    machine. Our own PID: the dashboard would kill itself.
    """
    own_pid = os.getpid() if own_pid is None else own_pid
    return pid <= KTHREADD_PID or ppid == KTHREADD_PID or pid == own_pid


def safe_field(getter, default=None):
    """Call a psutil getter; a refused field becomes `default`.

    A zombie (exited, waiting for its parent) still exists, so it stays
    listed. psutil.NoSuchProcess (really exited) propagates to the caller.
    """
    try:
        return getter()
    except (psutil.AccessDenied, psutil.ZombieProcess):
        return default


class ProcessTable:
    """Keeps psutil.Process objects between calls.

    cpu_percent() is the CPU used *since the previous call on the same
    object*: recreating the objects each time would always give 0 %.
    The lock is needed because FastAPI may run two requests in two threads.
    """

    def __init__(self) -> None:
        self._procs: dict[int, psutil.Process] = {}
        self._lock = threading.Lock()

    def snapshot(self) -> ProcessList:
        with self._lock:
            current: dict[int, psutil.Process] = {}
            rows = []
            for proc in psutil.process_iter():
                proc = self._procs.get(proc.pid, proc)
                try:
                    rows.append(self._detail(proc))
                except psutil.NoSuchProcess:
                    continue  # exited during the scan: really gone, not hidden
                current[proc.pid] = proc
            self._procs = current
        rows.sort(key=lambda p: (p.cpu_percent or 0, p.memory_bytes or 0), reverse=True)
        return ProcessList(processes=rows, total=len(rows), current_user=getpass.getuser())

    @staticmethod
    def _detail(proc: psutil.Process) -> ProcessDetail:
        with proc.oneshot():  # read /proc/<pid>/stat once for all fields
            ppid = safe_field(proc.ppid)
            cmdline = safe_field(proc.cmdline)
            mem = safe_field(proc.memory_info)
            created = safe_field(proc.create_time)
            kernel = proc.pid == KTHREADD_PID or ppid == KTHREADD_PID
            name = safe_field(proc.name, "?")
            return ProcessDetail(
                pid=proc.pid,
                ppid=ppid,
                name=name,
                cmdline=" ".join(cmdline) if cmdline is not None else None,
                user=safe_field(proc.username),
                status=safe_field(proc.status),
                cpu_percent=safe_field(proc.cpu_percent),
                memory_bytes=mem.rss if mem else None,
                memory_percent=safe_field(proc.memory_percent),
                threads=safe_field(proc.num_threads),
                nice=safe_field(proc.nice),
                started=datetime.fromtimestamp(created, timezone.utc) if created else None,
                kernel_thread=kernel,
                protected=is_protected(proc.pid, ppid),
                critical=is_critical(name),
            )


process_table = ProcessTable()
