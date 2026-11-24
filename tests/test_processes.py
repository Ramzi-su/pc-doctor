import contextlib
import os

import psutil
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.system import processes

client = TestClient(app, base_url="http://127.0.0.1")


@pytest.mark.parametrize(("pid", "ppid", "protected"), [
    (1, 0, True),         # systemd
    (2, 0, True),         # kthreadd
    (150, 2, True),       # kernel thread
    (4242, 1, False),     # ordinary process
    (4242, None, False),  # parent refused
])
def test_is_protected(pid, ppid, protected):
    assert processes.is_protected(pid, ppid, own_pid=999_999) is protected


def test_own_process_is_protected():
    assert processes.is_protected(os.getpid(), 1)


def test_safe_field_turns_refusal_into_default():
    def refused():
        raise psutil.AccessDenied(pid=1)

    assert processes.safe_field(refused) is None
    assert processes.safe_field(refused, "?") == "?"


def test_safe_field_lets_exited_process_propagate():
    def gone():
        raise psutil.NoSuchProcess(pid=1)

    with pytest.raises(psutil.NoSuchProcess):
        processes.safe_field(gone)


class FakeProcess:
    """Another user's process: the kernel refuses its command line and memory."""

    pid = 4242

    @contextlib.contextmanager
    def oneshot(self):
        yield

    def _deny(self):
        raise psutil.AccessDenied(pid=self.pid)

    cmdline = memory_info = _deny

    def ppid(self): return 1
    def name(self): return "sshd"
    def username(self): return "root"
    def status(self): return "sleeping"
    def cpu_percent(self): return 0.0
    def memory_percent(self): return 0.1
    def num_threads(self): return 1
    def nice(self): return 0
    def create_time(self): return 1_700_000_000.0


def test_process_with_refused_fields_is_still_listed(monkeypatch):
    """The whole point of the tab: an AccessDenied must not hide a process."""
    monkeypatch.setattr(psutil, "process_iter", lambda: iter([FakeProcess()]))

    result = processes.ProcessTable().snapshot()

    assert result.total == 1
    row = result.processes[0]
    assert (row.pid, row.name, row.user) == (4242, "sshd", "root")
    assert row.cmdline is None and row.memory_bytes is None
    assert not row.protected


def test_snapshot_lists_every_process():
    result = processes.ProcessTable().snapshot()
    pids = {p.pid for p in result.processes}
    assert 1 in pids and os.getpid() in pids
    assert result.total == len(result.processes)


def test_processes_endpoint():
    res = client.get("/api/processes")
    assert res.status_code == 200
    body = res.json()
    assert body["total"] > 0 and body["current_user"]
