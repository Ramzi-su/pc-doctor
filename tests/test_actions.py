import os
import subprocess
import time
from datetime import datetime, timedelta, timezone

import psutil
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.system import actions, network

client = TestClient(app, base_url="http://127.0.0.1")
CSRF = {"X-Requested-With": "pc-doctor"}


def fake_runner(returncode: int = 0, stdout: str = "", stderr: str = ""):
    """Records the command instead of running it: no real pkexec in tests."""
    calls: list[list[str]] = []

    def run(cmd, **_kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)

    run.calls = calls
    return run


def started_at(pid: int) -> datetime:
    return datetime.fromtimestamp(psutil.Process(pid).create_time(), timezone.utc)


@pytest.fixture
def sleeper():
    proc = subprocess.Popen(["sleep", "60"])
    time.sleep(0.05)  # let it exec, so its name is "sleep"
    yield proc
    proc.kill()
    proc.wait()


# ---------- pkexec ----------

@pytest.mark.parametrize(("code", "message"), [
    (126, "annulée"),
    (127, "refusée"),
    (1, "boom"),
])
def test_run_privileged_explains_failures(code, message):
    with pytest.raises(actions.ActionError, match=message):
        actions.run_privileged(["/usr/bin/true"], fake_runner(code, stderr="boom"))


def test_run_privileged_prefixes_pkexec_with_absolute_paths():
    run = fake_runner(stdout="ok")
    assert actions.run_privileged([actions.KILL, "-s", "TERM", "--", "42"], run) == "ok"
    assert run.calls == [["/usr/bin/pkexec", "/usr/bin/kill", "-s", "TERM", "--", "42"]]


# ---------- kill ----------

def test_kill_own_process_without_root(sleeper):
    run = fake_runner()
    result = actions.kill_process(sleeper.pid, started_at(sleeper.pid), "TERM", run)
    assert not result.privileged and run.calls == []
    assert sleeper.wait(timeout=2) == -15  # killed by SIGTERM


def test_kill_refuses_reused_pid(sleeper):
    """The page saw another process with this PID: never kill the new one."""
    wrong = started_at(sleeper.pid) - timedelta(seconds=30)
    with pytest.raises(actions.ActionError, match="autre programme"):
        actions.kill_process(sleeper.pid, wrong, "KILL", fake_runner())
    assert sleeper.poll() is None  # still alive


def test_kill_refuses_protected_processes():
    with pytest.raises(actions.ActionError, match="protégé"):
        actions.kill_process(os.getpid(), started_at(os.getpid()), "KILL", fake_runner())


def test_kill_other_users_process_goes_through_pkexec(sleeper, monkeypatch):
    def denied(_pid, _sig):
        raise PermissionError

    monkeypatch.setattr(actions.os, "kill", denied)
    run = fake_runner()
    result = actions.kill_process(sleeper.pid, started_at(sleeper.pid), "KILL", run)
    assert result.privileged
    assert run.calls == [["/usr/bin/pkexec", "/usr/bin/kill", "-s", "KILL", "--", str(sleeper.pid)]]


def test_kill_rejects_unknown_signal(sleeper):
    with pytest.raises(actions.ActionError):
        actions.kill_process(sleeper.pid, started_at(sleeper.pid), "HUP", fake_runner())


# ---------- ports ----------

LIST_SOCKETS = """\
0.0.0.0:22          Stream    ssh.socket     ssh.service
[::]:22             Stream    ssh.socket     ssh.service
/run/dbus/system_bus_socket Stream dbus.socket dbus.service
*:5353              Datagram  avahi.socket   avahi-daemon.service
"""


def test_parse_list_sockets():
    units = network.parse_list_sockets(LIST_SOCKETS)
    assert units[("tcp", 22, "*")] == ["ssh.socket", "ssh.service"]
    assert units[("udp", 5353, "*")] == ["avahi.socket", "avahi-daemon.service"]
    assert len(units) == 2  # the unix socket is ignored


SS_OUTPUT = """\
tcp   LISTEN 0 128  0.0.0.0:22       0.0.0.0:* users:(("systemd",pid=1,fd=50))
tcp   LISTEN 0 70   127.0.0.1:3306   0.0.0.0:* users:(("mysqld",pid=2347,fd=21))
udp   UNCONN 0 0    127.0.0.53%lo:53 0.0.0.0:* users:(("systemd-resolve",pid=812,fd=13))
udp   UNCONN 0 0    *:5353           *:*
"""


def test_parse_ss_owners():
    assert network.parse_ss_owners(SS_OUTPUT) == {
        ("tcp", 22, "*"): 1,
        ("tcp", 3306, "127.0.0.1"): 2347,
        ("udp", 53, "127.0.0.53"): 812,
    }


@pytest.mark.parametrize(("raw", "normalized"), [
    ("0.0.0.0", "*"), ("::", "*"), ("[::]", "*"), ("*", "*"),
    ("127.0.0.53%lo", "127.0.0.53"), ("[::1]", "::1"),
])
def test_normalize_address(raw, normalized):
    assert network.normalize_address(raw) == normalized


def test_unit_of_pid(tmp_path):
    (tmp_path / "42").mkdir()
    (tmp_path / "42/cgroup").write_text("0::/system.slice/mysql.service\n")
    (tmp_path / "43").mkdir()
    (tmp_path / "43/cgroup").write_text("0::/user.slice/user-1000.slice/session-2.scope\n")
    assert network.unit_of_pid(42, tmp_path) == "mysql.service"
    assert network.unit_of_pid(43, tmp_path) is None


def test_revealed_owner_dropped_when_pid_is_reused():
    owners = network.RevealedOwners()
    owners.update({("tcp", 9999, "*"): os.getpid()})
    assert owners.get("tcp", 9999, "*") == os.getpid()
    owners._owners[("tcp", 9999, "*")] = (os.getpid(), 0.0)  # recorded start time no longer matches
    assert owners.get("tcp", 9999, "*") is None


def test_stop_service_uses_units_found_by_the_server(monkeypatch):
    monkeypatch.setattr(actions, "units_for_port", lambda proto, port: ["ssh.socket", "ssh.service"])
    run = fake_runner()
    actions.stop_port_service("tcp", 22, True, run)
    assert run.calls == [["/usr/bin/systemctl", "disable", "--now", "--", "ssh.socket", "ssh.service"]]


def test_stop_service_without_unit_is_refused(monkeypatch):
    monkeypatch.setattr(actions, "units_for_port", lambda proto, port: [])
    with pytest.raises(actions.ActionError, match="Aucun service"):
        actions.stop_port_service("udp", 5353, False, fake_runner())


# ---------- firewall ----------

@pytest.mark.parametrize(("content", "enabled"), [
    ("# comment\nENABLED=yes\n", True),
    ("ENABLED=no\n", False),
    ("", False),
])
def test_firewall_status(tmp_path, content, enabled):
    conf = tmp_path / "ufw.conf"
    conf.write_text(content)
    assert actions.firewall_status(conf).enabled is enabled


def test_firewall_rule_commands(monkeypatch):
    monkeypatch.setattr(actions, "firewall_status", lambda: actions.FirewallStatus(installed=True, enabled=True))
    run = fake_runner()
    actions.firewall_rule("tcp", 22, True, run)
    actions.firewall_rule("udp", 5353, False, run)
    assert run.calls == [
        ["/usr/bin/pkexec", "/usr/sbin/ufw", "deny", "22/tcp"],
        ["/usr/bin/pkexec", "/usr/sbin/ufw", "delete", "deny", "5353/udp"],
    ]


def test_firewall_rule_warns_when_ufw_is_off(monkeypatch):
    monkeypatch.setattr(actions, "firewall_status", lambda: actions.FirewallStatus(installed=True, enabled=False))
    assert "désactivé" in actions.firewall_rule("tcp", 22, True, fake_runner()).message


def test_firewall_enable_needs_force_without_terminal():
    run = fake_runner()
    actions.firewall_enable(True, run)
    assert run.calls == [["/usr/bin/pkexec", "/usr/sbin/ufw", "--force", "enable"]]


# ---------- API: CSRF and validation ----------

ACTIONS = [
    ("/api/processes/4242/kill", {"started": "2026-01-01T00:00:00Z"}),
    ("/api/ports/reveal", None),
    ("/api/ports/stop-service", {"protocol": "tcp", "port": 22}),
    ("/api/firewall/rule", {"protocol": "tcp", "port": 22}),
    ("/api/firewall/enable", {"enabled": True}),
]


@pytest.mark.parametrize(("url", "body"), ACTIONS)
def test_every_action_requires_csrf_header(url, body):
    assert client.post(url, json=body).status_code == 403


@pytest.mark.parametrize(("url", "body"), [
    ("/api/processes/1/kill", {"started": "2026-01-01T00:00:00Z"}),        # PID 1
    ("/api/processes/abc/kill", {"started": "2026-01-01T00:00:00Z"}),      # not a number
    ("/api/processes/4242/kill", {"started": "2026-01-01T00:00:00Z", "signal": "HUP"}),
    ("/api/processes/4242/kill", {"started": "2026-01-01T00:00:00Z", "cmd": "rm -rf ~"}),  # extra field
    ("/api/firewall/rule", {"protocol": "tcp", "port": 70000}),
    ("/api/firewall/rule", {"protocol": "icmp", "port": 22}),
    ("/api/firewall/rule", {"protocol": "tcp", "port": "22; reboot"}),
    ("/api/ports/stop-service", {"protocol": "tcp", "port": 22, "units": ["sshd"]}),  # page can't choose units
])
def test_actions_validate_input(url, body):
    assert client.post(url, json=body, headers=CSRF).status_code == 422


def test_kill_api_reports_vanished_process(sleeper):
    started = started_at(sleeper.pid).isoformat()
    sleeper.kill()
    sleeper.wait()
    res = client.post(f"/api/processes/{sleeper.pid}/kill", json={"started": started}, headers=CSRF)
    assert res.status_code == 400 and "terminé" in res.json()["detail"]


def test_firewall_status_endpoint():
    body = client.get("/api/firewall").json()
    assert set(body) == {"installed", "enabled"}
