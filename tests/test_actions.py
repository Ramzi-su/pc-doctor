import json
import os
import socket
import subprocess
import time
from datetime import datetime, timedelta, timezone

import psutil
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.system import actions, network, procnet, root_helpers

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


def test_run_privileged_prefixes_pkexec_and_keeps_exit_code():
    run = fake_runner(stdout="ok")
    assert actions.run_privileged([actions.UFW, "status"], run) == "ok"
    assert run.calls == [["/usr/bin/pkexec", "/usr/sbin/ufw", "status"]]
    with pytest.raises(actions.ActionError) as err:
        actions.run_privileged([actions.UFW], fake_runner(3))
    assert err.value.returncode == 3


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


def deny_signal(monkeypatch):
    def denied(_fd, _sig):
        raise PermissionError

    monkeypatch.setattr(actions.signal, "pidfd_send_signal", denied)


def test_kill_other_users_process_runs_the_root_helper(sleeper, monkeypatch):
    deny_signal(monkeypatch)
    run = fake_runner()
    result = actions.kill_process(sleeper.pid, started_at(sleeper.pid), "KILL", run)
    assert result.privileged
    ticks = actions.start_ticks(sleeper.pid)
    assert run.calls == [["/usr/bin/pkexec", "/usr/bin/python3", "-I", "-S", "-c",
                          root_helpers.KILL_IF_SAME, str(sleeper.pid), ticks, "KILL"]]


@pytest.mark.parametrize(("code", "message"), [(3, "autre programme"), (4, "terminé pendant")])
def test_kill_root_helper_refusals_are_explained(sleeper, monkeypatch, code, message):
    deny_signal(monkeypatch)
    with pytest.raises(actions.ActionError, match=message):
        actions.kill_process(sleeper.pid, started_at(sleeper.pid), "TERM", fake_runner(code))


def run_helper(code: str, *args: str) -> subprocess.CompletedProcess:
    """Run a root helper for real, without pkexec, on our own processes."""
    return subprocess.run(root_helpers.command(code, *args), capture_output=True, text=True, timeout=10)


def test_kill_helper_kills_the_right_process(sleeper):
    result = run_helper(root_helpers.KILL_IF_SAME, str(sleeper.pid), actions.start_ticks(sleeper.pid), "TERM")
    assert result.returncode == 0, result.stderr
    assert sleeper.wait(timeout=2) == -15


def test_kill_helper_refuses_another_process(sleeper):
    wrong = str(int(actions.start_ticks(sleeper.pid)) - 1)
    assert run_helper(root_helpers.KILL_IF_SAME, str(sleeper.pid), wrong, "KILL").returncode == 3
    assert sleeper.poll() is None


def test_kill_helper_reports_gone_process(sleeper):
    pid, ticks = sleeper.pid, actions.start_ticks(sleeper.pid)
    sleeper.kill()
    sleeper.wait()
    assert run_helper(root_helpers.KILL_IF_SAME, str(pid), ticks, "TERM").returncode == 4


def test_start_ticks_handles_parentheses_in_name(tmp_path):
    (tmp_path / "42").mkdir()
    # a process may name itself "a) b" to shift naive field splitting
    (tmp_path / "42/stat").write_text("42 (a) b) S 1 42 42 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 98765 0 0")
    assert actions.start_ticks(42, tmp_path) == "98765"


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


def test_socket_owners_helper_finds_our_listening_socket():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        port = server.getsockname()[1]
        result = run_helper(root_helpers.SOCKET_OWNERS)
        owners = {int(k): v for k, v in json.loads(result.stdout).items()}
        inode = actions.listening_inodes(procnet.sockets())[("tcp", port, "127.0.0.1")]
    assert owners[inode] == os.getpid()


def test_reveal_matches_inodes_with_listening_ports(monkeypatch):
    entries = [
        procnet.SocketEntry("tcp", "0.0.0.0", 22, "0.0.0.0", 0, "0A", 0, 111),
        procnet.SocketEntry("tcp", "127.0.0.1", 50000, "127.0.0.1", 22, "01", 1000, 222),  # not listening
        procnet.SocketEntry("udp", "127.0.0.53", 53, "0.0.0.0", 0, "07", 991, 333),
    ]
    monkeypatch.setattr(procnet, "sockets", lambda: entries)
    revealed = network.RevealedOwners()
    monkeypatch.setattr(network, "revealed_owners", revealed)
    monkeypatch.setattr(revealed, "update", lambda owners: setattr(revealed, "got", owners))
    actions.reveal_port_owners(fake_runner(stdout='{"111": 1, "222": 4000, "333": 812}'))
    assert revealed.got == {("tcp", 22, "*"): 1, ("udp", 53, "127.0.0.53"): 812}


def test_reveal_rejects_garbage_output():
    with pytest.raises(actions.ActionError, match="inattendue"):
        actions.reveal_port_owners(fake_runner(stdout="not json"))


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

UFW_HELPER = ["/usr/bin/pkexec", *root_helpers.command(root_helpers.UFW_THEN_RULES)]
SSH_V4 = "allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 in comment=737368"
SSH_V6 = "allow tcp 22 ::/0 any ::/0 in comment=737368"


def ufw_runner(rules4=(), rules6=(), returncode=0, stdout="", stderr=""):
    """Fake pkexec running UFW_THEN_RULES: the JSON the root helper prints."""
    dump = {"returncode": returncode, "stdout": stdout, "stderr": stderr,
            "rules": {"user.rules": list(rules4), "user6.rules": list(rules6)}}
    return fake_runner(stdout=json.dumps(dump))


@pytest.fixture(autouse=True)
def fresh_rules(monkeypatch):
    monkeypatch.setattr(actions, "firewall_rules", actions.FirewallRules())


def ufw_args(run):
    """The ufw arguments of each call (after the helper's fixed prefix)."""
    return [call[len(UFW_HELPER):] for call in run.calls]


@pytest.mark.parametrize(("content", "enabled"), [
    ("# comment\nENABLED=yes\n", True),
    ("ENABLED=no\n", False),
    ("", False),
])
def test_firewall_status(tmp_path, content, enabled):
    conf = tmp_path / "ufw.conf"
    conf.write_text(content)
    assert actions.firewall_status(conf, tmp_path / "none").enabled is enabled


def test_firewall_status_reads_policies_and_logging(tmp_path):
    conf, defaults = tmp_path / "ufw.conf", tmp_path / "ufw"
    conf.write_text("ENABLED=yes\nLOGLEVEL=medium\n")
    defaults.write_text('# DEFAULT_INPUT_POLICY="ACCEPT"\nDEFAULT_INPUT_POLICY="DROP"\n'
                        'DEFAULT_OUTPUT_POLICY="ACCEPT"\nDEFAULT_FORWARD_POLICY="REJECT"\n')
    status = actions.firewall_status(conf, defaults)
    assert status.logging == "medium"
    assert status.policies.model_dump() == {"incoming": "deny", "outgoing": "allow", "routed": "reject"}
    assert status.rules is None  # not read as root yet


def test_old_logging_on_means_low(tmp_path):
    conf = tmp_path / "ufw.conf"
    conf.write_text("LOGLEVEL=on\n")
    assert actions.firewall_status(conf, tmp_path / "none").logging == "low"


def test_parse_simple_tuple():
    rule = actions.parse_tuple(SSH_V4, ipv6=False)
    assert (rule.action, rule.direction, rule.protocol, rule.to_port, rule.comment) == \
        ("allow", "in", "tcp", "22", "ssh")
    assert rule.from_port == "" and rule.log == "" and not rule.route and not rule.ipv6


def test_parse_tuple_with_log_interface_and_app():
    rule = actions.parse_tuple(
        "deny_log-all any 22 0.0.0.0/0 any 10.0.0.0/8 OpenSSH%20Server - out_wlp2s0", ipv6=False)
    assert (rule.action, rule.log, rule.direction, rule.interface_out, rule.to_app) == \
        ("deny", "log-all", "out", "wlp2s0", "OpenSSH Server")


def test_parse_route_tuple():
    rule = actions.parse_tuple("route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1", ipv6=False)
    assert rule.route and (rule.interface_in, rule.interface_out, rule.direction) == ("eth0", "eth1", "in")


@pytest.mark.parametrize("line", ["allow tcp 22", "allow tcp 22 a b c sideways", ""])
def test_malformed_tuples_are_skipped(line):
    assert actions.parse_tuple(line, ipv6=False) is None


def test_rule_ids_are_stable_and_distinct():
    a = actions.parse_tuple(SSH_V4, False)
    assert a.id == actions.parse_tuple(SSH_V4, False).id
    assert a.id != actions.parse_tuple(SSH_V4, True).id  # same line in user6.rules


def test_reveal_rules_fills_the_cache():
    run = ufw_runner([SSH_V4], [SSH_V6])
    assert "2 règles" in actions.reveal_firewall_rules(run).message
    assert ufw_args(run) == [[]]  # no ufw command, only the read
    rules, read_at = actions.firewall_rules.get()
    assert [r.ipv6 for r in rules] == [False, True] and read_at is not None


def test_ufw_error_is_reported_and_rules_still_refreshed():
    run = ufw_runner([SSH_V4], returncode=1, stderr="ERROR: Bad port")
    with pytest.raises(actions.ActionError, match="Bad port"):
        actions.firewall_default("incoming", "deny", run)
    assert len(actions.firewall_rules.get()[0]) == 1


def test_bad_helper_output_is_an_error():
    with pytest.raises(actions.ActionError, match="inattendue"):
        actions.reveal_firewall_rules(fake_runner(stdout="not json"))


def test_firewall_rule_commands(monkeypatch):
    monkeypatch.setattr(actions, "firewall_status", lambda: actions.FirewallStatus(installed=True, enabled=True))
    run = ufw_runner()
    actions.firewall_rule("tcp", 22, True, run)
    actions.firewall_rule("udp", 5353, False, run)
    assert ufw_args(run) == [["deny", "22/tcp"], ["delete", "deny", "5353/udp"]]


def test_firewall_rule_warns_when_ufw_is_off(monkeypatch):
    monkeypatch.setattr(actions, "firewall_status", lambda: actions.FirewallStatus(installed=True, enabled=False))
    assert "désactivé" in actions.firewall_rule("tcp", 22, True, ufw_runner()).message


def test_firewall_enable_needs_force_without_terminal():
    run = ufw_runner()
    actions.firewall_enable(True, run)
    actions.firewall_enable(False, run)
    assert ufw_args(run) == [["--force", "enable"], ["disable"]]


def test_default_policy_and_logging_commands():
    run = ufw_runner()
    actions.firewall_default("outgoing", "reject", run)
    actions.firewall_logging("off", run)
    assert ufw_args(run) == [["default", "reject", "outgoing"], ["logging", "off"]]


@pytest.mark.parametrize(("func", "args"), [
    (actions.firewall_default, ("incoming; reboot", "deny")),
    (actions.firewall_default, ("incoming", "accept")),
    (actions.firewall_logging, ("debug",)),
])
def test_policy_and_logging_refuse_unknown_values(func, args):
    run = ufw_runner()
    with pytest.raises(actions.ActionError):
        func(*args, run)
    assert run.calls == []


@pytest.mark.parametrize(("value", "expected"), [
    ("", ""), ("22", "22"), (" 8000:8100 ", "8000:8100"), ("80,443", "80,443"),
])
def test_check_ports_accepts(value, expected):
    assert actions.check_ports(value) == expected


@pytest.mark.parametrize("value", [
    "0", "65536", "22/tcp", "-1", "100:90", "22:22", "22;reboot", "22 23", "ssh",
    ",".join(str(p) for p in range(1, 17)),  # 16 ports > multiport limit
])
def test_check_ports_refuses(value):
    with pytest.raises(ValueError):
        actions.check_ports(value)


@pytest.mark.parametrize(("value", "expected"), [
    ("", "any"), ("ANY", "any"), ("192.168.1.10", "192.168.1.10/32"),
    ("192.168.1.10/24", "192.168.1.0/24"), ("fe80::1", "fe80::1/128"),
])
def test_check_address_normalizes(value, expected):
    assert actions.check_address(value) == expected


@pytest.mark.parametrize("value", ["192.168.1.300", "fe80::1%eth0", "example.com", "1.2.3.4 any", "-h"])
def test_check_address_refuses(value):
    with pytest.raises(ValueError):
        actions.check_address(value)


@pytest.mark.parametrize("value", ["ssh", "Serveur web 2", "jeu-vidéo_local.v2"])
def test_check_comment_accepts(value):
    assert actions.check_comment(value) == value


@pytest.mark.parametrize("value", ["-x", "a'; rm -rf ~", "a\nb", "$(id)", "x" * 61, "_x"])
def test_check_comment_refuses(value):
    with pytest.raises(ValueError):
        actions.check_comment(value)


def test_add_rule_builds_the_full_command():
    run = ufw_runner()
    actions.add_firewall_rule("allow", "in", "tcp", "192.168.1.0/24", "", "any", "22", True, "ssh", run)
    assert ufw_args(run) == [["allow", "in", "log", "proto", "tcp", "from", "192.168.1.0/24",
                              "to", "any", "port", "22", "comment", "ssh"]]


def test_add_outgoing_block_without_protocol():
    run = ufw_runner()
    actions.add_firewall_rule("deny", "out", "any", "any", "", "1.1.1.1", "", False, "", run)
    assert ufw_args(run) == [["deny", "out", "from", "any", "to", "1.1.1.1/32"]]


def test_add_existing_rule_says_so():
    run = ufw_runner(stdout="Skipping adding existing rule")
    assert "existe déjà" in actions.add_firewall_rule(
        "allow", "in", "tcp", "any", "", "any", "22", False, "", run).message


@pytest.mark.parametrize(("args", "match"), [
    (("allow", "in", "any", "any", "", "any", "8000:8100", False, ""), "tcp ou udp"),
    (("allow", "in", "tcp", "10.0.0.1", "", "fe80::1", "", False, ""), "IPv4 ou IPv6"),
    (("allow", "in", "tcp", "any", "", "any", "22", False, "a;b"), "commentaire"),
    (("accept", "in", "tcp", "any", "", "any", "22", False, ""), "invalide"),
])
def test_add_rule_refuses_bad_input_before_asking_password(args, match):
    run = ufw_runner()
    with pytest.raises(actions.ActionError, match=match):
        actions.add_firewall_rule(*args, run)
    assert run.calls == []


@pytest.mark.parametrize(("line", "expected"), [
    (SSH_V4, ["delete", "allow", "in", "proto", "tcp", "from", "any", "to", "any", "port", "22"]),
    ("deny_log udp 53 1.1.1.1 any 0.0.0.0/0 out_wlp2s0",
     ["delete", "deny", "out", "on", "wlp2s0", "log", "proto", "udp", "from", "any",
      "to", "1.1.1.1", "port", "53"]),
    ("allow tcp 22 0.0.0.0/0 any 0.0.0.0/0 OpenSSH - in",
     ["delete", "allow", "in", "from", "any", "to", "any", "app", "OpenSSH"]),
    ("route:allow any any 0.0.0.0/0 any 0.0.0.0/0 in_eth0!out_eth1",
     ["route", "delete", "allow", "in", "on", "eth0", "out", "on", "eth1", "from", "any", "to", "any"]),
])
def test_delete_args_mirror_the_rule(line, expected):
    assert actions.delete_args(actions.parse_tuple(line, False)) == expected


def test_delete_uses_the_cached_rule_not_page_text():
    actions.reveal_firewall_rules(ufw_runner([SSH_V4]))
    rule_id = actions.firewall_rules.get()[0][0].id
    run = ufw_runner()  # after deletion: no rules left
    assert "IPv4 et IPv6" in actions.delete_firewall_rule(rule_id, run).message
    assert ufw_args(run)[0][:2] == ["delete", "allow"]
    assert actions.firewall_rules.get()[0] == []


def test_delete_unknown_id_asks_nothing():
    run = ufw_runner()
    with pytest.raises(actions.ActionError, match="inconnue"):
        actions.delete_firewall_rule("0123456789abcdef", run)
    assert run.calls == []


def test_delete_of_vanished_rule_is_an_error():
    actions.reveal_firewall_rules(ufw_runner([SSH_V4]))
    rule_id = actions.firewall_rules.get()[0][0].id
    with pytest.raises(actions.ActionError, match="n'existe plus"):
        actions.delete_firewall_rule(rule_id, ufw_runner(stdout="Could not delete non-existent rule"))


def test_ufw_helper_only_runs_fixed_program():
    assert '["/usr/sbin/ufw", *sys.argv[1:]]' in root_helpers.UFW_THEN_RULES
    assert "shell=True" not in root_helpers.UFW_THEN_RULES


def test_ufw_helper_reads_rules_without_arguments(tmp_path):
    """Run the helper for real (as us): without root it cannot read the files."""
    result = run_helper(root_helpers.UFW_THEN_RULES)
    data = json.loads(result.stdout)
    assert result.returncode == 0 and set(data["rules"]) == {"user.rules", "user6.rules"}


# ---------- API: CSRF and validation ----------

ACTIONS = [
    ("/api/processes/4242/kill", {"started": "2026-01-01T00:00:00Z"}),
    ("/api/ports/reveal", None),
    ("/api/ports/stop-service", {"protocol": "tcp", "port": 22}),
    ("/api/firewall/rule", {"protocol": "tcp", "port": 22}),
    ("/api/firewall/enable", {"enabled": True}),
    ("/api/firewall/default", {"direction": "incoming", "policy": "deny"}),
    ("/api/firewall/logging", {"level": "low"}),
    ("/api/firewall/rules/reveal", None),
    ("/api/firewall/rules", {"to_port": "22"}),
    ("/api/firewall/rules/delete", {"id": "0123456789abcdef"}),
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
    ("/api/firewall/default", {"direction": "input", "policy": "deny"}),
    ("/api/firewall/default", {"direction": "incoming", "policy": "ACCEPT"}),
    ("/api/firewall/logging", {"level": "debug"}),
    ("/api/firewall/rules", {"to_port": "22; reboot"}),
    ("/api/firewall/rules", {"from_address": "evil.example.com"}),
    ("/api/firewall/rules", {"comment": "$(reboot)"}),
    ("/api/firewall/rules", {"action": "insert 1 allow"}),
    ("/api/firewall/rules", {"to_port": "22", "args": ["--force"]}),  # extra field
    ("/api/firewall/rules/delete", {"id": "allow 22"}),           # only an id, never rule text
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
    assert set(body) == {"installed", "enabled", "policies", "logging", "rules", "rules_read_at"}
