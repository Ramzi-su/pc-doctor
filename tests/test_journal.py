import json
import subprocess
from datetime import datetime, timedelta

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app import journal
from app.main import app
from app.models import LogQuery, Priority


def fake_runner(stdout: str = "", returncode: int = 0, stderr: str = ""):
    """Return a runner that records the command instead of running journalctl."""
    calls: list[list[str]] = []

    def run(cmd, **_kwargs):
        calls.append(cmd)
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)

    run.calls = calls
    return run


def line(**fields) -> str:
    base = {"__REALTIME_TIMESTAMP": "1795470605555000", "PRIORITY": "6"}
    return json.dumps(base | fields)


# ---------- validation ----------

def test_defaults_to_last_hour_and_all_priorities():
    q = LogQuery()
    assert q.until - q.since == timedelta(hours=1)
    assert q.priorities == set(Priority)


@pytest.mark.parametrize("ident", ["brave; rm -rf ~", "a b", "$(id)", "x" * 129, "`id`"])
def test_rejects_suspicious_identifiers(ident):
    with pytest.raises(ValidationError):
        LogQuery(identifiers=[ident])


@pytest.mark.parametrize("bad", [
    {"limit": 0}, {"limit": 5001}, {"priorities": {8}}, {"priorities": set()},
    {"text": "x" * 201}, {"unknown": 1},
    {"since": datetime.now() - timedelta(days=40)},
    {"since": datetime.now(), "until": datetime.now() - timedelta(hours=1)},
])
def test_rejects_invalid_queries(bad):
    with pytest.raises(ValidationError):
        LogQuery(**bad)


# ---------- command building ----------

def test_command_is_an_argument_list_with_single_token_options():
    q = LogQuery(identifiers=["brave-browser.desktop", "kernel"], priorities={0, 3}, limit=50)
    cmd = journal.build_command(q)
    assert cmd[0] == "journalctl"
    assert "--lines=50" in cmd and "--reverse" in cmd
    assert "--priority=0..3" in cmd
    assert "--identifier=brave-browser.desktop" in cmd
    assert "--identifier=kernel" in cmd
    assert not any(a.startswith("--grep") for a in cmd)


def test_user_text_is_escaped_as_literal():
    cmd = journal.build_command(LogQuery(text="ld.so (x)"))
    assert r"--grep=ld\.so\ \(x\)" in cmd
    assert "--case-sensitive=false" in cmd


def test_crash_mode_uses_crash_pattern():
    cmd = journal.build_command(LogQuery(crash_only=True, text="ignored-here"))
    assert f"--grep={journal.CRASH_PATTERN}" in cmd


# ---------- parsing ----------

def test_parse_entry_fields_and_crash_hint():
    e = journal.parse_entry(json.loads(line(
        PRIORITY="3", SYSLOG_IDENTIFIER="kernel", _PID="42",
        MESSAGE="Isolated Web Co[1]: segfault at 0 ip 0",
    )))
    assert e.priority is Priority.ERR and e.priority_name == "err"
    assert e.identifier == "kernel" and e.pid == 42
    assert e.crash_hint is True


def test_parse_entry_binary_message_and_fallbacks():
    e = journal.parse_entry(json.loads(line(PRIORITY="99", _COMM="brave", MESSAGE=[104, 105, 255])))
    assert e.message == "hi�"
    assert e.priority is Priority.INFO
    assert e.identifier == "brave"
    assert e.crash_hint is False


def test_parse_entry_without_timestamp_is_skipped():
    assert journal.parse_entry({"MESSAGE": "x"}) is None


# ---------- query_logs ----------

def test_query_logs_filters_priority_gaps_and_bad_lines():
    out = "\n".join([line(PRIORITY="0", MESSAGE="a"), line(PRIORITY="2", MESSAGE="b"), "not json"])
    result = journal.query_logs(LogQuery(priorities={0, 3}), runner=fake_runner(out))
    assert [e.message for e in result.entries] == ["a"]  # prio 2 is in the gap


def test_query_logs_crash_mode_applies_text_in_python():
    out = "\n".join([line(MESSAGE="brave segfault"), line(MESSAGE="firefox segfault")])
    result = journal.query_logs(LogQuery(crash_only=True, text="Brave"), runner=fake_runner(out))
    assert [e.message for e in result.entries] == ["brave segfault"]


def test_query_logs_reports_truncation():
    out = "\n".join(line(MESSAGE=str(i)) for i in range(2))
    assert journal.query_logs(LogQuery(limit=2), runner=fake_runner(out)).truncated


def test_no_grep_match_is_not_an_error():
    result = journal.query_logs(LogQuery(text="zz"), runner=fake_runner(returncode=1))
    assert result.entries == []


def test_journalctl_error_is_raised():
    with pytest.raises(journal.JournalError, match="boom"):
        journal.query_logs(LogQuery(), runner=fake_runner(returncode=1, stderr="boom"))


# ---------- HTTP API ----------

client = TestClient(app, base_url="http://127.0.0.1")


def test_api_rejects_invalid_identifier():
    assert client.get("/api/logs", params={"identifiers": "a;b"}).status_code == 422


def test_api_rejects_foreign_host_header():
    # A DNS-rebinding page would send its own domain as Host.
    assert client.get("/api/priorities", headers={"Host": "evil.example"}).status_code == 400


def test_api_returns_logs(monkeypatch):
    monkeypatch.setattr(journal.subprocess, "run", fake_runner(line(MESSAGE="hello")))
    res = client.get("/api/logs", params=[("priorities", "6"), ("identifiers", "kernel")])
    assert res.status_code == 200
    assert res.json()["entries"][0]["message"] == "hello"
    assert "default-src 'self'" in res.headers["content-security-policy"]
