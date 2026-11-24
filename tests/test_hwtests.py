import threading
import time

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.system import hwtests
from app.system.models import Severity

client = TestClient(app, base_url="http://127.0.0.1")
CSRF = {"X-Requested-With": "pc-doctor"}


def new_ctx() -> hwtests.Context:
    state = hwtests._idle_state()
    state.status = "running"
    return hwtests.Context(state, threading.Event())


def severities(ctx) -> dict[str, Severity]:
    return {c.label: c.severity for c in ctx.state.checks}


# ---------- parsers ----------

def test_parse_ping():
    out = "20 packets transmitted, 19 received, 5% packet loss, time 3810ms\n" \
          "rtt min/avg/max/mdev = 1.021/2.345/9.870/1.200 ms"
    assert hwtests.parse_ping(out) == (5.0, 2.345)
    assert hwtests.parse_ping("ping: connect: Network is unreachable") == (None, None)


def test_default_gateway(tmp_path):
    (tmp_path / "net").mkdir()
    (tmp_path / "net/route").write_text(
        "Iface\tDestination\tGateway\tFlags\n"
        "eth0\t0000A8C0\t00000000\t0001\n"
        "eth0\t00000000\t0100A8C0\t0003\n")
    assert hwtests.default_gateway(tmp_path) == ("eth0", "192.168.0.1")


HEALTHY_NVME = {
    "smart_status": {"passed": True},
    "nvme_smart_health_information_log": {
        "critical_warning": 0, "available_spare": 100, "available_spare_threshold": 10,
        "percentage_used": 3, "media_errors": 0, "power_on_hours": 1200,
        "unsafe_shutdowns": 40, "data_units_written": 20_000_000,
    },
}


def test_parse_smart_healthy():
    ctx = new_ctx()
    hwtests.parse_smart(HEALTHY_NVME, ctx)
    sev = severities(ctx)
    assert sev["Verdict SMART"] == Severity.OK
    assert sev["Erreurs de support (media errors)"] == Severity.OK


def test_parse_smart_failing_disk():
    data = {"smart_status": {"passed": False},
            "nvme_smart_health_information_log": {**HEALTHY_NVME["nvme_smart_health_information_log"],
                                                   "media_errors": 12, "available_spare": 5}}
    ctx = new_ctx()
    hwtests.parse_smart(data, ctx)
    sev = severities(ctx)
    assert sev["Verdict SMART"] == Severity.CRITICAL
    assert sev["Erreurs de support (media errors)"] == Severity.CRITICAL
    assert sev["Réserve de cellules"] == Severity.CRITICAL


def test_parse_smart_ata_reallocated_sectors():
    ctx = new_ctx()
    hwtests.parse_smart({"ata_smart_attributes": {"table": [
        {"id": 5, "name": "Reallocated_Sector_Ct", "raw": {"value": 8}},
        {"id": 9, "name": "Power_On_Hours", "raw": {"value": 5000}},
    ]}}, ctx)
    assert severities(ctx) == {"Reallocated_Sector_Ct": Severity.CRITICAL}


# ---------- tests that really run (short) ----------

def test_pattern_test_finds_no_error_on_healthy_memory():
    ctx = new_ctx()
    assert hwtests.pattern_test(ctx, hwtests.RAM_CHUNK) == 0
    assert ctx.state.progress == 1


def test_disk_speed_cleans_up_and_verifies(tmp_path):
    ctx = new_ctx()
    hwtests.test_disk_speed(ctx, size=32 * hwtests.MIB, folder=tmp_path)
    assert list(tmp_path.iterdir()) == []  # temporary file deleted
    assert severities(ctx)["Intégrité des données"] == Severity.OK


def test_disk_speed_refuses_when_disk_is_full(tmp_path, monkeypatch):
    monkeypatch.setattr(hwtests.shutil, "disk_usage", lambda _p: type("U", (), {"free": 10})())
    with pytest.raises(hwtests.TestFailed, match="espace"):
        hwtests.test_disk_speed(new_ctx(), size=32 * hwtests.MIB, folder=tmp_path)


def test_cpu_fallback_runs_and_verifies(monkeypatch):
    monkeypatch.setattr(hwtests.shutil, "which", lambda _tool: None)  # no stress-ng
    ctx = new_ctx()
    hwtests.test_cpu(ctx, duration=1)
    check = ctx.state.checks[0]
    assert check.severity == Severity.OK and "aucune erreur" in check.value


def test_battery(tmp_path):
    bat = tmp_path / "class/power_supply/BAT0"
    bat.mkdir(parents=True)
    (bat / "uevent").write_text(
        "POWER_SUPPLY_STATUS=Discharging\nPOWER_SUPPLY_CAPACITY=80\n"
        "POWER_SUPPLY_ENERGY_FULL=25000000\nPOWER_SUPPLY_ENERGY_FULL_DESIGN=50000000\n"
        "POWER_SUPPLY_ENERGY_NOW=20000000\nPOWER_SUPPLY_POWER_NOW=10000000\n")
    ctx = new_ctx()
    hwtests.test_battery(ctx, tmp_path)
    values = {c.label: c.value for c in ctx.state.checks}
    assert severities(ctx)["BAT0 : santé"] == Severity.WARNING  # 50 %
    assert "2.0 h" in values["BAT0 : consommation"]


def test_context_run_is_killed_on_cancel():
    ctx = new_ctx()
    threading.Timer(0.3, ctx.cancel.set).start()
    t0 = time.monotonic()
    with pytest.raises(hwtests.TestCancelled):
        ctx.run(["sleep", "30"], timeout=60)
    assert time.monotonic() - t0 < 5


# ---------- runner and API ----------

def wait_finished(runner_: hwtests.TestRunner) -> str:
    for _ in range(100):
        if runner_.state.status != "running":
            return runner_.state.status
        time.sleep(0.05)
    raise AssertionError("test still running")


def test_runner_one_test_at_a_time(monkeypatch):
    gate = threading.Event()
    slow = hwtests.TestDef("slow", "Slow", "", 1, lambda ctx: gate.wait(5))
    monkeypatch.setitem(hwtests.BY_ID, "slow", slow)
    r = hwtests.TestRunner()
    r.start("slow")
    with pytest.raises(RuntimeError):
        r.start("slow")
    gate.set()
    assert wait_finished(r) == "done"
    assert "slow" in r.snapshot().last_results


def test_runner_reports_failures_instead_of_dying(monkeypatch):
    def boom(_ctx):
        raise ValueError("bad sensor")

    monkeypatch.setitem(hwtests.BY_ID, "boom", hwtests.TestDef("boom", "Boom", "", 1, boom))
    r = hwtests.TestRunner()
    r.start("boom")
    assert wait_finished(r) == "failed"
    assert "bad sensor" in r.state.checks[0].value


def test_runner_cancel(monkeypatch):
    monkeypatch.setitem(hwtests.BY_ID, "wait", hwtests.TestDef("wait", "Wait", "", 1, lambda ctx: ctx.wait_timed(10)))
    r = hwtests.TestRunner()
    r.start("wait")
    r.cancel()
    assert wait_finished(r) == "cancelled"


def test_api_lists_tests():
    body = client.get("/api/hwtests").json()
    assert {t["id"] for t in body["tests"]} >= {"cpu", "ram", "disk", "smart", "gpu", "network", "battery"}


@pytest.mark.parametrize(("url", "headers", "status"), [
    ("/api/hwtests/cpu/start", {}, 403),           # CSRF guard
    ("/api/hwtests/nope/start", CSRF, 404),
    ("/api/hwtests/../../x/start", CSRF, 404),
    ("/api/hwtests/CPU;rm/start", CSRF, 422),
    ("/api/hwtests/cancel", {}, 403),
])
def test_api_guards(url, headers, status):
    assert client.post(url, headers=headers).status_code == status


def test_fan_sensor_stuck_at_zero_is_not_a_false_alarm(monkeypatch):
    monkeypatch.setattr(hwtests.hardware, "cpu_info", lambda: type("C", (), {"max_mhz": 4500})())
    ctx = new_ctx()
    ctx.state.series = {"Temp. CPU (°C)": [60, 74], "Fréquence CPU (MHz)": [3700, 3700],
                        "Ventilateur (tr/min)": [0, 0]}
    hwtests.summarize_monitor(ctx, idle_fan=0)
    assert severities(ctx)["Ventilateur"] == Severity.INFO


def test_monitor_keeps_one_slot_per_second():
    state = hwtests._idle_state()
    monitor = hwtests.Monitor(state)
    monitor.start()
    time.sleep(2.3)
    monitor.stop.set()
    monitor.join()
    assert 2 <= len(state.series["Temp. CPU (°C)"]) <= 4


@pytest.mark.parametrize("direct_supported", [True, False])
def test_disk_read_back_with_and_without_o_direct(tmp_path, monkeypatch, direct_supported):
    if not direct_supported:
        def no_direct(path):
            return hwtests.os.open(path, hwtests.os.O_RDONLY), False
        monkeypatch.setattr(hwtests, "_open_direct", no_direct)
    ctx = new_ctx()
    hwtests.test_disk_speed(ctx, size=32 * hwtests.MIB, folder=tmp_path)
    assert severities(ctx)["Intégrité des données"] == Severity.OK
    assert list(tmp_path.iterdir()) == []
