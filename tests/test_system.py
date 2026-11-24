import gzip
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.system import accounts, doctor, hardware, live, logfiles, network, permissions, runner
from app.system.models import (
    Accounts,
    Group,
    Hardware,
    Machine,
    Memory,
    Cpu,
    Permissions,
    Port,
    Severity,
    SuidScan,
    User,
)

client = TestClient(app, base_url="http://127.0.0.1")


def fake_runner(stdout: str = "", returncode: int = 0, stderr: str = ""):
    calls: list[tuple[list[str], dict]] = []

    def run(cmd, **kwargs):
        calls.append((cmd, kwargs))
        return subprocess.CompletedProcess(cmd, returncode, stdout, stderr)

    run.calls = calls
    return run


def write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


# ---------- runner ----------

def test_runner_never_uses_a_shell_and_forces_c_locale():
    run = fake_runner("ok")
    assert runner.run(["lspci"], runner=run) == "ok"
    cmd, kwargs = run.calls[0]
    assert cmd == ["lspci"]
    assert "shell" not in kwargs  # default shell=False
    assert kwargs["env"]["LC_ALL"] == "C"
    assert kwargs["timeout"] > 0


def test_runner_missing_tool_raises_command_error():
    with pytest.raises(runner.CommandError, match="not installed"):
        runner.run(["definitely-not-a-real-tool-xyz"])


def test_runner_keeps_stdout_when_exit_code_is_nonzero():
    # `find` exits 1 on unreadable dirs but its results are still valid.
    assert runner.run(["find"], runner=fake_runner("a\n", returncode=1)) == "a\n"


def test_runner_failure_without_output_raises():
    with pytest.raises(runner.CommandError, match="boom"):
        runner.run(["x"], runner=fake_runner("", returncode=2, stderr="boom"))


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read everything")
def test_read_text_reports_root_only(tmp_path):
    secret = tmp_path / "serial"
    secret.write_text("ABC")
    secret.chmod(0)
    assert runner.read_text(secret) == runner.ROOT_ONLY
    assert runner.read_text(tmp_path / "missing") is None


# ---------- hardware ----------

def test_machine_info_ignores_vendor_placeholders(tmp_path):
    dmi = tmp_path / "class/dmi/id"
    write(dmi / "sys_vendor", "HP\n")
    write(dmi / "product_name", "Pavilion\n")
    write(dmi / "product_version", "Type1ProductConfigId")
    write(dmi / "chassis_type", "10")
    write(dmi / "bios_date", "03/17/2025")
    write(dmi / "board_vendor", "HP")
    write(dmi / "board_name", "8742")
    m = hardware.machine_info(tmp_path)
    assert (m.vendor, m.product, m.chassis_type, m.board) == ("HP", "Pavilion", "Notebook", "HP 8742")
    assert m.bios_date == "03/17/2025"


def test_disks_skip_virtual_devices(tmp_path):
    write(tmp_path / "block/loop0/size", "8")
    write(tmp_path / "block/nvme0n1/size", "1000")
    write(tmp_path / "block/nvme0n1/device/model", "SAMSUNG")
    write(tmp_path / "block/nvme0n1/queue/rotational", "0")
    disks = hardware.disks(tmp_path)
    assert [d.name for d in disks] == ["nvme0n1"]
    assert disks[0].size_bytes == 512_000 and not disks[0].rotational


def test_battery_health_and_manufacture_date(tmp_path):
    bat = tmp_path / "class/power_supply/BAT1"
    write(bat / "type", "Battery")
    write(bat / "energy_full", "40300000")
    write(bat / "energy_full_design", "52500000")
    write(bat / "cycle_count", "0")
    write(bat / "manufacture_year", "2021")
    write(bat / "manufacture_month", "3")
    write(tmp_path / "class/power_supply/ACAD/type", "Mains")
    [b] = hardware.batteries(tmp_path)
    assert b.health_percent == 76.8
    assert b.cycle_count is None  # 0 = not reported
    assert b.manufacture_date == "2021-03"


LSPCI = """Slot:\t00:02.0
Class:\tVGA compatible controller
Vendor:\tIntel Corporation
Device:\tUHD Graphics
Driver:\ti915
Rev:\t05

Slot:\t01:00.0
Class:\tVGA compatible controller
Vendor:\tNVIDIA Corporation
Device:\tGTX 1650 Ti
SVendor:\tHewlett-Packard Company
Driver:\tnvidia

Slot:\t09:00.0
Class:\tNetwork controller
Vendor:\tRealtek
Device:\tRTL8822CE
"""


def test_parse_lspci():
    devices = hardware.parse_lspci(LSPCI)
    assert [d.slot for d in devices] == ["00:02.0", "01:00.0", "09:00.0"]
    assert devices[0].revision == "05" and devices[1].subsystem_vendor == "Hewlett-Packard Company"


def test_gpus_are_enriched_with_nvidia_smi():
    run = fake_runner("00000000:01:00.0, 580.1, 4096, 90.17\n")
    gpus = hardware.gpus(hardware.parse_lspci(LSPCI), run)
    assert len(gpus) == 2  # the network card is not a GPU
    nvidia = gpus[1]
    assert (nvidia.vram_total_mib, nvidia.driver_version, nvidia.vbios_version) == (4096, "580.1", "90.17")
    assert gpus[0].vram_total_mib is None


def test_usb_devices_hide_root_hubs():
    out = ("Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub\n"
           "Bus 001 Device 003: ID 0bda:b00c Realtek Semiconductor Corp. Bluetooth Radio\n")
    assert hardware.usb_devices(fake_runner(out)) == ["Realtek Semiconductor Corp. Bluetooth Radio"]


# ---------- network ----------

@pytest.mark.parametrize("address,exposed", [
    ("127.0.0.1", False), ("127.0.0.53", False), ("::1", False), ("::ffff:127.0.0.1", False),
    ("0.0.0.0", True), ("::", True), ("192.168.1.10", True), ("fe80::1%wlo1", True), ("garbage", True),
])
def test_is_exposed(address, exposed):
    assert network.is_exposed(address) is exposed


def test_with_prefix():
    assert network._with_prefix("10.0.0.3", "255.255.255.0") == "10.0.0.3/24"
    assert network._with_prefix("fe80::1%eth0", "ffff:ffff:ffff:ffff::") == "fe80::1/64"
    assert network._with_prefix("10.0.0.3", None) == "10.0.0.3"


def test_parse_ethtool():
    info = network.parse_ethtool("driver: r8169\nfirmware-version: rtl8168h-2_0.0.2 02/26/15\n")
    assert info == {"driver": "r8169", "firmware-version": "rtl8168h-2_0.0.2 02/26/15"}


def test_listening_ports_returns_valid_models():
    ports = network.listening_ports()  # reads /proc/net: works as a normal user
    assert all(isinstance(p, Port) and 0 <= p.port <= 65535 for p in ports)
    # Exposed ports are listed first.
    flags = [p.exposed for p in ports]
    assert flags == sorted(flags, reverse=True)


# ---------- accounts ----------

LAST = """ramsis   :1           :1               2026-11-24T11:51:33+01:00   still logged in
reboot   system boot  6.8.0-41-generic 2026-11-24T11:47:15+01:00   still running
bob      pts/0        192.168.1.20     2026-11-20T10:00:00+01:00 - 2026-11-20T10:05:00+01:00  (00:05)

wtmp begins 2025-09-25T22:30:50+01:00
"""


def test_parse_last():
    logins = accounts.parse_last(LAST)
    assert [l.user for l in logins] == ["ramsis", "reboot", "bob"]
    assert logins[2].source == "192.168.1.20"
    assert logins[2].end.startswith("2026-11-20T10:05")
    assert logins[0].end == "still logged in"


def test_uid_min(tmp_path):
    defs = tmp_path / "login.defs"
    defs.write_text("# comment\nUID_MIN\t\t\t 500\nUID_MAX 60000\n")
    assert accounts.uid_min(defs) == 500
    assert accounts.uid_min(tmp_path / "missing") == 1000


def test_accounts_contains_root_and_current_user():
    acc = accounts.accounts(run=fake_runner(""))
    names = {u.name for u in acc.users}
    assert "root" in names and acc.current_user in names
    root = next(u for u in acc.users if u.name == "root")
    assert root.admin and root.uid == 0


# ---------- permissions ----------

def test_audit_file_detects_world_readable_secret(tmp_path):
    secret = tmp_path / "shadow"
    secret.write_text("x")
    rule = permissions.Rule(str(secret), permissions._O_ALL, "640")
    secret.chmod(0o644)
    assert permissions.audit_file(rule).ok is False
    secret.chmod(0o640)
    audit = permissions.audit_file(rule)
    assert audit.ok and audit.octal == "640" and audit.mode == "-rw-r-----"


def test_audit_file_requires_sticky_bit(tmp_path):
    rule = permissions.Rule(str(tmp_path), 0, "1777", required=0o1000)
    tmp_path.chmod(0o777)
    assert permissions.audit_file(rule).ok is False
    tmp_path.chmod(0o1777)
    assert permissions.audit_file(rule).ok is True
    tmp_path.chmod(0o755)


def test_audit_missing_file_is_skipped(tmp_path):
    assert permissions.audit_file(permissions.Rule(str(tmp_path / "nope"), 0, "")) is None


def test_world_writable(tmp_path):
    (tmp_path / "ok").write_text("")
    bad = tmp_path / "bad"
    bad.write_text("")
    bad.chmod(0o666)
    assert permissions.world_writable([str(tmp_path)]) == [str(bad)]


FIND = "4755\troot\t/usr/bin/passwd\n4755\troot\t/usr/bin/find\n" \
       "2755\troot\t/opt/weird/helper\n4755\tme\t/home/me/c/su\nbad line\n"


def test_parse_find_classifies_suid_files():
    files = {f.path: f for f in permissions.parse_find(FIND, ignore_owner="me")}
    assert "/home/me/c/su" not in files  # owned by the user: grants nothing
    assert files["/usr/bin/find"].dangerous  # GTFOBins: find -exec /bin/sh -p
    assert files["/usr/bin/passwd"].known and not files["/usr/bin/passwd"].dangerous
    assert files["/opt/weird/helper"].kind == "sgid" and not files["/opt/weird/helper"].known
    # Dangerous first.
    assert permissions.parse_find(FIND)[0].path == "/usr/bin/find"


def test_sgid_find_is_not_dangerous():
    [f] = permissions.parse_find("2755\troot\t/usr/bin/find\n")
    assert not f.dangerous  # SGID only gives the group, not root


def test_suid_scanner_prunes_containers_and_caches():
    run = fake_runner(FIND)
    scanner = permissions.SuidScanner()
    assert scanner.cached is None
    first = scanner.get(run=run)
    cmd = run.calls[0][0]
    assert cmd[:3] == ["find", "/", "-xdev"] and "*/.local/share/containers" in cmd
    assert scanner.get(run=run) is first and len(run.calls) == 1  # cached
    scanner.get(refresh=True, run=run)
    assert len(run.calls) == 2


# ---------- log files ----------

@pytest.fixture
def log_root(tmp_path):
    root = tmp_path / "log"
    write(root / "syslog", "".join(f"line {i}\n" for i in range(10)))
    with gzip.open(root / "syslog.2.gz", "wt") as fh:
        fh.write("old 1\nold ERROR 2\n")
    write(root / "wtmp", "binary")
    (root / "journal").mkdir()
    write(root / "journal/system.journal", "x")
    write(tmp_path / "secret.txt", "TOP SECRET")
    (root / "escape").symlink_to(tmp_path / "secret.txt")
    return root


def test_list_log_files_skips_binary_journal_and_symlinks(log_root):
    names = {Path(f.path).name for f in logfiles.list_log_files(log_root)}
    assert names == {"syslog", "syslog.2.gz"}


@pytest.mark.parametrize("attack", ["{root}/../secret.txt", "{root}/escape", "/etc/passwd", "{root}/nope"])
def test_path_traversal_is_refused(log_root, attack):
    with pytest.raises(logfiles.LogFileError):
        logfiles.read_log_file(attack.format(root=log_root), root=log_root)


def test_read_plain_tail_and_filter(log_root):
    content = logfiles.read_log_file(str(log_root / "syslog"), limit=3, root=log_root)
    assert content.lines == ["line 7", "line 8", "line 9"] and content.truncated
    filtered = logfiles.read_log_file(str(log_root / "syslog"), text="LINE 4", root=log_root)
    assert filtered.lines == ["line 4"]


def test_read_gzip(log_root):
    content = logfiles.read_log_file(str(log_root / "syslog.2.gz"), text="error", root=log_root)
    assert content.lines == ["old ERROR 2"]


def test_binary_content_is_refused(log_root):
    (log_root / "app.log").write_bytes(b"\x00\x01binary")
    with pytest.raises(logfiles.LogFileError, match="binaire"):
        logfiles.read_log_file(str(log_root / "app.log"), root=log_root)


# ---------- live ----------

def test_parse_nvidia_live_handles_not_available():
    gpus = live.parse_nvidia_live("GTX 1650, 00:01:00.0, 45, 12, 300, 4096, [N/A], P8\nbad\n")
    assert len(gpus) == 1
    g = gpus[0]
    assert (g.temperature_c, g.utilization_percent, g.power_w, g.pstate) == (45, 12, None, "P8")


def test_nvidia_sleeping(tmp_path):
    dev = tmp_path / "bus/pci/devices/0000:01:00.0"
    write(dev / "vendor", "0x10de")
    write(dev / "class", "0x030000")
    write(dev / "power/runtime_status", "suspended")
    assert live.nvidia_sleeping(tmp_path)
    write(dev / "power/runtime_status", "active")
    assert not live.nvidia_sleeping(tmp_path)
    assert not live.nvidia_sleeping(tmp_path / "empty")  # no NVIDIA GPU at all


def test_gzip_bomb_single_huge_line_is_bounded(tmp_path, monkeypatch):
    # 5 MB without any newline compresses to a few KB.
    bomb = tmp_path / "bomb.log.gz"
    with gzip.open(bomb, "wb") as fh:
        fh.write(b"A" * 5_000_000)
    monkeypatch.setattr(logfiles, "MAX_DECOMPRESSED", 1_000_000)
    content = logfiles.read_log_file(str(bomb), root=tmp_path)
    assert content.truncated
    assert all(len(line) <= logfiles.MAX_LINE for line in content.lines)


def test_gzip_lines_split_across_chunks(tmp_path, monkeypatch):
    monkeypatch.setattr(logfiles, "CHUNK", 7)  # force lines to span chunks
    f = tmp_path / "x.log.gz"
    with gzip.open(f, "wt") as fh:
        fh.write("first line\nsecond line\nlast")
    assert logfiles.read_log_file(str(f), root=tmp_path).lines == ["first line", "second line", "last"]


def test_live_sampler_produces_a_snapshot():
    sampler = live.LiveSampler(run=fake_runner("", returncode=1, stderr="no gpu"))
    snap = sampler.sample()
    assert 0 <= snap.cpu_percent <= 100
    assert snap.memory_total_bytes > 0 and snap.process_count > 0
    assert len(snap.top_processes) <= live.TOP_PROCESSES


# ---------- doctor ----------

def _hw() -> Hardware:
    return Hardware(
        machine=Machine(vendor=None, product=None, family=None, sku=None, serial=None, board=None,
                        bios_vendor=None, bios_version=None, bios_date=None, chassis_type=None),
        cpu=Cpu(model="x", physical_cores=1, logical_cores=1, max_mhz=None, flags_virtualization=None),
        memory=Memory(total_bytes=1, swap_bytes=0), disks=[], partitions=[], batteries=[],
        gpus=[], usb_devices=[],
    )


def _user(name: str, uid: int, **kw) -> User:
    base = dict(gid=uid, home="/", shell="/bin/bash", human=uid >= 1000, can_login=True,
                groups=[], admin=uid == 0)
    return User(name=name, uid=uid, **(base | kw))


def test_doctor_flags_real_problems():
    acc = Accounts(
        users=[_user("root", 0), _user("toor", 0), _user("me", 1000, groups=["docker"])],
        groups=[Group(name="docker", gid=999, members=["me"], sensitive=True, why="root")],
        logins=[], current_user="me",
    )
    ports = [Port(protocol="tcp", address="0.0.0.0", port=22, exposed=True, pid=None,
                  process=None, user=None, service="SSH"),
             Port(protocol="tcp6", address="::", port=22, exposed=True, pid=None,
                  process=None, user=None, service="SSH")]
    suid = SuidScan(files=permissions.parse_find("4755\troot\t/usr/bin/bash\n"),
                    scanned_at=datetime.now(timezone.utc), duration_seconds=1)
    findings = doctor.diagnose(_hw(), ports, acc, Permissions(files=[], world_writable=[]), suid)
    messages = [f.message for f in findings]
    assert findings[0].severity == Severity.CRITICAL  # sorted by severity
    assert any("toor" in m and "UID 0" in m for m in messages)
    assert any("/usr/bin/bash" in m for m in messages)
    assert sum("22" in m for m in messages) == 1  # tcp + tcp6 merged
    assert any("probablement SSH" in m for m in messages)
    assert any("docker" in m for m in messages)


# ---------- API ----------

def test_suid_scan_requires_csrf_header():
    assert client.post("/api/suid/scan").status_code == 403


def test_logfile_api_refuses_traversal():
    res = client.get("/api/logfiles/content", params={"path": "/var/log/../../etc/passwd"})
    assert res.status_code == 400


def test_logfile_api_validates_limit():
    res = client.get("/api/logfiles/content", params={"path": "/var/log/syslog", "limit": 99999})
    assert res.status_code == 422


@pytest.mark.parametrize("url", ["/api/hardware", "/api/network", "/api/ports",
                                 "/api/accounts", "/api/permissions", "/api/suid", "/api/diagnosis"])
def test_endpoints_answer_as_normal_user(url):
    assert client.get(url).status_code == 200


def test_rejects_foreign_host_header():
    # DNS rebinding: evil.com resolving to 127.0.0.1 must not reach the API.
    assert client.get("/api/accounts", headers={"Host": "evil.com"}).status_code == 400


def test_kernel_errors_are_grouped_and_classified():
    out = ("EXT4-fs error (device nvme0n1p4): inode #1: checksum invalid\n" * 3
           + "NVRM: Xid (PCI:0000:01:00): 79, GPU has fallen off the bus\n")
    run = fake_runner(out)
    findings = doctor.kernel_errors(run=run)
    cmd = run.calls[0][0]
    assert cmd[:2] == ["journalctl", "-k"] and any(a.startswith("--grep=") for a in cmd)
    assert [f.severity for f in findings] == [Severity.CRITICAL, Severity.WARNING]
    assert "3×" in findings[0].message and "fsck" in findings[0].message


def test_kernel_errors_none_found():
    # journalctl --grep exits 1 with no output when nothing matches.
    assert doctor.kernel_errors(run=fake_runner("", returncode=1)) == []
