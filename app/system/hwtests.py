"""Hardware tests: CPU, RAM, disk, SMART, GPU, network, battery.

One test at a time, in a background thread, with progress, a cancel button
and a once-per-second monitor (temperatures, CPU frequency, fans) so the
user sees how the machine reacts under load.

Each test uses the dedicated tool when installed (stress-ng, memtester,
glmark2) and otherwise a Python fallback, so it works out of the box.
Nothing writes to a raw disk: the disk test uses a temporary file in the
user's home and always deletes it.
"""

import json
import os
import re
import shutil
import socket
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

import psutil

from app.system import actions, hardware, runner
from app.system.models import HwCheck, HwTestInfo, HwTestState, HwTests, Severity
from app.system.runner import CommandError

SYS = Path("/sys")
MIB = 1024 * 1024


class TestCancelled(Exception):
    pass


class TestFailed(Exception):
    """The test could not run (tool error, not enough space...)."""


# ---------- context given to each test ----------

class Context:
    """What a test function can do: report progress, log, add result lines,
    run a killable subprocess, and check for cancellation."""

    def __init__(self, state: HwTestState, cancel: threading.Event) -> None:
        self.state = state
        self.cancel = cancel
        self.proc: subprocess.Popen | None = None

    def check_cancel(self) -> None:
        if self.cancel.is_set():
            raise TestCancelled

    def progress(self, value: float) -> None:
        self.state.progress = max(0.0, min(1.0, value))

    def log(self, line: str) -> None:
        self.state.log.append(line)
        del self.state.log[:-200]  # keep the last 200 lines

    def add(self, severity: Severity, label: str, value: str) -> None:
        self.state.checks.append(HwCheck(severity=severity, label=label, value=value))

    def wait_timed(self, seconds: float, start: float = 0.0, span: float = 1.0) -> None:
        """Sleep `seconds`, advancing progress from `start` to `start + span`."""
        t0 = time.monotonic()
        while (elapsed := time.monotonic() - t0) < seconds:
            self.check_cancel()
            self.progress(start + span * elapsed / seconds)
            time.sleep(0.25)

    def run(self, cmd: list[str], timeout: float, env: dict | None = None,
            on_line: Callable[[str], None] | None = None) -> tuple[int, str]:
        """Run `cmd` (argument list, no shell) and return (exit code, output).
        Killed on cancel or timeout."""
        try:
            self.proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                env={**os.environ, "LC_ALL": "C", **(env or {})}, start_new_session=True)
        except FileNotFoundError as exc:
            raise TestFailed(f"{cmd[0]} n'est pas installé") from exc
        lines: list[str] = []
        reader = threading.Thread(target=self._read, args=(self.proc, lines, on_line), daemon=True)
        reader.start()
        deadline = time.monotonic() + timeout
        try:
            while self.proc.poll() is None:
                if self.cancel.is_set() or time.monotonic() > deadline:
                    self._kill()
                    self.check_cancel()
                    raise TestFailed(f"{cmd[0]} : délai dépassé")
                time.sleep(0.2)
        finally:
            reader.join(timeout=2)
        return self.proc.returncode, "\n".join(lines)

    def _read(self, proc, lines, on_line) -> None:
        for line in proc.stdout:
            line = line.rstrip()
            lines.append(line)
            if on_line:
                on_line(line)

    def _kill(self) -> None:
        if self.proc and self.proc.poll() is None:
            # The tool runs in its own session: kill its whole process group
            # (stress-ng starts one worker per core).
            try:
                os.killpg(self.proc.pid, 9)
            except ProcessLookupError:
                pass
            self.proc.wait()


# ---------- monitor ----------

def cpu_temperature() -> float | None:
    temps = psutil.sensors_temperatures()
    for chip in ("coretemp", "k10temp", "zenpower"):
        entries = temps.get(chip, [])
        for t in entries:
            if t.label in ("Package id 0", "Tctl", "Tdie"):
                return t.current
        if entries:
            return max(t.current for t in entries)
    return None


def fan_speeds(sys_root: Path = SYS) -> list[int]:
    speeds = []
    for f in sorted(sys_root.glob("class/hwmon/hwmon*/fan*_input")):
        value = runner.read_text(f)
        if value and value.isdigit():
            speeds.append(int(value))
    return speeds


def gpu_temperature() -> float | None:
    try:
        out = runner.run(["nvidia-smi", "--query-gpu=temperature.gpu", "--format=csv,noheader,nounits"],
                         timeout=3)
        return float(out.split()[0])
    except (CommandError, ValueError, IndexError):
        return None


class Monitor(threading.Thread):
    """Samples sensors every second into state.series while a test runs."""

    def __init__(self, state: HwTestState, gpu: bool = False) -> None:
        super().__init__(daemon=True)
        self.state = state
        self.gpu = gpu
        self.stop = threading.Event()
        state.series = {"Temp. CPU (°C)": [], "Fréquence CPU (MHz)": [], "Ventilateur (tr/min)": []}
        if gpu:
            state.series["Temp. GPU (°C)"] = []

    def run(self) -> None:
        t0 = time.monotonic()
        while not self.stop.is_set():
            freq = psutil.cpu_freq()
            fans = fan_speeds()
            sample = {
                "Temp. CPU (°C)": cpu_temperature(),
                "Fréquence CPU (MHz)": round(freq.current) if freq else None,
                "Ventilateur (tr/min)": max(fans) if fans else None,
            }
            if self.gpu:
                sample["Temp. GPU (°C)"] = gpu_temperature()
            # One slot per second of wall-clock time. Under full load this
            # thread can wake up late: the missed seconds repeat the value
            # (sample-and-hold), so the chart's x axis stays in real seconds.
            slot = min(int(time.monotonic() - t0), 600)
            for name, value in sample.items():
                values = self.state.series[name]
                values.extend([value] * (slot + 1 - len(values)))
            self.stop.wait(1 - (time.monotonic() - t0) % 1)


def summarize_monitor(ctx: Context, idle_fan: int | None) -> None:
    """Result lines from what the monitor saw: heat, throttling, fans."""
    series = ctx.state.series
    temps = [t for t in series.get("Temp. CPU (°C)", []) if t is not None]
    if temps:
        peak = max(temps)
        sev = Severity.CRITICAL if peak >= 95 else Severity.WARNING if peak >= 85 else Severity.OK
        ctx.add(sev, "Température CPU max", f"{peak:.0f} °C"
                + (" : refroidissement insuffisant (nettoyer les ventilateurs, pâte thermique)" if sev != Severity.OK else ""))
    freqs = [f for f in series.get("Fréquence CPU (MHz)", []) if f is not None]
    max_mhz = hardware.cpu_info().max_mhz
    if freqs and max_mhz:
        tail = freqs[len(freqs) // 2:]  # second half: after the turbo boost burst
        avg = sum(tail) / len(tail)
        hot = temps and max(temps) >= 90
        ratio = avg / max_mhz
        sev = Severity.WARNING if ratio < 0.5 and hot else Severity.OK
        ctx.add(sev, "Fréquence CPU sous charge",
                f"{avg:.0f} MHz en moyenne (max {max_mhz:.0f} MHz)"
                + (" : le CPU ralentit car il chauffe (throttling)" if sev == Severity.WARNING else ""))
    fans = [f for f in series.get("Ventilateur (tr/min)", []) if f is not None]
    if fans:
        peak = max(fans)
        if peak == 0:
            # Some laptop drivers (hp-wmi...) expose a fan sensor that always
            # reads 0. A blocked fan would show up as overheating above.
            ctx.add(Severity.INFO, "Ventilateur", "le capteur reste à 0 tr/min : probablement non pris en charge "
                    "par le pilote. Écoute s'il souffle pendant le test.")
        else:
            reacted = idle_fan is not None and peak > idle_fan
            ctx.add(Severity.OK, "Ventilateur",
                    f"{idle_fan or 0} → {peak} tr/min" + (" (réagit à la charge)" if reacted else ""))


# ---------- CPU ----------

CPU_WORKER = r"""
import hashlib, sys, time
end = time.monotonic() + float(sys.argv[1])
ref, rounds, errors = None, 0, 0
while time.monotonic() < end:
    h = b"pc-doctor"
    for _ in range(5000):
        h = hashlib.sha256(h).digest()
    if ref is None:
        ref = h
    elif h != ref:  # same input must always give the same digest
        errors += 1
    rounds += 1
print(rounds, errors)
"""


def test_cpu(ctx: Context, duration: int = 60) -> None:
    cores = os.cpu_count() or 1
    if shutil.which("stress-ng"):
        ctx.log(f"stress-ng sur {cores} cœurs pendant {duration} s, avec vérification des calculs")
        t0 = time.monotonic()

        def tick(line: str) -> None:
            ctx.log(line)
            ctx.progress((time.monotonic() - t0) / duration)

        code, out = ctx.run(["nice", "-n", "10", "stress-ng", "--cpu", "0", "--cpu-method", "all", "--verify",
                             "--timeout", f"{duration}s", "--metrics-brief"], timeout=duration + 60, on_line=tick)
        failed = code != 0 or re.search(r"\bfail(ed)?\b", out, re.I)
        ctx.add(Severity.CRITICAL if failed else Severity.OK, "Calculs vérifiés (stress-ng)",
                "ERREURS de calcul : CPU instable (surchauffe, overclocking, alimentation)" if failed else "aucune erreur")
        return

    ctx.log(f"stress-ng absent : test Python sur {cores} cœurs pendant {duration} s")
    # nice 10: still 100 % of every core, but the server and the UI keep priority.
    workers = [subprocess.Popen(["nice", "-n", "10", runner_python(), "-I", "-c", CPU_WORKER, str(duration)],
                                stdout=subprocess.PIPE, text=True) for _ in range(cores)]
    try:
        ctx.wait_timed(duration)
        results = [w.communicate(timeout=30)[0].split() for w in workers]
    finally:
        for w in workers:
            if w.poll() is None:
                w.kill()
    rounds = sum(int(r[0]) for r in results if len(r) == 2)
    errors = sum(int(r[1]) for r in results if len(r) == 2)
    ctx.add(Severity.CRITICAL if errors else Severity.OK, "Calculs vérifiés",
            f"{errors} erreur(s) sur {rounds} séries : CPU instable" if errors else f"{rounds} séries, aucune erreur")


def runner_python() -> str:
    return "/usr/bin/python3" if Path("/usr/bin/python3").exists() else "python3"


# ---------- RAM ----------

PATTERNS = [0x00, 0xFF, 0x55, 0xAA, 0x0F, 0xF0, 0x33, 0xCC]
RAM_CHUNK = 16 * MIB


def ram_test_size() -> int:
    """A quarter of the free RAM, capped at 2 GiB: enough to find a bad
    area without pushing the system into swap."""
    size = min(psutil.virtual_memory().available // 4, 2048 * MIB)
    return max(size - size % RAM_CHUNK, RAM_CHUNK)


def test_ram(ctx: Context) -> None:
    size = ram_test_size()
    if shutil.which("memtester"):
        mb = size // MIB
        ctx.log(f"memtester sur {mb} Mo (1 passe)")
        t0 = time.monotonic()

        def tick(line: str) -> None:
            if line.strip():
                ctx.log(line.strip()[-120:])
            ctx.progress(min((time.monotonic() - t0) / (mb * 0.35), 0.99))  # ~0.35 s per MB

        code, out = ctx.run(["nice", "-n", "10", "memtester", f"{mb}M", "1"], timeout=3600, on_line=tick)
        failed = code != 0 and "FAILURE" in out
        ctx.add(Severity.CRITICAL if failed else Severity.OK, f"memtester ({mb} Mo)",
                "ERREURS mémoire : barrette défectueuse probable" if failed else "aucune erreur")
    else:
        ctx.log(f"memtester absent : test Python sur {size // MIB} Mo")
        errors = pattern_test(ctx, size)
        ctx.add(Severity.CRITICAL if errors else Severity.OK, f"Motifs écrits/relus ({size // MIB} Mo)",
                f"{errors} zone(s) corrompue(s) : barrette défectueuse probable" if errors else "aucune erreur")
    ctx.add(Severity.INFO, "Limite de ce test",
            "Linux ne teste que la mémoire qu'il nous prête. Test complet : memtest86+ "
            "(menu GRUB au démarrage, ou clé USB).")


# Runs in its own process: big memory copies hold Python's GIL, which would
# freeze the server's threads (API, monitor) if done in-process. The memory
# also goes back to the system as soon as the process exits.
# Prints "p <done>/<total>" for progress and "err <offset>" for each bad chunk.
RAM_WORKER = r"""
import os, sys
size, chunk = int(sys.argv[1]), int(sys.argv[2])
patterns = [0x00, 0xFF, 0x55, 0xAA, 0x0F, 0xF0, 0x33, 0xCC]
blocks = [bytes([p]) * chunk for p in patterns] + [os.urandom(chunk)]
buf = bytearray(size)
view = memoryview(buf)
total = len(blocks) * 2 * (size // chunk)
done = 0
for block in blocks:
    for phase in ("write", "verify"):
        for off in range(0, size, chunk):
            if phase == "write":
                view[off:off + chunk] = block
            elif view[off:off + chunk] != block:
                print("err", hex(off), flush=True)
            done += 1
            if done % 8 == 0 or done == total:
                print(f"p {done}/{total}", flush=True)
"""


def pattern_test(ctx: Context, size: int) -> int:
    """Write each pattern over `size` bytes, read it back; returns bad chunks."""
    errors = 0

    def on_line(line: str) -> None:
        nonlocal errors
        if line.startswith("p "):
            done, total = map(int, line[2:].split("/"))
            ctx.progress(done / total)
        elif line.startswith("err "):
            errors += 1
            ctx.log(f"Erreur dans le bloc à l'octet {line[4:]}")

    code, out = ctx.run(["nice", "-n", "10", runner_python(), "-I", "-c", RAM_WORKER, str(size), str(RAM_CHUNK)],
                        timeout=3600, on_line=on_line)
    if code != 0:
        raise TestFailed(f"Le test mémoire s'est arrêté (code {code}) : {out[-200:]}")
    return errors


# ---------- disk ----------

def test_disk_speed(ctx: Context, size: int = 1024 * MIB, folder: Path | None = None) -> None:
    folder = folder or Path.home() / ".cache" / "pc-doctor"
    folder.mkdir(parents=True, exist_ok=True)
    if shutil.disk_usage(folder).free < size * 3:
        raise TestFailed("Pas assez d'espace libre pour le test (il faut 3 Go).")
    path = folder / f"disktest-{os.getpid()}.bin"
    chunk = 8 * MIB
    base = os.urandom(chunk)  # random data: nothing to compress or deduplicate

    def block(i: int) -> bytes:
        return i.to_bytes(8, "little") + base[8:]  # each chunk unique and checkable

    count = size // chunk
    try:
        ctx.log(f"Écriture de {size // MIB} Mo dans {path}")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        t0 = time.monotonic()
        try:
            for i in range(count):
                ctx.check_cancel()
                os.write(fd, block(i))
                ctx.progress(0.5 * i / count)
            os.fsync(fd)  # include the time to really reach the disk
        finally:
            os.close(fd)
        write_speed = size / (time.monotonic() - t0)

        ctx.log("Relecture et vérification")
        fd = os.open(path, os.O_RDONLY)
        try:
            # Drop our file from the page cache, otherwise we would measure RAM.
            os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
            t0 = time.monotonic()
            corrupted = 0
            for i in range(count):
                ctx.check_cancel()
                if os.read(fd, chunk) != block(i):
                    corrupted += 1
                ctx.progress(0.5 + 0.5 * i / count)
            read_speed = size / (time.monotonic() - t0)
        finally:
            os.close(fd)
    finally:
        path.unlink(missing_ok=True)

    ssd = any(not d.rotational for d in hardware.disks())
    slow = 150 * MIB if ssd else 40 * MIB
    for label, speed in (("Écriture", write_speed), ("Lecture", read_speed)):
        ctx.add(Severity.WARNING if speed < slow else Severity.OK, f"{label} séquentielle",
                f"{speed / MIB:.0f} Mo/s" + (" : lent pour ce type de disque" if speed < slow else ""))
    ctx.add(Severity.CRITICAL if corrupted else Severity.OK, "Intégrité des données",
            f"{corrupted} bloc(s) relu(s) différent(s) de ce qui a été écrit" if corrupted else "relu à l'identique")


def root_disk(sys_root: Path = SYS) -> str | None:
    """Disk holding "/": nvme0n1p4 -> nvme0n1 (from /sys, no root)."""
    source = next((p.device for p in psutil.disk_partitions() if p.mountpoint == "/"), "")
    part = Path(source).name
    if not part:
        return None
    parent = (sys_root / "class/block" / part).resolve().parent.name
    disk = parent if (sys_root / "block" / parent).exists() else part
    return disk if re.fullmatch(r"[a-z0-9]+", disk) else None


def parse_smart(data: dict, ctx: Context) -> None:
    passed = data.get("smart_status", {}).get("passed")
    if passed is not None:
        ctx.add(Severity.OK if passed else Severity.CRITICAL, "Verdict SMART",
                "bon" if passed else "ÉCHEC : le disque annonce sa propre panne, sauvegarde immédiatement")
    nvme = data.get("nvme_smart_health_information_log")
    if nvme:
        used = nvme.get("percentage_used", 0)
        spare, threshold = nvme.get("available_spare"), nvme.get("available_spare_threshold")
        media = nvme.get("media_errors", 0)
        warn_bits = nvme.get("critical_warning", 0)
        ctx.add(Severity.WARNING if used >= 90 else Severity.OK, "Usure", f"{used} % de la durée de vie prévue")
        if spare is not None:
            low = threshold is not None and spare <= threshold
            ctx.add(Severity.CRITICAL if low else Severity.OK, "Réserve de cellules", f"{spare} %")
        ctx.add(Severity.CRITICAL if media else Severity.OK, "Erreurs de support (media errors)",
                f"{media}" + (" : secteurs illisibles, cohérent avec une corruption de fichiers" if media else ""))
        ctx.add(Severity.CRITICAL if warn_bits else Severity.OK, "Alertes critiques NVMe",
                f"code {warn_bits}" if warn_bits else "aucune")
        ctx.add(Severity.INFO, "Utilisation",
                f"{nvme.get('power_on_hours', '?')} h allumé, {nvme.get('unsafe_shutdowns', '?')} coupures brutales, "
                f"{nvme.get('data_units_written', 0) * 512_000 / 1e12:.1f} To écrits")
    for attr in data.get("ata_smart_attributes", {}).get("table", []):
        if attr.get("id") in (5, 197, 198):  # reallocated, pending, uncorrectable sectors
            raw = attr.get("raw", {}).get("value", 0)
            ctx.add(Severity.CRITICAL if raw else Severity.OK, attr.get("name", str(attr["id"])), str(raw))


def test_smart(ctx: Context) -> None:
    disk = root_disk()
    if not disk:
        raise TestFailed("Disque système introuvable.")
    ctx.log(f"Lecture SMART de /dev/{disk} (mot de passe demandé)")
    ctx.progress(0.2)
    try:
        proc = runner.run_full([actions.PKEXEC, "/usr/sbin/smartctl", "-a", "-j", f"/dev/{disk}"],
                               timeout=actions.AUTH_TIMEOUT)
    except runner.CommandError as exc:
        raise TestFailed(str(exc)) from exc
    if proc.returncode in (actions.PKEXEC_DISMISSED, actions.PKEXEC_NOT_AUTHORIZED):
        raise TestFailed("Authentification annulée ou refusée.")
    # smartctl's exit code is a bit mask that is non-zero for mere warnings:
    # the JSON is the source of truth.
    try:
        data = json.loads(proc.stdout)
    except ValueError as exc:
        raise TestFailed(proc.stdout.strip()[:300] or "smartctl n'a rien renvoyé") from exc
    ctx.log(data.get("model_name", disk))
    parse_smart(data, ctx)
    ctx.progress(1)


# ---------- GPU ----------

NVIDIA_FIELDS = ("name,temperature.gpu,pcie.link.gen.current,pcie.link.gen.max,"
                 "pcie.link.width.current,pcie.link.width.max,clocks_event_reasons.active")


def test_gpu(ctx: Context) -> None:
    if not shutil.which("nvidia-smi"):
        raise TestFailed("Pas de GPU NVIDIA détecté (nvidia-smi absent).")
    code, out = ctx.run(["nvidia-smi", f"--query-gpu={NVIDIA_FIELDS}", "--format=csv,noheader"], timeout=15)
    if code != 0:
        code, out = ctx.run(["nvidia-smi", f"--query-gpu={NVIDIA_FIELDS.replace('clocks_event', 'clocks_throttle')}",
                             "--format=csv,noheader"], timeout=15)
    parts = [p.strip() for p in out.strip().splitlines()[0].split(",")] if out.strip() else []
    if len(parts) == 7:
        name, temp, gen, gen_max, width, width_max, _reasons = parts
        ctx.log(name)
        ctx.add(Severity.OK, "Température au repos", f"{temp} °C")
        notes = []
        if gen != gen_max:
            notes.append(f"Gen {gen} au lieu de {gen_max} : baisse au repos pour économiser l'énergie, normal")
        if width.isdigit() and width_max.isdigit() and int(width) < int(width_max):
            notes.append(f"x{width} au lieu de x{width_max} : fréquent sur portable (carte câblée en x{width}), impact faible")
        ctx.add(Severity.INFO, "Lien PCIe", f"Gen {gen}, x{width}" + (" ; " + " ; ".join(notes) if notes else ""))
    ctx.progress(0.1)

    if not shutil.which("glmark2"):
        ctx.add(Severity.INFO, "Test de charge 3D", "glmark2 non installé : sudo apt install glmark2")
        ctx.progress(1)
        return
    ctx.log("glmark2 sur la carte NVIDIA (PRIME offload), environ 2 min")
    # PRIME render offload: draw on the NVIDIA card instead of the integrated GPU.
    env = {"__NV_PRIME_RENDER_OFFLOAD": "1", "__GLX_VENDOR_LIBRARY_NAME": "nvidia"}
    t0 = time.monotonic()

    def tick(line: str) -> None:
        if line.startswith("["):
            ctx.log(line[:120])
        ctx.progress(0.1 + 0.9 * min((time.monotonic() - t0) / 150, 0.99))

    code, out = ctx.run(["glmark2", "--off-screen"], timeout=600, env=env, on_line=tick)
    score = re.search(r"glmark2 Score:\s*(\d+)", out)
    renderer = re.search(r"GL_RENDERER:\s*(.+)", out)
    if renderer:
        ctx.add(Severity.INFO, "Carte utilisée", renderer.group(1).strip())
    if code != 0 or not score:
        ctx.add(Severity.WARNING, "Test de charge 3D", "glmark2 a échoué : voir le journal ci-dessous")
    else:
        ctx.add(Severity.OK, "Score glmark2", f"{score.group(1)} (plus c'est haut, mieux c'est)")
    temps = [t for t in ctx.state.series.get("Temp. GPU (°C)", []) if t is not None]
    if temps:
        peak = max(temps)
        sev = Severity.CRITICAL if peak >= 92 else Severity.WARNING if peak >= 85 else Severity.OK
        ctx.add(sev, "Température GPU max", f"{peak:.0f} °C")


# ---------- network ----------

def default_gateway(proc_root: Path = Path("/proc")) -> tuple[str, str] | None:
    """(interface, gateway IP) of the default route, from /proc/net/route."""
    for line in (runner.read_text(proc_root / "net/route") or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) > 2 and parts[1] == "00000000" and parts[2] != "00000000":
            return parts[0], socket.inet_ntoa(bytes.fromhex(parts[2])[::-1])
    return None


def parse_ping(output: str) -> tuple[float | None, float | None]:
    """-> (packet loss %, average latency ms)."""
    loss = re.search(r"([\d.]+)% packet loss", output)
    rtt = re.search(r"= [\d.]+/([\d.]+)/", output)
    return (float(loss.group(1)) if loss else None, float(rtt.group(1)) if rtt else None)


def _ping(ctx: Context, label: str, target: str, count: int, warn_ms: float) -> None:
    _code, out = ctx.run(["ping", "-n", "-c", str(count), "-i", "0.2", "-W", "1", target], timeout=30)
    loss, avg = parse_ping(out)
    if loss is None:
        ctx.add(Severity.WARNING, label, "pas de réponse")
        return
    sev = Severity.CRITICAL if loss >= 50 else Severity.WARNING if loss > 0 or (avg or 0) > warn_ms else Severity.OK
    ctx.add(sev, label, f"{loss:.0f} % de pertes" + (f", {avg:.1f} ms en moyenne" if avg is not None else ""))


def test_network(ctx: Context) -> None:
    route = default_gateway()
    if not route:
        raise TestFailed("Aucune route par défaut : pas de réseau.")
    iface, gateway = route
    speed = runner.read_text(SYS / "class/net" / iface / "speed")
    ctx.add(Severity.INFO, "Interface", f"{iface}" + (f", lien {speed} Mb/s" if speed and speed.isdigit() and int(speed) > 0 else ""))
    ctx.progress(0.1)
    _ping(ctx, f"Box / passerelle ({gateway})", gateway, 20, warn_ms=20)
    ctx.progress(0.5)
    _ping(ctx, "Internet (1.1.1.1)", "1.1.1.1", 10, warn_ms=100)
    ctx.progress(0.8)
    t0 = time.monotonic()
    try:
        socket.getaddrinfo("example.com", 443)
        ms = (time.monotonic() - t0) * 1000
        ctx.add(Severity.WARNING if ms > 500 else Severity.OK, "Résolution DNS", f"{ms:.0f} ms")
    except OSError:
        ctx.add(Severity.CRITICAL, "Résolution DNS", "échec : les noms de sites ne se traduisent plus")
    ctx.progress(1)


# ---------- battery ----------

def test_battery(ctx: Context, sys_root: Path = SYS) -> None:
    bats = sorted((sys_root / "class/power_supply").glob("BAT*"))
    if not bats:
        raise TestFailed("Pas de batterie.")
    for bat in bats:
        values = dict(line.split("=", 1) for line in (runner.read_text(bat / "uevent") or "").splitlines()
                      if "=" in line)
        get = lambda key: values.get(f"POWER_SUPPLY_{key}")  # noqa: E731
        full = int(get("ENERGY_FULL") or get("CHARGE_FULL") or 0)
        design = int(get("ENERGY_FULL_DESIGN") or get("CHARGE_FULL_DESIGN") or 0)
        if full and design:
            health = 100 * full / design
            sev = Severity.WARNING if health < 60 else Severity.OK
            ctx.add(sev, f"{bat.name} : santé", f"{health:.0f} % de la capacité d'origine"
                    + (" : à remplacer bientôt" if health < 60 else ""))
        ctx.add(Severity.INFO, f"{bat.name} : état", f"{get('STATUS')}, {get('CAPACITY')} % chargée")
        cycles = get("CYCLE_COUNT")
        if cycles and cycles != "0":
            ctx.add(Severity.INFO, f"{bat.name} : cycles", cycles)
        power = int(get("POWER_NOW") or 0)
        now = int(get("ENERGY_NOW") or 0)
        if power and get("STATUS") == "Discharging":
            ctx.add(Severity.INFO, f"{bat.name} : consommation",
                    f"{power / 1e6:.1f} W, autonomie estimée {now / power:.1f} h")
        elif get("STATUS") != "Discharging":
            ctx.add(Severity.INFO, f"{bat.name} : consommation", "débranche le secteur pour mesurer l'autonomie")
    ctx.progress(1)


# ---------- catalogue and runner ----------

@dataclass(frozen=True)
class TestDef:
    id: str
    title: str
    description: str
    duration: int
    func: Callable[[Context], None]
    tool: str | None = None
    install: str | None = None
    needs_root: bool = False
    monitor: bool = False
    gpu_monitor: bool = False


CATALOGUE = [
    TestDef("cpu", "Processeur", "Charge tous les cœurs 60 s et vérifie que les calculs restent justes. "
            "Surveille température, fréquence (ralentissement thermique) et ventilateurs.",
            75, test_cpu, "stress-ng", "sudo apt install stress-ng", monitor=True),
    TestDef("ram", "Mémoire vive", "Écrit des motifs dans un quart de la RAM libre puis les relit.",
            120, test_ram, "memtester", "sudo apt install memtester", monitor=True),
    TestDef("disk", "Disque : vitesse et intégrité", "Écrit 1 Go dans un fichier temporaire de ton dossier, "
            "le relit, vérifie chaque octet puis le supprime. Aucune écriture directe sur le disque.",
            30, test_disk_speed, monitor=True),
    TestDef("smart", "Disque : santé SMART", "Lit le diagnostic interne du SSD : usure, réserve, erreurs. "
            "À lancer en priorité après une erreur de système de fichiers.", 10, test_smart, "smartctl", "sudo apt install smartmontools",
            needs_root=True),
    TestDef("gpu", "Carte graphique", "Vérifie l'état de la carte NVIDIA puis la charge en 3D (glmark2).",
            160, test_gpu, "glmark2", "sudo apt install glmark2", monitor=True, gpu_monitor=True),
    TestDef("network", "Réseau", "Pertes et latence vers ta box et Internet, résolution DNS.",
            15, test_network),
    TestDef("battery", "Batterie", "Santé, charge et consommation actuelle.", 1, test_battery),
]
BY_ID = {t.id: t for t in CATALOGUE}


def _idle_state() -> HwTestState:
    return HwTestState(test_id=None, status="idle", progress=0, started=None, finished=None,
                       log=[], checks=[], series={})


class TestRunner:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._cancel = threading.Event()
        self.state = _idle_state()
        self.last: dict[str, HwTestState] = {}

    def snapshot(self) -> HwTests:
        tests = [HwTestInfo(
            id=t.id, title=t.title, description=t.description, duration_seconds=t.duration,
            tool=t.tool, tool_available=bool(t.tool and shutil.which(t.tool)),
            install_hint=t.install, needs_root=t.needs_root) for t in CATALOGUE]
        with self._lock:
            return HwTests(tests=tests, state=self.state.model_copy(deep=True),
                           last_results={k: v.model_copy(deep=True) for k, v in self.last.items()})

    def start(self, test_id: str) -> None:
        test = BY_ID.get(test_id)
        if test is None:
            raise KeyError(test_id)
        with self._lock:
            if self.state.status == "running":
                raise RuntimeError("Un test est déjà en cours.")
            self._cancel.clear()
            self.state = HwTestState(test_id=test_id, status="running", progress=0,
                                     started=datetime.now(timezone.utc), finished=None,
                                     log=[], checks=[], series={})
        threading.Thread(target=self._run, args=(test, self.state), daemon=True).start()

    def cancel(self) -> None:
        self._cancel.set()

    def _run(self, test: TestDef, state: HwTestState) -> None:
        ctx = Context(state, self._cancel)
        idle_fan = max(fan_speeds(), default=None)
        monitor = Monitor(state, gpu=test.gpu_monitor) if test.monitor else None
        if monitor:
            monitor.start()
        status = "done"
        try:
            test.func(ctx)
        except TestCancelled:
            status = "cancelled"
            ctx.log("Test arrêté.")
        except TestFailed as exc:
            status = "failed"
            ctx.add(Severity.WARNING, "Test impossible", str(exc))
        except Exception as exc:  # noqa: BLE001 - shown to the user instead of a silent dead thread
            status = "failed"
            ctx.add(Severity.WARNING, "Erreur inattendue", f"{type(exc).__name__}: {exc}")
        finally:
            ctx._kill()
            if monitor:
                monitor.stop.set()
                monitor.join(timeout=3)
            if monitor and status == "done" and test.id in ("cpu", "ram"):
                summarize_monitor(ctx, idle_fan)
        with self._lock:
            state.status = status
            state.progress = 1 if status == "done" else state.progress
            state.finished = datetime.now(timezone.utc)
            if status == "done":
                self.last[test.id] = state.model_copy(deep=True)


test_runner = TestRunner()
