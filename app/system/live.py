"""Live metrics, sampled every few seconds and streamed to the browser.

Rates (CPU %, network/disk throughput) are differences between two samples,
so each browser connection keeps its own LiveSampler with the previous values.
"""

import time
from datetime import datetime, timezone
from pathlib import Path

import psutil

from app.system import runner
from app.system.models import GpuLive, InterfaceRate, LiveSnapshot, ProcessInfo, Temperature
from app.system.processes import safe_field
from app.system.runner import CommandError

NVIDIA_LIVE = "name,pci.bus_id,temperature.gpu,utilization.gpu,memory.used,memory.total,power.draw,pstate"
TOP_PROCESSES = 10


def _float(value: str) -> float | None:
    try:
        return float(value)
    except ValueError:
        return None  # "[N/A]" or "[Not Supported]"


def parse_nvidia_live(output: str) -> list[GpuLive]:
    gpus = []
    for line in output.strip().splitlines():
        parts = [v.strip() for v in line.split(",")]
        if len(parts) != 8:
            continue
        name, _bus, temp, util, used, total, power, pstate = parts
        gpus.append(GpuLive(
            name=name, temperature_c=_float(temp), utilization_percent=_float(util),
            memory_used_mib=_float(used), memory_total_mib=_float(total),
            power_w=_float(power), pstate=pstate,
        ))
    return gpus


def nvidia_sleeping(sys_root: Path = Path("/sys")) -> bool:
    """True when every NVIDIA GPU is in runtime suspend (laptop dGPU asleep).

    Calling nvidia-smi wakes the GPU up: polling it every 2 s would keep it
    powered and drain the battery. We skip the query while it sleeps.
    """
    statuses = []
    for dev in (sys_root / "bus/pci/devices").glob("*"):
        if runner.read_text(dev / "vendor") == "0x10de" and \
                (runner.read_text(dev / "class") or "").startswith("0x03"):
            statuses.append(runner.read_text(dev / "power/runtime_status"))
    return bool(statuses) and all(s == "suspended" for s in statuses)


class LiveSampler:
    def __init__(self, run: runner.Runner | None = None) -> None:
        self._run = run
        self._last_time = time.monotonic()
        self._last_net = psutil.net_io_counters(pernic=True)
        self._last_disk = psutil.disk_io_counters()
        self._procs: dict[int, psutil.Process] = {}
        self._nvidia = True  # becomes False if nvidia-smi is missing
        psutil.cpu_percent(percpu=True)  # prime: first call always returns 0

    def _gpus(self) -> list[GpuLive]:
        if not self._nvidia:
            return []
        if nvidia_sleeping():
            return [GpuLive(name="NVIDIA (en veille)", temperature_c=None, utilization_percent=0,
                            memory_used_mib=None, memory_total_mib=None, power_w=None,
                            pstate="suspended")]
        try:
            out = runner.run(["nvidia-smi", f"--query-gpu={NVIDIA_LIVE}",
                              "--format=csv,noheader,nounits"], timeout=3, runner=self._run)
        except CommandError:
            self._nvidia = False
            return []
        return parse_nvidia_live(out)

    def _top_processes(self) -> tuple[list[ProcessInfo], int]:
        # Keep Process objects between samples: cpu_percent() compares with the
        # previous call *on the same object*.
        current = {}
        infos = []
        for proc in psutil.process_iter():
            proc = self._procs.get(proc.pid, proc)
            current[proc.pid] = proc
            try:
                with proc.oneshot():  # read /proc/<pid> once for all fields
                    mem = safe_field(proc.memory_info)
                    infos.append(ProcessInfo(
                        pid=proc.pid, name=safe_field(proc.name, "?"), user=safe_field(proc.username),
                        cpu_percent=safe_field(proc.cpu_percent, 0.0),
                        memory_bytes=mem.rss if mem else 0,
                    ))
            except psutil.NoSuchProcess:
                continue  # exited meanwhile; a refused field no longer hides a process
        self._procs = current
        infos.sort(key=lambda p: (p.cpu_percent, p.memory_bytes), reverse=True)
        return infos[:TOP_PROCESSES], len(current)

    def sample(self) -> LiveSnapshot:
        now = time.monotonic()
        elapsed = max(now - self._last_time, 1e-3)

        net = psutil.net_io_counters(pernic=True)
        rates = [
            InterfaceRate(
                name=name,
                rx_bps=(c.bytes_recv - self._last_net[name].bytes_recv) / elapsed,
                tx_bps=(c.bytes_sent - self._last_net[name].bytes_sent) / elapsed,
            )
            for name, c in net.items() if name in self._last_net and name != "lo"
        ]
        disk = psutil.disk_io_counters()
        read_bps = write_bps = 0.0
        if disk and self._last_disk:
            read_bps = (disk.read_bytes - self._last_disk.read_bytes) / elapsed
            write_bps = (disk.write_bytes - self._last_disk.write_bytes) / elapsed
        self._last_time, self._last_net, self._last_disk = now, net, disk

        temps = [
            Temperature(sensor=sensor, label=t.label or sensor, celsius=t.current)
            for sensor, entries in psutil.sensors_temperatures().items()
            for t in entries if 0 < t.current < 150  # drop unplugged/bogus sensors
        ]
        battery = psutil.sensors_battery()
        mem, swap = psutil.virtual_memory(), psutil.swap_memory()
        freq = psutil.cpu_freq()
        per_core = psutil.cpu_percent(percpu=True)
        top, count = self._top_processes()

        return LiveSnapshot(
            time=datetime.now(timezone.utc),
            uptime_seconds=time.time() - psutil.boot_time(),
            load_average=psutil.getloadavg(),
            cpu_percent=round(sum(per_core) / len(per_core), 1) if per_core else 0.0,
            cpu_per_core=per_core,
            cpu_mhz=freq.current if freq else None,
            memory_used_bytes=mem.total - mem.available,
            memory_total_bytes=mem.total,
            swap_used_bytes=swap.used, swap_total_bytes=swap.total,
            disk_read_bps=read_bps, disk_write_bps=write_bps,
            network=rates, temperatures=temps, gpus=self._gpus(),
            battery_percent=battery.percent if battery else None,
            on_ac=battery.power_plugged if battery else None,
            top_processes=top, process_count=count,
        )
