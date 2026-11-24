"""Hardware inventory: machine, CPU, RAM, disks, battery, GPUs, USB.

Mostly read from /sys and /proc (readable by normal users). Paths are
parameters so tests can point them at a fake directory tree.
"""

import re
from pathlib import Path

import psutil

from app.system import runner
from app.system.models import (
    Battery,
    Cpu,
    Disk,
    Gpu,
    Hardware,
    Machine,
    Memory,
    Partition,
    PciDevice,
)
from app.system.runner import CommandError, read_text

SYS = Path("/sys")
PROC = Path("/proc")

# SMBIOS chassis types (subset): https://www.dmtf.org/standards/smbios
CHASSIS_TYPES = {
    "3": "Desktop", "4": "Low profile desktop", "6": "Mini tower", "7": "Tower",
    "8": "Portable", "9": "Laptop", "10": "Notebook", "13": "All in one",
    "14": "Sub notebook", "30": "Tablet", "31": "Convertible", "32": "Detachable",
    "35": "Mini PC",
}

# Placeholder strings that vendors leave in DMI fields.
_DMI_PLACEHOLDERS = {"", "to be filled by o.e.m.", "default string", "not specified",
                     "chassis version", "type1productconfigid", "system version"}


def _dmi(sys_root: Path, field: str) -> str | None:
    value = read_text(sys_root / "class/dmi/id" / field)
    if value is None or value.lower() in _DMI_PLACEHOLDERS:
        return None
    return value


def machine_info(sys_root: Path = SYS) -> Machine:
    chassis = _dmi(sys_root, "chassis_type")
    board = " ".join(filter(None, [_dmi(sys_root, "board_vendor"), _dmi(sys_root, "board_name")]))
    return Machine(
        vendor=_dmi(sys_root, "sys_vendor"),
        product=_dmi(sys_root, "product_name"),
        family=_dmi(sys_root, "product_family"),
        sku=_dmi(sys_root, "product_sku"),
        serial=_dmi(sys_root, "product_serial"),
        board=board or None,
        bios_vendor=_dmi(sys_root, "bios_vendor"),
        bios_version=_dmi(sys_root, "bios_version"),
        bios_date=_dmi(sys_root, "bios_date"),
        chassis_type=CHASSIS_TYPES.get(chassis or "", chassis),
    )


def cpu_info(proc_root: Path = PROC) -> Cpu:
    cpuinfo = read_text(proc_root / "cpuinfo") or ""
    model = re.search(r"^model name\s*:\s*(.+)$", cpuinfo, re.M)
    flags = re.search(r"^flags\s*:\s*(.+)$", cpuinfo, re.M)
    flag_set = set(flags.group(1).split()) if flags else set()
    virt = "Intel VT-x" if "vmx" in flag_set else "AMD-V" if "svm" in flag_set else None
    freq = psutil.cpu_freq()
    return Cpu(
        model=model.group(1).strip() if model else "unknown",
        physical_cores=psutil.cpu_count(logical=False),
        logical_cores=psutil.cpu_count() or 0,
        max_mhz=freq.max if freq and freq.max else None,
        flags_virtualization=virt,
    )


def disks(sys_root: Path = SYS) -> list[Disk]:
    result = []
    for dev in sorted((sys_root / "block").glob("*")):
        if dev.name.startswith(("loop", "ram", "zram")):
            continue  # virtual devices (snap images, RAM disks)
        sectors = read_text(dev / "size")
        result.append(Disk(
            name=dev.name,
            model=read_text(dev / "device/model"),
            size_bytes=int(sectors) * 512 if sectors and sectors.isdigit() else 0,
            rotational=read_text(dev / "queue/rotational") == "1",
            removable=read_text(dev / "removable") == "1",
        ))
    return result


def partitions() -> list[Partition]:
    result, seen = [], set()
    for part in psutil.disk_partitions(all=False):
        if part.fstype in {"squashfs", "tmpfs"} or part.device in seen:
            continue  # snap images and duplicates (bind mounts)
        seen.add(part.device)
        try:
            usage = psutil.disk_usage(part.mountpoint)
        except OSError:
            continue
        result.append(Partition(
            device=part.device, mountpoint=part.mountpoint, fstype=part.fstype,
            total_bytes=usage.total, used_bytes=usage.used, percent=usage.percent,
        ))
    return result


def _int(value: str | None) -> int | None:
    return int(value) if value and value.lstrip("-").isdigit() else None


def batteries(sys_root: Path = SYS) -> list[Battery]:
    result = []
    for supply in sorted((sys_root / "class/power_supply").glob("*")):
        if read_text(supply / "type") != "Battery":
            continue
        # Some drivers report energy (µWh), others charge (µAh): same ratio.
        full = _int(read_text(supply / "energy_full")) or _int(read_text(supply / "charge_full"))
        design = (_int(read_text(supply / "energy_full_design"))
                  or _int(read_text(supply / "charge_full_design")))
        health = round(100 * full / design, 1) if full and design else None
        date_parts = [read_text(supply / f"manufacture_{p}") for p in ("year", "month", "day")]
        manufactured = "-".join(p.zfill(2) for p in date_parts if p) if date_parts[0] else None
        cycles = _int(read_text(supply / "cycle_count"))
        result.append(Battery(
            name=supply.name,
            manufacturer=read_text(supply / "manufacturer"),
            model=read_text(supply / "model_name"),
            technology=read_text(supply / "technology"),
            cycle_count=cycles or None,  # 0 means "not reported" on most laptops
            health_percent=health,
            manufacture_date=manufactured,
        ))
    return result


def parse_lspci(output: str) -> list[PciDevice]:
    """Parse `lspci -vmmk` (blank-line separated "Key:\\tValue" records)."""
    devices = []
    for block in output.strip().split("\n\n"):
        fields = {}
        for line in block.splitlines():
            key, sep, value = line.partition(":\t")
            if sep:
                fields[key.strip()] = value.strip()
        if "Slot" not in fields:
            continue
        devices.append(PciDevice(
            slot=fields["Slot"],
            kind=fields.get("Class", "?"),
            vendor=fields.get("Vendor", "?"),
            device=fields.get("Device", "?"),
            subsystem_vendor=fields.get("SVendor"),
            driver=fields.get("Driver"),
            revision=fields.get("Rev"),
        ))
    return devices


def pci_devices(run: runner.Runner | None = None) -> list[PciDevice]:
    try:
        return parse_lspci(runner.run(["lspci", "-vmmk"], runner=run))
    except CommandError:
        return []


GPU_CLASSES = ("VGA compatible controller", "3D controller", "Display controller")
NVIDIA_STATIC = "pci.bus_id,driver_version,memory.total,vbios_version"


def gpus(pci: list[PciDevice], run: runner.Runner | None = None) -> list[Gpu]:
    result = [Gpu(**d.model_dump()) for d in pci if d.kind in GPU_CLASSES]
    try:
        out = runner.run(["nvidia-smi", f"--query-gpu={NVIDIA_STATIC}",
                          "--format=csv,noheader,nounits"], runner=run)
    except CommandError:
        return result  # no NVIDIA GPU or driver
    for line in out.strip().splitlines():
        bus, driver, vram, vbios = (v.strip() for v in line.split(","))
        for gpu in result:
            # nvidia-smi: "00000000:01:00.0", lspci: "01:00.0"
            if bus.lower().endswith(gpu.slot.lower()):
                gpu.driver_version, gpu.vbios_version = driver, vbios
                gpu.vram_total_mib = _int(vram)
    return result


_LSUSB = re.compile(r"^Bus \d+ Device \d+: ID [0-9a-f]{4}:[0-9a-f]{4} (.+)$", re.M)


def usb_devices(run: runner.Runner | None = None) -> list[str]:
    try:
        out = runner.run(["lsusb"], runner=run)
    except CommandError:
        return []
    return [name for name in _LSUSB.findall(out) if "root hub" not in name]


def hardware(run: runner.Runner | None = None) -> Hardware:
    pci = pci_devices(run)
    mem = psutil.virtual_memory()
    return Hardware(
        machine=machine_info(),
        cpu=cpu_info(),
        memory=Memory(total_bytes=mem.total, swap_bytes=psutil.swap_memory().total),
        disks=disks(),
        partitions=partitions(),
        batteries=batteries(),
        gpus=gpus(pci, run),
        usb_devices=usb_devices(run),
    )
