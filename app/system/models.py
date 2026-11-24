"""Pydantic response models for every PC Doctor endpoint."""

from datetime import datetime
from enum import StrEnum

from pydantic import BaseModel


class Severity(StrEnum):
    OK = "ok"
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class Finding(BaseModel):
    """A diagnosis line shown in the "Diagnostic" panel."""

    severity: Severity
    area: str
    message: str


# ---------- hardware ----------

class Machine(BaseModel):
    vendor: str | None
    product: str | None
    family: str | None
    sku: str | None
    serial: str | None  # usually ROOT_ONLY for normal users
    board: str | None
    bios_vendor: str | None
    bios_version: str | None
    bios_date: str | None  # firmware date, NOT the manufacturing date
    chassis_type: str | None


class Cpu(BaseModel):
    model: str
    physical_cores: int | None
    logical_cores: int
    max_mhz: float | None
    flags_virtualization: str | None


class Memory(BaseModel):
    total_bytes: int
    swap_bytes: int


class Disk(BaseModel):
    name: str
    model: str | None
    size_bytes: int
    rotational: bool
    removable: bool


class Partition(BaseModel):
    device: str
    mountpoint: str
    fstype: str
    total_bytes: int
    used_bytes: int
    percent: float


class Battery(BaseModel):
    name: str
    manufacturer: str | None
    model: str | None
    technology: str | None
    cycle_count: int | None
    health_percent: float | None  # full capacity now vs. when new
    manufacture_date: str | None  # only some batteries expose it


class PciDevice(BaseModel):
    slot: str
    kind: str
    vendor: str
    device: str
    subsystem_vendor: str | None
    driver: str | None
    revision: str | None


class Gpu(PciDevice):
    vram_total_mib: int | None = None
    driver_version: str | None = None
    vbios_version: str | None = None


class Hardware(BaseModel):
    machine: Machine
    cpu: Cpu
    memory: Memory
    disks: list[Disk]
    partitions: list[Partition]
    batteries: list[Battery]
    gpus: list[Gpu]
    usb_devices: list[str]


# ---------- network ----------

class Interface(BaseModel):
    name: str
    kind: str  # ethernet, wifi, loopback, virtual
    mac: str | None
    state: str
    mtu: int | None
    speed_mbps: int | None
    addresses: list[str]
    driver: str | None
    firmware: str | None
    hardware: PciDevice | None
    rx_bytes: int
    tx_bytes: int
    rx_errors: int
    tx_errors: int


class Port(BaseModel):
    protocol: str
    address: str
    port: int
    exposed: bool  # reachable from other machines (not loopback-only)
    pid: int | None
    process: str | None  # None when owned by another user (needs root)
    user: str | None
    started: datetime | None = None  # owner's start time (detects PID reuse)
    service: str | None  # usual service for this port number (a hint, not proof)
    units: list[str] = []  # systemd units to stop to close it (from the server, never the page)
    revealed: bool = False  # owner found by the root "reveal" action


# ---------- accounts & permissions ----------

class User(BaseModel):
    name: str
    uid: int
    gid: int
    home: str
    shell: str
    human: bool  # regular account vs. system/service account
    can_login: bool
    groups: list[str]
    admin: bool  # member of sudo/wheel/admin


class Group(BaseModel):
    name: str
    gid: int
    members: list[str]
    sensitive: bool
    why: str | None


class Login(BaseModel):
    user: str
    terminal: str
    source: str
    start: str
    end: str


class Accounts(BaseModel):
    users: list[User]
    groups: list[Group]
    logins: list[Login]
    current_user: str


class FileAudit(BaseModel):
    path: str
    mode: str  # e.g. "-rw-r-----"
    octal: str
    owner: str
    group: str
    expected: str
    ok: bool
    note: str | None


class SuidFile(BaseModel):
    path: str
    mode: str
    owner: str
    kind: str  # "suid", "sgid" or "suid+sgid"
    known: bool  # part of the usual Linux base set
    dangerous: bool  # allows trivial privilege escalation if SUID root


class Permissions(BaseModel):
    files: list[FileAudit]
    world_writable: list[str]


class SuidScan(BaseModel):
    files: list[SuidFile]
    scanned_at: datetime
    duration_seconds: float


# ---------- processes ----------

class ProcessDetail(BaseModel):
    """One row of the Processus tab. A field the kernel refuses to give is
    None (shown "nécessite root"); the process itself is never skipped."""

    pid: int
    ppid: int | None
    name: str
    cmdline: str | None  # None = access denied; "" = kernel thread
    user: str | None
    status: str | None
    cpu_percent: float | None
    memory_bytes: int | None
    memory_percent: float | None
    threads: int | None
    nice: int | None
    started: datetime | None
    kernel_thread: bool
    protected: bool  # PID 1, kernel threads, PC Doctor itself: kill refused
    critical: bool  # killing it closes the desktop session: stronger warning


class ProcessList(BaseModel):
    processes: list[ProcessDetail]
    total: int
    current_user: str


# ---------- live ----------

class Temperature(BaseModel):
    sensor: str
    label: str
    celsius: float


class InterfaceRate(BaseModel):
    name: str
    rx_bps: float
    tx_bps: float


class GpuLive(BaseModel):
    name: str
    temperature_c: float | None
    utilization_percent: float | None
    memory_used_mib: float | None
    memory_total_mib: float | None
    power_w: float | None
    pstate: str | None


class ProcessInfo(BaseModel):
    pid: int
    name: str
    user: str | None
    cpu_percent: float
    memory_bytes: int


class LiveSnapshot(BaseModel):
    time: datetime
    uptime_seconds: float
    load_average: tuple[float, float, float]
    cpu_percent: float
    cpu_per_core: list[float]
    cpu_mhz: float | None
    memory_used_bytes: int
    memory_total_bytes: int
    swap_used_bytes: int
    swap_total_bytes: int
    disk_read_bps: float
    disk_write_bps: float
    network: list[InterfaceRate]
    temperatures: list[Temperature]
    gpus: list[GpuLive]
    battery_percent: float | None
    on_ac: bool | None
    top_processes: list[ProcessInfo]
    process_count: int


# ---------- log files ----------

class LogFile(BaseModel):
    path: str
    size_bytes: int
    modified: datetime
    compressed: bool


class LogFileContent(BaseModel):
    path: str
    lines: list[str]
    truncated: bool


# ---------- privileged actions ----------

class ActionResult(BaseModel):
    message: str
    privileged: bool  # True when the system password dialog was used


class FirewallStatus(BaseModel):
    installed: bool
    enabled: bool
