"""PC Doctor FastAPI app: JSON API + static UI. Run it bound to 127.0.0.1 only."""

import asyncio
import os
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Path as PathParam, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import AfterValidator, BaseModel, Field

from app import journal
from app.models import LogQuery, LogResult, Priority
from app.system import accounts, actions, doctor, hardware, live, hwtests, logfiles, network, permissions, processes, procnet
from app.system.models import (
    Accounts,
    ActionResult,
    FirewallStatus,
    HwTests,
    Finding,
    Hardware,
    Interface,
    LogFile,
    LogFileContent,
    Permissions,
    Port,
    ProcessList,
    SuidScan,
)
from app.system.runner import CommandError

STATIC_DIR = Path(__file__).parent / "static"
LIVE_INTERVAL_SECONDS = 2
MAX_LIVE_STREAMS = 4

def _background_suid_scan() -> None:
    try:
        permissions.suid_scanner.get()
    except CommandError:
        pass  # the user can still retry from the UI


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Code before `yield` runs once at server start, after it at shutdown.
    We start the slow SUID scan in a daemon thread so the diagnosis has it
    without making the first page load wait."""
    threading.Thread(target=_background_suid_scan, daemon=True).start()
    yield


app = FastAPI(title="PC Doctor", docs_url=None, redoc_url=None, openapi_url=None,
              lifespan=lifespan)
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
# Reject requests whose Host header is not local (blocks DNS rebinding attacks).
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost"])


ENFORCE_SAME_USER = True  # tests switch it off: TestClient has no real socket


@app.middleware("http")
async def only_same_user(request: Request, call_next):
    """Refuse connections from programs of other local accounts.

    127.0.0.1 is reachable by every user of the machine, and the CSRF header
    only stops web pages. Without this check, another account (a service
    user, a guest...) could kill our processes without any password, or
    read the full map of the machine. The kernel records the owner UID of
    every socket in /proc/net/tcp: the client's end must be ours.
    """
    if ENFORCE_SAME_USER:
        client, server = request.scope.get("client"), request.scope.get("server")
        uid = None
        if client and server:
            uid = await run_in_threadpool(procnet.peer_uid, client[0], client[1], server[0], server[1])
        if uid != os.getuid():
            return Response("PC Doctor only answers its own user.", status_code=403)
    return await call_next(request)


@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    # Only our own scripts may run; no inline scripts, no framing.
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon() -> Response:
    return Response(status_code=204)  # browsers always ask; answer "nothing" instead of 404


@app.get("/api/logs")
async def get_logs(query: Annotated[LogQuery, Query()]) -> LogResult:
    try:
        # journalctl is blocking: run it in a worker thread, not the event loop.
        return await run_in_threadpool(journal.query_logs, query)
    except journal.JournalError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/identifiers")
async def get_identifiers() -> list[str]:
    try:
        return await run_in_threadpool(journal.list_identifiers)
    except journal.JournalError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/priorities")
async def get_priorities() -> list[dict[str, int | str]]:
    return [{"value": p.value, "name": p.name.lower()} for p in Priority]


# ---------- PC Doctor ----------
# Every collector is blocking (files, subprocesses): run_in_threadpool keeps
# the event loop free so the live stream never stalls.

@app.get("/api/hardware")
async def get_hardware() -> Hardware:
    return await run_in_threadpool(hardware.hardware)


@app.get("/api/network")
async def get_network() -> list[Interface]:
    pci = await run_in_threadpool(hardware.pci_devices)
    return await run_in_threadpool(network.interfaces, pci)


@app.get("/api/ports")
async def get_ports() -> list[Port]:
    return await run_in_threadpool(network.listening_ports)


@app.get("/api/processes")
async def get_processes() -> ProcessList:
    return await run_in_threadpool(processes.process_table.snapshot)


@app.get("/api/accounts")
async def get_accounts() -> Accounts:
    return await run_in_threadpool(accounts.accounts)


@app.get("/api/permissions")
async def get_permissions() -> Permissions:
    return await run_in_threadpool(permissions.permissions)


@app.get("/api/suid")
async def get_suid() -> SuidScan | None:
    """Last scan result; never starts a scan (that is the POST below)."""
    return permissions.suid_scanner.cached


def require_app_header(x_requested_with: Annotated[str | None, Header()] = None) -> None:
    """CSRF guard for actions. A malicious web page can send a POST to
    127.0.0.1, but adding a custom header forces a CORS preflight that our
    server never approves, so only our own page can send it."""
    if x_requested_with != "pc-doctor":
        raise HTTPException(status_code=403, detail="missing X-Requested-With header")


@app.post("/api/suid/scan", dependencies=[Depends(require_app_header)])
async def scan_suid() -> SuidScan:
    try:
        return await run_in_threadpool(permissions.suid_scanner.get, True)
    except CommandError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc


@app.get("/api/diagnosis")
async def get_diagnosis() -> list[Finding]:
    # The collectors are independent: run them in parallel threads.
    hw, ports, acc, perms, kernel = await asyncio.gather(
        run_in_threadpool(hardware.hardware),
        run_in_threadpool(network.listening_ports),
        run_in_threadpool(accounts.accounts),
        run_in_threadpool(permissions.permissions),
        run_in_threadpool(doctor.kernel_errors),
    )
    return doctor.diagnose(hw, ports, acc, perms, permissions.suid_scanner.cached, kernel)


_live_streams = 0


@app.get("/api/live")
async def live_stream(request: Request) -> StreamingResponse:
    """Server-Sent Events: one JSON snapshot every LIVE_INTERVAL_SECONDS."""
    if _live_streams >= MAX_LIVE_STREAMS:  # fast path: plain HTTP error
        raise HTTPException(status_code=429, detail="too many live views open")

    async def events() -> AsyncIterator[str]:
        global _live_streams
        # Check and increment with no `await` in between: the event loop only
        # switches tasks at an await, so two streams cannot both pass the check.
        # Counting inside the generator also guarantees the `finally` below
        # runs for every increment.
        if _live_streams >= MAX_LIVE_STREAMS:
            yield "event: error\ndata: too many live views open\n\n"
            return
        _live_streams += 1
        try:
            sampler = await run_in_threadpool(live.LiveSampler)
            await asyncio.sleep(0.5)  # rates need a time window: avoid a first "0 %" sample
            while not await request.is_disconnected():
                snap = await run_in_threadpool(sampler.sample)
                yield f"data: {snap.model_dump_json()}\n\n"
                await asyncio.sleep(LIVE_INTERVAL_SECONDS)
        finally:
            _live_streams -= 1  # also runs when the browser tab is closed

    return StreamingResponse(events(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache"})


class LogFileQuery(BaseModel):
    model_config = {"extra": "forbid"}

    path: str = Field(min_length=1, max_length=4096)
    text: str = Field(default="", max_length=200)
    limit: int = Field(default=500, ge=1, le=logfiles.MAX_LINES)


@app.get("/api/logfiles")
async def get_log_files() -> list[LogFile]:
    return await run_in_threadpool(logfiles.list_log_files)


@app.get("/api/logfiles/content")
async def get_log_file(query: Annotated[LogFileQuery, Query()]) -> LogFileContent:
    try:
        return await run_in_threadpool(
            logfiles.read_log_file, query.path, query.text.strip(), query.limit)
    except logfiles.LogFileError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


# ---------- privileged actions ----------
# Each one may open the system password dialog. One at a time: a second
# click while a dialog is open gets 409 instead of stacking dialogs.

_action_lock = asyncio.Lock()
PID_MAX = 4_194_304  # Linux upper bound (/proc/sys/kernel/pid_max)


async def _privileged(func, *args) -> ActionResult:
    if _action_lock.locked():
        raise HTTPException(status_code=409, detail="Une autre action attend déjà ton mot de passe.")
    async with _action_lock:
        try:
            return await run_in_threadpool(func, *args)
        except actions.ActionError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc


class KillRequest(BaseModel):
    model_config = {"extra": "forbid"}

    started: datetime  # start time shown in the page: detects PID reuse
    signal: actions.Signal = "TERM"


class PortRequest(BaseModel):
    model_config = {"extra": "forbid"}

    protocol: actions.Protocol
    port: int = Field(ge=1, le=65535)


class StopServiceRequest(PortRequest):
    disable: bool = False


class FirewallRuleRequest(PortRequest):
    block: bool = True


class FirewallEnableRequest(BaseModel):
    model_config = {"extra": "forbid"}

    enabled: bool


class FirewallDefaultRequest(BaseModel):
    model_config = {"extra": "forbid"}

    direction: actions.PolicyDirection
    policy: actions.Policy


class FirewallLoggingRequest(BaseModel):
    model_config = {"extra": "forbid"}

    level: actions.LogLevel


# AfterValidator runs our own check after Pydantic's type check: a bad value
# becomes a 422 with the reason, before any code (or password dialog) runs.
Ports = Annotated[str, Field(max_length=100), AfterValidator(actions.check_ports)]
Address = Annotated[str, Field(max_length=50), AfterValidator(actions.check_address)]


class FirewallAddRequest(BaseModel):
    model_config = {"extra": "forbid"}

    action: actions.RuleAction = "allow"
    direction: actions.Direction = "in"
    protocol: actions.RuleProtocol = "any"
    from_address: Address = "any"
    from_port: Ports = ""
    to_address: Address = "any"
    to_port: Ports = ""
    log: bool = False
    comment: Annotated[str, Field(max_length=60), AfterValidator(actions.check_comment)] = ""


class FirewallDeleteRequest(BaseModel):
    model_config = {"extra": "forbid"}

    id: str = Field(pattern=r"^[0-9a-f]{16}$")


@app.post("/api/processes/{pid}/kill", dependencies=[Depends(require_app_header)])
async def kill_process(pid: Annotated[int, PathParam(gt=2, le=PID_MAX)],
                       body: KillRequest) -> ActionResult:
    return await _privileged(actions.kill_process, pid, body.started, body.signal)


@app.post("/api/ports/reveal", dependencies=[Depends(require_app_header)])
async def reveal_ports() -> ActionResult:
    return await _privileged(actions.reveal_port_owners)


@app.post("/api/ports/stop-service", dependencies=[Depends(require_app_header)])
async def stop_port_service(body: StopServiceRequest) -> ActionResult:
    return await _privileged(actions.stop_port_service, body.protocol, body.port, body.disable)


@app.get("/api/firewall")
async def get_firewall() -> FirewallStatus:
    return actions.firewall_status()


@app.post("/api/firewall/rule", dependencies=[Depends(require_app_header)])
async def firewall_rule(body: FirewallRuleRequest) -> ActionResult:
    return await _privileged(actions.firewall_rule, body.protocol, body.port, body.block)


@app.post("/api/firewall/enable", dependencies=[Depends(require_app_header)])
async def firewall_enable(body: FirewallEnableRequest) -> ActionResult:
    return await _privileged(actions.firewall_enable, body.enabled)


@app.post("/api/firewall/default", dependencies=[Depends(require_app_header)])
async def firewall_default(body: FirewallDefaultRequest) -> ActionResult:
    return await _privileged(actions.firewall_default, body.direction, body.policy)


@app.post("/api/firewall/logging", dependencies=[Depends(require_app_header)])
async def firewall_logging(body: FirewallLoggingRequest) -> ActionResult:
    return await _privileged(actions.firewall_logging, body.level)


@app.post("/api/firewall/rules/reveal", dependencies=[Depends(require_app_header)])
async def reveal_firewall_rules() -> ActionResult:
    return await _privileged(actions.reveal_firewall_rules)


@app.post("/api/firewall/rules", dependencies=[Depends(require_app_header)])
async def add_firewall_rule(body: FirewallAddRequest) -> ActionResult:
    return await _privileged(actions.add_firewall_rule, body.action, body.direction, body.protocol,
                             body.from_address, body.from_port, body.to_address, body.to_port,
                             body.log, body.comment)


@app.post("/api/firewall/rules/delete", dependencies=[Depends(require_app_header)])
async def delete_firewall_rule(body: FirewallDeleteRequest) -> ActionResult:
    return await _privileged(actions.delete_firewall_rule, body.id)


# ---------- hardware tests ----------

@app.get("/api/hwtests")
async def get_hwtests() -> HwTests:
    return hwtests.test_runner.snapshot()


@app.post("/api/hwtests/{test_id}/start", dependencies=[Depends(require_app_header)])
async def start_hwtest(test_id: Annotated[str, PathParam(pattern=r"^[a-z]{1,20}$")]) -> HwTests:
    try:
        hwtests.test_runner.start(test_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail="Test inconnu.") from exc
    except RuntimeError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    return hwtests.test_runner.snapshot()


@app.post("/api/hwtests/cancel", dependencies=[Depends(require_app_header)])
async def cancel_hwtest() -> HwTests:
    hwtests.test_runner.cancel()
    return hwtests.test_runner.snapshot()
