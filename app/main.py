"""PC Doctor FastAPI app: JSON API + static UI. Run it bound to 127.0.0.1 only."""

import asyncio
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from app import journal
from app.models import LogQuery, LogResult, Priority
from app.system import accounts, doctor, hardware, live, logfiles, network, permissions, processes
from app.system.models import (
    Accounts,
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
