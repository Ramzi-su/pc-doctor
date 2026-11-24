"""FastAPI app: JSON API + static UI. Run it bound to 127.0.0.1 only."""

from pathlib import Path
from typing import Annotated

from fastapi import FastAPI, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app import journal
from app.models import LogQuery, LogResult, Priority

STATIC_DIR = Path(__file__).parent / "static"

app = FastAPI(title="Log Viewer", docs_url=None, redoc_url=None, openapi_url=None)
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
