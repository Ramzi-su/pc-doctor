"""Read the systemd journal through `journalctl` and turn it into LogEntry objects.

Security notes:
- journalctl is always called with an argument *list* and never through a shell,
  so a filter value can never be interpreted as a shell command.
- Options are passed as `--opt=value` (single argv item), so a value starting
  with "-" cannot be mistaken for another option.
"""

import json
import re
import subprocess
import time
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

from app.models import LogEntry, LogQuery, LogResult, Priority

JOURNALCTL = "journalctl"
TIMEOUT_SECONDS = 30
IDENTIFIERS_CACHE_TTL = 300  # seconds

# Patterns seen in real browser/system crashes (see the earlier diagnosis).
# Both PCRE2 (journalctl --grep) and Python's `re` accept this syntax.
CRASH_PATTERN = (
    r"segfault|ld\.so|out of memory|oom-kill|killed process|NVRM: Xid"
    r"|crashed|signal 11|core dumped|general protection|GPU has fallen"
)
_crash_re = re.compile(CRASH_PATTERN, re.IGNORECASE)

OUTPUT_FIELDS = "PRIORITY,SYSLOG_IDENTIFIER,_COMM,MESSAGE,_PID,_SYSTEMD_UNIT,_SYSTEMD_USER_UNIT"

Runner = Callable[..., subprocess.CompletedProcess[str]]


class JournalError(RuntimeError):
    """journalctl failed or timed out."""


def _fmt_time(dt: datetime) -> str:
    # journalctl interprets this format in local time.
    return dt.astimezone().strftime("%Y-%m-%d %H:%M:%S")


def build_command(query: LogQuery) -> list[str]:
    """Translate a validated LogQuery into journalctl arguments."""
    assert query.since and query.until  # filled in by the model validator
    cmd = [
        JOURNALCTL,
        "--no-pager",
        "--quiet",
        "--output=json",
        f"--output-fields={OUTPUT_FIELDS}",
        "--reverse",  # newest first, so --lines keeps the most recent entries
        f"--lines={query.limit}",
        f"--since={_fmt_time(query.since)}",
        f"--until={_fmt_time(query.until)}",
    ]
    # journalctl only supports a contiguous range; gaps are filtered afterwards.
    cmd.append(f"--priority={min(query.priorities)}..{max(query.priorities)}")
    cmd += [f"--identifier={ident}" for ident in query.identifiers]

    if query.crash_only:
        pattern = CRASH_PATTERN
    elif query.text:
        pattern = re.escape(query.text)  # user text is literal, not a regex
    else:
        pattern = None
    if pattern:
        cmd += [f"--grep={pattern}", "--case-sensitive=false"]
    return cmd


def _decode_message(raw: Any) -> str:
    # journald stores non-UTF-8 messages as a list of byte values.
    if isinstance(raw, list):
        return bytes(raw).decode("utf-8", errors="replace")
    return raw if isinstance(raw, str) else ""


def _to_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_entry(raw: dict[str, Any]) -> LogEntry | None:
    """Convert one journalctl JSON object; returns None if it is unusable."""
    usec = _to_int(raw.get("__REALTIME_TIMESTAMP"))
    if usec is None:
        return None
    prio_value = _to_int(raw.get("PRIORITY"))
    priority = Priority(prio_value) if prio_value in range(8) else Priority.INFO
    message = _decode_message(raw.get("MESSAGE"))
    return LogEntry(
        timestamp=datetime.fromtimestamp(usec / 1_000_000, tz=timezone.utc),
        priority=priority,
        priority_name=priority.name.lower(),
        identifier=raw.get("SYSLOG_IDENTIFIER") or raw.get("_COMM") or "?",
        pid=_to_int(raw.get("_PID")),
        unit=raw.get("_SYSTEMD_UNIT") or raw.get("_SYSTEMD_USER_UNIT"),
        message=message,
        crash_hint=bool(_crash_re.search(message)),
    )


def _run(cmd: list[str], runner: Runner | None) -> subprocess.CompletedProcess[str]:
    # Resolved at call time so tests can monkeypatch subprocess.run.
    runner = runner or subprocess.run
    try:
        return runner(
            cmd, capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False
        )
    except subprocess.TimeoutExpired as exc:
        raise JournalError("journalctl timed out: narrow the time range") from exc
    except FileNotFoundError as exc:
        raise JournalError("journalctl not found") from exc


def query_logs(query: LogQuery, runner: Runner | None = None) -> LogResult:
    proc = _run(build_command(query), runner)
    # With --grep, journalctl exits 1 when nothing matches: that is not an error.
    if proc.returncode != 0 and proc.stderr.strip():
        raise JournalError(proc.stderr.strip()[:500])

    lines = proc.stdout.splitlines()
    text = query.text.lower()
    entries: list[LogEntry] = []
    for line in lines:
        try:
            entry = parse_entry(json.loads(line))
        except (json.JSONDecodeError, ValueError):
            continue
        if entry is None or entry.priority not in query.priorities:
            continue
        # In crash mode --grep holds the crash pattern, so apply text here.
        if query.crash_only and text and text not in entry.message.lower():
            continue
        entries.append(entry)
    return LogResult(entries=entries, truncated=len(lines) >= query.limit)


_identifiers_cache: tuple[float, list[str]] | None = None


def list_identifiers(runner: Runner | None = None) -> list[str]:
    """All distinct SYSLOG_IDENTIFIER values, cached for a few minutes."""
    global _identifiers_cache
    now = time.monotonic()
    if _identifiers_cache and now - _identifiers_cache[0] < IDENTIFIERS_CACHE_TTL:
        return _identifiers_cache[1]
    proc = _run([JOURNALCTL, "--no-pager", "--field=SYSLOG_IDENTIFIER"], runner)
    if proc.returncode != 0:
        raise JournalError(proc.stderr.strip()[:500] or "journalctl failed")
    idents = sorted({line for line in proc.stdout.splitlines() if line}, key=str.lower)
    _identifiers_cache = (now, idents)
    return idents
