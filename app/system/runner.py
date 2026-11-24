"""Single entry point for external commands and /sys reads.

Security rules enforced here, so collectors cannot get them wrong:
- argument list only, never `shell=True` (no shell injection possible);
- a timeout on every command (a hung tool cannot freeze the server);
- LC_ALL=C so output is not translated (stable parsing).
"""

import os
import subprocess
from collections.abc import Callable
from pathlib import Path

DEFAULT_TIMEOUT = 10
_ENV = {**os.environ, "LC_ALL": "C", "LANG": "C"}

Runner = Callable[..., subprocess.CompletedProcess[str]]


class CommandError(RuntimeError):
    """The command is missing, failed or timed out."""


def run(cmd: list[str], timeout: float = DEFAULT_TIMEOUT, runner: Runner | None = None) -> str:
    """Run `cmd` and return its stdout. Raises CommandError on any failure."""
    runner = runner or subprocess.run  # resolved at call time for monkeypatching
    try:
        proc = runner(
            cmd, capture_output=True, text=True, timeout=timeout, check=False, env=_ENV
        )
    except FileNotFoundError as exc:
        raise CommandError(f"{cmd[0]} is not installed") from exc
    except subprocess.TimeoutExpired as exc:
        raise CommandError(f"{cmd[0]} timed out") from exc
    if proc.returncode != 0 and not proc.stdout:
        raise CommandError(proc.stderr.strip()[:300] or f"{cmd[0]} failed")
    return proc.stdout


ROOT_ONLY = "requires root"


def read_text(path: Path) -> str | None:
    """Read a small /sys or /proc file. Returns ROOT_ONLY or None instead of raising."""
    try:
        return path.read_text(errors="replace").strip()
    except PermissionError:
        return ROOT_ONLY
    except OSError:
        return None
