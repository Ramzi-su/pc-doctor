"""Text log files under /var/log that the current user may read.

The browser sends a file path: this is the classic *path traversal* risk
(`/var/log/../../home/me/.ssh/id_ed25519`). We resolve the path (which
collapses `..` and follows symlinks) and only accept it if the real file is
still inside /var/log.
"""

import gzip
import os
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from app.system.models import LogFile, LogFileContent

LOG_ROOT = Path("/var/log")
BINARY_NAMES = {"wtmp", "btmp", "lastlog", "faillog", "wtmp.db"}
SKIP_DIRS = {"journal"}  # binary journald files: use the "Journal" tab instead
MAX_PLAIN_READ = 2 * 1024 * 1024  # read at most the last 2 MiB of a plain file
MAX_DECOMPRESSED = 50 * 1024 * 1024  # stop gunzipping after 50 MiB (gzip bombs)
MAX_LINES = 2000


class LogFileError(ValueError):
    """Path refused or file unreadable."""


def _is_candidate(path: Path) -> bool:
    name = path.name
    if name in BINARY_NAMES or name.split(".")[0] in BINARY_NAMES:
        return False
    return not name.endswith((".xz", ".zst", ".bz2"))  # unsupported compressions


def list_log_files(root: Path = LOG_ROOT) -> list[LogFile]:
    files = []
    for dirpath, dirnames, filenames in os.walk(root, onerror=lambda _e: None):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            path = Path(dirpath, name)
            if not _is_candidate(path) or path.is_symlink() or not os.access(path, os.R_OK):
                continue
            try:
                st = path.stat()
            except OSError:
                continue
            if st.st_size == 0:
                continue
            files.append(LogFile(
                path=str(path), size_bytes=st.st_size,
                modified=datetime.fromtimestamp(st.st_mtime, tz=timezone.utc),
                compressed=name.endswith(".gz"),
            ))
    return sorted(files, key=lambda f: f.modified, reverse=True)


def safe_path(raw: str, root: Path = LOG_ROOT) -> Path:
    """Return the real path if it is a readable regular file inside `root`."""
    try:
        real = Path(raw).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise LogFileError("fichier introuvable") from exc
    if not real.is_relative_to(root.resolve()):
        raise LogFileError("chemin refusé : uniquement les fichiers de /var/log")
    if not real.is_file() or not _is_candidate(real):
        raise LogFileError("ce n'est pas un fichier de log texte")
    if not os.access(real, os.R_OK):
        raise LogFileError("lecture refusée : ce fichier nécessite root")
    return real


def _tail_plain(path: Path) -> tuple[list[str], bool]:
    size = path.stat().st_size
    with path.open("rb") as fh:
        if size > MAX_PLAIN_READ:
            fh.seek(size - MAX_PLAIN_READ)
        data = fh.read()
    if b"\0" in data[:4096]:
        raise LogFileError("fichier binaire")
    lines = data.decode("utf-8", errors="replace").splitlines()
    if size > MAX_PLAIN_READ:
        lines = lines[1:]  # first line was cut in the middle
    return lines, size > MAX_PLAIN_READ


CHUNK = 64 * 1024
MAX_LINE = 64 * 1024  # longer "lines" are cut: no unbounded buffer


def _tail_gzip(path: Path) -> tuple[list[str], bool]:
    """Read fixed-size decompressed chunks, so the byte cap is enforced before
    any line is built: iterating lines would first load a whole line, and a
    tiny .gz can hold a multi-GB line without any newline (gzip bomb)."""
    lines: deque[bytes] = deque(maxlen=MAX_LINES * 10)
    carry = b""
    read = 0
    truncated = False
    with gzip.open(path, "rb") as fh:
        while chunk := fh.read(CHUNK):
            read += len(chunk)
            if read > MAX_DECOMPRESSED:
                truncated = True
                break
            parts = (carry + chunk).split(b"\n")
            carry = parts.pop()[:MAX_LINE]  # unfinished last line, bounded
            lines.extend(part[:MAX_LINE] for part in parts)
    if carry:
        lines.append(carry)
    return [line.decode("utf-8", errors="replace") for line in lines], truncated


def read_log_file(raw_path: str, text: str = "", limit: int = 500,
                  root: Path = LOG_ROOT) -> LogFileContent:
    path = safe_path(raw_path, root)
    try:
        lines, truncated = (_tail_gzip if path.suffix == ".gz" else _tail_plain)(path)
    except (OSError, EOFError) as exc:
        raise LogFileError(f"lecture impossible : {exc}") from exc
    if text:
        needle = text.lower()
        lines = [line for line in lines if needle in line.lower()]
    limit = min(limit, MAX_LINES)
    return LogFileContent(path=str(path), lines=lines[-limit:],
                          truncated=truncated or len(lines) > limit)
