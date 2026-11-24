# Log Viewer

Local web UI to browse the systemd journal (filters by software, priority,
time range, text, and a "crashes only" preset).

```bash
uv sync
uv run uvicorn app.main:app --host 127.0.0.1 --port 8765
# open http://127.0.0.1:8765
```

Or install it as a command (once), then just type `log-viewer`:

```bash
uv tool install --editable .
log-viewer              # starts the server and opens the browser
log-viewer --port 9000 --no-browser
```

Never bind to `0.0.0.0`: logs contain sensitive data. Reading system logs
requires membership of the `adm` or `systemd-journal` group.

Tests: `uv run pytest`
