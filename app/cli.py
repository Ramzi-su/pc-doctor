"""Command-line entry point: `pc-doctor` starts the server and opens the browser."""

import argparse
import os
import sys
import threading
import webbrowser

import uvicorn

# Hard-coded on purpose: logs are sensitive, never expose them on the network.
HOST = "127.0.0.1"
DEFAULT_PORT = 8765


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="pc-doctor", description="Monitor and diagnose this PC in your browser.")
    parser.add_argument("--port", type=int, default=DEFAULT_PORT, help=f"port (default {DEFAULT_PORT})")
    parser.add_argument("--no-browser", action="store_true", help="do not open the browser")
    args = parser.parse_args(argv)
    if not 1024 <= args.port <= 65535:
        parser.error("--port must be between 1024 and 65535")
    return args


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    if os.geteuid() == 0:
        # A web server running as root turns any bug into full control of the PC.
        sys.exit("pc-doctor refuses to run as root: start it as your normal user.")
    url = f"http://{HOST}:{args.port}"
    if not args.no_browser:
        # Open slightly after startup so the server is ready to answer.
        threading.Timer(1.0, webbrowser.open, args=(url,)).start()
    print(f"PC Doctor running on {url} (Ctrl+C to stop)")
    uvicorn.run("app.main:app", host=HOST, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
