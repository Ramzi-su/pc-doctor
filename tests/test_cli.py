import pytest

from app import cli


def test_defaults() -> None:
    args = cli.parse_args([])
    assert args.port == cli.DEFAULT_PORT
    assert args.no_browser is False


def test_custom_port_and_no_browser() -> None:
    args = cli.parse_args(["--port", "9000", "--no-browser"])
    assert args.port == 9000
    assert args.no_browser is True


@pytest.mark.parametrize("port", ["80", "70000", "abc"])
def test_invalid_port_rejected(port: str) -> None:
    with pytest.raises(SystemExit):
        cli.parse_args(["--port", port])


def test_main_binds_localhost_only(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: dict = {}
    monkeypatch.setattr(cli.uvicorn, "run", lambda app, **kw: calls.update(kw))
    cli.main(["--no-browser"])
    assert calls["host"] == "127.0.0.1"


def test_refuses_to_run_as_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli.os, "geteuid", lambda: 0)
    monkeypatch.setattr(cli.uvicorn, "run", lambda *a, **kw: pytest.fail("server started as root"))
    with pytest.raises(SystemExit, match="root"):
        cli.main(["--no-browser"])
