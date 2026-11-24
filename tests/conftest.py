import pytest

from app import main


@pytest.fixture(autouse=True)
def no_peer_check(monkeypatch):
    """TestClient talks to the app in memory, without a real TCP socket, so
    the same-user check cannot find it in /proc/net/tcp. It is tested
    separately in test_security.py with real sockets."""
    monkeypatch.setattr(main, "ENFORCE_SAME_USER", False)
