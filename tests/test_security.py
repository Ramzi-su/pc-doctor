"""Same-user check: only the account running PC Doctor may use it."""

import os
import socket

import pytest
from fastapi.testclient import TestClient

from app import main
from app.system import procnet


def test_decode_ipv4_address():
    assert procnet.decode_address("0100007F:1F90") == ("127.0.0.1", 8080)


def test_decode_ipv6_address():
    assert procnet.decode_address("00000000000000000000000001000000:0016") == ("::1", 22)


TCP_TABLE = """\
  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 0100007F:223D 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1
   1: 0100007F:C350 0100007F:223D 01 00000000:00000000 00:00000000 00000000   112        0 4343 1
"""


def test_peer_uid_reads_the_client_end_of_the_connection():
    entries = procnet.parse_table(TCP_TABLE, "tcp")
    # client 127.0.0.1:50000 -> server port 8765 (0x223D) belongs to UID 112
    assert procnet.peer_uid("127.0.0.1", 50000, 8765, entries) == 112
    assert procnet.peer_uid("127.0.0.1", 50001, 8765, entries) is None


def test_peer_uid_on_a_real_connection():
    with socket.socket() as server:
        server.bind(("127.0.0.1", 0))
        server.listen()
        with socket.create_connection(server.getsockname()) as client:
            host, port = client.getsockname()
            assert procnet.peer_uid(host, port, server.getsockname()[1]) == os.getuid()


def test_requests_from_unknown_peers_are_refused(monkeypatch):
    monkeypatch.setattr(main, "ENFORCE_SAME_USER", True)
    client = TestClient(main.app, base_url="http://127.0.0.1")
    monkeypatch.setattr(procnet, "peer_uid", lambda *_: os.getuid() + 1)  # another account
    assert client.get("/api/processes").status_code == 403
    monkeypatch.setattr(procnet, "peer_uid", lambda *_: os.getuid())
    assert client.get("/api/firewall").status_code == 200


@pytest.mark.parametrize("url", ["/", "/api/live", "/api/processes"])
def test_every_route_is_covered(monkeypatch, url):
    monkeypatch.setattr(main, "ENFORCE_SAME_USER", True)
    monkeypatch.setattr(procnet, "peer_uid", lambda *_: None)
    assert TestClient(main.app, base_url="http://127.0.0.1").get(url).status_code == 403
