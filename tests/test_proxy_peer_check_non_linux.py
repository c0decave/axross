"""Without /proc/net/tcp the loopback proxy tunnel and shim no longer let
every local user in (review 1 of 0.15.176).

Before: core.proxy._peer_is_same_user returned True whenever
``/proc/net/tcp`` was missing - on macOS and Windows any local account
could ride a proxy tunnel (and the proxy credentials behind it). Now
macOS and the BSDs ask lsof for the sockets of their own user (getpeereid
and LOCAL_PEERCRED answer for Unix-domain sockets only, and the tunnel's
clients dial TCP), and where nothing can tell (Windows) the tunnel and
the shim are not started, with the reason. Linux is unchanged.
"""

from __future__ import annotations

import os
import socket
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import proxy as P  # noqa: E402

PEER = ("127.0.0.1", 52345)
SERVER = ("127.0.0.1", 61000)


@pytest.fixture
def no_proc(monkeypatch, tmp_path):
    """A system without Linux's /proc/net/tcp."""
    monkeypatch.setattr(P, "_PROC_NET_TCP", str(tmp_path / "no-proc-net-tcp"), raising=False)
    real_exists = os.path.exists
    # The old code looked at the literal path.
    monkeypatch.setattr(os.path, "exists",
                        lambda p: False if p == "/proc/net/tcp" else real_exists(p))


@pytest.fixture
def windows(no_proc, monkeypatch):
    monkeypatch.setattr(P, "_lsof_path", lambda: None, raising=False)
    monkeypatch.setattr(P, "_posix_uids", lambda: False, raising=False)


def _fake_lsof(tmp_path: Path, output: str) -> tuple[str, Path]:
    """An lsof that records its argv and prints *output*."""
    log = tmp_path / "lsof-argv"
    script = tmp_path / "lsof"
    script.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$@\" > {log}\nprintf '{output}'\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    return str(script), log


def test_sad_without_a_peer_check_a_foreign_peer_is_refused(windows):
    assert P._peer_is_same_user(PEER, server=SERVER) is False
    assert P.peer_check_problem()


def test_sad_without_a_peer_check_the_tunnel_does_not_start_and_says_why(windows):
    tunnel = P.LocalTunnel(P.ProxyConfig("socks5", "proxy.example", 1080), "db.example", 5432)
    with pytest.raises(P.ProxyUnsupportedError) as err:
        tunnel.start()
    assert "not started" in str(err.value) and "local user" in str(err.value)
    assert tunnel._listener is None


def test_sad_without_a_peer_check_the_shim_is_not_started(windows, monkeypatch):
    import core.proxy_http as PH

    monkeypatch.setattr(P, "_assert_proxy_host_not_private", lambda *a, **k: None)
    monkeypatch.setattr(PH, "shim_for", lambda cfg: pytest.fail("shim started"))
    with pytest.raises(P.ProxyUnsupportedError):
        P.build_requests_proxies("https", "proxy.example", 3128)
    with pytest.raises(P.ProxyUnsupportedError):
        P.effective_http_proxy(P.ProxyConfig("socks5", "proxy.example", 1080))


def test_happy_macos_asks_lsof_for_its_own_sockets_only(no_proc, tmp_path, monkeypatch):
    lsof, log = _fake_lsof(tmp_path, "p4242\\nf7\\nn127.0.0.1:52345->127.0.0.1:61000\\n")
    monkeypatch.setattr(P, "_LSOF_PATHS", (lsof,), raising=False)
    assert P._peer_is_same_user(PEER, server=SERVER) is True
    assert P.peer_check_problem() == ""
    argv = log.read_text().split()
    assert argv[argv.index("-u") + 1] == str(os.getuid())  # this user's sockets only
    assert "-a" in argv and "-iTCP@127.0.0.1:52345" in argv


def test_sad_macos_refuses_a_peer_no_process_of_its_user_holds(no_proc, tmp_path, monkeypatch):
    # Only axross's own accepted end is listed: the client is another user's.
    lsof, _ = _fake_lsof(tmp_path, "p99\\nf9\\nn127.0.0.1:61000->127.0.0.1:52345\\n")
    monkeypatch.setattr(P, "_LSOF_PATHS", (lsof,), raising=False)
    assert P._peer_is_same_user(PEER, server=SERVER) is False


def test_sad_macos_fails_closed_when_lsof_fails(no_proc, tmp_path, monkeypatch):
    broken = tmp_path / "lsof"
    broken.write_text("#!/bin/sh\nexit 1\n")
    broken.chmod(0o755)
    monkeypatch.setattr(P, "_LSOF_PATHS", (str(broken),), raising=False)
    assert P._peer_is_same_user(PEER, server=SERVER) is False
    assert P._peer_is_same_user(PEER) is False  # no server address: nothing to match


def test_edge_root_peers_are_asked_for_only_when_allowed(no_proc, tmp_path, monkeypatch):
    lsof, log = _fake_lsof(tmp_path, "")
    monkeypatch.setattr(P, "_LSOF_PATHS", (lsof,), raising=False)
    P._peer_is_same_user(PEER, root_ok=True, server=SERVER)
    argv = log.read_text().split()
    assert argv[argv.index("-u") + 1] == f"{os.getuid()},0"


@pytest.mark.skipif(not os.path.exists("/proc/net/tcp"), reason="Linux only")
def test_happy_linux_is_unchanged_a_same_user_peer_gets_in():
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    client = socket.create_connection(listener.getsockname())
    conn, peer = listener.accept()
    try:
        assert P._peer_is_same_user(peer, server=conn.getsockname()[:2]) is True
        assert P.peer_check_problem() == ""
    finally:
        for s in (client, conn, listener):
            s.close()
