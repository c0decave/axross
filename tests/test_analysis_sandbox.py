"""sift in bubblewrap: the file's folder read-only, the LLM host only.

Reported: sift ran unsandboxed - with the user's rights over the whole
home folder and the network. Decided: bubblewrap by default, only the
folder read-only, network egress to the LLM profile's host alone; without
bubblewrap a warning and the analysis unsandboxed.

This machine may have no usable bubblewrap (no user namespaces in a
container), so the parts are tested on their own: the command line, the
relay (a real Unix socket and TCP), the child's name resolution, and the
worker's choice of sandbox per folder and host.
"""

from __future__ import annotations

import logging
import os
import socket
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import analysis_sandbox as SB  # noqa: E402
from core import analysis_worker as AW  # noqa: E402


def _pairs(argv: list[str], flag: str) -> list[tuple[str, str]]:
    return [(argv[i + 1], argv[i + 2]) for i, a in enumerate(argv) if a == flag]


# -- the command line --------------------------------------------------------------------------


def test_happy_the_folder_is_read_only_and_there_is_no_network(tmp_path):
    argv = SB.bwrap_command(["python", "-m", "core.analysis_worker"], folder=str(tmp_path),
                            cache_dir=str(tmp_path / "cache"), relay_dir=None, env={})
    assert argv[0] == "bwrap" and "--unshare-all" in argv and "--share-net" not in argv
    assert "--clearenv" in argv and "--die-with-parent" in argv
    assert (str(tmp_path), str(tmp_path)) in _pairs(argv, "--ro-bind")
    assert (str(tmp_path), str(tmp_path)) not in _pairs(argv, "--bind")
    assert (str(tmp_path / "cache"), str(tmp_path / "cache")) in _pairs(argv, "--bind")
    home = str(Path.home())
    assert all(src != home for src, _ in _pairs(argv, "--ro-bind") + _pairs(argv, "--bind"))
    assert argv[-3:] == ["python", "-m", "core.analysis_worker"]


def test_happy_with_an_llm_the_relay_folder_and_tls_store_are_mounted(tmp_path):
    relay = tmp_path / "relay"
    relay.mkdir()
    argv = SB.bwrap_command(["x"], folder=str(tmp_path), cache_dir=None, relay_dir=str(relay),
                            env={SB.ENV_HOSTS: "api.example.com:443"})
    assert (str(relay), os.path.dirname(SB.RELAY_SOCKET_INSIDE)) in _pairs(argv, "--ro-bind")
    assert (SB.ENV_HOSTS, "api.example.com:443") in _pairs(argv, "--setenv")
    assert "--share-net" not in argv
    if os.path.exists("/etc/ssl"):
        assert ("/etc/ssl", "/etc/ssl") in _pairs(argv, "--ro-bind")


@pytest.mark.parametrize("endpoint, expected", [
    ("https://api.example.com/v1", ("api.example.com", 443)),
    ("http://127.0.0.1:11434", ("127.0.0.1", 11434)),
    ("http://LocalHost:1234/v1", ("localhost", 1234)),
    ("http://[::1]:8080", ("::1", 8080)),
    ("ftp://x", None),
    ("", None),
])
def test_edge_the_llm_host_of_an_endpoint(endpoint, expected):
    assert SB.llm_host({"endpoint": endpoint}) == expected
    assert SB.llm_host(None) is None


# -- the relay ---------------------------------------------------------------------------------


@pytest.fixture
def echo_server():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(4)

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                data = conn.recv(100)
                conn.sendall(b"echo:" + data)

    threading.Thread(target=serve, daemon=True).start()
    yield server.getsockname()[1]
    server.close()


def _through_relay(relay: SB.SocketRelay, header: bytes, payload: bytes) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.settimeout(5)
        s.connect(relay.path)
        s.sendall(header + payload)
        chunks = []
        try:
            while True:
                piece = s.recv(100)
                if not piece:
                    break
                chunks.append(piece)
        except OSError:
            pass
        return b"".join(chunks)


def test_happy_the_relay_joins_an_allowed_host(echo_server):
    relay = SB.SocketRelay({("127.0.0.1", echo_server)})
    try:
        assert stat_mode(relay.folder) == 0o700
        assert _through_relay(relay, f"127.0.0.1:{echo_server}\n".encode(), b"hi") == b"echo:hi"
    finally:
        relay.close()
    assert not os.path.exists(relay.folder)


def test_sad_the_relay_refuses_any_other_host(echo_server, caplog):
    relay = SB.SocketRelay({("127.0.0.1", echo_server + 1)})
    try:
        with caplog.at_level(logging.WARNING, logger="core.analysis_sandbox"):
            assert _through_relay(relay, f"127.0.0.1:{echo_server}\n".encode(), b"hi") == b""
        assert "refused" in caplog.text
    finally:
        relay.close()


def stat_mode(path: str) -> int:
    return os.stat(path).st_mode & 0o777


def test_happy_in_the_child_the_llm_host_resolves_to_the_relay(echo_server, monkeypatch):
    relay = SB.SocketRelay({("localhost", echo_server)})
    original = socket.getaddrinfo
    try:
        mapping = SB.install_child_bridge({SB.ENV_SOCKET: relay.path,
                                           SB.ENV_HOSTS: f"localhost:{echo_server}"})
        assert set(mapping) == {("localhost", echo_server)}
        assert socket.getaddrinfo("localhost", echo_server)[0][4][1] != echo_server
        with socket.create_connection(("localhost", echo_server), timeout=5) as s:
            s.sendall(b"ping")
            assert s.recv(100) == b"echo:ping"
    finally:
        socket.getaddrinfo = original
        relay.close()


def test_edge_without_a_relay_nothing_is_installed():
    original = socket.getaddrinfo
    assert SB.install_child_bridge({}) == {}
    assert socket.getaddrinfo is original


# -- the worker --------------------------------------------------------------------------------

_STUB = r"""
import json, os, sys
out = os.fdopen(os.dup(1), "wb", buffering=0)
for raw in sys.stdin.buffer:
    req = json.loads(raw)
    out.write(json.dumps({"id": req["id"], "ok": True, "summary": {"pid": os.getpid()},
                          "error": "", "from_cache": False, "elapsed": 0.0}).encode() + b"\n")
"""


def test_sad_without_bubblewrap_a_warning_and_the_analysis_runs(monkeypatch, caplog):
    monkeypatch.setattr(SB, "bwrap_usable", lambda: False)
    monkeypatch.setattr(AW.AnalysisWorker, "_warned_unsandboxed", False)
    worker = AW.AnalysisWorker(command=[sys.executable, "-c", _STUB], sandbox=True)
    try:
        with caplog.at_level(logging.WARNING, logger="core.analysis_worker"):
            first = worker.analyse("/a/x.txt", "x.txt", timeout=20)
            second = worker.analyse("/b/y.txt", "y.txt", timeout=20)
        assert first.ok and second.ok
        assert first.summary["pid"] == second.summary["pid"]  # one plain child for all
        assert caplog.text.count("WITHOUT a sandbox") == 1
        assert not worker.sandboxed
    finally:
        worker.close()


def test_happy_one_sandbox_per_folder_and_llm_host(monkeypatch):
    """A new folder or another LLM host is a new sandbox: the old one may
    only see its own folder and reach its own host."""
    made = []

    def command(inner, *, folder, cache_dir, relay_dir, env):
        made.append((folder, env.get(SB.ENV_HOSTS), relay_dir))
        return inner  # no bubblewrap here: the stub runs as it is

    monkeypatch.setattr(SB, "bwrap_usable", lambda: True)
    monkeypatch.setattr(SB, "bwrap_command", command)
    worker = AW.AnalysisWorker(command=[sys.executable, "-c", _STUB], sandbox=True)
    try:
        a1 = worker.analyse("/a/x.txt", "x.txt", timeout=20)
        a2 = worker.analyse("/a/y.txt", "y.txt", timeout=20)
        b = worker.analyse("/b/z.txt", "z.txt", timeout=20)
        assert a1.summary["pid"] == a2.summary["pid"] != b.summary["pid"]
        assert [m[0] for m in made] == ["/a", "/b"]
        assert made[0][1] is None and made[0][2] is None  # no LLM: no network at all
        assert worker._relay is None
    finally:
        worker.close()


def test_happy_an_llm_analysis_gets_a_relay_for_its_host_only(monkeypatch):
    made = []

    def command(inner, *, folder, cache_dir, relay_dir, env):
        made.append((env.get(SB.ENV_HOSTS), env.get(SB.ENV_SOCKET), relay_dir))
        return inner

    monkeypatch.setattr(SB, "bwrap_usable", lambda: True)
    monkeypatch.setattr(SB, "bwrap_command", command)
    worker = AW.AnalysisWorker(command=[sys.executable, "-c", _STUB], sandbox=True)
    try:
        worker.analyse("/a/x.txt", "x.txt", timeout=20,
                       llm={"endpoint": "https://api.example.com/v1", "model": "m"})
        ((hosts, sock, relay_dir),) = made
        assert hosts == "api.example.com:443" and sock == SB.RELAY_SOCKET_INSIDE
        assert worker._relay is not None and worker._relay.allowed == {("api.example.com", 443)}
        assert relay_dir == worker._relay.folder
    finally:
        worker.close()
    assert not os.path.exists(relay_dir)  # closed with the worker


def test_edge_a_callers_own_command_is_not_sandboxed_by_default():
    assert AW.AnalysisWorker(command=["x"])._sandbox is False
    assert AW.AnalysisWorker()._sandbox is True
