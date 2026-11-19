"""Round 4 (independent verification) of the headless MCP server.

Each test is the reviewer's repro (/root/mcptest/round4/...) reduced to
what it proves; the section headers name the review's item.
"""

from __future__ import annotations

import io
import json
import os
import threading
import time
from pathlib import Path

import pytest

from core import mcp_server as M
from tests import mcp_group_testkit as T

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "root"
    r.mkdir()
    return r


# --- 1: the listing budget counts everything an answer carries ----------------------


@pytest.fixture
def sftp_attrs(tmp_path, monkeypatch):
    """An SFTP server whose listing entries carry 50 KB of extended
    attributes each (the reviewer's /attrlist sent 900 KiB per entry)."""
    pytest.importorskip("paramiko")
    import paramiko

    from tests import sftp_testkit
    from tests.sftp_testkit import SftpServer

    served = tmp_path / "served"
    (served / "attrs").mkdir(parents=True)
    for i in range(300):
        (served / "attrs" / f"f{i:04d}").write_text("")
    real = sftp_testkit._Sftp.list_folder

    def fat(self, path):
        out = real(self, path)
        if isinstance(out, list):
            for attr in out:
                attr.attr = {"x@example": "Z" * 50_000}
        return out

    monkeypatch.setattr(sftp_testkit._Sftp, "list_folder", fat)
    server = SftpServer(str(served))
    transport = paramiko.Transport(("127.0.0.1", server.port))
    transport.connect(username="u", password="p")
    try:
        yield paramiko.SFTPClient.from_transport(transport)
    finally:
        transport.close()
        server.close()


def test_sad_extended_attributes_count_against_the_listing_budget(sftp_attrs, monkeypatch):
    """Only the names (+64) were counted: 900 KiB of attributes per entry
    took list_dir to 971 MB and walk past 2.5 GB."""
    from core import ssh_client

    monkeypatch.setattr(ssh_client, "MAX_LISTING_BYTES", 2_000_000)
    with pytest.raises(OSError, match="more than 2000000 bytes"):
        ssh_client._listdir_attr(sftp_attrs, "/attrs")


def test_happy_a_listing_keeps_no_extended_attributes(sftp_attrs):
    from core import ssh_client

    attrs = ssh_client._listdir_attr(sftp_attrs, "/attrs")
    assert len(attrs) == 300 and all(not a.attr for a in attrs)


# --- 2: a full connection table makes room instead of locking clients out ---------


def _http_server(monkeypatch, **consts):
    from core import mcp_http as H
    from core.local_fs import LocalFS

    for key, value in consts.items():
        monkeypatch.setattr(H, key, value)
    config = H.HTTPServerConfig(backend=LocalFS(), host="127.0.0.1", port=0,
                                auth_token="t" * 32)
    server = H.build_server(config)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return H, server


def _stop(H, server):
    server.shutdown()
    server.server_close()
    fwd = getattr(server, "_mcp_log_forwarder", None)
    if fwd is not None:
        H._mcp._detach_log_forwarder(fwd)


def _health(port, timeout=5.0):
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    conn.request("GET", "/health")
    status = conn.getresponse().status
    conn.close()
    return status


def test_sad_trickling_connections_do_not_lock_a_client_out(monkeypatch):
    """An attacker that keeps 256 connections half-sent held every slot:
    0 of 119 legitimate requests got through in 60 s."""
    import socket

    H, server = _http_server(monkeypatch, MAX_CONNECTIONS=4,
                             REQUEST_READ_DEADLINE_SECONDS=60.0)
    try:
        port = server.server_address[1]
        socks = []
        for _ in range(8):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(b"GET /health HTTP/1.1\r\n")
            socks.append(s)
        time.sleep(0.3)
        ok = 0
        for _ in range(5):
            try:
                ok += _health(port) == 200
            except OSError:
                pass
        assert ok == 5
        for s in socks:
            s.close()
    finally:
        _stop(H, server)


def test_sad_one_address_off_loopback_holds_only_its_share():
    from core import mcp_http as H

    table = H._ConnectionTable(max_connections=10, per_ip=3)

    class Sock:
        def __init__(self):
            self.shut = False

        def shutdown(self, how):
            self.shut = True

    attacker = [Sock() for _ in range(5)]
    for s in attacker:
        assert table.admit(s, "203.0.113.9")
    assert sum(not s.shut for s in attacker) == 3  # its oldest made room
    other = Sock()
    assert table.admit(other, "198.51.100.7") and not other.shut
    # A connection whose request is in (a running call) is never taken.
    for s in attacker:
        table.reading(s, False)
    late = Sock()
    assert table.admit(late, "203.0.113.9") is False


# --- 3: every session keeps its own minimum share -----------------------------------


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


@pytest.mark.parametrize("flooders", [4, 8, 32])
def test_sad_many_flooding_sessions_leave_a_quiet_one_its_calls(monkeypatch, flooders):
    """With 4 flooding sessions B got 1 of 11 calls, with 8 none."""
    from core import mcp_http as H

    clock = _Clock()
    monkeypatch.setattr(M, "_monotonic", clock)
    registry = H._SessionRegistry(rate_burst=30, rate_refill_per_sec=1.0, per_client_cap=False)
    quiet = registry.create("127.0.0.1|")
    floods = [registry.create("127.0.0.1|") for _ in range(flooders)]
    got = 0
    for second in range(22):
        for s in floods:
            for _ in range(50):
                s.rate_limiter.try_acquire()
        if second % 2 == 0:
            got += quiet.rate_limiter.try_acquire()
        clock.now += 1.0
    assert got == 11


def test_sad_the_http_edge_leaves_a_quiet_session_its_requests(monkeypatch):
    from core import mcp_http as H

    clock = _Clock()
    monkeypatch.setattr(H, "_now", clock)
    limiter = H._PerIPRateLimiter(burst=120, refill_per_sec=60.0)
    got = 0
    for second in range(22):
        for m in range(16):
            for _ in range(500):
                limiter.try_acquire("127.0.0.1", member=f"flood{m}")
        if second % 2 == 0:
            got += limiter.try_acquire("127.0.0.1", member="quiet")
        clock.now += 1.0
    assert got == 11


# --- 4: more key formats and encodings ----------------------------------------------

_PEM_MARK = b"PRIVATE " + b"KEY"


def _pem():
    import base64 as _b64

    body = _b64.encodebytes(os.urandom(600))
    return b"-----BEGIN " + _PEM_MARK + b"-----\n" + body + b"-----END " + _PEM_MARK + b"-----\n"


def _cases():
    import base64 as _b64

    ppk = (b"PuTTY-User-Key-File-" + b"3: ssh-ed25519\nEncryption: none\nPrivate-Lines: 1\n"
           b"AAAAIBSECRET\n")
    ssh2_mark = b"SSH2 ENCRYPTED " + _PEM_MARK
    tectia = (b"---- BEGIN " + ssh2_mark + b" ----\nComment: \"rsa-key\"\n"
              + _b64.encodebytes(os.urandom(600)) + b"---- END " + ssh2_mark + b" ----\n")
    age = b"# created: 2026\n" + b"AGE-SECRET-" + b"KEY-1" + b"Q" * 58 + b"\n"
    pem = _pem()
    return {
        "tectia": tectia,
        "ppk_lower": ppk.replace(b"PuTTY-User-Key-File-3", b"putty-user-key-file-3"),
        "pem_utf32": pem.decode().encode("utf-32"),
        "pem_spaced": pem.replace(b"-----BEGIN " + _PEM_MARK + b"-----",
                                  b"----- BEGIN " + _PEM_MARK + b" -----").replace(
            b"-----END " + _PEM_MARK + b"-----", b"----- END " + _PEM_MARK + b" -----"),
        "age_utf16": age.decode().encode("utf-16"),
        "age_lower": age.lower(),
    }


@pytest.mark.parametrize("name", list(_cases()))
def test_sad_more_key_formats_are_found(name):
    """ssh.com/Tectia keys (PuTTYgen's "Export ssh.com key"), a lower-case
    PuTTY header, a spaced PEM line, UTF-32 PEM and UTF-16 age keys were
    handed out."""
    from core import protected_places as PP

    data = _cases()[name]
    assert PP.secret_in_content(data), name
    reader = PP.SecretScanningReader(io.BytesIO(b"a" * 3000 + data), name)
    with pytest.raises(PermissionError):
        while reader.read(5):
            pass


def test_happy_the_middle_of_a_tectia_key_is_not_served(root):
    from core import protected_places as PP

    data = _cases()["tectia"]
    path = root / "notes_backup.txt"
    path.write_bytes(b"x" * (PP.SECRET_CONTENT_SCAN + 10) + b"\n" + data)
    tools = T.build(root, set(), allow_write=False)
    with pytest.raises(T.RpcError) as caught:
        T.call(tools, "read_file", {"path": str(path),
                                    "offset": PP.SECRET_CONTENT_SCAN + 10 + 200,
                                    "max_bytes": 100})
    assert "private key" in str(caught.value)


# --- 5: slow-by-nature requests get the long wait ----------------------------------


class _Chan:
    closed = False

    def gettimeout(self):
        return 0.05

    def get_transport(self):
        return None

    def close(self):
        self.closed = True


def test_sad_a_slow_close_after_an_upload_is_waited_for(monkeypatch):
    """A CLOSE that takes 70 s (a NAS flushing) failed at the 60 s deadline
    and the finished upload was removed."""
    pytest.importorskip("paramiko")
    import paramiko
    from paramiko.sftp import CMD_CLOSE, CMD_READDIR

    from core import ssh_client

    monkeypatch.setattr(ssh_client, "transport_answers", lambda *a, **k: True)
    numbers = iter(range(7, 100))
    monkeypatch.setattr(paramiko.SFTPClient, "_async_request",
                        lambda self, fileobj, t, *a: next(numbers))
    client = object.__new__(ssh_client._SurrogateSftpClient)
    client.sock = _Chan()
    client.slow_server_cap = 0.2

    def wait(seconds):
        started = time.monotonic()
        since = None
        while time.monotonic() - started < seconds:
            since = client._still_waiting(since)
            time.sleep(0.05)

    # sftp_io sends the CLOSE behind the last WRITEs with _async_request.
    close = client._async_request(None, CMD_CLOSE, b"handle")
    client._expecting = {close: None}
    wait(0.8)  # past the short deadline: waited for
    readdir = client._async_request(None, CMD_READDIR, b"handle")
    client._expecting = {readdir: None}  # the CLOSE was answered
    with pytest.raises(OSError, match="did not answer"):
        wait(0.8)


def test_happy_the_remote_deadline_can_be_set(monkeypatch):
    from core import mcp_groups

    monkeypatch.setenv("AXROSS_MCP_REMOTE_TIMEOUT", "300")
    assert mcp_groups.remote_io_timeout() == 300.0
    monkeypatch.setenv("AXROSS_MCP_REMOTE_TIMEOUT", "nonsense")
    assert mcp_groups.remote_io_timeout() == mcp_groups.REMOTE_IO_TIMEOUT_SECONDS


# --- 6: one client cannot hold every session ----------------------------------------


def test_sad_sessions_that_only_hold_a_stream_make_room_at_the_cap():
    """One local client held all 256 sessions, each with an SSE stream
    (busy, never evicted): nobody else could initialize."""
    from core import mcp_http as H

    registry = H._SessionRegistry(idle_seconds=600, max_sessions=3, per_client_cap=False)
    hog = [registry.create("127.0.0.1|") for _ in range(3)]
    for s in hog:
        s.sse_stream = (threading.Event(), threading.Event())
        s.last_seen = time.monotonic() - 100
    hog[0].cancels.register("running")  # one is at work: never taken
    newcomer = registry.create("127.0.0.1|")
    assert newcomer is not None
    gone = [s for s in hog if s.closed.is_set()]
    assert len(gone) == 1 and gone[0] is not hog[0]
    # The idle sweep still keeps a session that waits on its stream.
    hog[1].last_seen = hog[2].last_seen = time.monotonic() - 10_000
    kept = [s for s in hog[1:] if not s.closed.is_set()]
    registry.evict_idle()
    assert all(not s.closed.is_set() for s in kept)


# --- 7: a half-closed client is no hung-up client -----------------------------------


def _wait_tool(monkeypatch, seconds, seen):
    real = M._build_tools

    def build(*a, **k):
        tools = real(*a, **k)

        def wait(args, ctx):
            started = time.monotonic()
            while time.monotonic() - started < seconds:
                if ctx.cancel_event is not None and ctx.cancel_event.is_set():
                    seen.append("cancelled")
                    return {"cancelled": True}
                time.sleep(0.05)
            seen.append("done")
            return {"cancelled": False}

        tools.append(M._Tool(name="wait", description="w", schema={"type": "object"},
                             handler=wait, timeout_seconds=60))
        return tools

    monkeypatch.setattr(M, "_build_tools", build)


def _post(port, body, sid=None):
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Content-Type": "application/json", "Authorization": "Bearer " + "t" * 32}
    if sid:
        headers.update({"Mcp-Session-Id": sid, "MCP-Protocol-Version": "2025-11-25"})
    conn.request("POST", "/messages", body=json.dumps(body), headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, resp.getheader("Mcp-Session-Id"), (json.loads(data) if data else None)


def _session(port):
    status, sid, _ = _post(port, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "t", "version": "0"}}})
    assert status == 200
    _post(port, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
    return sid


def test_sad_a_half_closed_client_gets_its_answer(monkeypatch):
    """nc -N style: the client shuts its sending side after the request and
    waits for the answer; the call was cancelled as if it had hung up."""
    import socket

    seen: list = []
    _wait_tool(monkeypatch, 1.5, seen)
    H, server = _http_server(monkeypatch)
    try:
        port = server.server_address[1]
        sid = _session(port)
        body = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                           "params": {"name": "wait", "arguments": {}}}).encode()
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        sock.sendall(
            b"POST /messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
            + f"Authorization: Bearer {'t' * 32}\r\nMcp-Session-Id: {sid}\r\n".encode()
            + b"MCP-Protocol-Version: 2025-11-25\r\nConnection: close\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        sock.shutdown(socket.SHUT_WR)
        answer = b""
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            answer += chunk
        sock.close()
        assert seen == ["done"]
        assert b'\\"cancelled\\": false' in answer or b'"cancelled": false' in answer
    finally:
        _stop(H, server)


# --- 8: checksum runs no command on a pseudo file -----------------------------------


class _PseudoRemote:
    def __init__(self, real_path, size):
        self.ran = []

        class Attr:
            st_mode = 0o100400
            st_size = size

        class Sftp:
            def stat(self, path):
                return Attr()

            lstat = stat

            def normalize(self, path):
                return real_path

        self.sftp = Sftp()

    def checksum(self, path, algorithm="sha256"):
        self.ran.append("checksum")
        return "sha256:" + "0" * 64

    def stat(self, path):
        return type("I", (), {"size": 0, "is_dir": False})()

    def open_read(self, path):
        self.ran.append("open_read")
        return io.BytesIO(b"")


@pytest.mark.parametrize("real", ["/proc/kmsg", "/sys/kernel/x", "/dev/shm/x"])
def test_sad_checksum_refuses_kernel_pseudo_files(real):
    """/proc/kmsg is a regular file of size 0 under a root login: sha256sum
    on it held the channel for 300 s (and runs on on the server)."""
    remote = _PseudoRemote(real, 0)
    with pytest.raises(OSError, match="pseudo"):
        M._hash_one_path(remote, "/link-to-it", "sha256", M._ToolContext())
    assert remote.ran == []


def test_sad_an_empty_remote_file_is_hashed_here_not_by_a_command():
    remote = _PseudoRemote("/srv/empty.txt", 0)
    out = M._hash_one_path(remote, "/srv/empty.txt", "sha256", M._ToolContext())
    assert remote.ran == ["open_read"] and out["source"] != "native"


# --- server.json names the project's own repository --------------------------------


def test_sad_server_json_must_name_the_headless_repository(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("check_mcp_release",
                                                  ROOT / "scripts" / "check_mcp_release.py")
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    for rel in ("server.json", "Dockerfile.mcp", "scripts/export_standalone.py",
                "axross/_version.py", "core/mcp_server.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text((ROOT / rel).read_text(encoding="utf-8"), encoding="utf-8")
    version = check.source_version(ROOT)
    data = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    assert data["repository"]["url"] == "https://github.com/c0decave/axross-headless-mcp"
    assert data["websiteUrl"] == "https://github.com/c0decave/axross-headless-mcp"
    assert check.problems(version, tmp_path) == []
    for broken in ({**data, "websiteUrl": "https://github.com/c0decave/axross"},
                   {**data, "repository": {"url": "https://github.com/c0decave/axross",
                                           "source": "github"}}):
        (tmp_path / "server.json").write_text(json.dumps(broken), encoding="utf-8")
        assert any("github.com/c0decave/axross-headless-mcp" in p
                   for p in check.problems(version, tmp_path))


def test_sad_a_client_that_keeps_every_session_busy_with_pings_still_makes_room():
    """The hog pinged its 256 sessions every 10 s (never idle 30 s): every
    other client's initialize got 503."""
    from core import mcp_http as H

    registry = H._SessionRegistry(idle_seconds=600, max_sessions=4, per_client_cap=False)
    hog = [registry.create("127.0.0.1|") for _ in range(4)]
    for n, s in enumerate(hog):
        s.last_seen = time.monotonic() - 5 + n  # pinged seconds ago
    newcomer = registry.create("127.0.0.1|")
    assert newcomer is not None and hog[0].closed.is_set()  # least recently used
    for s in hog[1:] + [newcomer]:
        s.cancels.register("running")  # every one at work: none may go
    with pytest.raises(H.SessionLimitError):
        registry.create("127.0.0.1|")
