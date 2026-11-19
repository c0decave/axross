"""Round 5 (independent verification) of the headless MCP server.

Each test is the reviewer's repro (/root/mcptest/round5/...) reduced to
what it proves; the section headers name the review's item.
"""

from __future__ import annotations

import json
import struct
import threading
import time
from pathlib import Path

import pytest

from core import mcp_server as M
from tests.test_mcp_round3 import ram  # noqa: F401 - the RAM-profile fixture

ROOT = Path(__file__).resolve().parents[1]


def _within(seconds, fn):
    """fn() run on a thread; its result or exception, or TimeoutError when
    it did not end within *seconds* (the old code looped for good)."""
    box = {}

    def run():
        try:
            box["value"] = fn()
        except BaseException as exc:  # noqa: BLE001 - handed to the test
            box["error"] = exc

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    worker.join(seconds)
    if worker.is_alive():
        raise TimeoutError(f"still running after {seconds} s")
    if "error" in box:
        raise box["error"]
    return box.get("value")


# --- N1: counts off the wire are bounded by the bytes that carry them ---------------


class _RawSftp:
    """Just enough of paramiko's SFTPClient for core.ssh_client._listdir_attr:
    every READDIR is answered with *answer* (raw bytes after the request id)."""

    def __init__(self, answer: bytes, closed=False) -> None:
        import paramiko

        self._answer = answer
        self._expecting = {}
        self._pending = []
        self._n = 0
        self.Message = paramiko.Message
        self.sock = type("S", (), {"closed": closed})()

    def _adjust_cwd(self, path):
        return path

    def _request(self, t, *args):
        from paramiko.sftp import CMD_HANDLE, CMD_STATUS

        msg = self.Message()
        msg.add_string(b"handle")
        msg.rewind()
        return (CMD_HANDLE if t == 11 else CMD_STATUS), msg  # 11: OPENDIR

    def _async_request(self, receiver, t, *args):
        self._n += 1
        self._expecting[self._n] = receiver
        self._pending.append(self._n)
        return self._n

    def _read_response(self, waitfor=None):
        from paramiko.sftp import CMD_NAME

        num = self._pending.pop(0)
        receiver = self._expecting.pop(num)
        receiver._async_response(CMD_NAME, self.Message(self._answer), num)

    def _convert_status(self, msg):
        raise EOFError()


def test_sad_a_13_byte_answer_with_a_huge_count_is_refused_at_once():
    """NAME with count 0xFFFFFFFF and no entries: paramiko pads with zeros,
    so the loop made billions of empty entries (2.2 GB and rising)."""
    pytest.importorskip("paramiko")
    from core import ssh_client

    with pytest.raises(Exception) as caught:
        _within(5, lambda: ssh_client._listdir_attr(_RawSftp(struct.pack(">I", 0xFFFFFFFF)), "/x"))
    assert not isinstance(caught.value, TimeoutError)
    assert "malformed" in str(caught.value) or "more than" in str(caught.value)


def test_sad_a_huge_extended_attribute_count_is_refused_at_once():
    """An attribute block with extended count 0xFFFFFFFF spun a worker in
    paramiko's SFTPAttributes._unpack (listing /xextcnt, stat /xextst)."""
    pytest.importorskip("paramiko")
    import paramiko

    from core import ssh_client  # noqa: F401 - installs the bounded parser

    raw = struct.pack(">II", paramiko.SFTPAttributes.FLAG_EXTENDED, 0xFFFFFFFF)
    with pytest.raises(Exception) as caught:
        _within(5, lambda: paramiko.SFTPAttributes._from_msg(paramiko.Message(raw)))
    assert not isinstance(caught.value, TimeoutError)
    # And inside a listing entry.
    entry = (struct.pack(">I", 1) + struct.pack(">I", 1) + b"a" + struct.pack(">I", 0) + raw)
    with pytest.raises(Exception) as caught:
        _within(5, lambda: ssh_client._listdir_attr(_RawSftp(entry), "/x"))
    assert not isinstance(caught.value, TimeoutError)


def test_happy_valid_attributes_parse_as_before():
    pytest.importorskip("paramiko")
    import paramiko

    from core import ssh_client  # noqa: F401

    attr = paramiko.SFTPAttributes()
    attr.st_size, attr.st_uid, attr.st_gid, attr.st_mode = 5, 1, 2, 0o100644
    attr.st_atime, attr.st_mtime = 10, 20
    attr.attr = {"k": "v"}
    msg = paramiko.Message()
    attr._pack(msg)
    msg.rewind()
    got = paramiko.SFTPAttributes._from_msg(msg, "f", "")
    assert (got.st_size, got.st_uid, got.st_gid, got.st_mode, got.st_atime, got.st_mtime) == \
        (5, 1, 2, 0o100644, 10, 20)


def test_sad_a_listing_stops_when_its_connection_is_closed():
    """remote_close did not stop the abandoned worker: it never read the
    channel again, it only built entries."""
    pytest.importorskip("paramiko")
    from core import ssh_client

    entry = (struct.pack(">I", 1) + struct.pack(">I", 1) + b"a" + struct.pack(">I", 0)
             + struct.pack(">I", 0))
    many = struct.pack(">I", 2000) + entry[4:] * 2000
    with pytest.raises(Exception) as caught:
        _within(5, lambda: ssh_client._listdir_attr(_RawSftp(many, closed=True), "/x"))
    assert isinstance(caught.value, (EOFError, OSError)) and \
        not isinstance(caught.value, TimeoutError)


# --- N2: the edge reserve is only for sessions the server knows ----------------------


def _http_server(monkeypatch, config_args=None, **consts):
    from core import mcp_http as H
    from core.local_fs import LocalFS

    for key, value in consts.items():
        monkeypatch.setattr(H, key, value)
    config = H.HTTPServerConfig(backend=LocalFS(), host="127.0.0.1", port=0,
                                auth_token="t" * 32, **(config_args or {}))
    server = H.build_server(config)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return H, server


def _stop(H, server):
    server.shutdown()
    server.server_close()
    fwd = getattr(server, "_mcp_log_forwarder", None)
    if fwd is not None:
        H._mcp._detach_log_forwarder(fwd)


def _raw_post(port, sid, body=b'{"jsonrpc":"2.0","id":1,"method":"ping"}'):
    import socket

    s = socket.create_connection(("127.0.0.1", port), timeout=5)
    s.sendall(b"POST /messages HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer "
              + b"t" * 32 + b"\r\nContent-Type: application/json\r\nMcp-Session-Id: "
              + sid.encode() + b"\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
    data = s.recv(64)
    s.close()
    return int(data.split()[1])


def test_sad_random_session_ids_get_no_fresh_reserve_at_the_edge(monkeypatch):
    """A fresh random Mcp-Session-Id per request passed the edge cap at
    2693 req/s (72/s with one id) and grew the bucket map to 364k entries."""
    import uuid

    H, server = _http_server(monkeypatch, {"http_ip_burst": 20,
                                           "http_ip_refill_per_sec": 0.001})
    try:
        port = server.server_address[1]
        limiter = server.RequestHandlerClass._http_ip_limiter
        statuses = [_raw_post(port, uuid.uuid4().hex) for _ in range(300)]
        passed = sum(1 for s in statuses if s != 429)
        assert passed <= 20 * H.FAIR_SHARE_SESSIONS + H.FAIR_RESERVE_BURST
        assert len(limiter._buckets) <= 4
    finally:
        _stop(H, server)


def test_sad_the_edge_bucket_map_is_bounded():
    from core import mcp_http as H

    limiter = H._PerIPRateLimiter(burst=5, refill_per_sec=1.0)
    for n in range(H.MAX_EDGE_BUCKETS + 500):
        limiter.try_acquire(f"10.0.{n // 250}.{n % 250}")
    assert len(limiter._buckets) <= H.MAX_EDGE_BUCKETS


# --- N4: a slow remote write does not hold the local disk's writes ------------------


def test_sad_a_hung_remote_close_does_not_block_local_writes(tmp_path, monkeypatch, ram):
    """A transfer_copy whose CLOSE hangs (up to 30 min while keepalives are
    answered) held the process-wide write lock: local write_file and mkdir
    timed out for minutes."""
    from tests import mcp_group_testkit as T
    from tests.test_mcp_round3 import _backend

    root = tmp_path / "root"
    root.mkdir()
    (root / "up.bin").write_bytes(b"x" * 1000)
    tools = T.build(root, {"remote", "transfer"}, allow_write=True)
    bid = T.call(tools, "remote_open", {"profile": "ram"})["backend"]
    remote = _backend(bid)
    real_open_write = remote.open_write
    release = threading.Event()

    class SlowClose:
        def __init__(self, fh):
            self._fh = fh

        def write(self, data):
            return self._fh.write(data)

        def close(self):
            release.wait(10)  # a NAS flushing
            self._fh.close()

        def __getattr__(self, name):
            return getattr(self._fh, name)

    monkeypatch.setattr(remote, "open_write",
                        lambda p, *a, **k: SlowClose(real_open_write(p, *a, **k)))
    copier = threading.Thread(target=lambda: T.call(tools, "transfer_copy", {
        "src": str(root / "up.bin"), "dst_backend": bid, "dst": "/up.bin"}), daemon=True)
    copier.start()
    time.sleep(0.5)
    try:
        started = time.monotonic()
        _within(5, lambda: T.call(tools, "write_file", {"path": str(root / "local.txt"),
                                                         "content": "x"}))
        assert time.monotonic() - started < 3
    finally:
        release.set()
        copier.join(10)


# --- N3: a slow legitimate request is not taken for a trickling attacker ------------


def _trickle(port, stop, opened):
    import socket

    while not stop.is_set():
        s = None
        try:
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            opened.append(1)
            s.sendall(b"POST /messages HTTP/1.1\r\n")
            while not stop.is_set():
                s.settimeout(0.5)
                try:
                    if s.recv(1) == b"":
                        break
                except OSError:
                    try:
                        s.sendall(b"X")
                    except OSError:
                        break
        except OSError:
            time.sleep(0.02)
        finally:
            if s is not None:
                s.close()


def test_sad_a_slow_upload_survives_a_trickling_flood(monkeypatch):
    """With 300 trickling attackers, 0 of 31 legitimate 2 MiB uploads at
    ~1 MiB/s got through: the body still being read made the connection
    "still sending", the oldest of which a newcomer closed."""
    import socket

    # More trickling attackers than request threads (8).
    H, server = _http_server(monkeypatch, MAX_CONNECTIONS=8)
    stop = threading.Event()
    opened: list = []
    attackers = [threading.Thread(target=_trickle, args=(server.server_address[1], stop, opened),
                                  daemon=True) for _ in range(80)]
    try:
        port = server.server_address[1]
        for a in attackers:
            a.start()
        time.sleep(1.0)
        ok = 0
        pad = "x" * (1024 * 1024)
        body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
            "protocolVersion": "2025-11-25", "capabilities": {},
            "clientInfo": {"name": "t", "version": "0"}, "pad": pad}}).encode()
        for _ in range(3):
            s = socket.create_connection(("127.0.0.1", port), timeout=10)
            try:
                s.sendall(b"POST /messages HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer "
                          + b"t" * 32 + b"\r\nContent-Type: application/json\r\n"
                          + b"Content-Length: %d\r\n\r\n" % len(body))
                for i in range(0, len(body), 64 * 1024):  # ~640 KiB/s
                    s.sendall(body[i:i + 64 * 1024])
                    time.sleep(0.1)
                answer = s.recv(64)
                ok += answer.split(b"\r\n", 1)[0].endswith(b" 200 OK")
            except OSError:
                pass
            finally:
                s.close()
        assert ok == 3 and len(opened) >= 80
    finally:
        stop.set()
        for a in attackers:
            a.join(5)
        _stop(H, server)


# --- N6: half-closed, then closed: noticed ------------------------------------------


def test_sad_a_client_that_half_closes_and_then_closes_is_noticed(monkeypatch):
    """After the probe of a half-closed client nothing watched it: closing
    fully later left its checksum hashing until the tool's 300 s time-out."""
    import socket

    from tests.test_mcp_round4 import _session, _wait_tool

    seen: list = []
    _wait_tool(monkeypatch, 20, seen)
    H, server = _http_server(monkeypatch)
    monkeypatch.setattr(H._HangupWatch, "REPROBE_SECONDS", 0.5)
    try:
        port = server.server_address[1]
        sid = _session(port)
        body = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                           "params": {"name": "wait", "arguments": {}}}).encode()
        sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        sock.sendall(
            b"POST /messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
            + f"Authorization: Bearer {'t' * 32}\r\nMcp-Session-Id: {sid}\r\n".encode()
            + b"MCP-Protocol-Version: 2025-11-25\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        sock.shutdown(socket.SHUT_WR)
        time.sleep(1.5)
        assert seen == []  # half-closed: runs on
        sock.close()
        deadline = time.monotonic() + 5
        while not seen and time.monotonic() < deadline:
            time.sleep(0.1)
        assert seen == ["cancelled"]
    finally:
        _stop(H, server)


# --- N5: a client's reserves are capped together ------------------------------------


class _Clock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self):
        return self.now


def test_sad_more_sessions_do_not_add_up_to_more_rate(monkeypatch):
    """Each session added its 0.5/s reserve: 64 flooding sessions got about
    41 calls/s through instead of the client's share."""
    from core import mcp_http as H

    clock = _Clock()
    monkeypatch.setattr(M, "_monotonic", clock)
    registry = H._SessionRegistry(rate_burst=30, rate_refill_per_sec=1.0, per_client_cap=False)
    floods = [registry.create("127.0.0.1|") for _ in range(64)]
    quiet = registry.create("127.0.0.1|")
    for _ in range(60):  # burn the initial bursts
        for s in floods:
            for _ in range(5):
                s.rate_limiter.try_acquire()
        clock.now += 1.0
    passed = 0
    got = 0
    for second in range(20):
        for s in floods:
            for _ in range(5):
                passed += s.rate_limiter.try_acquire()
        if second % 2 == 0:
            got += quiet.rate_limiter.try_acquire()
        clock.now += 1.0
    shared = 1.0 * H.FAIR_SHARE_SESSIONS
    assert passed / 20 <= shared * 3  # the shared rate and a pool of twice it
    assert got == 10  # the quiet session still gets every call


def test_sad_the_edge_reserves_are_capped_together(monkeypatch):
    from core import mcp_http as H

    clock = _Clock()
    monkeypatch.setattr(H, "_now", clock)
    limiter = H._PerIPRateLimiter(burst=120, refill_per_sec=60.0)
    for _ in range(10):
        for m in range(64):
            for _ in range(50):
                limiter.try_acquire("127.0.0.1", member=f"s{m}")
        clock.now += 1.0
    passed = 0
    for _ in range(20):
        for m in range(64):
            for _ in range(50):
                passed += limiter.try_acquire("127.0.0.1", member=f"s{m}")
        clock.now += 1.0
    assert passed / 20 <= 60.0 * H.FAIR_SHARE_SESSIONS * 3


# --- N7: serverInfo names the same website as server.json ---------------------------


def test_sad_server_info_and_server_json_name_one_website(tmp_path):
    import importlib.util

    data = json.loads((ROOT / "server.json").read_text(encoding="utf-8"))
    assert M.SERVER_WEBSITE == data["websiteUrl"]
    spec = importlib.util.spec_from_file_location("check_mcp_release",
                                                  ROOT / "scripts" / "check_mcp_release.py")
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    for rel in ("server.json", "Dockerfile.mcp", "scripts/export_standalone.py",
                "axross/_version.py", "core/mcp_server.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text((ROOT / rel).read_text(encoding="utf-8"), encoding="utf-8")
    version = check.source_version(ROOT)
    assert check.problems(version, tmp_path) == []
    server = tmp_path / "core" / "mcp_server.py"
    server.write_text(server.read_text(encoding="utf-8").replace(
        f'SERVER_WEBSITE = "{M.SERVER_WEBSITE}"', 'SERVER_WEBSITE = "https://example.org"'),
        encoding="utf-8")
    assert any("SERVER_WEBSITE" in p for p in check.problems(version, tmp_path))


def test_sad_after_a_hostile_answer_the_channel_is_closed_not_drained():
    """/xkeys: 15 MB answers, 16 READDIRs on the wire - after the first was
    refused the worker still read every other one (240 MB) before giving up."""
    pytest.importorskip("paramiko")
    from core import ssh_client

    raw = _RawSftp(struct.pack(">I", 0xFFFFFFFF))
    closed = []
    raw.sock = type("S", (), {"closed": False, "close": lambda self: closed.append(True)})()
    reads = []
    real_read = raw._read_response

    def counting(waitfor=None):
        reads.append(1)
        return real_read(waitfor)

    raw._read_response = counting
    with pytest.raises(Exception):
        _within(5, lambda: ssh_client._listdir_attr(raw, "/x"))
    assert closed == [True] and len(reads) == 1
