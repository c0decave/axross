"""Round 3 (the final review) of the headless MCP server.

Each test is the reviewer's repro (/root/mcptest/round3/...) reduced to
what it proves; the section headers name the review's item.
"""

from __future__ import annotations

import io
import json
import os
from pathlib import Path

import pytest

from core import mcp_server as M  # noqa: F401 - used by later sections
from tests import mcp_group_testkit as T

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "root"
    r.mkdir()
    return r


@pytest.fixture
def ram(monkeypatch, tmp_path):
    """Two RAM-workspace profiles (``ram``, ``ram2``) the remote and
    transfer groups can open; the registries are closed afterwards."""
    from core import credentials
    from core import profiles as P
    from core.profiles import ConnectionProfile

    monkeypatch.setattr(credentials, "_keyring_checked", True)
    monkeypatch.setattr(credentials, "_keyring_usable", False)
    path = tmp_path / "profiles.json"
    monkeypatch.setattr(P, "PROFILES_FILE", path)
    path.write_text(json.dumps({
        name: ConnectionProfile(name=name, protocol="ramfs").to_dict() for name in ("ram", "ram2")
    }))
    yield
    from core import mcp_groups

    for registry in list(mcp_groups.RemoteRegistry._live):
        registry.close_all()


def _backend(bid: str):
    from core import mcp_groups

    for registry in list(mcp_groups.RemoteRegistry._live):
        for scope in registry._scopes.values():
            for key, opened in scope.items():
                if bid.endswith(key) or key.endswith(bid.split(":", 1)[-1]):
                    return opened.backend
    raise LookupError(bid)


class _Short(io.BytesIO):
    """A source that says it has its size and sends 10 bytes."""


def _short_sender(backend, monkeypatch):
    real = backend.open_read

    def open_read(path, *a, **k):
        if "shortliar" in path:
            with real(path, *a, **k) as fh:
                return _Short(fh.read(10))
        return real(path, *a, **k)

    monkeypatch.setattr(backend, "open_read", open_read)


# --- 1: a short copy is no copy, a short move keeps its source ----------------------


def _put(tools, bid, path, data: bytes, root):
    local = root / "seed.bin"
    local.write_bytes(data)
    T.call(tools, "transfer_copy", {"src": str(local), "dst_backend": bid, "dst": path})
    local.unlink()


@pytest.mark.parametrize("to_remote", [False, True])
def test_sad_a_move_from_a_short_sending_source_keeps_the_source(root, ram, monkeypatch,
                                                                  to_remote):
    tools = T.build(root, {"remote", "transfer"}, allow_write=True)
    a = T.call(tools, "remote_open", {"profile": "ram"})["backend"]
    b = T.call(tools, "remote_open", {"profile": "ram2"})["backend"]
    _put(tools, a, "/shortliar.txt", b"REAL DATA " * 1000, root)
    src_backend = _backend(a)
    _short_sender(src_backend, monkeypatch)
    args = {"src_backend": a, "src": "/shortliar.txt"}
    args.update({"dst_backend": b, "dst": "/m.txt"} if to_remote else {"dst": str(root / "m.txt")})
    with pytest.raises(T.RpcError) as caught:
        T.call(tools, "transfer_move", args)
    assert "10" in str(caught.value) and "10000" in str(caught.value)
    assert src_backend.exists("/shortliar.txt")  # kept
    assert src_backend.stat("/shortliar.txt").size == 10000
    if to_remote:
        assert not _backend(b).exists("/m.txt")
    else:
        assert not (root / "m.txt").exists()


def test_sad_a_short_copy_is_an_error_not_complete(root, ram, monkeypatch):
    tools = T.build(root, {"remote", "transfer"}, allow_write=True)
    a = T.call(tools, "remote_open", {"profile": "ram"})["backend"]
    _put(tools, a, "/shortliar.txt", b"REAL DATA " * 1000, root)
    _short_sender(_backend(a), monkeypatch)
    out = T.call(tools, "transfer_copy", {"src_backend": a, "src": "/shortliar.txt",
                                          "dst": str(root / "c.txt")})
    assert out["complete"] is False and out["copied"] == 0
    entry = out["entries"][0]
    assert entry["action"] == "error" and entry["reason"] == "size-mismatch"
    assert not (root / "c.txt").exists()


# --- 2: a failing resumable copy leaves the destination as it was ------------------


class _FailsMidway(io.RawIOBase):
    """1 MiB said, 64 KiB given, then the read fails (errmid.bin)."""

    def __init__(self, data: bytes) -> None:
        self._data = data[: 64 << 10]
        self._given = False

    def readable(self) -> bool:
        return True

    def read(self, n=-1):
        if not self._given:
            self._given = True
            return self._data
        raise OSError("Failure")


def _fails_midway(backend, monkeypatch, marker="errmid"):
    real = backend.open_read

    def open_read(path, *a, **k):
        if marker in path:
            with real(path, *a, **k) as fh:
                return _FailsMidway(fh.read())
        return real(path, *a, **k)

    monkeypatch.setattr(backend, "open_read", open_read)
    if hasattr(backend, "open_read_range"):
        monkeypatch.delattr(type(backend), "open_read_range", raising=False)


@pytest.mark.parametrize("to_remote", [False, True])
def test_sad_a_failing_resumable_copy_keeps_the_existing_destination(root, ram, monkeypatch,
                                                                      to_remote):
    tools = T.build(root, {"remote", "transfer"}, allow_write=True)
    a = T.call(tools, "remote_open", {"profile": "ram"})["backend"]
    b = T.call(tools, "remote_open", {"profile": "ram2"})["backend"]
    _put(tools, a, "/errmid.bin", os.urandom(1 << 20), root)
    victim = b"IMPORTANT " * 200
    if to_remote:
        _put(tools, b, "/victim.txt", victim, root)
        dst = {"dst_backend": b, "dst": "/victim.txt"}
    else:
        (root / "victim.txt").write_bytes(victim)
        dst = {"dst": str(root / "victim.txt")}
    _fails_midway(_backend(a), monkeypatch)
    out = T.call(tools, "transfer_copy", {"src_backend": a, "src": "/errmid.bin", **dst,
                                          "overwrite": True, "resumable": True})
    assert out["complete"] is False and out["entries"][0]["action"] == "error"
    if to_remote:
        with _backend(b).open_read("/victim.txt") as fh:
            assert fh.read() == victim
    else:
        assert (root / "victim.txt").read_bytes() == victim


def test_sad_a_refused_secret_upload_keeps_the_remote_file(root, ram):
    from tests.test_mcp_round2 import _late_key

    tools = T.build(root, {"remote", "transfer"}, allow_write=True)
    b = T.call(tools, "remote_open", {"profile": "ram"})["backend"]
    victim = b"IMPORTANT DATA " * 100
    _put(tools, b, "/victim.txt", victim, root)
    _late_key(root)
    out = T.call(tools, "transfer_copy", {"src": str(root / "late.txt"), "dst_backend": b,
                                          "dst": "/victim.txt", "overwrite": True,
                                          "resumable": True})
    assert out["entries"][0]["action"] == "error"
    with _backend(b).open_read("/victim.txt") as fh:
        assert fh.read() == victim
    assert sorted(i.name for i in _backend(b).list_dir("/")) == ["victim.txt"]


def test_sad_a_download_is_never_under_its_final_name_until_whole(root, ram, monkeypatch):
    """remote -> MCP root: the confined local file system renames atomically,
    so the stream copy writes a temporary name (a stall or a kill mid-file
    left a partial file under the final name)."""
    tools = T.build(root, {"remote", "transfer"}, allow_write=True)
    a = T.call(tools, "remote_open", {"profile": "ram"})["backend"]
    _put(tools, a, "/big.bin", os.urandom(3 << 20), root)
    backend = _backend(a)
    real = backend.open_read
    seen = []

    class Watch(io.RawIOBase):
        def __init__(self, fh):
            self._fh = fh

        def readable(self):
            return True

        def read(self, n=-1):
            seen.append((root / "big.bin").exists())
            return self._fh.read(n)

        def close(self):
            self._fh.close()
            super().close()

    monkeypatch.setattr(backend, "open_read", lambda p, *a, **k: Watch(real(p, *a, **k)))
    out = T.call(tools, "transfer_copy", {"src_backend": a, "src": "/big.bin",
                                          "dst": str(root / "big.bin")})
    assert out["complete"] is True
    assert len(seen) > 2 and not any(seen)


# --- 3: a listing is bounded in bytes, not only in entries -------------------------


@pytest.fixture
def sftp_dir(tmp_path):
    pytest.importorskip("paramiko")
    import paramiko

    from tests.sftp_testkit import SftpServer

    served = tmp_path / "served"
    (served / "fat").mkdir(parents=True)
    for i in range(300):
        (served / "fat" / (f"{i:04d}" + "F" * 200)).write_text("")
    (served / "fat" / "short.txt").write_text("")
    server = SftpServer(str(served))
    transport = paramiko.Transport(("127.0.0.1", server.port))
    transport.connect(username="u", password="p")
    try:
        yield paramiko.SFTPClient.from_transport(transport)
    finally:
        transport.close()
        server.close()


def test_sad_a_listing_of_long_names_stops_at_its_byte_budget(sftp_dir, monkeypatch):
    """4000-character names pushed the server to 1.5 GB in 8 s: the cap
    counted entries, each entry kept its name and its ls -l longname."""
    from core import ssh_client

    monkeypatch.setattr(ssh_client, "MAX_LISTING_BYTES", 20_000)
    with pytest.raises(OSError, match="more than 20000 bytes"):
        ssh_client._listdir_attr(sftp_dir, "/fat")


def test_sad_an_overlong_name_is_left_out_and_no_longname_is_kept(sftp_dir, monkeypatch):
    from core import ssh_client

    monkeypatch.setattr(ssh_client, "MAX_NAME_BYTES", 100)
    attrs = ssh_client._listdir_attr(sftp_dir, "/fat")
    assert [a.filename for a in attrs] == ["short.txt"]
    assert not attrs[0].longname


# --- 4: stalled remote calls hold their backend, not the whole server ---------------


def _zombies(n):
    import threading

    stop = threading.Event()
    threads = [threading.Thread(target=stop.wait, daemon=True) for _ in range(n)]
    for t in threads:
        t.start()
    return stop, threads


def _call(name, args):
    return M._handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                              "params": {"name": name, "arguments": args}}, [])


def test_sad_stalled_remote_calls_refuse_only_their_backend(monkeypatch):
    """After ~8 stalled list_dir calls on one profile every later call -
    local tools and remote_close too - got -32001 until a restart."""
    stop, threads = _zombies(3)
    monkeypatch.setattr(M, "MAX_ABANDONED_WORKERS", 3)
    registry = M._AbandonedWorkers()
    monkeypatch.setattr(M, "_ABANDONED", registry)
    for t in threads:
        registry.add(t, {"backend": "profile:nas", "path": "/slowdir"})
    try:
        stuck = _call("list_dir", {"backend": "profile:nas", "path": "/"})
        assert stuck["error"]["code"] == M.ERR_RATE_LIMITED
        assert "profile:nas" in stuck["error"]["message"]
        assert "remote_close" in stuck["error"]["message"]
        moved = _call("transfer_copy", {"src_backend": "profile:nas", "src": "/a", "dst": "/b"})
        assert moved["error"]["code"] == M.ERR_RATE_LIMITED
        # Other work goes on: a local tool, the way out, another profile.
        for name, args in (("list_dir", {"path": "/"}),
                           ("remote_close", {"backend": "profile:nas"}),
                           ("list_dir", {"backend": "profile:other", "path": "/"})):
            resp = _call(name, args)
            assert resp.get("error", {}).get("code") != M.ERR_RATE_LIMITED, (name, resp)
    finally:
        stop.set()
        for t in threads:
            t.join(5)


def test_sad_a_silent_sftp_request_ends_at_its_deadline_though_keepalives_answer(monkeypatch):
    """The 60 s I/O time-out never fired: the server answered keepalives,
    so a request waited up to the 30-minute slow-server cap."""
    pytest.importorskip("paramiko")
    import time as _time

    from core import ssh_client

    class Chan:
        closed = False

        def gettimeout(self):
            return 0.05

        def get_transport(self):
            return None

        def close(self):
            self.closed = True

    monkeypatch.setattr(ssh_client, "transport_answers", lambda *a, **k: True)
    client = object.__new__(ssh_client._SurrogateSftpClient)
    client.sock = Chan()
    client.slow_server_cap = 0.3
    since = None
    started = _time.monotonic()
    with pytest.raises(OSError, match="did not answer"):
        while _time.monotonic() - started < 5:
            since = client._still_waiting(since)
            _time.sleep(0.05)
    assert client.sock.closed and _time.monotonic() - started < 2


def test_sad_a_cancelled_call_stops_waiting_on_a_silent_sftp_request(monkeypatch):
    pytest.importorskip("paramiko")
    import threading

    from core import ssh_client, transfer_hooks

    class Chan:
        closed = False

        def gettimeout(self):
            return 0.05

        def get_transport(self):
            return None

        def close(self):
            self.closed = True

    monkeypatch.setattr(ssh_client, "transport_answers", lambda *a, **k: True)
    client = object.__new__(ssh_client._SurrogateSftpClient)
    client.sock = Chan()
    stop = threading.Event()
    stop.set()
    with transfer_hooks.active(transfer_hooks.TransferHooks(cancel_event=stop)):
        with pytest.raises(InterruptedError):
            client._still_waiting(None)
    assert client.sock.closed


def test_happy_an_mcp_profile_bounds_every_threads_sftp_channel(monkeypatch):
    """The channel time-out was set on the opening thread's SFTP client
    only; every worker thread opens its own."""
    pytest.importorskip("paramiko")
    from core import mcp_groups, ssh_client

    class Client:
        def __init__(self):
            self.timeout = None

        def get_channel(self):
            return self

        def settimeout(self, t):
            self.timeout = t

    session = object.__new__(ssh_client.SSHSession)
    session._thread_sftp = {1: Client(), 2: Client()}
    session._sftp_lock = __import__("threading").Lock()
    mcp_groups._bound_remote_io(session)
    assert session.sftp_request_deadline == mcp_groups.REMOTE_IO_TIMEOUT_SECONDS
    for c in session._thread_sftp.values():
        assert c.slow_server_cap == mcp_groups.REMOTE_IO_TIMEOUT_SECONDS
        assert c.timeout is not None and c.timeout <= 5


def test_happy_remote_close_tears_down_a_connection_with_stalled_calls(root, ram, monkeypatch):
    """remote_close only dropped a reference: the stalled calls kept their
    channels and the connection, and kept the profile refused."""
    tools = T.build(root, {"remote"}, allow_write=False)
    bid = T.call(tools, "remote_open", {"profile": "ram"})["backend"]
    backend = _backend(bid)
    closed = []
    monkeypatch.setattr(backend, "close", lambda: closed.append(True), raising=False)
    stop, threads = _zombies(2)
    registry = M._AbandonedWorkers()
    monkeypatch.setattr(M, "_ABANDONED", registry)
    for t in threads:
        registry.add(t, {"backend": bid})
    try:
        assert T.call(tools, "remote_close", {"backend": bid})["closed"] is True
        assert closed == [True]
    finally:
        stop.set()
        for t in threads:
            t.join(5)


# --- 5: HTTP never evicts a busy session --------------------------------------------


def _registry(monkeypatch, *, per_client=2):
    from core import mcp_http as H

    monkeypatch.setattr(H, "MAX_SESSIONS_PER_CLIENT", per_client)
    return H, H._SessionRegistry(idle_seconds=600)


def _idle(sess, seconds=10_000):
    import time as _time

    sess.last_seen = _time.monotonic() - seconds


@pytest.mark.parametrize("busy", ["call", "sse", "task"])
def test_sad_an_idle_sweep_never_takes_a_busy_session(monkeypatch, busy):
    import threading

    H, registry = _registry(monkeypatch)
    a = registry.create("loopback")
    if busy == "call":
        a.cancels.register(7)  # a tools/call still running
    elif busy == "sse":
        a.sse_stream = (threading.Event(), threading.Event())
    else:
        class Tasks:
            def list_all(self):
                return [type("T", (), {"scope": a.session_id, "status": "running"})()]

            def drop_scope(self, scope):
                pass

        registry.tasks = Tasks()
    _idle(a)
    assert registry.evict_idle() == []
    assert registry.get(a.session_id) is a and not a.closed.is_set()


def test_sad_a_new_session_never_evicts_one_with_a_running_call(monkeypatch):
    """Client B opening sessions evicted A's session during A's 100 s
    tools/call (on loopback every local client is one client)."""
    H, registry = _registry(monkeypatch)
    a = registry.create("loopback")
    a.cancels.register(1)
    _idle(a, 100)
    b = registry.create("loopback")
    _idle(b, 100)
    c = registry.create("loopback")  # b - idle, nothing running - makes room
    assert registry.get(b.session_id) is None and c is not None
    _idle(c, 100)
    c.cancels.register(2)
    with pytest.raises(H.SessionLimitError):
        registry.create("loopback")
    assert not a.closed.is_set() and registry.get(a.session_id) is a


# --- 6: a PuTTY key is found anywhere, not only at a line start ---------------------

_PPK = (b"PuTTY-User-Key-File-" + b"3: ssh-ed25519\nEncryption: none\nComment: t\n"
        b"Public-Lines: 1\nAAAAC3NzaC1lZDI1NTE5\nPrivate-Lines: 1\nAAAAIBSECRETSECRET\n"
        b"Private-MAC: 00\n")


def _ppk_files(root):
    import tarfile

    bio = io.BytesIO()
    with tarfile.open(fileobj=bio, mode="w") as tar:
        info = tarfile.TarInfo("home/u/.ssh/id.ppk")
        info.size = len(_PPK)
        tar.addfile(info, io.BytesIO(_PPK))
    (root / "backup.tar").write_bytes(bio.getvalue())
    (root / "notes.txt").write_bytes(b"note: " + _PPK)
    return ("backup.tar", "notes.txt")


@pytest.mark.parametrize("name", ["backup.tar", "notes.txt"])
def test_sad_a_putty_key_inside_a_tar_or_mid_line_is_refused(root, name):
    _ppk_files(root)
    tools = T.build(root, {"crypto"}, allow_write=True)
    for tool, args in (("read_file", {"path": str(root / name)}),
                       ("encrypt", {"path": str(root / name), "passphrase": "pw"})):
        with pytest.raises(T.RpcError) as caught:
            T.call(tools, tool, args)
        assert "private key" in str(caught.value), tool
    resp = M._handle_request({"jsonrpc": "2.0", "id": 1, "method": "resources/read",
                              "params": {"uri": "axross:///" + str(root / name).lstrip("/")}},
                             tools, resources=M._build_resources(
                                 __import__("core.local_fs", fromlist=["LocalFS"]).LocalFS(),
                                 root=str(root)))
    assert "SECRET" not in json.dumps(resp) and "QUFBQUlCU0VDUkVU" not in json.dumps(resp)


def test_sad_grep_does_not_show_a_putty_key_line(root):
    _ppk_files(root)
    tools = T.build(root, set(), allow_write=False)
    out = json.dumps(T.call(tools, "grep", {"pattern": "AAAAIB", "path": str(root)}))
    assert "SECRET" not in out


def test_sad_a_utf16_private_key_is_found():
    from core import protected_places as PP

    key = ("-----BEGIN OPENSSH " + "PRIVATE KEY-----\nb3BlbnNzaA==\n").encode("utf-16-le")
    assert PP.secret_in_content(b"\xff\xfe" + key)
    assert PP.secret_in_content(("x-----BEGIN RSA " + "PRIVATE KEY-----\n").encode("utf-16-be"))
    reader = PP.SecretScanningReader(io.BytesIO(b"a" * 5000 + key), "k.txt")
    with pytest.raises(PermissionError):
        while reader.read(7):
            pass


# --- 7: no server-side command on a device ------------------------------------------


class _DeviceRemote:
    """A remote whose /zero is a symlink to a device (SFTP's stat follows
    it, lstat does not)."""

    def __init__(self, mode):
        self.ran = []

        class Attr:
            st_mode = mode
            st_size = 0

        class Link:
            st_mode = 0o120777
            st_size = 9

        class Sftp:
            def stat(self, path):
                return Attr()

            def lstat(self, path):
                return Link()

        self.sftp = Sftp()

    def checksum(self, path, algorithm="sha256"):
        self.ran.append(("checksum", path))
        return "sha256:" + "0" * 64

    def stat(self, path):
        return type("I", (), {"size": 0, "is_dir": False})()

    def open_read(self, path):
        self.ran.append(("open_read", path))
        return io.BytesIO(b"")


@pytest.mark.parametrize("mode", [0o020666, 0o060660, 0o010644])  # char, block device, FIFO
def test_sad_checksum_runs_no_command_on_a_device(mode):
    """sha256sum on a symlink to /dev/zero ran on the server for good (it
    never writes, so a closed channel does not end it), even read-only and
    on production profiles."""
    remote = _DeviceRemote(mode)
    with pytest.raises(OSError, match="not a regular file"):
        M._hash_one_path(remote, "/zero", "sha256", M._ToolContext())
    assert remote.ran == []


def test_sad_the_hash_stream_of_a_remote_file_stops_past_its_size(monkeypatch):
    """A remote whose file says 10 bytes and sends without end is not
    hashed for ever (the streaming fallback when no tool answers)."""
    class Endless(io.RawIOBase):
        given = 0

        def readable(self):
            return True

        def readinto(self, buf):
            if self.given > 200 << 20:  # the test's own end
                return 0
            self.given += len(buf)
            buf[:] = b"\0" * len(buf)
            return len(buf)

    class Item:
        size = 10

    class Remote:
        def checksum(self, path, algorithm="sha256"):
            return ""

        def stat(self, path):
            return Item()

        def open_read(self, path):
            return io.BufferedReader(Endless())

    ctx = M._ToolContext()
    with pytest.raises(OSError, match="more than"):
        M._hash_one_path(Remote(), "/x", "sha256", ctx)


# --- 8: a planted sweep record deletes nothing --------------------------------------


def _plant(state, pid, path):
    folder = state / "axross" / "partials"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{pid}-deadbeef0000").write_text(str(path))


def test_sad_a_planted_record_does_not_delete_a_file(tmp_path, monkeypatch):
    """The agent wrote a record naming a file outside the root (its state
    folder lay inside the root at one start); the next start deleted it."""
    from core import partials

    root = tmp_path / "root"
    outside = tmp_path / "outside"
    outside.mkdir()
    canary = outside / "canary.txt"
    canary.write_text("C")
    state = tmp_path / "state"
    monkeypatch.setenv("XDG_STATE_HOME", str(state))
    root.mkdir()
    _plant(state, 999999999, canary)
    # A temp-looking name, but outside the root: left too.
    fake_temp = outside / ".x.txt.axross-part-999999999-ab12"
    fake_temp.write_text("x")
    _plant(state, 999999999, fake_temp)
    # Inside the root, a temp name of another process: left.
    other = root / ".y.txt.axross-part-123-ab12"
    other.write_text("y")
    _plant(state, 999999999, other)
    assert partials.sweep(root=str(root)) == 0
    assert canary.exists() and fake_temp.exists() and other.exists()


def test_happy_the_sweep_removes_a_real_leftover_inside_the_root(tmp_path, monkeypatch):
    from core import partials

    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    left = root / ".x.txt.axross-part-999999999-ab12"
    left.write_text("half")
    _plant(tmp_path / "state", 999999999, left)
    assert partials.sweep(root=str(root)) == 1 and not left.exists()


def test_sad_records_are_never_kept_inside_a_served_root(tmp_path, monkeypatch):
    from core import partials

    root = tmp_path / "root"
    root.mkdir()
    monkeypatch.setenv("XDG_STATE_HOME", str(root / "st"))
    partials.serve_roots([str(root)])
    try:
        left = root / ".x.txt.axross-part-999999999-ab12"
        left.write_text("half")
        _plant(root / "st", 999999999, left)
        assert partials.track(str(root / ".z.axross-part-1-aa")) is None
        assert partials.sweep(root=str(root)) == 0 and left.exists()
    finally:
        partials.serve_roots([])


def test_sad_a_symlinked_folder_on_the_way_is_not_followed(tmp_path, monkeypatch):
    from core import partials

    root = tmp_path / "root"
    root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / ".v.axross-part-999999999-ab12"
    victim.write_text("v")
    (root / "link").symlink_to(outside)
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    _plant(tmp_path / "state", 999999999, root / "link" / victim.name)
    assert partials.sweep(root=str(root)) == 0 and victim.exists()


def test_happy_temp_names_carry_the_process_id():
    from core import server_ops
    from core.local_fs import LocalFS

    name = server_ops._temp_destination_path(LocalFS(), "/tmp/x/f.bin").rsplit("/", 1)[1]
    assert f".copy-{os.getpid()}-" in name


# --- 12: a write or copy never carries setuid or world-writable bits ----------------


def test_sad_copy_and_write_file_drop_the_bits_chmod_refuses(root):
    """chmod refuses setuid/setgid/sticky and group/world write; write_file
    over a 6755 file kept it setuid (agent code, run as its owner) and copy
    carried 6755 and 0666 to the new file."""
    import stat as _stat

    tool = root / "tool"
    tool.write_text("#!/bin/sh\necho orig\n")
    os.chmod(tool, 0o6755)
    ww = root / "ww"
    ww.write_text("w")
    os.chmod(ww, 0o666)
    tools = T.build(root, set(), allow_write=True)
    T.call(tools, "copy", {"src": str(tool), "dst": str(root / "tool2")})
    T.call(tools, "copy", {"src": str(ww), "dst": str(root / "ww2")})
    T.call(tools, "write_file", {"path": str(tool), "content": "#!/bin/sh\necho agent\n"})
    for name in ("tool", "tool2", "ww2"):
        mode = _stat.S_IMODE((root / name).stat().st_mode)
        assert mode & ~0o755 == 0, (name, oct(mode))
    assert _stat.S_IMODE((root / "tool").stat().st_mode) == 0o755


# --- 11: connections are capped, a request is read within a deadline ----------------


def _http_server(monkeypatch, **consts):
    import threading

    from core import mcp_http as H
    from core.local_fs import LocalFS

    for key, value in consts.items():
        monkeypatch.setattr(H, key, value)
    config = H.HTTPServerConfig(backend=LocalFS(), host="127.0.0.1", port=0,
                                auth_token="t" * 32)
    server = H.build_server(config)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
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


def test_sad_a_header_trickle_is_cut_at_the_read_deadline(monkeypatch):
    """One byte every 20 s kept a connection - and its thread - for good."""
    import socket
    import time as _time

    H, server = _http_server(monkeypatch, REQUEST_READ_DEADLINE_SECONDS=1.0)
    try:
        port = server.server_address[1]
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        sock.sendall(b"GET /health HTTP/1.1\r\n")
        started = _time.monotonic()
        ended = False
        while _time.monotonic() - started < 4:
            try:
                sock.sendall(b"X")
                sock.settimeout(0.3)
                if sock.recv(100) == b"":
                    ended = True
                    break
            except (socket.timeout, TimeoutError):
                continue
            except OSError:
                ended = True
                break
        assert ended and _time.monotonic() - started < 3
    finally:
        _stop(H, server)


def test_sad_connections_past_the_cap_are_turned_away_not_given_threads(monkeypatch):
    import socket
    import threading

    H, server = _http_server(monkeypatch, MAX_CONNECTIONS=4,
                             REQUEST_READ_DEADLINE_SECONDS=30.0)
    try:
        port = server.server_address[1]
        before = threading.active_count()
        socks = []
        for _ in range(20):
            s = socket.create_connection(("127.0.0.1", port), timeout=5)
            s.sendall(b"GET /health HTTP/1.1\r\n")
            socks.append(s)
        __import__("time").sleep(0.5)
        assert threading.active_count() - before <= 4 + 1  # and the deadline watchdog
        for s in socks:
            s.close()
        __import__("time").sleep(0.5)
        assert _health(port) == 200  # the slots came back
    finally:
        _stop(H, server)


# --- 10: one local client does not starve the others --------------------------------


def test_sad_one_flooding_session_leaves_the_others_their_share():
    """A flooding tools/call left B (same loopback client) 1 success in 11."""
    from core import mcp_http as H

    registry = H._SessionRegistry(rate_burst=3, rate_refill_per_sec=0.0)
    a = registry.create("127.0.0.1|")
    b = registry.create("127.0.0.1|")
    while a.rate_limiter.try_acquire():
        pass
    assert b.rate_limiter.try_acquire()
    # New sessions bring no unlimited budget: the client's share is bounded.
    total = 0
    for _ in range(20):
        s = registry.create("127.0.0.1|")
        while s.rate_limiter.try_acquire():
            total += 1
    # (Round 4: each session also keeps a small reserve of its own, so a
    # quiet one is never starved; the total stays bounded.)
    assert total <= 3 * H.FAIR_SHARE_SESSIONS + 20 * H.FAIR_RESERVE_BURST


def test_sad_the_http_edge_cap_is_shared_fairly_between_sessions():
    from core import mcp_http as H

    limiter = H._PerIPRateLimiter(burst=5, refill_per_sec=0.0)
    while limiter.try_acquire("127.0.0.1", member="A"):
        pass
    assert limiter.try_acquire("127.0.0.1", member="B")
    taken = 0
    for m in range(50):
        while limiter.try_acquire("127.0.0.1", member=f"m{m}"):
            taken += 1
    # Bounded: the address's shared bucket plus each session's small
    # reserve (round 4: a quiet session keeps its minimum).
    assert taken <= 5 * H.FAIR_SHARE_SESSIONS + 50 * H.FAIR_RESERVE_BURST


def test_sad_on_loopback_the_session_cap_is_the_servers_not_one_clients(monkeypatch):
    """Every local client is one address: 32 sessions holding SSE streams
    gave everyone else 503 for 10 minutes."""
    H, server = _http_server(monkeypatch)
    try:
        registry = server.RequestHandlerClass._sessions
        for _ in range(H.MAX_SESSIONS_PER_CLIENT + 8):
            registry.create("127.0.0.1|")
    finally:
        _stop(H, server)


# --- LOW ----------------------------------------------------------------------------


def test_sad_one_hostile_name_does_not_abort_a_remote_folder_copy(root, ram):
    tools = T.build(root, {"remote", "transfer"}, allow_write=True)
    a = T.call(tools, "remote_open", {"profile": "ram"})["backend"]
    b = T.call(tools, "remote_open", {"profile": "ram2"})["backend"]
    src = _backend(a)
    src.mkdir("/evil")
    for name in ("C:..", "ok.txt"):
        with src.open_write(f"/evil/{name}") as fh:
            fh.write(b"x")
    out = T.call(tools, "transfer_copy", {"src_backend": a, "src": "/evil", "dst_backend": b,
                                          "dst": "/d"})
    actions = {e["src"].rsplit("/", 1)[-1]: (e["action"], e.get("reason")) for e in out["entries"]}
    assert actions["ok.txt"] == ("copied", None)
    assert actions["C:.."] == ("skipped", "unsafe-name")


def test_sad_a_folder_that_cannot_be_listed_makes_a_walk_truncated(root, ram, monkeypatch):
    """A remote listing over its cap fails; index_build, file_type_scan,
    metadata_read and duplicates_scan answered an empty result with
    truncated: false - "nothing there"."""
    tools = T.build(root, {"remote", "index", "filetype", "metadata", "duplicates"},
                    allow_write=False)
    bid = T.call(tools, "remote_open", {"profile": "ram"})["backend"]
    backend = _backend(bid)
    backend.mkdir("/big")
    real = backend.list_dir

    def list_dir(path):
        if path.rstrip("/") == "/big":
            raise OSError(27, "/big: more than 300000 entries; not listed")
        return real(path)

    monkeypatch.setattr(backend, "list_dir", list_dir)
    for tool, args in (("index_build", {"path": "/big"}),
                       ("file_type_scan", {"path": "/big"}),
                       ("metadata_read", {"path": "/big", "recursive": True}),
                       ("duplicates_scan", {"path": "/big"})):
        out = T.call(tools, tool, {"backend": bid, **args})
        # A tree walk says it with complete=false (truncated is for a limit
        # that cut it, as walk has it); metadata_read, which has no
        # complete, with truncated.
        if "complete" in out:
            assert out["complete"] is False and out["unreadable"], (tool, out)
        else:
            assert out["truncated"] is True, (tool, out)


def test_sad_every_command_in_the_host_key_advice_runs_as_given():
    """Pasted literally, "ssh-keygen -lf /tmp/hostkey (it must show ...)"
    was a bash syntax error."""
    import re
    import shutil
    import subprocess

    from core import mcp_groups

    class Profile:
        host, port = "nas.example", 2222

    class Exc:
        host, key_type, fingerprint_sha256 = "[nas.example]:2222", "ssh-ed25519", "abc"

    text = mcp_groups._unknown_host_advice(Profile(), Exc())
    commands = re.findall(r"`([^`]+)`", text)
    assert any(c.startswith("ssh-keyscan -p 2222 -t ed25519 nas.example") for c in commands)
    assert any("known_hosts" in c for c in commands)
    bash = shutil.which("bash")
    if bash:
        for command in commands:
            assert subprocess.run([bash, "-n", "-c", command]).returncode == 0, command


def test_sad_the_middle_of_a_large_key_block_is_not_served_in_windows(root):
    """The fixed 16 KiB margin around a read_file window: the middle of a
    key block larger than that was served (no BEGIN or END line near)."""
    import base64 as _b64

    from core import protected_places as PP

    body = _b64.encodebytes(os.urandom(300_000)).replace(b"\n", b"")
    lines = b"\n".join(body[i:i + 64] for i in range(0, len(body), 64))
    mark = b"PGP " + b"PRIVATE KEY BLOCK-----"
    key = b"-----BEGIN " + mark + b"\n\n" + lines + b"\n-----END " + mark + b"\n"
    path = root / "notes.txt"
    path.write_bytes(b"x" * (PP.SECRET_CONTENT_SCAN + 10) + b"\n" + key)
    tools = T.build(root, set(), allow_write=False)
    middle = PP.SECRET_CONTENT_SCAN + 10 + len(key) // 2
    with pytest.raises(T.RpcError) as caught:
        T.call(tools, "read_file", {"path": str(path), "offset": middle, "max_bytes": 1000})
    assert "private key" in str(caught.value)
    # Plain base64 data that is no key stays readable.
    blob = root / "data.b64"
    blob.write_bytes(b"x" * (PP.SECRET_CONTENT_SCAN + 10) + b"\n" + lines + b"\n")
    out = T.call(tools, "read_file", {"path": str(blob), "offset": middle, "max_bytes": 1000})
    assert out["size"] == 1000 or "content_b64" in out


def test_sad_one_sessions_task_results_do_not_evict_anothers():
    """B's finished results erased A's unread one (one byte budget for all)."""
    import time as _time

    registry = M._TaskRegistry(max_result_bytes=4000, max_per_scope=100)

    def finished(scope, n, size):
        task = M._Task(task_id=f"{scope}{n}", scope=scope, tool_name="t", arguments={},
                       status="running", started_at=_time.time())
        task.finish("done", result={"x": n}, result_bytes=size)
        registry._tasks[task.task_id] = task

    finished("A", 0, 500)
    for n in range(30):
        finished("B", n, 500)
        registry.note_finished()
    assert registry.get("A0", "A") is not None
    assert sum(t.result_bytes for t in registry._tasks.values()) <= 4000


def _post(port, body, sid=None, token="t" * 32):
    import http.client

    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    if sid:
        headers["Mcp-Session-Id"] = sid
        headers["MCP-Protocol-Version"] = "2025-11-25"
    conn.request("POST", "/messages", body=json.dumps(body), headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, resp.getheader("Mcp-Session-Id"), (json.loads(data) if data else None)


def _waiting_tool(monkeypatch, seen):
    import threading
    import time as _time

    real = M._build_tools

    def build(*a, **k):
        tools = real(*a, **k)

        def wait(args, ctx):
            started = _time.monotonic()
            while _time.monotonic() - started < 20:
                if ctx.cancel_event is not None and ctx.cancel_event.is_set():
                    seen.append(_time.monotonic() - started)
                    return {"cancelled": True}
                _time.sleep(0.05)
            return {"cancelled": False}

        tools.append(M._Tool(name="wait", description="w", schema={"type": "object"},
                             handler=wait, timeout_seconds=60))
        return tools

    monkeypatch.setattr(M, "_build_tools", build)
    return threading


def _http_session(port):
    status, sid, _ = _post(port, {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
        "protocolVersion": "2025-11-25", "capabilities": {},
        "clientInfo": {"name": "t", "version": "0"}}})
    assert status == 200
    _post(port, {"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)
    return sid


def test_sad_a_client_that_hangs_up_has_its_call_cancelled(monkeypatch):
    import socket
    import time as _time

    seen: list = []
    _waiting_tool(monkeypatch, seen)
    H, server = _http_server(monkeypatch)
    try:
        port = server.server_address[1]
        sid = _http_session(port)
        body = json.dumps({"jsonrpc": "2.0", "id": 9, "method": "tools/call",
                           "params": {"name": "wait", "arguments": {}}}).encode()
        sock = socket.create_connection(("127.0.0.1", port), timeout=5)
        sock.sendall(
            b"POST /messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Type: application/json\r\n"
            + f"Authorization: Bearer {'t' * 32}\r\nMcp-Session-Id: {sid}\r\n".encode()
            + b"MCP-Protocol-Version: 2025-11-25\r\n"
            + f"Content-Length: {len(body)}\r\n\r\n".encode() + body)
        _time.sleep(0.5)
        sock.close()
        deadline = _time.monotonic() + 5
        while not seen and _time.monotonic() < deadline:
            _time.sleep(0.1)
        assert seen and seen[0] < 4
    finally:
        _stop(H, server)


def test_sad_a_session_runs_a_bounded_number_of_calls_at_once(monkeypatch):
    H, server = _http_server(monkeypatch)
    try:
        port = server.server_address[1]
        sid = _http_session(port)
        sess = server.RequestHandlerClass._sessions.get(sid)
        for n in range(H.MAX_CALLS_PER_SESSION):
            sess.cancels.register(f"busy{n}")
        status, _, resp = _post(port, {"jsonrpc": "2.0", "id": 5, "method": "tools/call",
                                       "params": {"name": "stat", "arguments": {"path": "/"}}},
                                sid)
        assert resp["error"]["code"] == M.ERR_RATE_LIMITED and "at once" in resp["error"]["message"]
    finally:
        _stop(H, server)


def test_sad_stopping_the_http_server_stops_its_tasks(monkeypatch):
    """SIGTERM ended stdio's tasks, not HTTP's: their workers ran on."""
    import time as _time

    seen: list = []
    _waiting_tool(monkeypatch, seen)
    H, server = _http_server(monkeypatch)
    try:
        port = server.server_address[1]
        sid = _http_session(port)
        status, _, resp = _post(port, {"jsonrpc": "2.0", "id": 3, "method": "axross/tasks/start",
                                       "params": {"name": "wait", "arguments": {}}}, sid)
        assert "result" in resp, resp
        _time.sleep(0.3)
        started = _time.monotonic()
        H.shutdown_sessions(server)
        assert seen and _time.monotonic() - started < 5
    finally:
        _stop(H, server)


# --- the release check ---------------------------------------------------------------


def _release_tree(tmp_path):
    import importlib.util

    spec = importlib.util.spec_from_file_location("check_mcp_release",
                                                  ROOT / "scripts" / "check_mcp_release.py")
    check = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check)
    for rel in ("server.json", "Dockerfile.mcp", "scripts/export_standalone.py",
                "axross/_version.py", "core/mcp_server.py"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        (tmp_path / rel).write_text((ROOT / rel).read_text(encoding="utf-8"), encoding="utf-8")
    return check, check.source_version(ROOT)


def test_sad_the_release_check_catches_what_it_passed(tmp_path):
    check, version = _release_tree(tmp_path)
    assert check.problems(version, tmp_path) == []
    docker = tmp_path / "Dockerfile.mcp"
    text = docker.read_text(encoding="utf-8")
    docker.write_text(text.replace("LABEL io.modelcontextprotocol", "# LABEL io.modelcontextprotocol",
                                   1), encoding="utf-8")
    assert any("LABEL" in p for p in check.problems(version, tmp_path))
    docker.write_text(text, encoding="utf-8")
    server = tmp_path / "server.json"
    data = json.loads(server.read_text(encoding="utf-8"))
    for broken in ({k: v for k, v in data.items() if k != "$schema"},
                   {**data, "description": "x" * 101}):
        server.write_text(json.dumps(broken), encoding="utf-8")
        assert check.problems(version, tmp_path), broken.keys()
    server.write_text("{not json", encoding="utf-8")
    found = check.problems(version, tmp_path)
    assert found and "JSON" in found[0]


def test_sad_the_exported_workflows_pin_their_actions_by_commit():
    import re

    text = (ROOT / "scripts" / "export_standalone.py").read_text(encoding="utf-8")
    uses = re.findall(r"uses:\s*(\S+)", text)
    assert uses
    for ref in uses:
        assert re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", ref), ref


def test_sad_an_age_secret_key_is_found():
    from core import protected_places as PP

    key = b"# created: 2026\nAGE-SECRET-KEY-1" + b"QYZ" * 19 + b"Q\n"
    assert PP.secret_in_content(b"notes\n" + key)
    assert not PP.secret_in_content(b"age keys start with AGE-SECRET-KEY-1 and so on")


def test_sad_a_stream_copy_stops_at_the_calls_cancel(tmp_path):
    """SIGTERM cancelled the HTTP server's tasks, but a `copy` task copied
    on (its stream copy never looked at the cancel) and left its temp."""
    import threading

    from core import server_ops, transfer_hooks
    from core.local_fs import LocalFS

    src = tmp_path / "big.bin"
    src.write_bytes(b"x" * (8 << 20))
    stop = threading.Event()
    stop.set()
    with transfer_hooks.active(transfer_hooks.TransferHooks(cancel_event=stop)):
        with pytest.raises(InterruptedError):
            server_ops.stream_copy_between_backends(LocalFS(), str(src), LocalFS(),
                                                    str(tmp_path / "copy.bin"),
                                                    buffer_size=1 << 20)
    assert sorted(p.name for p in tmp_path.iterdir()) == ["big.bin"]
