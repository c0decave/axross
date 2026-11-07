"""axross's own NFSv3 client: the sender information is the profile's.

Against tests/fake_nfsd.py (portmapper, MOUNT v3, NFSv3 on 127.0.0.1, its
own XDR code): every call carries the AUTH_SYS machine name, UID, GID and
extra GIDs the profile chose; a server that permits only one UID answers
accordingly; the file operations work over short reads and writes and paged
directories; nothing outside the export is reachable; a hostile server's
oversized answers are refused.
"""

from __future__ import annotations

import os
import socket
import struct
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from core import nfs3_rpc as R  # noqa: E402
from core.nfs_user_client import NfsUserSession  # noqa: E402
from fake_nfsd import FakeNfsd  # noqa: E402

SENDER = dict(machine_name="build-07.lab.example", uid=4242, gid=777, gids=(10, 20, 30))


@pytest.fixture
def server(tmp_path):
    root = tmp_path / "export"
    root.mkdir()
    (root / "docs").mkdir()
    (root / "docs" / "a.txt").write_bytes(b"alpha\n")
    (root / "big.bin").write_bytes(os.urandom(50_000))
    for i in range(7):
        (root / f"f{i}").write_text(str(i))
    srv = FakeNfsd(str(root))
    yield srv, root
    srv.close()


def _open(srv, **kw):
    return NfsUserSession("127.0.0.1", "/export", port=srv.port, mount_port=srv.port,
                          proxy_type="none", **{**SENDER, **kw})


def test_happy_every_call_carries_the_profile_s_sender_information(server):
    srv, _root = server
    with _open(srv) as s:
        s.list_dir("/")
        s.stat("/docs/a.txt")
    assert srv.creds, "no AUTH_SYS call seen"
    assert set(srv.creds) == {("build-07.lab.example", 4242, 777, (10, 20, 30))}


def test_happy_the_server_decides_by_what_the_client_says(server):
    srv, _root = server
    srv.allowed_uids = {4242}
    with _open(srv) as s:
        assert [i.name for i in s.list_dir("/docs")] == ["a.txt"]
    with pytest.raises(PermissionError):
        _open(srv, uid=1000)


def test_happy_files_folders_links(server):
    srv, root = server
    with _open(srv) as s:
        names = [i.name for i in s.list_dir("/")]
        assert names[0] == "docs" and set(names[1:]) == {"big.bin", *(f"f{i}" for i in range(7))}
        with s.open_read("/big.bin") as f:
            assert f.read() == (root / "big.bin").read_bytes()
        data = os.urandom(20_000)
        with s.open_write("/new/../out.bin") as f:
            f.write(data)
        assert (root / "out.bin").read_bytes() == data
        with s.open_write("/out.bin", append=True) as f:
            f.write(b"tail")
        assert (root / "out.bin").read_bytes() == data + b"tail"
        s.mkdir("/x/y/z")
        assert (root / "x" / "y" / "z").is_dir()
        s.rename("/out.bin", "/x/moved.bin")
        assert s.exists("/x/moved.bin") and not s.exists("/out.bin")
        s.chmod("/x/moved.bin", 0o600)
        assert (root / "x" / "moved.bin").stat().st_mode & 0o777 == 0o600
        s.symlink("../docs/a.txt", "/x/link")
        assert s.readlink("/x/link") == "../docs/a.txt"
        assert s.stat("/x/link").is_link
        with s.open_read("/x/link") as f:      # followed inside the export
            assert f.read() == b"alpha\n"
        s.remove("/x", recursive=True)
        assert not (root / "x").exists()
        assert s.is_dir("/docs") and not s.is_dir("/docs/a.txt") and not s.is_dir("/nothing")
        assert s.checksum("/docs/a.txt").startswith("sha256:")
        total, used, free = s.disk_usage("/")
        assert total > 0 and free >= 0


def test_sad_nothing_outside_the_export_is_reachable(server, tmp_path):
    srv, root = server
    (tmp_path / "secret").write_text("outside")
    os.symlink("/../../secret", root / "abs-escape")
    with _open(srv) as s:
        with pytest.raises(PermissionError):
            s.list_dir("/..")
        with pytest.raises(PermissionError):
            s.open_read("/docs/../../secret")
        # an absolute link target counts from the export's root
        with pytest.raises(PermissionError):
            s.open_read("/abs-escape")
    assert srv.lookups and ".." not in srv.lookups and "." not in srv.lookups


def test_sad_missing_paths_are_file_not_found(server):
    srv, _root = server
    with _open(srv) as s:
        with pytest.raises(FileNotFoundError):
            s.stat("/nope")
        assert not s.exists("/nope")
        with pytest.raises(FileNotFoundError):
            s.open_read("/docs/nope")


def test_sad_an_unknown_export_is_refused(server):
    srv, _root = server
    with pytest.raises(OSError, match="no such export"):
        NfsUserSession("127.0.0.1", "/other", port=srv.port, mount_port=srv.port, proxy_type="none")


def test_happy_portmapper_and_exports(server):
    srv, _root = server
    assert R.getport(R.connector("127.0.0.1", srv.port), R.MOUNT_PROG, R.MOUNT_VERS) == srv.port
    assert NfsUserSession.exports_list("127.0.0.1", mount_port=srv.port) == [
        {"path": "/export", "clients": ["127.0.0.1"]}]


@pytest.mark.parametrize("kw,match", [
    (dict(machine_name="x" * 256), "longer than 255"),
    (dict(machine_name="a\nb"), "control"),
    (dict(uid=-1), "UID"),
    (dict(gid=2**32), "GID"),
    (dict(gids=tuple(range(17))), "at most 16"),
])
def test_sad_sender_information_that_auth_sys_cannot_carry(kw, match):
    with pytest.raises(ValueError, match=match):
        R.AuthSys(**kw)


def test_happy_gid_lists():
    assert R.parse_gids("") == ()
    assert R.parse_gids("10, 20 30") == (10, 20, 30)
    with pytest.raises(ValueError):
        R.parse_gids("ten")


# --- a hostile server ------------------------------------------------------------------

def _hostile(reply_for):
    """A server answering every call with reply_for(xid) raw bytes."""
    sock = socket.create_server(("127.0.0.1", 0))

    def serve():
        conn, _ = sock.accept()
        with conn:
            head = conn.recv(4)
            n = struct.unpack(">I", head)[0] & 0x7FFFFFFF
            body = b""
            while len(body) < n:
                body += conn.recv(n - len(body))
            xid = body[:4]
            try:
                conn.sendall(reply_for(xid))
            except OSError:
                pass
    threading.Thread(target=serve, daemon=True).start()
    return sock


def test_sad_a_huge_record_is_refused_before_it_is_read():
    sock = _hostile(lambda xid: struct.pack(">I", 0x80000000 | 0x7FFFFFFF))
    rpc = R.RpcConnection(R.connector("127.0.0.1", sock.getsockname()[1]), R.NFS_PROG, 3, None, 5)
    with pytest.raises(R.RpcError, match="larger than"):
        rpc.call(0, retry=False)
    sock.close()


def test_sad_an_oversized_opaque_is_refused():
    accepted = lambda xid: xid + b"\0\0\0\1" + b"\0" * 4 + b"\0" * 8 + b"\0" * 4  # noqa: E731
    body = lambda xid: accepted(xid) + struct.pack(">I", 0) + struct.pack(">I", 10**9)  # noqa: E731
    sock = _hostile(lambda xid: struct.pack(">I", 0x80000000 | len(body(xid))) + body(xid))
    rpc = R.RpcConnection(R.connector("127.0.0.1", sock.getsockname()[1]), R.MOUNT_PROG, 3, None, 5)
    with pytest.raises(R.RpcError):
        R.mount(rpc, "/x")
    sock.close()


# --- profile, ConnectionManager, scripting, window ---------------------------------------

from core.profiles import ConnectionProfile  # noqa: E402


def _profile(srv, **kw):
    return ConnectionProfile(name="n", protocol="nfs", host="127.0.0.1", port=srv.port,
                             nfs_export="/export", nfs_version=3, **kw)


def test_happy_a_profile_with_sender_fields_uses_the_own_client(server, monkeypatch):
    srv, _root = server
    from core import connection_manager as CM
    from core import nfs3_rpc

    real = nfs3_rpc.getport
    monkeypatch.setattr(nfs3_rpc, "getport", lambda connect, prog, vers, t=10.0: srv.port)
    p = _profile(srv, nfs_machine_name="ws-1", nfs_uid=0, nfs_gids="4, 24")
    back = ConnectionProfile.from_dict(p.to_dict())
    assert (back.nfs_machine_name, back.nfs_uid, back.nfs_gid, back.nfs_gids) == ("ws-1", 0, -1, "4, 24")
    assert back.nfs_sender_chosen()
    s = CM.ConnectionManager().connect(back)
    try:
        assert type(s).__name__ == "NfsUserSession"
        s.list_dir("/")
    finally:
        s.close()
    machine, uid, gid, gids = srv.creds[-1]
    assert (machine, uid, gids) == ("ws-1", 0, (4, 24))
    assert gid == os.getegid()            # left empty: this process's
    monkeypatch.setattr(nfs3_rpc, "getport", real)


def test_happy_without_sender_fields_the_kernel_mount_stays():
    p = ConnectionProfile(name="n", protocol="nfs", host="h", nfs_export="/e")
    assert not p.nfs_sender_chosen()
    assert "nfs_uid" not in p.to_dict() and "nfs_machine_name" not in p.to_dict()


def test_sad_an_nfs_version_the_own_client_does_not_speak_is_refused():
    with pytest.raises(ValueError, match="speaks 3, 4.0 and 4.1"):
        NfsUserSession("127.0.0.1", "/e", version=2, uid=1)


def test_happy_scripting_open_url_takes_the_sender_fields(server, monkeypatch):
    srv, _root = server
    from core import nfs3_rpc, scripting

    monkeypatch.setattr(nfs3_rpc, "getport", lambda connect, prog, vers, t=10.0: srv.port)
    s = scripting.open_url(f"nfs://127.0.0.1:{srv.port}/export", proxy_type="none",
                           nfs_machine_name="script-host", nfs_uid=1234, nfs_gid=99, nfs_gids="5")
    try:
        s.list_dir("/")
    finally:
        s.close()
    assert srv.creds[-1] == ("script-host", 1234, 99, (5,))


def test_happy_the_window_mode_dialog_keeps_and_checks_the_fields():
    pytest.importorskip("PyQt6.QtWidgets")
    from unittest import mock

    from PyQt6.QtWidgets import QApplication, QMessageBox

    from core.profiles import ProfileManager
    from ui.connection_dialog import ConnectionDialog

    app = QApplication.instance() or QApplication([])
    warnings: list[str] = []
    with (mock.patch.object(QMessageBox, "warning", side_effect=lambda *a, **k: warnings.append(a[2])),
          mock.patch.object(ConnectionDialog, "_validate_backend_available", return_value=True)):
        dlg = ConnectionDialog(ProfileManager())
        dlg._protocol_combo.setCurrentIndex(dlg._protocol_ids.index("nfs"))
        app.processEvents()
        dlg._profile_name.setText("n")
        dlg._host.setText("192.0.2.4")
        dlg._nfs_export.setText("/srv")
        for w in (dlg._nfs_machine_name, dlg._nfs_uid, dlg._nfs_gid, dlg._nfs_gids):
            assert not w.isHidden()
        dlg._nfs_machine_name.setText("anything-goes.example")
        dlg._nfs_uid.setText("0")
        dlg._nfs_gids.setText("1, 2, 3")
        assert dlg._validate(), warnings
        p = dlg._build_profile()
        assert (p.nfs_machine_name, p.nfs_uid, p.nfs_gid, p.nfs_gids) == ("anything-goes.example", 0, -1, "1, 2, 3")
        dlg._nfs_gids.setText(", ".join(str(i) for i in range(17)))
        assert not dlg._validate() and "at most 16" in warnings[-1]
        dlg._nfs_gids.setText("")
        dlg._nfs_version.setCurrentIndex(1)            # NFSv4 takes the sender fields too
        dlg._nfs_client_id.setText("lab-7")
        assert dlg._validate(), warnings
        assert dlg._build_profile().nfs_client_id == "lab-7"
        dlg._nfs_client_id.setText("x" * 1025)
        assert not dlg._validate() and "client id" in warnings[-1]
        dlg._nfs_client_id.setText("")
        dlg._nfs_version.setCurrentIndex(0)
        dlg._clear_fields()
        assert dlg._nfs_uid.text() == "" and dlg._nfs_machine_name.text() == ""
        dlg._load_profile(p)
        assert (dlg._nfs_machine_name.text(), dlg._nfs_uid.text(), dlg._nfs_gid.text(),
                dlg._nfs_gids.text()) == ("anything-goes.example", "0", "", "1, 2, 3")
        assert dlg._nfs_version.currentIndex() == 0
        dlg.close()


# --- NFSv4.0 -------------------------------------------------------------------------------

from fake_nfsd import FakeNfs4d  # noqa: E402


@pytest.fixture
def server4(tmp_path):
    root = tmp_path / "srv" / "export"
    root.mkdir(parents=True)
    (root / "docs").mkdir()
    (root / "docs" / "a.txt").write_bytes(b"alpha\n")
    (root / "big.bin").write_bytes(os.urandom(50_000))
    srv = FakeNfs4d(str(root))
    yield srv, root
    srv.close()


def _open4(srv, **kw):
    return NfsUserSession("127.0.0.1", "/export", port=srv.port, version=4, proxy_type="none",
                          **{**SENDER, **kw})


def test_happy_nfsv4_carries_the_sender_information_and_the_client_id(server4):
    srv, root = server4
    with _open4(srv, client_id="lab-client-7") as s:
        assert [i.name for i in s.list_dir("/")] == ["docs", "big.bin"]
        with s.open_write("/new.txt") as f:          # OPEN registers the client id
            f.write(b"hello v4")
    assert set(srv.creds) == {("build-07.lab.example", 4242, 777, (10, 20, 30))}
    assert srv.client_ids == [b"lab-client-7"] and srv.opens == 1
    assert (root / "new.txt").read_bytes() == b"hello v4"
    assert not any(prog == 100005 for prog, _ in srv.calls)      # no mountd in v4


def test_happy_nfsv4_files_folders_links(server4):
    srv, root = server4
    with _open4(srv) as s:
        with s.open_read("/big.bin") as f:
            assert f.read() == (root / "big.bin").read_bytes()
        data = os.urandom(10_000)
        with s.open_write("/out.bin") as f:
            f.write(data)
        with s.open_write("/out.bin", append=True) as f:
            f.write(b"!")
        assert (root / "out.bin").read_bytes() == data + b"!"
        s.mkdir("/x/y")
        s.rename("/out.bin", "/x/y/moved.bin")
        s.chmod("/x/y/moved.bin", 0o640)
        assert (root / "x" / "y" / "moved.bin").stat().st_mode & 0o777 == 0o640
        s.symlink("../../docs/a.txt", "/x/y/link")
        with s.open_read("/x/y/link") as f:
            assert f.read() == b"alpha\n"
        s.hardlink("/docs/a.txt", "/x/hard")
        assert (root / "x" / "hard").read_bytes() == b"alpha\n"
        s.remove("/x", recursive=True)
        assert not (root / "x").exists()
        assert s.stat("/docs/a.txt").size == 6 and s.disk_usage("/")[0] > 0
        with pytest.raises(FileNotFoundError):
            s.stat("/nope")
    assert srv.client_ids == [b"axross:build-07.lab.example"]   # the default id names the machine
    assert ".." not in srv.lookups


def test_sad_nfsv4_a_server_admitting_one_uid(server4):
    srv, _root = server4
    srv.allowed_uids = {4242}
    with _open4(srv) as s:
        assert s.exists("/docs/a.txt")
    with pytest.raises(PermissionError):
        _open4(srv, uid=1000)


def test_happy_a_v4_profile_with_sender_fields_uses_the_own_client(server4):
    srv, _root = server4
    from core import connection_manager as CM

    p = ConnectionProfile(name="n4", protocol="nfs", host="127.0.0.1", port=srv.port, nfs_export="/export",
                          nfs_version=4, nfs_client_id="from-profile")
    assert p.nfs_sender_chosen()
    s = CM.ConnectionManager().connect(p)
    try:
        with s.open_write("/p.txt") as f:
            f.write(b"x")
    finally:
        s.close()
    assert srv.client_ids == [b"from-profile"]


# --- NFSv4.1 -------------------------------------------------------------------------------

def test_happy_nfsv41_uses_a_session_and_the_chosen_client_id(server4):
    srv, root = server4
    with NfsUserSession("127.0.0.1", "/export", port=srv.port, version="4.1", proxy_type="none",
                        client_id="lab-41", **SENDER) as s:
        assert "NFSv4.1" in s.name
        assert [i.name for i in s.list_dir("/")] == ["docs", "big.bin"]
        with s.open_write("/v41.txt") as f:
            f.write(b"session")
        with s.open_read("/docs/a.txt") as f:
            assert f.read() == b"alpha\n"
        s.mkdir("/d41")
        s.rename("/v41.txt", "/d41/v41.txt")
    assert (root / "d41" / "v41.txt").read_bytes() == b"session"
    assert srv.client_ids == [b"lab-41"]                       # EXCHANGE_ID, not SETCLIENTID
    assert len(srv.sessions) == 1 and srv.destroyed == srv.sessions
    assert set(srv.minors) == {1}
    assert not any(op in (35, 36, 20) for _p, op in srv.calls)  # no SETCLIENTID / OPEN_CONFIRM in 4.1
    assert set(srv.creds) == {("build-07.lab.example", 4242, 777, (10, 20, 30))}


def test_happy_a_v41_profile_through_the_dialog_and_the_manager(server4):
    srv, _root = server4
    from core import connection_manager as CM

    p = ConnectionProfile(name="n41", protocol="nfs", host="127.0.0.1", port=srv.port, nfs_export="/export",
                          nfs_version=4, nfs_minor=1, nfs_uid=4242)
    back = ConnectionProfile.from_dict(p.to_dict())
    assert (back.nfs_version, back.nfs_minor) == (4, 1)
    s = CM.ConnectionManager().connect(back)
    try:
        assert "NFSv4.1" in s.name and s.exists("/docs/a.txt")
    finally:
        s.close()
    assert set(srv.minors) == {1}


def test_happy_the_kernel_mount_gets_vers_4_1():
    from core import nfs_client as NC

    seen = []
    session = object.__new__(NC.NfsSession)
    session._version, session._minor = 4, 1
    session._mount_host, session._mount_port = "h", 2049
    session._export, session._mount_point = "/e", "/mnt/x"
    session._run = lambda cmd, check=True: seen.append(cmd)
    try:
        session._connect()
    except Exception:
        pass
    assert any("vers=4.1" in " ".join(map(str, c)) for c in seen), seen
