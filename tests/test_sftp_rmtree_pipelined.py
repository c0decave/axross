"""A recursive SFTP delete keeps a batch of REMOVE requests on the wire.

``SSHSession._rmtree`` removed every file with its own ``sftp.remove`` and
waited for the answer before the next one: 500 files at 20 ms latency
took about 13 s (measured on the lab's ssh-alpha through toxiproxy), one
round trip per file. The files of a folder now go out in batches of
:data:`core.ssh_client.RMTREE_REMOVES_IN_FLIGHT` pipelined REMOVEs.

Cancel is checked before each batch (and before each sub-folder), so the
files of the running batch are removed anyway; progress is still reported
per file, one ``removal_cancel.removed`` per answer. A failing file raises
the error the sequential ``sftp.remove`` raised, after every answer still
on the wire was read, so the session stays usable.
"""

from __future__ import annotations

import errno
import os
import shutil
import socket
import sys
import tempfile
import threading
import unittest
import uuid
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import paramiko  # noqa: E402
import pytest  # noqa: E402
from paramiko.sftp import CMD_REMOVE, SFTP_PERMISSION_DENIED  # noqa: E402
from sftp_testkit import SftpServer, _Auth, _host_key, _Sftp  # noqa: E402

from core import removal_cancel as RC  # noqa: E402
from core import ssh_client as SC  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402

BATCH = SC.RMTREE_REMOVES_IN_FLIGHT if hasattr(SC, "RMTREE_REMOVES_IN_FLIGHT") else 16


class _DenyingSftp(_Sftp):
    """The test kit's real-folder server; REMOVE of a name in ``deny``
    answers "permission denied" and leaves the file."""

    deny: set[str] = set()

    def remove(self, path):
        if os.path.basename(path) in self.deny:
            return SFTP_PERMISSION_DENIED
        return super().remove(path)


class _Server(SftpServer):
    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(_host_key())
            t.set_subsystem_handler("sftp", paramiko.SFTPServer, _DenyingSftp, root=self.root,
                                    stats=self.stats)
            t.start_server(server=_Auth())
            self._transports.append(t)


class _Removes:
    """Every REMOVE the client sends: how many waited for their answer
    alone (``_request``) and the most that were on the wire at once."""

    def __init__(self) -> None:
        from paramiko import sftp_client

        self.sync = 0
        self.sent = 0
        self.max_in_flight = 0
        self._nums: set[int] = set()
        self._lock = threading.Lock()
        orig_request = sftp_client.SFTPClient._request
        orig_async = sftp_client.SFTPClient._async_request
        tracker = self

        def request(client, t, *args):
            if t == CMD_REMOVE:
                with tracker._lock:
                    tracker.sync += 1
            return orig_request(client, t, *args)

        def async_request(client, owner, t, *args):
            num = orig_async(client, owner, t, *args)
            if t == CMD_REMOVE and owner is not type(None):
                with tracker._lock:
                    tracker.sent += 1
                    tracker._nums.add(num)
                    tracker.max_in_flight = max(
                        tracker.max_in_flight,
                        len([n for n in tracker._nums if n in client._expecting]))
            return num

        self._patches = [
            mock.patch.object(sftp_client.SFTPClient, "_request", request),
            mock.patch.object(sftp_client.SFTPClient, "_async_request", async_request),
        ]

    def __enter__(self):
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc) -> None:
        for p in self._patches:
            p.stop()


class _Progress:
    """A cancellable_removal scope's callbacks: the removed paths in order,
    and how many were removed each time Cancel was asked (one ask per
    batch or sub-folder). ``cancel_after`` turns Cancel on."""

    def __init__(self, cancel_after: int | None = None) -> None:
        self.cancel_after = cancel_after
        self.removed: list[str] = []
        self.asked_at: list[int] = []

    def cancelled(self) -> bool:
        self.asked_at.append(len(self.removed))
        return self.cancel_after is not None and len(self.removed) >= self.cancel_after

    def on_removed(self, count: int, path: str) -> None:
        self.removed.append(path)
        assert count == len(self.removed)


class PipelinedRmtreeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.root = self.tmp / "srv"
        self.root.mkdir()
        home = self.tmp / "home"
        (home / ".ssh").mkdir(parents=True)
        p = mock.patch("pathlib.Path.home", return_value=home)
        p.start()
        self.addCleanup(p.stop)
        _DenyingSftp.deny = set()
        self.addCleanup(setattr, _DenyingSftp, "deny", set())
        self.server = _Server(str(self.root))
        self.addCleanup(self.server.close)
        profile = ConnectionProfile(name="t", protocol="sftp", host="127.0.0.1",
                                    port=self.server.port, username="u")
        self.s = SSHSession(profile)
        self.s.connect(password="x", on_unknown_host=lambda _e: True)
        self.addCleanup(self.s.disconnect)

    def _folder(self, name: str, count: int) -> str:
        folder = self.root / name
        folder.mkdir(parents=True)
        for i in range(count):
            (folder / f"f{i:05d}").write_bytes(b"x")
        return "/" + name

    def _remove(self, path: str, progress: _Progress | None = None) -> _Progress:
        progress = progress or _Progress()
        with RC.cancellable_removal(progress.cancelled, progress.on_removed):
            self.s.remove(path, recursive=True)
        return progress

    def _assert_session_clean(self) -> None:
        self.assertEqual(dict(self.s.sftp._expecting), {})
        self.assertTrue(self.s.exists("/"))

    # -- happy ----------------------------------------------------------------

    def test_happy_files_go_out_in_batches_and_the_tree_is_gone(self) -> None:
        path = self._folder("big", 40)
        with _Removes() as req:
            progress = self._remove(path)
        self.assertFalse((self.root / "big").exists())
        self.assertEqual(req.sync, 0)
        self.assertEqual(req.sent, 40)
        self.assertEqual(req.max_in_flight, BATCH)
        self.assertEqual(sorted(progress.removed), [f"/big/f{i:05d}" for i in range(40)])
        self._assert_session_clean()

    def test_happy_progress_is_counted_per_file_in_request_order(self) -> None:
        path = self._folder("order", 20)
        listed = [f"/order/{a.filename}" for a in self.s._list_attrs(path)]
        progress = self._remove(path)
        self.assertEqual(progress.removed, listed)
        self.assertEqual(progress.asked_at, [0, BATCH])

    def test_happy_without_a_cancel_scope(self) -> None:
        path = self._folder("plain", 30)
        self.s.remove(path, recursive=True)
        self.assertFalse((self.root / "plain").exists())
        self._assert_session_clean()

    # -- sad --------------------------------------------------------------------

    def _expected_denied_error(self, path: str) -> OSError:
        """What the sequential ``sftp.remove`` raises for a denied file."""
        with self.assertRaises(OSError) as ctx:
            self.s.sftp.remove(path)
        return ctx.exception

    def test_sad_a_denied_file_mid_folder_raises_the_sequential_error(self) -> None:
        path = self._folder("deny", 40)
        listed = [a.filename for a in self.s._list_attrs(path)]  # request order
        denied = listed[20]  # in the second batch (16..31)
        _DenyingSftp.deny = {denied}
        progress = _Progress()
        with self.assertRaises(PermissionError) as ctx:
            self._remove(path, progress)
        expected = self._expected_denied_error(f"/deny/{denied}")
        got = ctx.exception
        self.assertIs(type(got), type(expected))
        self.assertEqual(got.errno, errno.EACCES)
        self.assertEqual(got.args, expected.args)
        self.assertEqual(str(got), str(expected))
        # The first batch and the rest of the second are gone, the third
        # batch was never sent.
        left = sorted(os.listdir(self.root / "deny"))
        self.assertEqual(left, sorted([denied] + listed[2 * BATCH :]))
        self.assertEqual(len(progress.removed), 2 * BATCH - 1)
        self.assertNotIn(f"/deny/{denied}", progress.removed)
        self._assert_session_clean()

    def test_sad_two_denied_files_in_one_batch_raise_the_first(self) -> None:
        path = self._folder("deny2", 10)
        _DenyingSftp.deny = {"f00003", "f00007"}
        with _Removes() as req:
            with self.assertRaises(PermissionError) as ctx:
                self.s.remove(path, recursive=True)
        self.assertEqual(req.sent, 10)
        self.assertEqual(str(ctx.exception), str(self._expected_denied_error("/deny2/f00003")))
        self.assertEqual(sorted(os.listdir(self.root / "deny2")), ["f00003", "f00007"])
        self._assert_session_clean()

    def test_sad_a_file_gone_meanwhile_is_file_not_found(self) -> None:
        path = self._folder("gone", 5)
        real_list = SSHSession._list_attrs

        def list_then_vanish(session, folder):
            attrs = real_list(session, folder)
            if folder == "/gone":
                os.remove(self.root / "gone" / "f00002")
            return attrs

        with mock.patch.object(SSHSession, "_list_attrs", list_then_vanish):
            with self.assertRaises(FileNotFoundError):
                self.s.remove(path, recursive=True)
        self.assertEqual(os.listdir(self.root / "gone"), [])
        self._assert_session_clean()

    def test_sad_a_lost_connection_while_removing_is_an_oserror(self) -> None:
        path = self._folder("drop", 40)
        real_list = SSHSession._list_attrs

        def list_then_drop(session, folder):
            attrs = real_list(session, folder)
            for t in self.server._transports:
                t.close()
            return attrs

        with mock.patch.object(SSHSession, "_list_attrs", list_then_drop):
            with self.assertRaises(OSError):
                self.s.remove(path, recursive=True)

    def test_sad_a_failing_progress_callback_leaves_no_answer_on_the_wire(self) -> None:
        path = self._folder("cb", 10)

        def boom(count, p):
            raise RuntimeError("progress broke")

        with RC.cancellable_removal(lambda: False, boom):
            with self.assertRaises(RuntimeError):
                self.s.remove(path, recursive=True)
        self._assert_session_clean()

    # -- edge -------------------------------------------------------------------

    def test_edge_an_empty_folder_sends_no_remove(self) -> None:
        (self.root / "empty").mkdir()
        with _Removes() as req:
            progress = self._remove("/empty")
        self.assertFalse((self.root / "empty").exists())
        self.assertEqual((req.sent, req.sync), (0, 0))
        self.assertEqual(progress.asked_at, [])

    def test_edge_exactly_one_batch(self) -> None:
        path = self._folder("one", BATCH)
        with _Removes() as req:
            progress = self._remove(path)
        self.assertFalse((self.root / "one").exists())
        self.assertEqual(progress.asked_at, [0])
        self.assertEqual((req.sent, req.max_in_flight), (BATCH, BATCH))

    def test_edge_one_more_than_a_batch(self) -> None:
        path = self._folder("two", BATCH + 1)
        with _Removes() as req:
            progress = self._remove(path)
        self.assertFalse((self.root / "two").exists())
        self.assertEqual(progress.asked_at, [0, BATCH])
        self.assertEqual(len(progress.removed), BATCH + 1)
        self.assertEqual((req.sent, req.max_in_flight), (BATCH + 1, BATCH))

    def test_edge_cancel_lands_between_batches(self) -> None:
        path = self._folder("cancel", 40)
        listed = [a.filename for a in self.s._list_attrs(path)]
        progress = _Progress(cancel_after=1)
        with self.assertRaises(RC.RemovalCancelled) as ctx:
            self._remove(path, progress)
        self.assertEqual(ctx.exception.removed, BATCH)
        self.assertEqual(ctx.exception.path, f"/cancel/{listed[BATCH]}")
        self.assertEqual(sorted(os.listdir(self.root / "cancel")), sorted(listed[BATCH:]))
        self._assert_session_clean()

    def test_edge_cancel_before_the_first_batch_removes_nothing(self) -> None:
        path = self._folder("early", 5)
        with self.assertRaises(RC.RemovalCancelled) as ctx:
            self._remove(path, _Progress(cancel_after=0))
        self.assertEqual(ctx.exception.removed, 0)
        self.assertEqual(len(os.listdir(self.root / "early")), 5)

    def test_edge_nested_folders_recurse_and_count(self) -> None:
        self._folder("tree", 20)
        self._folder("tree/a", 3)
        self._folder("tree/a/deep", 17)
        (self.root / "tree" / "b").mkdir()
        os.symlink("f00001", self.root / "tree" / "link")
        with _Removes() as req:
            progress = self._remove("/tree")
        self.assertFalse((self.root / "tree").exists())
        # 20 + link + 3 + 17 files, the folders a/deep, a and b.
        self.assertEqual(req.sent, 41)
        self.assertEqual(len(progress.removed), 44)
        self.assertEqual(progress.removed.index("/tree/a/deep") + 1,
                         progress.removed.index("/tree/a"))
        self._assert_session_clean()

    def test_edge_the_depth_guard_still_stops_an_endless_tree(self) -> None:
        deep = self.root / "endless"
        cur = deep
        for _ in range(6):
            cur = cur / "d"
        cur.mkdir(parents=True)
        with mock.patch.object(SSHSession, "_MAX_TREE_DEPTH", 3):
            with self.assertRaises(OSError) as ctx:
                self.s.remove("/endless", recursive=True)
        self.assertIn("deeper than 3 levels", str(ctx.exception))


class StandInClientTest(unittest.TestCase):
    """A client that is not paramiko's (the tests' MagicMock) is still
    walked with one ``remove`` per file."""

    def test_edge_stand_in_client_removes_file_by_file(self) -> None:
        import types

        sftp = mock.MagicMock()
        sftp.listdir_attr.return_value = [
            types.SimpleNamespace(filename=f"f{i}", st_mode=0o100644) for i in range(3)
        ]
        session = SSHSession.__new__(SSHSession)
        with mock.patch.object(SSHSession, "sftp", new_callable=mock.PropertyMock) as prop:
            prop.return_value = sftp
            session._rmtree("/r")
        self.assertEqual([c.args[0] for c in sftp.remove.call_args_list],
                         ["/r/f0", "/r/f1", "/r/f2"])
        sftp.rmdir.assert_called_once_with("/r")


# -- live: the lab's OpenSSH server ---------------------------------------------------------

LAB_HOST, LAB_PORT, LAB_USER, LAB_PASS = "10.99.0.10", 22, "alpha", "alpha123"


def _lab_up() -> bool:
    try:
        with socket.create_connection((LAB_HOST, LAB_PORT), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.fixture
def lab(tmp_path, monkeypatch):
    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setattr(Path, "home", lambda: home)
    profile = ConnectionProfile(name="lab-alpha", protocol="sftp", host=LAB_HOST, port=LAB_PORT,
                                username=LAB_USER, auth_type="password")
    session = SSHSession(profile)
    session.connect(password=LAB_PASS, on_unknown_host=lambda _e: True)
    folder = session.join(session.home(), f"axross-rmtree-{uuid.uuid4().hex[:10]}")
    session.mkdir(folder)
    try:
        yield session, folder
    finally:
        try:
            for dirpath in (folder, session.join(folder, "locked")):
                if session.exists(dirpath):
                    session.sftp.chmod(dirpath, 0o755)
            if session.exists(folder):
                session.remove(folder, recursive=True)
        finally:
            session.disconnect()


@pytest.mark.skipif(not _lab_up(), reason="ssh-alpha lab container not reachable")
def test_happy_live_lab_tree_is_removed_in_batches(lab):
    session, folder = lab
    sub = session.join(folder, "sub")
    session.mkdir(sub)
    for i in range(BATCH * 2 + 3):
        with session.sftp.open(session.join(folder, f"f{i:03d}"), "wb") as fh:
            fh.write(b"x")
    for i in range(5):
        with session.sftp.open(session.join(sub, f"g{i}"), "wb") as fh:
            fh.write(b"y")
    progress = _Progress()
    with _Removes() as req:
        with RC.cancellable_removal(progress.cancelled, progress.on_removed):
            session.remove(folder, recursive=True)
    assert not session.exists(folder)
    assert req.sync == 0 and req.sent == BATCH * 2 + 3 + 5
    assert req.max_in_flight == BATCH
    assert len(progress.removed) == BATCH * 2 + 3 + 5 + 1
    assert dict(session.sftp._expecting) == {}


@pytest.mark.skipif(not _lab_up(), reason="ssh-alpha lab container not reachable")
def test_sad_live_lab_read_only_folder_raises_permission_error(lab):
    session, folder = lab
    locked = session.join(folder, "locked")
    session.mkdir(locked)
    for i in range(3):
        with session.sftp.open(session.join(locked, f"f{i}"), "wb") as fh:
            fh.write(b"x")
    session.sftp.chmod(locked, 0o555)
    with pytest.raises(OSError) as batched:
        session.remove(locked, recursive=True)
    with pytest.raises(OSError) as sequential:
        session.sftp.remove(session.join(locked, "f0"))
    assert type(batched.value) is type(sequential.value)
    assert batched.value.errno == errno.EACCES
    assert str(batched.value) == str(sequential.value)
    assert dict(session.sftp._expecting) == {}
    assert sorted(session.sftp.listdir(locked)) == ["f0", "f1", "f2"]
