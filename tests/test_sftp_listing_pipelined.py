"""An SFTP folder listing keeps several READDIR requests on the wire.

paramiko's ``listdir_attr`` sends one READDIR and waits for its answer
before the next. A server answers each with a slice of the folder
(OpenSSH about 100 names, paramiko's server 16), so a 2,000-entry folder
was some 20 round trips after OPENDIR, and every listing paid one more
round trip for the READDIR that says "end of folder". The listing now
keeps a window of READDIRs in flight; answers are taken in request order,
everything after the end-of-folder answer is ignored. Same entries, same
attributes, same errors.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import paramiko  # noqa: E402
from paramiko.sftp import CMD_CLOSE, CMD_OPENDIR, CMD_READDIR, SFTP_PERMISSION_DENIED  # noqa: E402
from sftp_testkit import SftpServer, _Auth, _host_key, _Sftp  # noqa: E402

from core.profiles import ConnectionProfile  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402


class _FailingReaddirServer(paramiko.SFTPServer):
    """Answers the n-th READDIR of a handle with "permission denied"."""

    fail_at: int | None = None

    def _read_folder(self, request_number, folder):
        folder._axross_reads = getattr(folder, "_axross_reads", 0) + 1
        if self.fail_at is not None and folder._axross_reads == self.fail_at:
            self._send_status(request_number, SFTP_PERMISSION_DENIED)
            return
        super()._read_folder(request_number, folder)


class _Server(SftpServer):
    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            t = paramiko.Transport(conn)
            t.add_server_key(_host_key())
            t.set_subsystem_handler("sftp", _FailingReaddirServer, _Sftp, root=self.root,
                                    stats=self.stats)
            t.start_server(server=_Auth())
            self._transports.append(t)


class _Requests:
    """Every SFTP request the client sends: which waited for its answer
    alone (``_request``) and the most READDIRs on the wire at once."""

    def __init__(self) -> None:
        from paramiko import sftp_client

        self.sync: dict[int, int] = {}
        self.max_readdirs_in_flight = 0
        self._readdirs: set[int] = set()
        self._lock = threading.Lock()
        orig_request = sftp_client.SFTPClient._request
        orig_async = sftp_client.SFTPClient._async_request
        orig_read = sftp_client.SFTPClient._read_response
        tracker = self

        def request(client, t, *args):
            with tracker._lock:
                tracker.sync[t] = tracker.sync.get(t, 0) + 1
            return orig_request(client, t, *args)

        def async_request(client, owner, t, *args):
            num = orig_async(client, owner, t, *args)
            if t == CMD_READDIR and owner is not type(None):
                with tracker._lock:
                    tracker._readdirs.add(num)
                    tracker.max_readdirs_in_flight = max(
                        tracker.max_readdirs_in_flight,
                        len([n for n in tracker._readdirs if n in client._expecting]))
            return num

        def read_response(client, waitfor=None):
            return orig_read(client, waitfor)

        self._patches = [
            mock.patch.object(sftp_client.SFTPClient, "_request", request),
            mock.patch.object(sftp_client.SFTPClient, "_async_request", async_request),
            mock.patch.object(sftp_client.SFTPClient, "_read_response", read_response),
        ]

    def __enter__(self):
        for p in self._patches:
            p.start()
        return self

    def __exit__(self, *exc) -> None:
        for p in self._patches:
            p.stop()


class PipelinedListingTest(unittest.TestCase):
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
        _FailingReaddirServer.fail_at = None
        self.addCleanup(setattr, _FailingReaddirServer, "fail_at", None)
        self.server = _Server(str(self.root))
        self.addCleanup(self.server.close)
        profile = ConnectionProfile(name="t", protocol="sftp", host="127.0.0.1",
                                    port=self.server.port, username="u")
        self.s = SSHSession(profile)
        self.s.connect(password="x", on_unknown_host=lambda _e: True)
        self.addCleanup(self.s.disconnect)

    def _folder(self, name: str, count: int) -> str:
        folder = self.root / name
        folder.mkdir()
        for i in range(count):
            (folder / f"e{i:05d}.dat").write_bytes(b"x" * (i % 13))
        return f"/{name}"

    def _expected(self, path: str) -> list[tuple]:
        """What paramiko's own sequential listing returns."""
        attrs = self.s.sftp.listdir_attr(path)
        return sorted((a.filename, a.st_size, a.st_mode, a.st_mtime, a.longname) for a in attrs)

    # -- happy ----------------------------------------------------------------

    def test_happy_a_big_folder_lists_whole_without_waiting_for_each_readdir(self) -> None:
        path = self._folder("big", 700)  # 44 answers of 16 names
        with _Requests() as req:
            items = self.s.list_dir(path)
        self.assertEqual(sorted(i.name for i in items), sorted(os.listdir(self.root / "big")))
        self.assertEqual(req.sync.get(CMD_READDIR, 0), 0, req.sync)
        self.assertGreater(req.max_readdirs_in_flight, 1)
        self.assertEqual(req.sync.get(CMD_OPENDIR), 1)
        self.assertEqual(req.sync.get(CMD_CLOSE), 1)

    def test_happy_attributes_are_those_of_the_sequential_listing(self) -> None:
        path = self._folder("attrs", 50)
        os.symlink("e00001.dat", self.root / "attrs" / "link")
        (self.root / "attrs" / "sub").mkdir()
        got = sorted((a.filename, a.st_size, a.st_mode, a.st_mtime, a.longname)
                     for a in self.s._list_attrs(path))
        self.assertEqual(got, self._expected(path))

    def test_happy_the_session_stays_usable_after_listings(self) -> None:
        path = self._folder("again", 40)
        for _ in range(3):
            self.assertEqual(len(self.s.list_dir(path)), 40)
        self.assertTrue(self.s.exists("/again/e00001.dat"))
        self.assertEqual(dict(self.s.sftp._expecting), {})

    # -- sad --------------------------------------------------------------------

    def test_sad_a_missing_folder_raises_file_not_found(self) -> None:
        with self.assertRaises(FileNotFoundError):
            self.s.list_dir("/nope")

    def test_sad_a_failing_readdir_mid_folder_raises_and_leaves_the_session_usable(self) -> None:
        path = self._folder("fail", 100)
        _FailingReaddirServer.fail_at = 3
        with self.assertRaises(PermissionError):
            self.s.list_dir(path)
        _FailingReaddirServer.fail_at = None
        self.assertEqual(dict(self.s.sftp._expecting), {})
        self.assertEqual(len(self.s.list_dir(path)), 100)

    def test_sad_a_lost_connection_while_listing_is_an_oserror(self) -> None:
        path = self._folder("drop", 100)
        for t in self.server._transports:
            t.close()
        with self.assertRaises(OSError):
            self.s.list_dir(path)

    # -- edge -------------------------------------------------------------------

    def test_edge_an_empty_folder(self) -> None:
        (self.root / "empty").mkdir()
        self.assertEqual(self.s.list_dir("/empty"), [])

    def test_edge_slice_boundaries(self) -> None:
        for count in (1, 15, 16, 17, 32, 33):
            path = self._folder(f"n{count}", count)
            self.assertEqual(len(self.s.list_dir(path)), count, count)

    def test_edge_a_failure_answered_after_the_end_of_the_folder_is_ignored(self) -> None:
        path = self._folder("tail", 20)  # 2 answers, then the end
        _FailingReaddirServer.fail_at = 4  # a READDIR past the end-of-folder answer
        self.assertEqual(len(self.s.list_dir(path)), 20)
        self.assertEqual(dict(self.s.sftp._expecting), {})

    def test_edge_dot_entries_are_left_out(self) -> None:
        path = self._folder("dots", 3)
        names = [a.filename for a in self.s._list_attrs(path)]
        self.assertNotIn(".", names)
        self.assertNotIn("..", names)


if __name__ == "__main__":
    unittest.main()
