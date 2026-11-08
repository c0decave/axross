"""An upload keeps the source's modification time on SFTP, SMB and FTP.

Review round 3: ``TransferWorker._apply_source_mtime`` calls the
destination's ``set_modified``, and only LocalFS had one. Every upload
carried the upload time, so Compare Panes called a 12 MiB file
"unknown - same size, mtime differs" for good, and "Overwrite if Newer"
read every uploaded copy as newer than its source.

Now SSHSession sets the time by SETSTAT (``sftp.utime``), SMB by
``smbclient.utime`` and FTP by ``MFMT`` when the server names it in FEAT;
the direct-write route (FTP, WebDAV, S3) applies it too. SFTP and FTP keep
whole seconds, so "newer" compares whole seconds: a copy given 10 s for a
source of 10.6 s is not older than it. WebDAV (getlastmodified is a
protected property) and S3 (LastModified is the upload time) get no
``set_modified``: their upload time is newer than the source, which is
what "Overwrite if Newer" and Compare then see.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferStatus  # noqa: E402

OLD = 1_600_000_000.6


class _DirectFS(LocalFS):
    """A destination the transfer engine writes directly (like FTP): its
    rename is not LocalFS's (core.transfer_manager._should_use_temp_file)."""

    def rename(self, src, dst):
        os.rename(src, dst)


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.transfer_manager import TransferManager

        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.src = self.tmp / "src"
        self.src.mkdir()
        self.mgr = TransferManager()
        self.addCleanup(self.mgr.shutdown)

    def _wait(self, jobs):
        deadline = time.monotonic() + 30
        while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs):
            self.app.processEvents()
            self.assertLess(time.monotonic(), deadline, "transfer did not finish")
            time.sleep(0.01)
        self.app.processEvents()
        return jobs

    def _file(self, name="f.txt", text="content", mtime=OLD) -> Path:
        path = self.src / name
        path.write_text(text)
        os.utime(path, (mtime, mtime))
        return path


class SftpKeepsMtimeTest(_Base):
    def setUp(self) -> None:
        super().setUp()
        from paramiko import SFTPServer
        from paramiko.sftp import SFTP_OK

        from core.profiles import ConnectionProfile
        from core.ssh_client import SSHSession
        from tests import sftp_testkit as K

        def chattr(server, path, attr):  # SETSTAT as OpenSSH carries it out
            try:
                SFTPServer.set_file_attr(server._real(path), attr)
            except OSError as exc:
                return server._err(exc)
            return SFTP_OK

        patch = mock.patch.object(K._Sftp, "chattr", chattr)
        patch.start()
        self.addCleanup(patch.stop)
        self.root = self.tmp / "srv"
        self.root.mkdir()
        home = self.tmp / "home"
        (home / ".ssh").mkdir(parents=True)
        home_patch = mock.patch("pathlib.Path.home", return_value=home)
        home_patch.start()
        self.addCleanup(home_patch.stop)
        server = K.SftpServer(str(self.root))
        self.addCleanup(server.close)
        profile = ConnectionProfile(
            name="t", protocol="sftp", host="127.0.0.1", port=server.port, username="u"
        )
        self.s = SSHSession(profile)
        self.s.connect(password="x", on_unknown_host=lambda _e: True)
        self.addCleanup(self.s.disconnect)

    def test_happy_an_upload_to_sftp_keeps_the_source_time(self) -> None:
        path = self._file()
        [job] = self._wait(self.mgr.transfer_files(
            LocalFS(), self.s, [str(path)], "/", TW.TransferDirection.UPLOAD))
        self.assertEqual(job.status, TransferStatus.DONE, job.error_message)
        self.assertEqual(os.stat(self.root / "f.txt").st_mtime, int(OLD))
        self.assertEqual(int(self.s.stat("/f.txt").modified.timestamp()), int(OLD))

    def test_edge_overwrite_if_newer_keeps_an_unchanged_upload(self) -> None:
        """The copy reads back as 1_600_000_000 for a source of ...000.6:
        compared to the fraction it looked older and was uploaded again."""
        path = self._file()
        self._wait(self.mgr.transfer_files(
            LocalFS(), self.s, [str(path)], "/", TW.TransferDirection.UPLOAD))
        (self.root / "f.txt").write_text("remote")
        os.utime(self.root / "f.txt", (int(OLD), int(OLD)))
        job = self.mgr.transfer_file(LocalFS(), self.s, str(path), "/f.txt",
                                     TW.TransferDirection.UPLOAD, if_exists="newer")
        self._wait([job])
        self.assertEqual(job.status, TransferStatus.DONE, job.error_message)
        self.assertTrue(job.skipped)
        self.assertEqual((self.root / "f.txt").read_text(), "remote")


class NewerWholeSecondsTest(_Base):
    def test_sad_a_source_newer_by_a_fraction_only_does_not_replace(self) -> None:
        path = self._file(text="new")
        dest = self.tmp / "dst"
        dest.mkdir()
        (dest / "f.txt").write_text("kept")
        os.utime(dest / "f.txt", (int(OLD), int(OLD)))
        job = self.mgr.transfer_file(LocalFS(), LocalFS(), str(path), str(dest / "f.txt"),
                                     if_exists="newer")
        self._wait([job])
        self.assertTrue(job.skipped, job.error_message)
        self.assertEqual((dest / "f.txt").read_text(), "kept")

    def test_happy_a_source_a_second_newer_still_replaces(self) -> None:
        path = self._file(text="new", mtime=OLD + 1)
        dest = self.tmp / "dst"
        dest.mkdir()
        (dest / "f.txt").write_text("old")
        os.utime(dest / "f.txt", (int(OLD), int(OLD)))
        # The direct route too (FTP): it now gives the copy the source's time.
        job = self.mgr.transfer_file(LocalFS(), _DirectFS(), str(path), str(dest / "f.txt"),
                                     if_exists="newer")
        self._wait([job])
        self.assertEqual(job.status, TransferStatus.DONE, job.error_message)
        self.assertFalse(job.skipped)
        self.assertEqual((dest / "f.txt").read_text(), "new")
        self.assertEqual(os.stat(dest / "f.txt").st_mtime, OLD + 1)


class _FakeFtp:
    def __init__(self, feat: str) -> None:
        self.feat = feat
        self.sent: list[str] = []

    def sendcmd(self, cmd: str) -> str:
        self.sent.append(cmd)
        if cmd == "FEAT":
            return self.feat
        return "213 ok"


class FtpMfmtTest(unittest.TestCase):
    def _session(self, feat: str):
        from core import ftp_client as FC

        s = FC.FtpSession.__new__(FC.FtpSession)
        ftp = _FakeFtp(feat)
        s._ensure_connected = lambda: ftp
        return s, ftp

    def test_happy_mfmt_sets_the_time_when_feat_names_it(self) -> None:
        s, ftp = self._session("211-Features:\n MFMT\n MDTM\n211 End")
        s.set_modified("/in/f.txt", 1_600_000_000.6)
        self.assertEqual(ftp.sent[-1], "MFMT 20200913122640 /in/f.txt")

    def test_sad_a_server_without_mfmt_is_not_asked(self) -> None:
        s, ftp = self._session("211-Features:\n MDTM\n SIZE\n211 End")
        with self.assertRaises(NotImplementedError):
            s.set_modified("/in/f.txt", 1_600_000_000)
        self.assertEqual(ftp.sent, ["FEAT"])


class SmbUtimeTest(unittest.TestCase):
    def test_happy_smb_sets_the_time_and_keeps_the_access_time(self) -> None:
        from core import smb_client as SC
        from smb_fake_client import make_session

        calls = []
        fake = types.SimpleNamespace(
            stat=lambda unc, **kw: types.SimpleNamespace(st_atime=123.0),
            utime=lambda unc, times=None, **kw: calls.append((unc, times)),
        )
        with mock.patch.object(SC, "smbclient", fake), \
                mock.patch.object(SC.SmbSession, "_kw", {}):
            make_session(fake).set_modified("/d/f.txt", OLD)
        self.assertEqual(calls, [("\\\\h\\s\\d\\f.txt", (123.0, OLD))])


if __name__ == "__main__":
    unittest.main()
