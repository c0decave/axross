"""An SFTP upload whose CLOSE the server refuses is a failed upload.

Measured before: ``PipelinedWriter.close`` left the CLOSE request to
paramiko's ``SFTPFile.close``, which swallows every IOError from it
("may have outlived the Transport connection"). OpenSSH's sftp-server
answers CLOSE with the errno of close(2), and close(2) is where NFS
reports a write it could not store (EDQUOT/ENOSPC). The transfer engine
saw a clean close, renamed the temp file over the destination and
reported DONE -- replacing the old file with one the server had just
said it failed to write.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402
from tests.sftp_testkit import SftpServer  # noqa: E402


class _NoChecksumLocal(LocalFS):
    def checksum(self, path, algorithm="sha256"):
        return ""


class SftpCloseStatusTest(unittest.TestCase):
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
        self.server = SftpServer(str(self.root))
        self.addCleanup(self.server.close)
        profile = ConnectionProfile(
            name="t", protocol="sftp", host="127.0.0.1", port=self.server.port, username="u"
        )
        self.s = SSHSession(profile)
        self.s.connect(password="x", on_unknown_host=lambda _e: True)
        self.addCleanup(self.s.disconnect)

    def upload_job(self, payload: bytes) -> TW.TransferJob:
        src = self.tmp / "local.bin"
        src.write_bytes(payload)
        job = TW.TransferJob(
            source_path=str(src),
            dest_path="/remote.bin",
            filename="local.bin",
            total_bytes=len(payload),
            source_backend=_NoChecksumLocal(),
            dest_backend=self.s,
            use_temp_file=True,
        )
        TW.TransferWorker()._process_job(job)
        return job

    def test_happy_a_clean_close_commits_the_upload(self) -> None:
        with self.s.open_write("/a.bin") as fh:
            fh.write(b"payload")
        self.assertEqual((self.root / "a.bin").read_bytes(), b"payload")

    def test_sad_a_refused_close_raises(self) -> None:
        self.server.stats["fail_close"] = True
        with self.assertRaises(OSError), self.s.open_write("/a.bin") as fh:
            fh.write(b"payload")

    def test_sad_a_refused_close_keeps_the_old_destination(self) -> None:
        (self.root / "remote.bin").write_bytes(b"old")
        self.server.stats["fail_close"] = True
        job = self.upload_job(b"new" * 1000)
        self.assertEqual(job.status, TW.TransferStatus.ERROR)
        self.assertEqual((self.root / "remote.bin").read_bytes(), b"old")

    def test_edge_a_failed_write_is_still_the_error_reported(self) -> None:
        self.server.stats["fail_writes"] = True
        self.server.stats["fail_close"] = True
        with self.assertRaisesRegex(OSError, "write failed"):
            with self.s.open_write("/a.bin") as fh:
                fh.write(b"x" * 100_000)

    def test_edge_close_twice_is_harmless(self) -> None:
        fh = self.s.open_write("/a.bin")
        fh.write(b"abc")
        fh.close()
        fh.close()
        self.assertEqual((self.root / "a.bin").read_bytes(), b"abc")

    def test_edge_an_empty_upload_with_a_clean_close(self) -> None:
        job = self.upload_job(b"")
        self.assertEqual(job.status, TW.TransferStatus.DONE, job.error_message)
        self.assertEqual((self.root / "remote.bin").read_bytes(), b"")


if __name__ == "__main__":
    unittest.main()
