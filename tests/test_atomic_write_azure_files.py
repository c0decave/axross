"""atomic_write on Azure Files goes through a temp file, not straight at the target.

atomic_io listed ``azure_files`` among the protocols whose single upload
replaces the object atomically. It does not: the SDK's ``upload_file``
first sends Create File (which resets an existing file to the new
length, zero-filled) and only then uploads the data in ranges
(azure/storage/fileshare/_file_client.py, ``_upload_file_helper``:
``client.create_file`` before ``upload_data_chunks``). A range upload
failing half way left the target zero-filled after the bytes that
arrived -- an "atomic" save that destroyed the file it was saving.
server_ops already knew ("Azure Files writes ranges as it goes") and
keeps its rollback snapshot for it.
"""

from __future__ import annotations

import os
import shutil
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import atomic_io  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

_RANGE = 4


class _RangeUploadWriter:
    """Models ShareFileClient.upload_file: Create File, then ranges."""

    def __init__(self, path: str, fail_after_ranges: int | None) -> None:
        self._path = path
        self._fail_after = fail_after_ranges
        self._buf = bytearray()
        self._closed = False

    def write(self, data: bytes) -> int:
        self._buf += data
        return len(data)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        data = bytes(self._buf)
        with open(self._path, "r+b" if os.path.exists(self._path) else "wb") as f:
            f.truncate(0)
            f.truncate(len(data))  # Create File: the new length, zero-filled
            for n, start in enumerate(range(0, len(data), _RANGE)):
                if self._fail_after is not None and n >= self._fail_after:
                    raise OSError("simulated range upload failure")
                f.seek(start)
                f.write(data[start : start + _RANGE])

    def discard(self) -> None:
        self._closed = True

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        if exc_type is not None:
            self.discard()
        else:
            self.close()


class AzureFilesSession(LocalFS):
    """Matched by class name, like the registry does for the real one."""

    fail_after_ranges: int | None = None

    def open_write(self, path, append=False):
        return _RangeUploadWriter(path, self.fail_after_ranges)


class S3Session(LocalFS):
    """Stays native: a single PUT replaces the object or nothing."""

    def __init__(self) -> None:
        super().__init__()
        self.opened: list[str] = []

    def open_write(self, path, append=False):
        self.opened.append(path)
        return super().open_write(path, append=append)


class AtomicWriteAzureFilesTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.target = self.tmp / "doc.txt"
        self.target.write_bytes(b"the old saved document")

    def test_happy_a_save_replaces_the_file(self) -> None:
        atomic_io.atomic_write(AzureFilesSession(), str(self.target), b"new text")
        self.assertEqual(self.target.read_bytes(), b"new text")
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["doc.txt"])

    def test_sad_a_failed_range_upload_keeps_the_old_file(self) -> None:
        backend = AzureFilesSession()
        backend.fail_after_ranges = 1
        with self.assertRaises(OSError):
            atomic_io.atomic_write(backend, str(self.target), b"a much longer new document")
        self.assertEqual(self.target.read_bytes(), b"the old saved document")
        self.assertEqual(sorted(p.name for p in self.tmp.iterdir()), ["doc.txt"])

    def test_sad_a_failed_streamed_save_keeps_the_old_file(self) -> None:
        import io

        backend = AzureFilesSession()
        backend.fail_after_ranges = 2
        with self.assertRaises(OSError):
            atomic_io.atomic_write_stream(
                backend, str(self.target), io.BytesIO(b"a much longer new document")
            )
        self.assertEqual(self.target.read_bytes(), b"the old saved document")

    def test_edge_the_saved_file_keeps_its_mode(self) -> None:
        os.chmod(self.target, 0o600)
        atomic_io.atomic_write(AzureFilesSession(), str(self.target), b"new text")
        self.assertEqual(stat.S_IMODE(self.target.stat().st_mode), 0o600)

    def test_edge_s3_still_writes_its_single_put_directly(self) -> None:
        backend = S3Session()
        atomic_io.atomic_write(backend, str(self.target), b"new text")
        self.assertEqual(backend.opened, [str(self.target)])
        self.assertEqual(self.target.read_bytes(), b"new text")


if __name__ == "__main__":
    unittest.main()
