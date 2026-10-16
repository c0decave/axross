"""ADB checksums carry the ``<algorithm>:`` prefix every backend uses.

AdbSession.checksum returned the bare hex digest. The transfer worker
splits native checksums on ``:`` and compares the algorithm parts: the
bare hex became the "algorithm", so ADB never matched any other backend
and, between two ADB devices, two DIFFERENT digests looked like two
different algorithms - the corrupted copy was skipped as
"incomparable" instead of failing verification.

The device is a stand-in at the adb-shell boundary.
"""

from __future__ import annotations

import hashlib
import sys
import threading
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.adb_client import AdbSession  # noqa: E402


class _Device:
    def __init__(self, files: dict[str, bytes]) -> None:
        self.files = files

    def shell(self, cmd: str, transport_timeout_s=None) -> str:
        tool, path = cmd.split(" ", 1)
        path = path.strip("'")
        if path not in self.files:
            return f"{tool}: {path}: No such file or directory\n"
        algo = {"sha256sum": "sha256", "sha1sum": "sha1", "md5sum": "md5"}[tool]
        return f"{hashlib.new(algo, self.files[path]).hexdigest()}  {path}\n"


def _adb(files: dict[str, bytes]) -> AdbSession:
    s = AdbSession.__new__(AdbSession)
    s._device = _Device(files)
    s._conn_lock = threading.Lock()
    s._transport_timeout = 5.0
    s._label = "fake-device"
    return s


class AdbChecksumPrefixTest(unittest.TestCase):
    def test_happy_prefixed_digest(self) -> None:
        s = _adb({"/sdcard/a": b"abc"})
        self.assertEqual(s.checksum("/sdcard/a"), "sha256:" + hashlib.sha256(b"abc").hexdigest())
        self.assertEqual(s.checksum("/sdcard/a", "md5"), "md5:" + hashlib.md5(b"abc").hexdigest())

    def test_sad_corrupt_adb_to_adb_copy_fails_verification(self) -> None:
        from core.transfer_worker import TransferWorker, _ChecksumMismatch

        job = SimpleNamespace(
            source_backend=_adb({"/sdcard/a": b"original"}),
            dest_backend=_adb({"/sdcard/a": b"0riginal"}),
            source_path="/sdcard/a",
            dest_path="/sdcard/a",
            filename="a",
            verify_checksum=False,
        )
        with self.assertRaises(_ChecksumMismatch):
            TransferWorker()._verify_integrity(job)

    def test_edge_missing_file_and_unknown_algorithm_give_empty(self) -> None:
        s = _adb({})
        self.assertEqual(s.checksum("/sdcard/none"), "")
        self.assertEqual(s.checksum("/sdcard/none", "blake2"), "")


if __name__ == "__main__":
    unittest.main()
