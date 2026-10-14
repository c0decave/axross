"""Overwriting on S3 / Azure Blob no longer downloads the old object first.

The rollback snapshot exists for writers that modify the destination as
they go. S3 and Azure Blob writers buffer locally and replace the object
in one commit at close (s3transfer aborts a failed multipart upload;
Azure commits the block list last), so a failed upload leaves the old
object as it was and the snapshot only cost a full download. Every other
backend keeps the snapshot.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import server_ops as SO  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class S3Session(LocalFS):
    """Stands in for core.s3_client.S3Session (matched by class name)."""


class AzureBlobSession(LocalFS):
    pass


class AzureFilesSession(LocalFS):
    """Writes ranges as it goes: must keep its snapshot."""


class SnapshotTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.dst = self.tmp / "obj.bin"
        self.dst.write_bytes(b"old" * 1000)

    def test_happy_commit_on_close_backends_skip_the_download(self) -> None:
        for cls in (S3Session, AzureBlobSession):
            with self.subTest(cls=cls.__name__), mock.patch.object(cls, "open_read") as rd:
                existed, snap = SO._snapshot_direct_destination(cls(), str(self.dst))
                self.assertEqual((existed, snap), (True, None))
                rd.assert_not_called()

    def test_sad_other_backends_keep_their_snapshot(self) -> None:
        for cls in (LocalFS, AzureFilesSession):
            with self.subTest(cls=cls.__name__):
                existed, snap = SO._snapshot_direct_destination(cls(), str(self.dst))
                self.assertTrue(existed)
                self.assertEqual(snap.read(), b"old" * 1000)
                snap.close()

    def test_edge_a_missing_destination_is_still_detected(self) -> None:
        existed, snap = SO._snapshot_direct_destination(S3Session(), str(self.tmp / "nope"))
        self.assertEqual((existed, snap), (False, None))

    def test_edge_rollback_without_snapshot_leaves_the_object_alone(self) -> None:
        with mock.patch.object(S3Session, "open_write") as wr, mock.patch.object(
            S3Session, "remove"
        ) as rm:
            SO._rollback_direct_destination(
                S3Session(), str(self.dst), destination_existed=True, destination_snapshot=None
            )
        wr.assert_not_called()
        rm.assert_not_called()
        self.assertEqual(self.dst.read_bytes(), b"old" * 1000)


if __name__ == "__main__":
    unittest.main()
