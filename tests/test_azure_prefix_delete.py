"""Recursive Azure Blob delete sends batches of up to 256 blobs.

Before: ``_remove_prefix`` deleted blob by blob - one HTTP round trip per
blob (10 000 blobs: 10 000 requests). ``ContainerClient.delete_blobs``
(Blob Batch, SDK 12.x: at most 256 per request) does the same in 40.
When the batch call fails as a whole (an account or emulator without
batch support) that chunk is deleted one by one as before.

A refusal can also arrive as a PartialBatchErrorException: Azurite answers
every batch with ONE "400 InvalidInput" part, whatever the number of
sub-requests (seen live 2026-10-15), so a recursive delete of a folder
failed there. Blobs whose part failed - all of them when the parts cannot
be matched to the requests - are deleted one by one; a blob that fails
alone too raises, as an OSError from ``remove``.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from azure.core.exceptions import HttpResponseError
    from azure.storage.blob import PartialBatchErrorException

    from core import azure_client as AC
except ImportError:  # pragma: no cover
    AC = None


class _Container:
    def __init__(self, names, *, batch_error=None) -> None:
        self.blobs = set(names)
        self.batch_calls: list[int] = []
        self.single_calls = 0
        self.batch_error = batch_error
        self.undeletable: set[str] = set()

    def list_blobs(self, name_starts_with=""):
        return iter([SimpleNamespace(name=n) for n in sorted(self.blobs) if n.startswith(name_starts_with)])

    def delete_blobs(self, *names, **kw):
        self.batch_calls.append(len(names))
        if self.batch_error is not None:
            raise self.batch_error
        assert len(names) <= 256
        for n in names:
            self.blobs.discard(n)
        return iter(())

    def delete_blob(self, name, **kw):
        self.single_calls += 1
        if name in self.undeletable:
            raise HttpResponseError(message=f"LeaseIdMissing: {name}")
        self.blobs.discard(name)


def _part(status: int):
    return SimpleNamespace(status_code=status)


@unittest.skipIf(AC is None, "azure-storage-blob not installed")
class PrefixDeleteTest(unittest.TestCase):
    def session(self, container) -> "AC.AzureBlobSession":
        s = object.__new__(AC.AzureBlobSession)
        s._container = container
        return s

    def names(self, n):
        return [f"dir/f{i:05d}" for i in range(n)] + ["other/keep"]

    def test_happy_batches_of_256(self) -> None:
        c = _Container(self.names(600))
        self.session(c)._remove_prefix("dir/")
        self.assertEqual(c.batch_calls, [256, 256, 88])
        self.assertEqual((c.single_calls, c.blobs), (0, {"other/keep"}))

    def test_sad_no_batch_support_falls_back_to_single_deletes(self) -> None:
        c = _Container(self.names(300), batch_error=HttpResponseError(message="FeatureNotSupported"))
        self.session(c)._remove_prefix("dir/")
        self.assertEqual(c.single_calls, 300)
        self.assertEqual(c.blobs, {"other/keep"})

    def test_sad_a_batch_refused_in_one_part_falls_back_to_single_deletes(self) -> None:
        # Azurite: one "400 InvalidInput" part for a batch of three.
        err = PartialBatchErrorException("refused", response=None, parts=[_part(400)])
        c = _Container(self.names(3), batch_error=err)
        self.session(c)._remove_prefix("dir/")
        self.assertEqual(c.single_calls, 3)
        self.assertEqual(c.blobs, {"other/keep"})

    def test_sad_only_the_failed_parts_are_retried_alone(self) -> None:
        names = self.names(3)
        c = _Container(names)
        parts = [_part(202), _part(503), _part(202)]

        def delete_blobs(*batch, **kw):
            c.batch_calls.append(len(batch))
            for name, part in zip(batch, parts):
                if part.status_code == 202:
                    c.blobs.discard(name)
            raise PartialBatchErrorException("1 failed", response=None, parts=parts)

        c.delete_blobs = delete_blobs
        self.session(c)._remove_prefix("dir/")
        self.assertEqual(c.single_calls, 1)
        self.assertEqual(c.blobs, {"other/keep"})

    def test_sad_a_blob_that_fails_alone_too_raises_oserror(self) -> None:
        err = PartialBatchErrorException("refused", response=None, parts=[_part(400)])
        c = _Container(self.names(2), batch_error=err)
        c.undeletable = {"dir/f00001"}
        s = self.session(c)
        s._to_key = lambda path: path.lstrip("/")
        s.is_dir = lambda path: True
        with self.assertRaises(OSError) as ctx:
            s.remove("/dir", recursive=True)
        self.assertIn("LeaseIdMissing", str(ctx.exception))
        self.assertEqual(c.blobs, {"dir/f00001", "other/keep"})

    def test_edge_a_refusal_without_parts_retries_every_blob(self) -> None:
        err = PartialBatchErrorException("refused", response=None, parts=[])
        c = _Container(self.names(10), batch_error=err)
        self.session(c)._remove_prefix("dir/")
        self.assertEqual(c.single_calls, 10)
        self.assertEqual(c.blobs, {"other/keep"})

    def test_edge_empty_prefix_and_exact_chunk(self) -> None:
        c = _Container(["other/keep"])
        self.session(c)._remove_prefix("dir/")
        self.assertEqual((c.batch_calls, c.single_calls), ([], 0))
        c = _Container(self.names(256))
        self.session(c)._remove_prefix("dir/")
        self.assertEqual(c.batch_calls, [256])


if __name__ == "__main__":
    unittest.main()
