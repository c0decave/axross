"""Recursive Azure Blob delete sends batches of up to 256 blobs.

Before: ``_remove_prefix`` deleted blob by blob - one HTTP round trip per
blob (10 000 blobs: 10 000 requests). ``ContainerClient.delete_blobs``
(Blob Batch, SDK 12.x: at most 256 per request) does the same in 40.
When the batch call fails as a whole (an account or emulator without
batch support) that chunk is deleted one by one as before; failures of
single blobs inside a batch still raise.
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
        self.blobs.discard(name)


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

    def test_sad_a_failing_blob_inside_a_batch_raises(self) -> None:
        err = PartialBatchErrorException("1 failed", response=None, parts=[])
        c = _Container(self.names(10), batch_error=err)
        with self.assertRaises(PartialBatchErrorException):
            self.session(c)._remove_prefix("dir/")
        self.assertEqual(c.single_calls, 0)

    def test_edge_empty_prefix_and_exact_chunk(self) -> None:
        c = _Container(["other/keep"])
        self.session(c)._remove_prefix("dir/")
        self.assertEqual((c.batch_calls, c.single_calls), ([], 0))
        c = _Container(self.names(256))
        self.session(c)._remove_prefix("dir/")
        self.assertEqual(c.batch_calls, [256])


if __name__ == "__main__":
    unittest.main()
