"""A malformed .axlink is a schema error, never another exception.

Found in review: ``_decode`` ran ``int(data.get("version") or 0)``, which
raises TypeError for ``[1]`` / ``{}`` and OverflowError for ``1e400``, and
``json.loads`` raises RecursionError for a payload nested past the
decoder's stack. All three escaped ``is_xlink`` (documented to return
False on any schema mismatch) and ``read_xlink`` / ``decode``
(documented to raise ValueError for a corrupt link). A .axlink is a file
on a server, so its bytes are whatever someone put there.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import xlink as XL  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class XlinkDecodeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.fs = LocalFS()
        self.path = self.tmp / "link.axlink"

    def payload(self, **fields) -> bytes:
        data = {"schema": XL.SCHEMA_TAG, "version": 1, "target_url": "sftp://h/x"}
        data.update(fields)
        return json.dumps(data).encode()

    def assert_corrupt(self, raw: bytes) -> None:
        self.path.write_bytes(raw)
        self.assertFalse(XL.is_xlink(self.fs, str(self.path)))
        with self.assertRaises(ValueError):
            XL.read_xlink(self.fs, str(self.path))
        with self.assertRaises(ValueError):
            XL.decode(raw)

    def test_happy_a_written_link_reads_back(self) -> None:
        final = XL.create_xlink(self.fs, str(self.tmp / "l"), "sftp://host/dir", "Dir")
        self.assertTrue(XL.is_xlink(self.fs, final))
        self.assertEqual(XL.read_xlink(self.fs, final).target_url, "sftp://host/dir")

    def test_sad_a_version_of_the_wrong_type_is_a_schema_error(self) -> None:
        for version in ([1], {"v": 1}, "one"):
            with self.subTest(version=version):
                self.assert_corrupt(self.payload(version=version))

    def test_sad_an_infinite_version_is_a_schema_error(self) -> None:
        raw = self.payload(version="INF").replace(b'"INF"', b"1e400")
        self.assert_corrupt(raw)

    def test_edge_a_payload_nested_past_the_decoders_stack_is_a_schema_error(self) -> None:
        self.assert_corrupt(b"[" * XL.MAX_LINK_SIZE)

    def test_edge_a_numeric_string_version_still_reads(self) -> None:
        self.path.write_bytes(self.payload(version="1"))
        self.assertTrue(XL.is_xlink(self.fs, str(self.path)))


if __name__ == "__main__":
    unittest.main()
