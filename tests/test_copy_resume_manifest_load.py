"""An unreadable resume manifest is discarded, never an exception.

Found in review: ``_load_manifest`` returns None for a manifest it cannot
use (the copy then starts without it), but caught only JSONDecodeError
around the read and TypeError / ValueError around the parse. A non-UTF-8
manifest (UnicodeDecodeError), a JSON root that is no object
(AttributeError on ``.get``), an infinite number (OverflowError in
``int``) or a payload nested past the decoder's stack (RecursionError)
escaped out of ``resumable_copy`` (``axross.resumable_copy`` in scripts)
instead.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import copy_resume as CR  # noqa: E402


def _good() -> dict:
    size = CR.MIN_SEGMENT_SIZE
    return {
        "src_label": "a",
        "src_path": "/s",
        "dst_label": "b",
        "dst_path": "/d",
        "total_bytes": size,
        "segment_size": size,
        "segments": [{"index": 0, "offset": 0, "length": size, "sha256": "", "done": False}],
    }


class ManifestLoadTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = self.tmp / "m.json"

    def load(self, raw: bytes):
        self.path.write_bytes(raw)
        return CR._load_manifest(self.path)

    def test_happy_a_valid_manifest_loads(self) -> None:
        m = self.load(json.dumps(_good()).encode())
        self.assertEqual(m.total_bytes, CR.MIN_SEGMENT_SIZE)

    def test_sad_unreadable_manifests_give_none(self) -> None:
        infinite = json.dumps({**_good(), "total_bytes": "INF"}).replace('"INF"', "1e400")
        for raw in (b'{"src_path": "\xff"}', b"[]", b'"text"', infinite.encode()):
            with self.subTest(raw=raw[:40]):
                self.assertIsNone(self.load(raw))

    def test_edge_a_manifest_nested_past_the_decoders_stack_gives_none(self) -> None:
        self.assertIsNone(self.load(b"[" * 200_000))

    def test_edge_wrong_typed_segments_give_none(self) -> None:
        for segments in (7, "abc", [{"index": [0]}]):
            with self.subTest(segments=segments):
                self.assertIsNone(self.load(json.dumps({**_good(), "segments": segments}).encode()))


if __name__ == "__main__":
    unittest.main()
