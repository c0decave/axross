"""A hostile ``.axlink`` is a ValueError (or ``is_xlink`` False), never a crash.

Before: ``_decode`` ran ``int(data.get("version") or 0)``. A planted
link with ``"version": [1]`` or ``{}`` raised ``TypeError``, ``1e400``
raised ``OverflowError``; ``is_xlink`` only catches ``ValueError``, so
the "reliable check that returns False on any schema mismatch" raised,
and ``read_xlink`` broke its documented OSError / ValueError contract.
"""

from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import xlink as X  # noqa: E402


class _Backend:
    def __init__(self, raw: bytes) -> None:
        self.raw = raw

    def open_read(self, path):
        return io.BytesIO(self.raw)


def _payload(version) -> bytes:
    return json.dumps(
        {"schema": X.SCHEMA_TAG, "version": version, "target_url": "sftp://host/doc"}
    ).encode("utf-8")


HOSTILE = ([1], {"v": 1}, 1e400)


class HostileVersionTest(unittest.TestCase):
    def test_happy_a_valid_link_still_parses(self) -> None:
        raw = _payload(1)
        self.assertTrue(X.is_xlink(_Backend(raw), "/a.axlink"))
        self.assertEqual(X.read_xlink(_Backend(raw), "/a.axlink").target_url, "sftp://host/doc")

    def test_sad_is_xlink_says_false(self) -> None:
        for version in HOSTILE:
            self.assertFalse(X.is_xlink(_Backend(_payload(version)), "/a.axlink"), version)

    def test_sad_read_xlink_and_decode_raise_value_error(self) -> None:
        for version in HOSTILE:
            with self.assertRaises(ValueError, msg=version):
                X.read_xlink(_Backend(_payload(version)), "/a.axlink")
            with self.assertRaises(ValueError, msg=version):
                X.decode(_payload(version))

    def test_edge_nan_and_out_of_range_versions_are_value_errors(self) -> None:
        nan = _payload("x").replace(b'"x"', b"NaN")
        for raw in (nan, _payload(2), _payload(0), _payload(-1)):
            with self.assertRaises(ValueError):
                X.decode(raw)
            self.assertFalse(X.is_xlink(_Backend(raw), "/a.axlink"))


if __name__ == "__main__":
    unittest.main()
