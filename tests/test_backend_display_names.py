"""Backend names in the protocol picker are English.

The S3 entry read "S3-kompatibel" in an otherwise English list.
"""

from __future__ import annotations

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import backend_registry as R  # noqa: E402

# German words that turn up in UI labels; none belongs in a protocol name.
_GERMAN = re.compile(r"(?i)kompatibel|nur[ -]lesen|schreibgesch|freigabe|laufwerk|ordner|datei|flüchtig")


class DisplayNameTest(unittest.TestCase):
    def setUp(self) -> None:
        R.ensure_initialized()

    def test_happy_s3_is_labelled_in_english(self) -> None:
        self.assertEqual(R.get("s3").display_name, "S3-compatible")

    def test_sad_no_protocol_name_carries_a_german_word(self) -> None:
        names = [b.display_name for b in R.all_backends()]
        self.assertGreater(len(names), 30)
        self.assertEqual([n for n in names if _GERMAN.search(n)], [])

    def test_edge_names_are_unique_and_not_blank(self) -> None:
        names = [b.display_name for b in R.all_backends()]
        self.assertTrue(all(n.strip() for n in names))
        self.assertEqual(len(names), len(set(names)))


if __name__ == "__main__":
    unittest.main()
