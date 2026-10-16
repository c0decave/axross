"""Exchange folders listed under a sanitised name can be opened.

The root listing shows ``_sanitize(folder.name)`` - ``Projects: 2025``
becomes ``Projects_ 2025``, ``A/B`` becomes ``A_B`` - but the path
lookup asked exchangelib for a child literally named ``Projects_ 2025``.
No such folder exists, so list_dir fell through to the attachment
branch and failed: every folder whose name has one of ``/\\:*?"<>|``
was visible and could not be opened.

The folder tree is a stand-in whose ``/`` operator matches children the
way exchangelib's ``BaseFolder.__truediv__`` does (case-insensitive,
exact name, ErrorFolderNotFound otherwise).
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from exchangelib.errors import ErrorFolderNotFound

    from core import exchange_client as EC
except ImportError:  # pragma: no cover
    EC = None


class _Folder:
    def __init__(self, name: str, children=(), messages=()) -> None:
        self.name = name
        self.children = list(children)
        self._messages = list(messages)

    def __truediv__(self, other: str) -> "_Folder":
        for c in self.children:
            if c.name.lower() == other.lower():
                return c
        raise ErrorFolderNotFound(f"No subfolder with name {other!r}")

    def all(self):
        msgs = self._messages

        class _QS:
            def only(self, *fields):
                return iter(msgs)

        return _QS()


def _msg(mid: str, subject: str):
    return SimpleNamespace(id=mid, subject=subject, size=10, datetime_received=None,
                           has_attachments=False)


@unittest.skipIf(EC is None, "exchangelib not installed")
class SanitizedFolderNameTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = _Folder(
            "root",
            [
                _Folder("Inbox", messages=[_msg("M1", "hi")]),
                _Folder("Projects: 2025", messages=[_msg("M2", "plan")]),
                _Folder("A/B", [_Folder("C?", messages=[_msg("M3", "deep")])]),
            ],
        )
        self.s = object.__new__(EC.ExchangeSession)
        self.s._account = SimpleNamespace(root=self.root)

    def _names(self, path: str) -> list[str]:
        return [i.name for i in self.s.list_dir(path)]

    def test_happy_plain_folder(self) -> None:
        self.assertIn("Inbox", self._names("/"))
        self.assertEqual(self._names("/Inbox"), ["M1_hi.eml"])

    def test_sad_listed_sanitised_name_opens_the_folder(self) -> None:
        listed = self._names("/")
        self.assertIn("Projects_ 2025", listed)
        self.assertEqual(self._names("/Projects_ 2025"), ["M2_plan.eml"])
        self.assertTrue(self.s.stat("/Projects_ 2025").is_dir)

    def test_edge_nested_sanitised_names_and_unknown_folder(self) -> None:
        self.assertEqual(self._names("/A_B/C_"), ["M3_deep.eml"])
        with self.assertRaises(OSError):
            self.s._resolve_folder(["Nope"])


if __name__ == "__main__":
    unittest.main()
