"""ramfs.json that cannot be read gives the defaults, as documented.

Found in review: ``RamFsSettings.load`` caught only JSONDecodeError, so a
non-UTF-8 ramfs.json raised UnicodeDecodeError out of ``get_settings()``
on every RamFS connect (connection_manager) instead of "falling back to
defaults on any error" as its docstring says.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import ramfs_settings as RS  # noqa: E402


class RamFsSettingsLoadTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "ramfs.json"
        patcher = mock.patch.object(RS, "SETTINGS_FILE", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(setattr, RS, "_CACHED", None)

    def test_happy_stored_values_are_read(self) -> None:
        self.path.write_text(json.dumps({"ramfs_enabled": False, "ramfs_max_bytes": 1024}))
        s = RS.reload_settings()
        self.assertFalse(s.ramfs_enabled)
        self.assertEqual(s.ramfs_max_bytes, 1024)

    def test_sad_a_non_utf8_file_gives_the_defaults(self) -> None:
        self.path.write_bytes(b'{"ramfs_enabled": "\xff"}')
        self.assertEqual(RS.reload_settings(), RS.RamFsSettings())

    def test_edge_a_file_nested_past_the_decoders_stack_gives_the_defaults(self) -> None:
        self.path.write_text("[" * 200_000)
        self.assertEqual(RS.reload_settings(), RS.RamFsSettings())


if __name__ == "__main__":
    unittest.main()
