"""Dropbox verbs beyond the core FS calls reach the API.

``list_versions``, ``open_version_read``, ``copy``, ``checksum`` and
``shared_link_create`` called ``self._norm``, which DropboxSession never
defined: every call raised AttributeError before reaching Dropbox.
``list_versions`` logged it and returned ``[]`` ("no history"), ``copy``
and ``checksum`` turned it into an OSError (so callers fell back to a
full stream copy / full read), ``shared_link_create`` let the
AttributeError escape.

Driven with a recording stand-in for the dropbox SDK client; the
session's own path mapping is what is under test.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import dropbox  # noqa: F401

    from core.dropbox_client import DropboxSession

    DROPBOX = True
except ImportError:  # pragma: no cover - optional extra
    DROPBOX = False


class _RecordingDbx:
    def __init__(self) -> None:
        self.calls: list[tuple] = []

    def files_list_revisions(self, path, limit=100):
        self.calls.append(("files_list_revisions", path))
        rev = SimpleNamespace(rev="r1", server_modified=None, size=3)
        return SimpleNamespace(entries=[rev])

    def files_download(self, path, rev=None):
        self.calls.append(("files_download", path, rev))
        return None, SimpleNamespace(content=b"old")

    def files_copy_v2(self, src, dst):
        self.calls.append(("files_copy_v2", src, dst))

    def files_get_metadata(self, path):
        self.calls.append(("files_get_metadata", path))
        return SimpleNamespace(content_hash="c0ffee")

    def sharing_create_shared_link_with_settings(self, path, settings=None):
        self.calls.append(("sharing_create_shared_link_with_settings", path))
        return SimpleNamespace(url="https://www.dropbox.com/s/x")


@unittest.skipUnless(DROPBOX, "dropbox SDK not installed")
class DropboxPathHelperTest(unittest.TestCase):
    def setUp(self) -> None:
        self.dbx = _RecordingDbx()
        self.s = DropboxSession.__new__(DropboxSession)
        self.s._dbx = self.dbx

    def test_happy_versions_and_version_read(self) -> None:
        versions = self.s.list_versions("/docs/a.txt")
        self.assertEqual([v.version_id for v in versions], ["r1"])
        self.assertEqual(self.s.open_version_read("/docs/a.txt", "r1").read(), b"old")
        self.assertEqual(
            self.dbx.calls,
            [("files_list_revisions", "/docs/a.txt"), ("files_download", "/docs/a.txt", "r1")],
        )

    def test_sad_copy_checksum_and_share_reach_the_api(self) -> None:
        self.s.copy("/a.txt", "/b/c.txt")
        self.assertEqual(self.s.checksum("/a.txt"), "dropbox:c0ffee")
        self.assertEqual(self.s.shared_link_create("/a.txt"), "https://www.dropbox.com/s/x")
        self.assertEqual(
            [c[0] for c in self.dbx.calls],
            ["files_copy_v2", "files_get_metadata", "sharing_create_shared_link_with_settings"],
        )

    def test_edge_paths_map_like_the_core_calls(self) -> None:
        # Relative and trailing-slash forms map to the API form that
        # list_dir/open_read use: leading "/", no trailing "/".
        self.s.copy("a.txt", "/dir/")
        self.assertEqual(self.dbx.calls, [("files_copy_v2", "/a.txt", "/dir")])


if __name__ == "__main__":
    unittest.main()
