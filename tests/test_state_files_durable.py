"""session.json and bookmarks.json reach the disk before they replace the old
file, and the language is read from a bounded session.json.

Measured before: the window's state files (session.json, the viewers' sizes)
and bookmarks.json were written to a temp file and renamed over the old one
without an fsync - a crash or power cut shortly after left an empty or
truncated file on ext4/xfs, the layout or every bookmark gone. The language
written from the settings page did the same. ``stored_language`` read the
whole session.json, of any size, before the window existed (the window itself
refuses one over 1 MB).
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import bookmarks as BM  # noqa: E402
from core import i18n  # noqa: E402


def _fsynced_before_replace(action, target: Path) -> bool:
    """Run *action*; True when a file descriptor was fsynced before the
    rename that put *target* in place."""
    events: list[str] = []
    real_fsync, real_replace = os.fsync, os.replace

    def fsync(fd):
        events.append("fsync")
        return real_fsync(fd)

    def replace(src, dst, *args, **kwargs):
        if Path(dst) == target:
            events.append("replace")
        return real_replace(src, dst, *args, **kwargs)

    with mock.patch("os.fsync", fsync), mock.patch("os.replace", replace):
        action()
    assert "replace" in events
    return "fsync" in events[: events.index("replace")]


def test_happy_the_window_state_write_is_synced(tmp_path):
    from ui.state_files import _write_private_text

    target = tmp_path / "session.json"
    assert _fsynced_before_replace(lambda: _write_private_text(target, "{}"), target)
    assert target.read_text(encoding="utf-8") == "{}"
    assert target.stat().st_mode & 0o777 == 0o600


def test_happy_the_bookmarks_write_is_synced(tmp_path):
    target = tmp_path / "bookmarks.json"
    with mock.patch.object(BM, "BOOKMARKS_FILE", target):
        mgr = BM.BookmarkManager()
        assert _fsynced_before_replace(
            lambda: mgr.add(BM.Bookmark(name="a", path="/a")), target
        )


def test_happy_the_stored_language_is_synced(tmp_path):
    target = tmp_path / "session.json"
    target.write_text(json.dumps({"window": {"x": 1}}), encoding="utf-8")
    assert _fsynced_before_replace(lambda: i18n.store_language("de", target), target)
    data = json.loads(target.read_text(encoding="utf-8"))
    assert data == {"window": {"x": 1, "language": "de"}}
    assert target.stat().st_mode & 0o777 == 0o600


def test_sad_the_language_is_not_read_from_an_oversized_session(tmp_path):
    target = tmp_path / "session.json"
    padding = "x" * (i18n.MAX_SESSION_BYTES + 10)
    target.write_text(json.dumps({"window": {"language": "de"}, "pad": padding}),
                      encoding="utf-8")
    reads: list[int] = []
    real = Path.read_bytes

    def read_bytes(self):
        data = real(self)
        reads.append(len(data))
        return data

    with mock.patch.object(Path, "read_bytes", read_bytes), mock.patch.object(
        Path, "read_text", side_effect=AssertionError("read whole")
    ):
        assert i18n.stored_language(target) is None
    assert all(n <= i18n.MAX_SESSION_BYTES for n in reads)


def test_happy_the_language_of_a_normal_session_is_read(tmp_path):
    target = tmp_path / "session.json"
    target.write_text(json.dumps({"window": {"language": "de"}}), encoding="utf-8")
    assert i18n.stored_language(target) == "de"
