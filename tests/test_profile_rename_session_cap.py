"""A profile rename does not rewrite a session.json the window never writes.

Measured before: _rename_in_session read session.json without a size limit
and rewrote one over 1 MB - the window refuses such a file and never writes
it again (docs/USAGE.md). Now the rename leaves it as it is, and the other
store (bookmarks) is renamed regardless.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import i18n  # noqa: E402
from core.profile_references import rename_profile_references  # noqa: E402


class _NoBookmarks:
    def all(self):
        return []

    def save(self):
        pass


def _session(path: Path, pad: int) -> bytes:
    data = {"window": {}, "pad": "x" * pad, "workspaces": [
        {"name": "W", "splitter": {"type": "splitter", "children": [
            {"type": "pane", "profile": "nas", "path": "/"}]}}]}
    raw = json.dumps(data).encode()
    path.write_bytes(raw)
    return raw


def test_sad_an_oversized_session_is_not_rewritten(tmp_path):
    path = tmp_path / "session.json"
    raw = _session(path, i18n.MAX_SESSION_BYTES)
    counts = rename_profile_references("nas", "nas2", bookmarks=_NoBookmarks(), session_file=path)
    assert counts["session"] == 0
    assert path.read_bytes() == raw


def test_happy_a_normal_session_is_renamed(tmp_path):
    path = tmp_path / "session.json"
    _session(path, 10)
    counts = rename_profile_references("nas", "nas2", bookmarks=_NoBookmarks(), session_file=path)
    assert counts["session"] == 1
    assert '"nas2"' in path.read_text()
