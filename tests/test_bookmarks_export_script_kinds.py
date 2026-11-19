"""The bundled bookmarks_export script: what it cannot restore it leaves out.

Measured before: write_json wrote name, path, backend and profile of every
bookmark, and import_json added each entry back as a folder bookmark. A
terminal bookmark came back as a folder on its profile (a host terminal's
profile name is its address: "the profile no longer exists"), and a Smart
Folder as a folder named "search:..." on a backend "Smart Folder" - two
broken bookmarks after a round trip. The export now names each one's kind,
and the import adds folder bookmarks only and says what it left out.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import bookmarks as BM  # noqa: E402
from core import scripting  # noqa: E402


def _script() -> dict:
    path = ROOT / "resources" / "scripts" / "bookmarks_export.py"
    ns: dict = {"__name__": "__axross_script__", "__file__": str(path), "axross": scripting}
    exec(compile(path.read_text(encoding="utf-8"), str(path), "exec"), ns)
    return ns


@pytest.fixture()
def store(tmp_path):
    file = tmp_path / "bookmarks.json"
    with mock.patch.object(BM, "BOOKMARKS_FILE", file):
        yield file


def test_sad_terminal_and_smart_folder_bookmarks_do_not_come_back_as_folders(
    store, tmp_path, capsys
):
    mgr = BM.BookmarkManager()
    mgr.add(BM.Bookmark(name="logs", path="/var/log"))
    mgr.add(BM.Bookmark(name="prod shell", path="/srv", profile_name="prod",
                        kind=BM.KIND_TERMINAL))
    mgr.add(BM.Bookmark(name="box", path="", kind=BM.KIND_TERMINAL, host="box.example",
                        username="me"))
    mgr.add(BM.new_smart_folder("big files", {"pattern": "*.iso"}))
    ns = _script()
    out = tmp_path / "export.json"
    assert ns["write_json"](str(out)) == 4
    exported = json.loads(out.read_text(encoding="utf-8"))
    assert [e["kind"] for e in exported] == ["folder", "terminal", "terminal", "folder"]
    assert exported[3]["smart_folder"] is True

    store.write_text("[]", encoding="utf-8")
    assert ns["import_json"](str(out)) == 1
    marks = BM.BookmarkManager().all()
    assert [(b.name, b.kind) for b in marks] == [("logs", "folder")]
    said = capsys.readouterr().out
    assert "prod shell" in said and "box" in said and "big files" in said


def test_happy_an_older_export_still_imports(store, tmp_path):
    out = tmp_path / "old.json"
    out.write_text(json.dumps([{"name": "logs", "path": "/var/log", "backend_name": "Local",
                                "profile_name": "", "icon_name": "bookmark"}]),
                   encoding="utf-8")
    assert _script()["import_json"](str(out)) == 1
    assert [b.path for b in BM.BookmarkManager().all()] == ["/var/log"]
