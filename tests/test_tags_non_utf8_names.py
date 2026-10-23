"""Tags work for a file whose name is not valid UTF-8.

Measured before: Linux file names are bytes; Python hands a name like
``caf\\xe9.txt`` (Latin-1, from an old archive or share) over as
``'caf\\udce9.txt'``. ``TagStore._save`` wrote ``tags.json`` with
``json.dump(..., ensure_ascii=False)`` into a UTF-8 text file, which
cannot encode that: tagging the file raised UnicodeEncodeError - and the
entry stayed in memory, so every later save (any tag on any file, a tag
following a move) failed the same way and nothing was written any more.

Now such a character is written as its JSON escape (``\\udce9``), which
reads back as the same name; every other character is written as it is,
so the file stays hand-editable.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import tags as TG  # noqa: E402

LATIN1 = os.fsdecode(b"/data/caf\xe9.txt")


def test_happy_a_non_utf8_name_is_tagged_and_read_back(tmp_path):
    store = TG.TagStore(tmp_path / "tags.json")
    store.tag("Local", "", LATIN1, "Important")
    again = TG.TagStore(tmp_path / "tags.json")
    assert again.tags_of("Local", LATIN1) == ["Important"]


def test_sad_one_such_name_no_longer_stops_every_later_save(tmp_path):
    store = TG.TagStore(tmp_path / "tags.json")
    store.tag("Local", "", LATIN1, "Important")
    store.tag("Local", "", "/data/plain.txt", "Review later")
    store.move_path("Local", LATIN1, os.fsdecode(b"/moved/caf\xe9.txt"))
    again = TG.TagStore(tmp_path / "tags.json")
    assert again.tags_of("Local", "/data/plain.txt") == ["Review later"]
    assert again.tags_of("Local", os.fsdecode(b"/moved/caf\xe9.txt")) == ["Important"]
    assert not list(tmp_path.glob(".tags.*"))  # no temp file left behind


def test_edge_the_file_stays_valid_utf8_with_readable_non_ascii(tmp_path):
    store = TG.TagStore(tmp_path / "tags.json")
    store.tag("Local", "", "/data/Größe café.txt", "Important")
    store.tag("Local", "", LATIN1, "Important")
    raw = (tmp_path / "tags.json").read_bytes()
    text = raw.decode("utf-8")  # strict: valid UTF-8
    assert "Größe café.txt" in text  # hand-editable, not \\u escaped
    assert "\\udce9" in text
    paths = {item["path"] for item in json.loads(text)["items"]}
    assert paths == {"/data/Größe café.txt", LATIN1}


def test_e2e_tag_from_the_pane_context_menu(tmp_path, monkeypatch):
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtWidgets import QApplication

    from tests.test_tags import _select, _window

    app = QApplication.instance() or QApplication([])
    monkeypatch.setattr(TG, "tags_file", lambda: tmp_path / "tags.json")
    TG.reset_cache()
    folder = tmp_path / "data"
    folder.mkdir()
    raw_name = b"caf\xe9.txt"
    with open(os.path.join(os.fsencode(folder), raw_name), "wb") as fh:
        fh.write(b"x")
    name = os.fsdecode(raw_name)
    win = _window(tmp_path)
    try:
        pane = win._active_pane
        pane.navigate(str(folder))
        app.processEvents()
        _select(pane, name)
        menu = pane._build_context_menu()
        tags_menu = next(a.menu() for a in menu.actions() if a.text().replace("&", "") == "Tags")
        important = next(a for a in tags_menu.actions() if a.text() == "Important")
        important.trigger()
        path = os.fsdecode(os.path.join(os.fsencode(folder), raw_name))
        assert TG.store().tags_of("Local", path) == ["Important"]
        TG.reset_cache()
        assert TG.store().tags_of("Local", path) == ["Important"]  # it was saved
    finally:
        win.close()
        win.deleteLater()
        TG.reset_cache()
