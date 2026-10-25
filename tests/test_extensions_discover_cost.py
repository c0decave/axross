"""Discovering extensions parses a file only when needed.

2026-10-25 performance round: core.extensions.discover() parsed all eleven
bundled extensions (45-56 ms) at every start, also when none is switched
on, and again each time Settings opened its Extensions page. A manifest is
now parsed once per file state, and the start parses only the switched-on
ones.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import extensions as EX  # noqa: E402

GOOD = 'EXTENSION = {"name": "%s", "version": "1"}\ndef activate(api):\n    pass\n'


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    (tmp_path / "home").mkdir()
    EX.clear_manifest_cache()
    yield
    EX.clear_manifest_cache()


def _user_ext(name: str, source: str) -> Path:
    folder = EX.extensions_dir()
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}.py"
    path.write_text(source, encoding="utf-8")
    return path


def _parses(act) -> int:
    with mock.patch.object(EX.ast, "parse", wraps=EX.ast.parse) as parse:
        act()
    return parse.call_count


def test_happy_a_second_discover_parses_nothing():
    first = _parses(lambda: EX.discover())
    assert first >= 11  # the bundled ones
    assert _parses(lambda: EX.discover()) == 0


def test_happy_the_cached_result_is_the_same():
    _user_ext("hello", GOOD % "Hello")
    assert EX.discover() == EX.discover()


def test_happy_only_the_asked_ids_are_parsed():
    _user_ext("hello", GOOD % "Hello")
    found = []
    assert _parses(lambda: found.extend(EX.discover(ids={"user:hello"}))) == 1
    assert [info.ext_id for info in found] == ["user:hello"]
    assert found[0].name == "Hello"


def test_edge_no_ids_parses_nothing_and_finds_nothing():
    _user_ext("hello", GOOD % "Hello")
    found = []
    assert _parses(lambda: found.extend(EX.discover(ids=set()))) == 0
    assert found == []


def test_sad_an_edited_file_is_parsed_again():
    path = _user_ext("hello", GOOD % "Hello")
    assert [i.name for i in EX.discover(ids={"user:hello"})] == ["Hello"]
    path.write_text(GOOD % "Hello Again", encoding="utf-8")
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    assert [i.name for i in EX.discover(ids={"user:hello"})] == ["Hello Again"]


def test_sad_an_edit_of_the_same_size_and_time_is_still_seen():
    """mtime alone can miss an edit on a coarse clock: the change time and
    the inode count too (a save by rename makes a new inode)."""
    path = _user_ext("hello", GOOD % "Hello")
    assert [i.name for i in EX.discover(ids={"user:hello"})] == ["Hello"]
    stat = path.stat()
    replacement = path.with_name("hello.tmp")
    replacement.write_text(GOOD % "Jello", encoding="utf-8")
    os.utime(replacement, ns=(stat.st_atime_ns, stat.st_mtime_ns))
    os.replace(replacement, path)
    assert [i.name for i in EX.discover(ids={"user:hello"})] == ["Jello"]


def test_sad_a_broken_file_keeps_its_error_and_a_fix_clears_it():
    path = _user_ext("hello", "def activate(api):\n    pass\n")
    assert EX.discover(ids={"user:hello"})[0].error
    assert EX.discover(ids={"user:hello"})[0].error  # from the cache, same answer
    time.sleep(0.01)
    path.write_text(GOOD % "Hello", encoding="utf-8")
    stat = path.stat()
    os.utime(path, ns=(stat.st_atime_ns, stat.st_mtime_ns + 1_000_000_000))
    assert EX.discover(ids={"user:hello"})[0].error == ""


def test_edge_a_removed_file_is_no_longer_found():
    path = _user_ext("hello", GOOD % "Hello")
    assert EX.discover(ids={"user:hello"})
    path.unlink()
    assert EX.discover(ids={"user:hello"}) == []


def test_happy_the_start_parses_no_extension_when_none_is_switched_on():
    """The host's start asks only for the switched-on ids."""
    asked = []
    real = EX.discover

    def spy(*args, **kwargs):
        asked.append(kwargs.get("ids"))
        return real(*args, **kwargs)

    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication, QMainWindow, QMenu

    from ui.extension_host import ExtensionHost

    _app = QApplication.instance() or QApplication([])
    window = QMainWindow()
    host = ExtensionHost(window, QMenu(window))
    with mock.patch.object(EX, "discover", side_effect=spy):
        parses = _parses(host.load_enabled)
    assert asked == [set()] and parses == 0
    window.deleteLater()
