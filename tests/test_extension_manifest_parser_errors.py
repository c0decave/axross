"""A malformed extension manifest is that extension's error, never the start's.

The review found ``core.extensions._read_manifest`` catching only
SyntaxError, OSError, UnicodeDecodeError and ValueError: ``ast.literal_eval``
raises TypeError on ``EXTENSION = {"name": "X", "tags": {["a"]}}`` (a set of
lists), and ``ast.parse`` raises RecursionError on a 300 KB ``x = 1+1+...``
(under the 512 KiB limit). ``discover()`` then raised - inside
``MainWindow.__init__`` (``ExtensionHost.load_enabled``), in Manage
Extensions, in Reload (after everything had been unloaded) - and safe mode
did not help: ``load_enabled`` ran ``discover()`` before it looked at safe
mode. Now both errors are the entry's error, and safe mode parses nothing.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import extensions as EX  # noqa: E402

SET_OF_LISTS = 'EXTENSION = {"name": "Tagged", "tags": {["a", "b"]}}\ndef activate(api): pass\n'
DEEP = 'EXTENSION = {"name": "Deep"}\nx = ' + "1+" * 150000 + "1\ndef activate(api): pass\n"
GOOD = 'EXTENSION = {"name": "Good"}\ndef activate(api): pass\n'


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    EX.clear_manifest_cache()
    monkeypatch.setattr(EX, "_SAFE_MODE", False)
    yield
    EX.clear_manifest_cache()


def _write(name: str, text: str) -> Path:
    folder = EX.extensions_dir()
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{name}.py"
    path.write_text(text, encoding="utf-8")
    return path


def test_sad_a_manifest_literal_eval_rejects_with_typeerror_is_the_entrys_error():
    _write("tagged", SET_OF_LISTS)
    _write("good", GOOD)
    found = {i.ext_id: i for i in EX.discover(include_bundled=False)}
    assert found["user:tagged"].error == "EXTENSION must be a plain literal dict"
    assert found["user:good"].error == ""


def test_sad_source_nested_too_deeply_for_the_parser_is_the_entrys_error():
    path = _write("deep", DEEP)
    assert path.stat().st_size < EX.MAX_SOURCE_BYTES
    (info,) = EX.discover(include_bundled=False, ids={"user:deep"})
    assert info.error.startswith("cannot parse")


def test_edge_any_other_parser_failure_is_the_entrys_error_too():
    path = _write("odd", GOOD)
    with mock.patch.object(EX.ast, "parse", side_effect=MemoryError()):
        fields, error = EX._manifest(path)
    assert fields == {} and error.startswith("cannot parse")


_APP = []


def _host():
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtWidgets import QApplication, QMainWindow

    from ui.extension_host import ExtensionHost

    if not _APP:  # kept: a collected QApplication takes the process down
        _APP.append(QApplication.instance() or QApplication([]))
    window = QMainWindow()
    menu = window.menuBar().addMenu("Extensions")
    return window, ExtensionHost(window, menu)


def test_happy_the_window_starts_with_a_broken_manifest_switched_on():
    _write("tagged", SET_OF_LISTS)
    EX.set_enabled("user:tagged", True)
    window, host = _host()
    try:
        host.load_enabled()  # what MainWindow.__init__ calls
        assert host.loaded_ids() == []
        assert host.error("user:tagged") == "EXTENSION must be a plain literal dict"
        host.reload()  # Extensions > Reload Extensions
        assert host.error("user:tagged") == "EXTENSION must be a plain literal dict"
    finally:
        window.deleteLater()


def test_happy_safe_mode_parses_no_source_at_all(monkeypatch):
    _write("deep", DEEP)
    EX.set_enabled("user:deep", True)
    monkeypatch.setattr(EX, "_SAFE_MODE", True)
    window, host = _host()
    try:
        with mock.patch.object(EX, "discover", side_effect=AssertionError("parsed in safe mode")):
            host.load_enabled()
        assert host.loaded_ids() == []
        assert host.error("user:deep") == "not loaded: safe mode (--safe-mode)"
    finally:
        window.deleteLater()
