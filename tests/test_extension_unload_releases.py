"""Switching an extension off (or Reload) lets go of all of it.

The review found two leaks in ui/extension_host.py:

* ``add_menu_action`` and the "Pause <name>" entry make ``QAction(...,
  window)``; ``_remove_all`` took them out of the menus but never deleted
  them, and their lambdas held the API and with it the extension's whole
  module - +50 MiB per on/off cycle of an extension with a 50 MiB global.
* For a package extension only the package left ``sys.modules`` on unload:
  its submodules stayed cached, so Reload ran the old ``words.py`` next to
  the new ``__init__.py``; and they were imported by the normal machinery,
  which wrote ``__pycache__`` into the user's extension folder.

A dock's own toggle action is not the API's to delete: it goes with its dock.
"""

from __future__ import annotations

import gc
import os
import sys
import textwrap
import time
import weakref
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtGui import QAction  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMainWindow  # noqa: E402

from core import extensions as EX  # noqa: E402
from ui.extension_host import ExtensionHost  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    EX.clear_manifest_cache()
    monkeypatch.setattr(EX, "_SAFE_MODE", False)


@pytest.fixture
def host():
    window = QMainWindow()
    menu = window.menuBar().addMenu("Extensions")
    yield ExtensionHost(window, menu)
    window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


def _settle() -> None:
    APP.processEvents()
    # What the running event loop does with deleteLater().
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    gc.collect()


def _write_ext(name: str, body: str) -> None:
    folder = EX.extensions_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.py").write_text(
        f'EXTENSION = {{"name": "{name.title()}"}}\n' + textwrap.dedent(body))


class _Marker:
    """Stands for the extension's module data: alive while the module is."""


def test_happy_switching_off_deletes_the_menu_and_pause_actions_and_frees_the_module(host):
    _write_ext("hello", """
        def activate(api):
            api.add_menu_action("Say Hello", lambda: api.notify(str(MARKER)))
            api.on("path_changed", lambda ctx: None)   # offers "Pause Hello"
    """)
    host.set_enabled("user:hello", True)
    module = host.module("user:hello")
    assert module is not None, host.error("user:hello")
    module.MARKER = _Marker()
    alive = weakref.ref(module.MARKER)
    texts = {a.text() for a in host.window.findChildren(QAction)}
    assert {"Say Hello", "Pause Hello"} <= texts
    del module
    host.set_enabled("user:hello", False)
    _settle()
    texts = {a.text() for a in host.window.findChildren(QAction)}
    assert "Say Hello" not in texts and "Pause Hello" not in texts
    assert alive() is None, "the switched-off extension's module is still alive"


def test_edge_on_off_cycles_leave_no_actions_behind(host):
    _write_ext("hello", """
        def activate(api):
            api.add_menu_action("Say Hello", lambda: None)
    """)
    for _ in range(3):
        host.set_enabled("user:hello", True)
        host.set_enabled("user:hello", False)
        _settle()
    assert [a for a in host.window.findChildren(QAction) if a.text() == "Say Hello"] == []


def test_edge_a_panels_toggle_action_goes_with_its_dock_the_rest_is_deleted(host):
    from PyQt6 import sip

    _write_ext("panel", """
        from PyQt6.QtWidgets import QLabel
        def activate(api):
            api.add_dock("My Panel", QLabel("x"))
            api.add_menu_action("Panel Settings", lambda: None)
    """)
    host.set_enabled("user:panel", True)
    (dock,) = host.docks("user:panel")
    toggle = dock.toggleViewAction()
    (settings,) = [a for a in host.window.findChildren(QAction) if a.text() == "Panel Settings"]
    host.set_enabled("user:panel", False)
    _settle()
    assert sip.isdeleted(dock) and sip.isdeleted(toggle)
    assert sip.isdeleted(settings)


def _write_package(words: str, name: str = "greeter") -> Path:
    pkg = EX.extensions_dir() / name
    pkg.mkdir(parents=True, exist_ok=True)
    (pkg / "__init__.py").write_text(
        f'EXTENSION = {{"name": "{name.title()}"}}\n'
        "from . import words\n"
        "SEEN = []\n"
        "def activate(api):\n"
        "    SEEN.append(words.GREETING)\n")
    (pkg / "words.py").write_text(f"GREETING = {words!r}\n")
    return pkg


def test_happy_reload_runs_the_current_source_of_a_packages_submodule(host):
    pkg = _write_package("hello v1")
    EX.set_enabled("user:greeter", True)
    host.load_enabled()
    assert host.module("user:greeter").SEEN == ["hello v1"], host.error("user:greeter")
    time.sleep(0.01)
    (pkg / "words.py").write_text('GREETING = "hello v2"\n')  # same size as before
    host.reload()
    assert host.module("user:greeter").SEEN == ["hello v2"]


def test_happy_switching_a_package_off_drops_its_submodules(host):
    _write_package("hello")
    host.set_enabled("user:greeter", True)
    assert "axross_extension_user_greeter.words" in sys.modules
    host.set_enabled("user:greeter", False)
    assert [m for m in sys.modules if m.startswith("axross_extension_user_greeter")] == []


def test_sad_no_byte_code_is_written_into_the_users_extension_folder(host, monkeypatch):
    # A name no other test uses: a submodule cached by an earlier test (the
    # leak above) would be reused and write nothing.
    monkeypatch.setattr(sys, "dont_write_bytecode", False)
    pkg = _write_package("hello", "bytecode_probe")
    host.set_enabled("user:bytecode_probe", True)
    assert host.module("user:bytecode_probe").SEEN == ["hello"], host.error("user:bytecode_probe")
    assert not (pkg / "__pycache__").exists()
