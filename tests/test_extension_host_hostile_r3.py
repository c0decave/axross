"""Extension code that fails in the less usual ways still never takes axross down.

Measured before (review round 3):

* an exception whose ``str()`` itself raises (a class that sets its message
  in ``__init__`` without calling ``super().__init__`` and reads it in
  ``__str__``) raised again while the host reported it: out of
  ``load_enabled`` inside the window's construction, at every start (the
  startup marker was removed already);
* any BaseException but SystemExit - ``asyncio.CancelledError`` from asyncio
  code - went past every guard the same way; from run_in_background's work
  the worker thread died and neither on_done nor on_error ever ran;
* a dock the extension had deleted itself (WA_DeleteOnClose, then [x]) made
  switching the extension off raise RuntimeError: its menu entry stayed and
  still ran its code, and unload_all (Reload, closing the window) stopped
  half way, the extensions after it never deactivated;
* "Keep Off" in the start notice raised an OSError of the settings file into
  the error dialog.

Ctrl+C (KeyboardInterrupt) stays the user's.
"""

from __future__ import annotations

import os
import sys
import textwrap
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication, QMainWindow, QMenu  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])

_UNPRINTABLE = """
class Odd(Exception):
    def __init__(self):
        pass  # no super().__init__: self.msg is never set

    def __str__(self):
        return self.msg
"""


@pytest.fixture(autouse=True)
def own_home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path / "home"))


def write_ext(name: str, body: str) -> None:
    folder = EX.extensions_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / f"{name}.py").write_text(
        f'EXTENSION = {{"name": "{name.title()}", "version": "1.0"}}\n\n' + textwrap.dedent(body))
    EX.set_enabled(f"user:{name}", True)


@pytest.fixture
def host():
    from ui.extension_host import ExtensionHost

    window = QMainWindow()
    h = ExtensionHost(window, QMenu(window))
    yield h
    h.unload_all()
    window.deleteLater()
    APP.processEvents()


def test_sad_an_unprintable_exception_in_activate_is_recorded(host):
    write_ext("odd", _UNPRINTABLE + "\ndef activate(api):\n    raise Odd()\n")
    host.load_enabled()  # raised AttributeError before
    assert "user:odd" not in host._loaded
    assert "Odd" in host._errors.get("user:odd", "")


def test_sad_an_unprintable_exception_in_a_handler_is_recorded(host):
    write_ext("odd2", _UNPRINTABLE + "\ndef activate(api):\n    pass\n")
    host.load_enabled()
    _module, api = host._loaded["user:odd2"]
    odd = host._loaded["user:odd2"][0].Odd

    def boom():
        raise odd()

    assert host.call(api, boom) is None
    assert "Odd" in host._errors.get("user:odd2", "")


def test_sad_a_cancelled_error_in_activate_is_recorded(host):
    write_ext("cancel", """
        import asyncio

        def activate(api):
            api.add_menu_action("Left behind", lambda: None)
            raise asyncio.CancelledError()
    """)
    host.load_enabled()  # raised CancelledError before
    assert "user:cancel" not in host._loaded
    assert "CancelledError" in host._errors.get("user:cancel", "")
    assert not any("Left behind" in a.text() for a in host.menu.actions())


def test_sad_a_cancelled_error_in_background_work_reaches_on_error(host):
    write_ext("bg", "def activate(api):\n    pass\n")
    host.load_enabled()
    _module, api = host._loaded["user:bg"]
    import asyncio

    got = []

    def work():
        raise asyncio.CancelledError()

    api.run_in_background(work, on_done=lambda v: got.append(("done", v)),
                          on_error=lambda e: got.append(("error", type(e).__name__)))
    deadline = time.monotonic() + 5
    while not got and time.monotonic() < deadline:
        APP.processEvents()
        time.sleep(0.01)
    assert got == [("error", "CancelledError")]


def test_edge_keyboard_interrupt_stays_the_users(host):
    write_ext("kbd", "def activate(api):\n    pass\n")
    host.load_enabled()
    _module, api = host._loaded["user:kbd"]

    def interrupt():
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        host.call(api, interrupt)


def test_sad_a_dock_the_extension_deleted_does_not_stop_switch_off(host):
    write_ext("dockdel", """
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import QLabel

        def activate(api):
            api.add_menu_action("Dockdel action", lambda: None)
            dock = api.add_dock("Dockdel", QLabel("x"))
            dock.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose, True)
            global DOCK
            DOCK = dock
    """)
    write_ext("after", "def activate(api):\n    pass\n\ndef deactivate(api):\n    api.gone = True\n")
    host.load_enabled()
    module, _api = host._loaded["user:dockdel"]
    module.DOCK.close()  # [x]: deleted
    APP.processEvents()
    from PyQt6.QtCore import QCoreApplication, QEvent

    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    _m, after_api = host._loaded["user:after"]
    host.unload_all()  # raised RuntimeError before
    assert host._loaded == {}
    assert not any("Dockdel action" in a.text() for a in host.menu.actions())
    assert getattr(after_api, "gone", False)


def test_sad_keep_off_with_an_unwritable_settings_file_is_told(host, monkeypatch):
    write_ext("keep", "def activate(api):\n    pass\n")
    host.load_enabled()
    with mock.patch.object(EX, "set_enabled", side_effect=OSError(30, "Read-only file system")):
        assert host.switch_off("user:keep") is False
    assert "Read-only file system" in host._errors.get("user:keep", "")


def _window_stub(module, set_enabled=None):
    import types

    from ui.main_window import MainWindow

    shown = []
    host = types.SimpleNamespace(
        module=lambda ext_id: module,
        loaded_ids=lambda: {"user:x"},
        set_enabled=set_enabled or (lambda *a: None),
        error=lambda ext_id: "",
    )
    stub = types.SimpleNamespace(
        extension_host=host,
        statusBar=lambda: types.SimpleNamespace(showMessage=lambda text, *a: shown.append(text)),
        _switch_on_extension=lambda ext_id, title: True,
    )
    stub._open_extension_window = types.MethodType(MainWindow._open_extension_window, stub)
    return stub, shown


def test_sad_sys_exit_in_show_window_does_not_end_axross():
    import types

    module = types.SimpleNamespace(show_window=lambda window: sys.exit(4))
    stub, shown = _window_stub(module)
    stub._open_extension_window("user:x", "X")  # ended the process before
    assert shown and "could not open" in shown[0]


def test_sad_switch_on_with_an_unwritable_settings_file_is_told(monkeypatch):
    import types

    from PyQt6.QtWidgets import QMessageBox

    from ui.main_window import MainWindow

    def unwritable(*a):
        raise OSError(30, "Read-only file system")

    shown = []
    host = types.SimpleNamespace(set_enabled=unwritable, loaded_ids=lambda: set(),
                                 error=lambda ext_id: "")
    stub = types.SimpleNamespace(
        extension_host=host,
        statusBar=lambda: types.SimpleNamespace(showMessage=lambda text, *a: shown.append(text)),
    )
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)
    switch = types.MethodType(MainWindow._switch_on_extension, stub)
    assert switch("user:x", "X") is False  # raised into the error dialog before
    assert shown and "Read-only file system" in shown[0]


def test_sad_add_dock_of_no_widget_leaves_no_dock_behind(host):
    write_ext("nodock", """
        def activate(api):
            try:
                api.add_dock("Nothing", "not a widget")
            except TypeError:
                pass
    """)
    host.load_enabled()
    from PyQt6.QtWidgets import QDockWidget

    window = host.window
    assert "user:nodock" in host._loaded
    host.unload_all()
    APP.processEvents()
    from PyQt6.QtCore import QCoreApplication, QEvent

    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    assert window.findChildren(QDockWidget) == []
