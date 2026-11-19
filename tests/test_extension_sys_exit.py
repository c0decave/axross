"""An extension that calls sys.exit() never takes axross down.

Review 2026-11-19 (round 1): ``ExtensionHost.load`` and ``call`` caught
``Exception`` only. ``sys.exit()`` in an extension's module code or
``activate()`` raised SystemExit out of ``load_enabled`` - inside
``MainWindow.__init__`` at start - and axross quit. The ``finally`` removed
the startup marker, so the next start did not suspend the extension:
axross quit at every start until --safe-mode. What it had registered
stayed. docs/EXTENSIONS.md: "An extension that raises an error never
takes axross down". A SystemExit in a handler or in run_in_background's
work is an error of the extension as well.
"""

from __future__ import annotations

import os
import sys
import textwrap
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")

from PyQt6.QtWidgets import QApplication, QMainWindow, QMenu  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])


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


@pytest.mark.parametrize("where", ["module", "activate"])
def test_sad_sys_exit_while_loading_is_an_error_of_the_extension(host, where):
    if where == "module":
        write_ext("bye", "import sys\nsys.exit(0)\ndef activate(api):\n    pass\n")
    else:
        write_ext("bye", """
            import sys

            def activate(api):
                api.add_menu_action("Left behind", lambda: None)
                sys.exit(3)
        """)
    host.load_enabled()  # raised SystemExit before
    assert "user:bye" not in host._loaded
    assert "SystemExit" in host._errors.get("user:bye", "")
    assert not any("Left behind" in a.text() for a in host.menu.actions())


def test_sad_sys_exit_in_a_handler_is_recorded(host):
    write_ext("handler", """
        import sys

        def activate(api):
            pass
    """)
    host.load_enabled()
    _module, api = host._loaded["user:handler"]
    assert host.call(api, lambda: sys.exit(1)) is None  # raised before
    assert "SystemExit" in host._errors.get("user:handler", "")


def test_sad_sys_exit_in_background_work_reaches_on_error(host):
    write_ext("worker", "def activate(api):\n    pass\n")
    host.load_enabled()
    _module, api = host._loaded["user:worker"]
    seen: list = []
    host.run_in_background(api, lambda: sys.exit(2), seen.append, lambda exc: seen.append(exc))
    end = time.time() + 5
    while not seen and time.time() < end:
        APP.processEvents()
        time.sleep(0.01)
    assert seen and isinstance(seen[0], SystemExit)


def test_edge_keyboard_interrupt_is_not_swallowed(host):
    write_ext("ctrlc", "def activate(api):\n    pass\n")
    host.load_enabled()
    _module, api = host._loaded["user:ctrlc"]

    def interrupt():
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        host.call(api, interrupt)


def test_edge_a_single_suffix_as_a_string_is_one_suffix(host):
    """Review 2026-11-19: ``extensions=".md"`` was iterated character by
    character, ``('.', 'm', 'd')``: the entry showed for every file whose
    name ends in m or d."""
    write_ext("ctx", """
        def activate(api):
            api.add_context_action("Render", lambda ctx: None, extensions=".md")
    """)
    host.load_enabled()
    _module, api = host._loaded["user:ctx"]
    assert [entry[3] for entry in api._reg.context] == [(".md",)]
