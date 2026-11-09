"""Create SHA256SUMS and the pane menu's Refresh do not block the window.

Audit (feedback: no blocked windows): the checksum_manifest extension
listed the folder and checked for an existing manifest on the GUI thread
before it hashed in the background, wrote the manifest from its done()
callback on the GUI thread, and then refreshed the pane synchronously;
image_batch and forensic_tools refreshed the same way, and the pane
menu's Refresh listed the folder on the GUI thread (Ctrl+R and the
toolbar did not). All of it runs in the background now.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _load(name: str):
    path = EX.bundled_dir() / f"{name}.py"
    spec = importlib.util.spec_from_file_location(f"offgui_{name}", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class WatchedFS(LocalFS):
    def __init__(self) -> None:
        super().__init__()
        self.threads: set[str] = set()

    def list_dir(self, path):
        self.threads.add(threading.current_thread().name)
        return super().list_dir(path)

    def exists(self, path):
        self.threads.add(threading.current_thread().name)
        return super().exists(path)

    def open_write(self, path, *a, **k):
        self.threads.add(threading.current_thread().name)
        return super().open_write(path, *a, **k)


class Api:
    """The extension API, its background runner a real thread."""

    def __init__(self) -> None:
        self.notes: list[str] = []
        self.entries: dict = {}
        self.results: list = []

    def notify(self, text, *a, **k):
        self.notes.append(text)

    def run_in_background(self, work, on_done=None, on_error=None):
        def run():
            self.results.append(work())

        thread = threading.Thread(target=run, name="bg")
        thread.start()
        thread.join()
        if on_done is not None:
            on_done(self.results[-1])

    def __getattr__(self, name):
        def register(*args, **kwargs):
            label = args[0] if args else kwargs.get("label")
            for a in args:
                if callable(a):
                    self.entries[label] = a
            for v in kwargs.values():
                if callable(v):
                    self.entries[label] = v
            return None
        return register


def test_happy_create_lists_checks_hashes_and_writes_off_the_gui_thread(tmp_path):
    CM = _load("checksum_manifest")
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "b.txt").write_text("b")
    api = Api()
    CM.activate(api)
    create = next(f for label, f in api.entries.items() if "SHA256SUMS" in str(label)
                  and "Create" in str(label))
    fs = WatchedFS()
    refreshed: list[str] = []
    pane = SimpleNamespace(refresh_after_change=lambda: refreshed.append("async"),
                           refresh=lambda: refreshed.append("sync"))
    create(SimpleNamespace(items=[], backend=fs, folder=str(tmp_path), pane=pane))
    assert (tmp_path / "SHA256SUMS").read_text().count("\n") == 2
    assert fs.threads == {"bg"}
    assert refreshed == ["async"]
    assert api.notes[-1] == "wrote SHA256SUMS for 2 file(s)"


def test_sad_an_existing_manifest_is_not_overwritten(tmp_path):
    CM = _load("checksum_manifest")
    (tmp_path / "a.txt").write_text("a")
    (tmp_path / "SHA256SUMS").write_text("keep")
    api = Api()
    CM.activate(api)
    CM.ask_existing = lambda *a: None   # Cancel in the Update / Replace question
    create = next(f for label, f in api.entries.items() if "Create" in str(label))
    create(SimpleNamespace(items=[], backend=WatchedFS(), folder=str(tmp_path), pane=None))
    assert (tmp_path / "SHA256SUMS").read_text() == "keep"
    assert "already exists" in api.notes[-1]


def test_happy_the_menu_refresh_loads_in_the_background(tmp_path):
    from ui.file_pane import FilePaneWidget

    pane = FilePaneWidget(LocalFS())
    pane.navigate(str(tmp_path))
    try:
        menu = pane._build_context_menu()
        from tests.menu_walk import all_actions  # Refresh sits under More now

        refresh = next(a for a in all_actions(menu) if a.text().replace("&", "") == "Refresh")
        calls: list[str] = []
        pane.navigate = lambda *a, **k: calls.append("sync")
        pane.navigate_async = lambda *a, **k: calls.append("async")
        refresh.trigger()
        assert calls == ["async"]
    finally:
        pane.shutdown()
        pane.deleteLater()
