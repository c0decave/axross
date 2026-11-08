"""Folder Treemap and Markdown Preview: only the latest request counts.

The review found:

* Folder Treemap started a walk of up to 20,000 ``list_dir`` calls on every
  ``path_changed`` and never stopped the walks of folders already left -
  only their result was thrown away. Ten folder changes on a slow remote
  left ten walks running side by side. Now each walk is told when it is
  stale (a generation counter) and stops at its next listing.
* In both, ``on_error`` did not check whether the request was still the
  current one: a late "connection reset" for a.md replaced the preview of
  b.md that had arrived meanwhile (and a failed walk the newer treemap).
"""

from __future__ import annotations

import importlib.util
import io
import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _load(name: str):
    spec = importlib.util.spec_from_file_location(f"stale_{name}", EX.bundled_dir() / f"{name}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class Api:
    """What these two use of ExtensionAPI; results are delivered by hand,
    in the order a test chooses."""

    def __init__(self) -> None:
        self.handlers: dict = {}
        self.widget = None
        self.jobs: list = []

    def add_dock(self, title, widget, icon=None):
        self.widget = widget

    def on(self, event, callback):
        self.handlers.setdefault(event, []).append(callback)

    def current(self):
        return None

    def notify(self, text):
        pass

    def run_in_background(self, work, on_done=None, on_error=None):
        self.jobs.append((work, on_done, on_error))

    def run(self, index: int) -> None:
        work, on_done, on_error = self.jobs[index]
        try:
            value = work()
        except Exception as exc:  # noqa: BLE001 - delivered like the host does
            on_error(exc)
        else:
            on_done(value)


class Item:
    def __init__(self, name, is_dir=False, size=0):
        self.name, self.is_dir, self.size = name, is_dir, size


class Ctx:
    def __init__(self, backend, folder, items=()):
        self.backend, self.folder, self.items, self.pane = backend, folder, tuple(items), None


class Tree:
    """An endless folder tree that counts its listings."""

    def __init__(self) -> None:
        self.listings = 0

    def join(self, *parts):
        return "/".join(parts)

    def list_dir(self, path):
        self.listings += 1
        return [Item(f"d{i}", True) for i in range(4)] + [Item("f", False, 10)]


# -- Folder Treemap ------------------------------------------------------------------


def test_happy_a_walk_of_a_folder_left_meanwhile_stops():
    FT = _load("folder_treemap")
    api = Api()
    FT.activate(api)
    old, new = Tree(), Tree()
    api.handlers["path_changed"][0](Ctx(old, "/srv/old"))
    api.handlers["path_changed"][0](Ctx(new, "/srv/new"))
    api.run(0)  # the old walk runs only now: it stops at once
    assert old.listings == 0
    api.run(1)
    assert new.listings > 1000  # the current walk runs to its bound


def test_happy_a_walk_stops_mid_way_when_the_folder_changes():
    FT = _load("folder_treemap")
    api = Api()
    FT.activate(api)

    class Slow(Tree):
        def list_dir(self, path):
            time.sleep(0.002)
            return super().list_dir(path)

    old = Slow()
    api.handlers["path_changed"][0](Ctx(old, "/srv/old"))
    worker = threading.Thread(target=api.run, args=(0,), daemon=True)
    worker.start()
    time.sleep(0.1)
    api.handlers["path_changed"][0](Ctx(Tree(), "/srv/new"))
    worker.join(2)
    assert not worker.is_alive(), "the walk of the folder left goes on"
    assert old.listings < 200


def test_sad_a_late_error_does_not_replace_the_newer_treemap():
    FT = _load("folder_treemap")
    api = Api()
    FT.activate(api)

    class Broken(Tree):
        def list_dir(self, path):
            raise OSError("connection reset")

    api.handlers["path_changed"][0](Ctx(Broken(), "/srv/old"))
    api.handlers["path_changed"][0](Ctx(Tree(), "/srv/new"))
    api.run(1)
    shown = api.widget.message
    api.run(0)
    assert "connection reset" not in api.widget.message
    assert api.widget.message == shown
    # The current walk's own error is still shown.
    api.handlers["path_changed"][0](Ctx(Broken(), "/srv/x"))
    api.run(2)
    assert "connection reset" in api.widget.message


def test_edge_folder_sizes_without_a_cancel_check_walks_as_before():
    FT = _load("folder_treemap")
    entries, complete = FT.folder_sizes(Tree(), "/", max_entries=50)
    assert entries and complete is False
    with pytest.raises(FT.WalkCancelled):
        FT.folder_sizes(Tree(), "/", cancelled=lambda: True)


# -- Markdown Preview ----------------------------------------------------------------


class Files:
    def join(self, *parts):
        return "/".join(parts)

    def open_read(self, path):
        if path.endswith("a.md"):
            raise OSError("connection reset")
        return io.BytesIO(b"# B is shown")


def test_sad_a_late_error_does_not_replace_the_newer_preview():
    MD = _load("markdown_preview")
    api = Api()
    MD.activate(api)
    files = Files()
    api.handlers["selection_changed"][0](Ctx(files, "/r", [Item("a.md")]))
    api.handlers["selection_changed"][0](Ctx(files, "/r", [Item("b.md")]))
    api.run(1)
    assert api.widget.toPlainText() == "B is shown"
    api.run(0)  # a.md's error arrives last
    assert api.widget.toPlainText() == "B is shown"
    # The current file's own error is still shown.
    api.handlers["selection_changed"][0](Ctx(files, "/r", [Item("a.md")]))
    api.run(2)
    assert "connection reset" in api.widget.toPlainText()
