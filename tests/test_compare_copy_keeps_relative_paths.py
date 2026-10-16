"""Compare-window copies and syncs land at their relative path, not the pane's folder.

Measured before: the compare window resolved every row against the roots
it compared ("/l/sub/a.txt" -> "/r/sub/a.txt") and handed the main
window absolute paths, but ``_copy_compared`` and ``_apply_sync`` passed
only the SOURCE paths to ``_start_transfer_between``, which queues into
``target.current_path``. A file from ``sub/`` was copied into the root
(or into whatever folder the pane had browsed to since), and the
transfer engine overwrites without asking: syncing ``sub/readme.txt``
replaced the root's ``readme.txt``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from ui.main_window import MainWindow  # noqa: E402


class _Backend:
    name = "fake"

    def parent(self, path: str) -> str:
        return path.rsplit("/", 1)[0] or "/"

    def separator(self) -> str:
        return "/"

    def mkdir(self, path: str) -> None:
        pass


class _Pane:
    def __init__(self, current_path: str) -> None:
        self.backend = _Backend()
        self.current_path = current_path


class _Manager:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], str]] = []

    def transfer_files(self, **kw):
        self.calls.append((list(kw["source_paths"]), kw["dest_dir"]))
        return []


class _StatusBar:
    def showMessage(self, *a):  # noqa: N802 - Qt name
        pass


class _Win:
    _start_transfer_between = MainWindow._start_transfer_between
    _transfer_direction = staticmethod(MainWindow._transfer_direction)
    _apply_sync = MainWindow._apply_sync
    _copy_compared = MainWindow._copy_compared
    if hasattr(MainWindow, "_transfer_compared"):
        _transfer_compared = MainWindow._transfer_compared

    def __init__(self) -> None:
        self._transfer_target_panes = set()
        self._transfer_manager = _Manager()

    def statusBar(self):  # noqa: N802 - Qt name
        return _StatusBar()

    def _compared_panes_open(self, *panes) -> bool:
        # Both panes are open here; a closed pane is covered by
        # tests/test_compare_closed_pane.py.
        return True


def _sync_item(rel: str, kind: str = "copy") -> dict:
    return {
        "rel_path": rel,
        "kind": kind,
        "direction": "to_right",
        "overwrites": False,
        "source": f"/l/{rel}",
        "dest": f"/r/{rel}",
    }


def test_happy_a_root_level_sync_goes_to_the_compared_root():
    win, left, right = _Win(), _Pane("/l"), _Pane("/r")
    win._apply_sync(left, right, [_sync_item("a.txt")])
    assert win._transfer_manager.calls == [(["/l/a.txt"], "/r")]


def test_sad_a_nested_sync_goes_to_its_subfolder_not_the_root():
    win, left, right = _Win(), _Pane("/l"), _Pane("/r")
    win._apply_sync(
        left, right, [_sync_item("sub", "mkdir"), _sync_item("sub/readme.txt"), _sync_item("x.txt")]
    )
    assert sorted(win._transfer_manager.calls) == [
        (["/l/sub/readme.txt"], "/r/sub"),
        (["/l/x.txt"], "/r"),
    ]


def test_sad_a_nested_copy_goes_to_its_subfolder():
    win, left, right = _Win(), _Pane("/l"), _Pane("/r")
    win._copy_compared(left, right, "to_right", [("/l/sub/a.txt", "/r/sub/a.txt")])
    assert win._transfer_manager.calls == [(["/l/sub/a.txt"], "/r/sub")]


def test_edge_a_pane_that_browsed_away_does_not_redirect_the_copy():
    win, left, right = _Win(), _Pane("/l"), _Pane("/r/elsewhere")
    win._copy_compared(left, right, "to_right", [("/l/a.txt", "/r/a.txt")])
    win._apply_sync(left, right, [_sync_item("b.txt")])
    assert win._transfer_manager.calls == [(["/l/a.txt"], "/r"), (["/l/b.txt"], "/r")]
