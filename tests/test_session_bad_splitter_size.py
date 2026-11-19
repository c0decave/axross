"""One bad splitter size in session.json no longer loses the whole layout.

Reproduced 2026-11-19 (independent review): a size above 2**31-1 in one
workspace's splitter (a hand edit, a bit flip) made QSplitter.setSizes
raise OverflowError half-way through the start-up restore; every
workspace was thrown away, and the next quit overwrote session.json with
the default layout - the saved layout gone for good. Now sizes are
clamped, sizes that are no list of integers are a problem _session_problem
names, and a session that cannot be restored is copied aside before the
default layout can replace it.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


# -- layout_utils ---------------------------------------------------------------


def test_happy_huge_sizes_are_clamped():
    from ui.layout_utils import MAX_SPLITTER_SIZE, sanitize_splitter_sizes

    assert sanitize_splitter_sizes([2**31, 300], 2) == [MAX_SPLITTER_SIZE, 300]
    assert sanitize_splitter_sizes([10**30, -5], 2) == [MAX_SPLITTER_SIZE, 100]
    assert MAX_SPLITTER_SIZE < 2**31


def test_sad_sizes_that_are_no_integers_are_refused():
    from ui.layout_utils import sanitize_splitter_sizes

    assert sanitize_splitter_sizes([True, 300], 2) is None
    assert sanitize_splitter_sizes([1.5, 300], 2) is None
    assert sanitize_splitter_sizes("300,300", 2) is None


# -- _session_problem -------------------------------------------------------------


def _tree(sizes):
    return {"type": "splitter", "orientation": "horizontal", "sizes": sizes,
            "children": [{"type": "pane", "local": True, "path": "/"},
                         {"type": "pane", "local": True, "path": "/tmp"}]}


@pytest.mark.parametrize("sizes", [[1, "x"], "300", {"a": 1}, [1, None], [True, 2], [1.5, 2]])
def test_sad_sizes_of_the_wrong_kind_are_a_session_problem(sizes):
    from ui.main_window import _session_problem

    data = {"workspaces": [{"name": "W", "splitter": _tree(sizes)}]}
    assert "size" in _session_problem(data)


def test_edge_an_out_of_range_integer_is_no_problem_it_is_clamped():
    from ui.main_window import _session_problem

    data = {"workspaces": [{"name": "W", "splitter": _tree([2**31, 300])}]}
    assert _session_problem(data) == ""


# -- the start-up restore ---------------------------------------------------------


def _session(home: Path, first_sizes) -> Path:
    path = home / "session.json"
    path.write_text(json.dumps({
        "window": {"language": "de"},
        "workspaces": [
            {"name": "One", "splitter": _tree([300, 300])},
            {"name": "Two", "splitter": _tree(first_sizes), "current": True},
        ],
        "splitter": _tree([300, 300]),
    }))
    return path


@pytest.fixture
def make_window(tmp_path, monkeypatch):
    from ui import main_window as MW

    made = []
    home = tmp_path / "home"
    home.mkdir()

    def make():
        with mock.patch("pathlib.Path.home", return_value=home):
            window = MW.MainWindow()
        made.append(window)
        return window

    monkeypatch.setattr(MW.MainWindow, "_SESSION_FILE", home / "session.json")
    make.home = home
    yield make
    for window in made:
        window.close()
        window.deleteLater()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    time.sleep(0.01)


def test_happy_one_huge_size_keeps_every_workspace(make_window):
    _session(make_window.home, [2**31, 300])
    window = make_window()
    assert window.restore_layout_on_start() is True
    assert [ws.name for ws in window._workspaces] == ["One", "Two"]


def test_sad_a_session_that_cannot_be_restored_is_kept_aside(make_window):
    path = _session(make_window.home, [1, "x"])
    original = path.read_text()
    window = make_window()
    assert window.restore_layout_on_start() is False
    kept = list(make_window.home.glob("session.json.unrestorable-*"))
    assert len(kept) == 1
    assert kept[0].read_text() == original
    # The file itself stays for what else it holds (window.language).
    assert json.loads(path.read_text())["window"]["language"] == "de"


def test_sad_a_restore_that_fails_half_way_is_kept_aside(make_window, monkeypatch):
    from ui import main_window as MW

    path = _session(make_window.home, [300, 300])
    original = path.read_text()
    window = make_window()

    def broken(self, data, **_kw):
        raise RuntimeError("half-way")

    monkeypatch.setattr(MW.MainWindow, "_apply_session", broken)
    assert window.restore_layout_on_start() is False
    kept = list(make_window.home.glob("session.json.unrestorable-*"))
    assert [p.read_text() for p in kept] == [original]


def test_edge_a_missing_session_is_not_set_aside(make_window):
    window = make_window()
    assert window.restore_layout_on_start() is False
    assert list(make_window.home.glob("session.json.*")) == []
