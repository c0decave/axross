"""The Folder Treemap lays a big folder out in linear time and only when its
entries or its size change.

Measured 2026-10-25: squarify() of 20,000 entries (a folder the size of
MAX_ENTRIES) took 465-647 ms - for every candidate box it summed the whole
row and scanned it for the worst aspect ratio (quadratic in the row) - and
paintEvent ran it on every repaint of the panel. Now the row keeps its sum
as it grows and the worst ratio comes from the row's first and last box
(the sizes are sorted, the ratio is convex in the size), and the panel
keeps the boxes until the entries or its size change. The old squarify is
kept below as the oracle: the rectangles are equal, float for float.
"""

from __future__ import annotations

import importlib.util
import os
import random
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QPointF, Qt  # noqa: E402
from PyQt6.QtWidgets import QApplication, QWidget  # noqa: E402

from core import extensions as EX  # noqa: E402

APP = QApplication.instance() or QApplication([])


def load():
    path = EX.bundled_dir() / "folder_treemap.py"
    spec = importlib.util.spec_from_file_location("treemap_under_test", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def old_squarify(sizes, x, y, w, h):
    """folder_treemap.squarify as it was before 2026-10-25."""
    values = [s for s in sizes if s > 0]
    rects = []
    total = sum(values)
    if not values or w <= 0 or h <= 0:
        return rects
    scaled = [v * w * h / total for v in values]

    def worst(row, side):
        s = sum(row)
        return max(max(side * side * r / (s * s), s * s / (side * side * r)) for r in row)

    i = 0
    while i < len(scaled):
        side = min(w, h)
        row = [scaled[i]]
        i += 1
        while i < len(scaled) and worst(row + [scaled[i]], side) <= worst(row, side):
            row.append(scaled[i])
            i += 1
        s = sum(row)
        if w >= h:
            cw = s / h
            cy = y
            for r in row:
                rects.append((x, cy, cw, r / cw))
                cy += r / cw
            x, w = x + cw, w - cw
        else:
            rh = s / w
            cx = x
            for r in row:
                rects.append((cx, y, r / rh, rh))
                cx += r / rh
            y, h = y + rh, h - rh
    return rects


def _sizes(rnd: random.Random, n: int, kind: int) -> list:
    if kind == 0:
        values = [rnd.randint(1, 10**6) for _ in range(n)]
    elif kind == 1:
        values = [1000] * n
    elif kind == 2:
        values = [rnd.expovariate(1e-6) for _ in range(n)]
    else:
        values = [rnd.choice([0, 1, 10**12, rnd.randint(1, 99)]) for _ in range(n)]
    return sorted(values, reverse=True)


class FakeApi:
    """What activate() uses of the extension API; background work runs at once."""

    def __init__(self, entries):
        self.entries = entries
        self.docks = []
        self.handlers = {}

    def add_dock(self, title, widget):
        self.docks.append(widget)

    def run_in_background(self, work, on_done=None, on_error=None):
        on_done((self.entries, True))

    def on(self, name, handler):
        self.handlers[name] = handler

    def current(self):
        return None


def _view(entries, width=800, height=600):
    FT = load()
    api = FakeApi(entries)
    FT.activate(api)
    view = api.docks[0]
    view.resize(width, height)
    view.set_entries(entries, True)
    view.show()
    APP.processEvents()
    return FT, view


# -- happy ---------------------------------------------------------------------


@pytest.mark.parametrize("seed", range(40))
def test_happy_the_rectangles_equal_the_old_layout_exactly(seed):
    FT = load()
    rnd = random.Random(seed)
    sizes = _sizes(rnd, rnd.randint(1, 400), seed % 4)
    box = (rnd.uniform(-50, 50), rnd.uniform(-50, 50), rnd.uniform(1, 1600), rnd.uniform(1, 900))
    assert FT.squarify(sizes, *box) == old_squarify(sizes, *box)


def test_happy_twenty_thousand_entries_take_a_fraction_of_the_old_time():
    FT = load()
    sizes = _sizes(random.Random(1), 20000, 0)
    t = time.process_time()
    new = FT.squarify(sizes, 0, 0, 800, 600)
    new_s = time.process_time() - t
    t = time.process_time()
    old = old_squarify(sizes, 0, 0, 800, 600)  # the negative control
    old_s = time.process_time() - t
    assert new == old
    assert new_s * 5 < old_s, (new_s, old_s)


def test_happy_a_repaint_reuses_the_boxes(monkeypatch):
    rnd = random.Random(3)
    FT, view = _view([(f"f{i}", rnd.randint(1, 10**6), i % 9 == 0) for i in range(3000)])
    calls = []
    real = FT.squarify
    monkeypatch.setitem(view.paintEvent.__globals__, "squarify",
                        lambda *a: (calls.append(1), real(*a))[1])
    for _ in range(5):
        view.repaint()
    assert calls == []  # laid out once already, at the first paint
    assert len(view.boxes) == 3000


# -- sad -----------------------------------------------------------------------


def test_sad_nothing_to_lay_out_is_still_nothing():
    FT = load()
    assert FT.squarify([], 0, 0, 100, 100) == []
    assert FT.squarify([0, 0], 0, 0, 100, 100) == []
    assert FT.squarify([5, 3], 0, 0, 0, 100) == []
    assert FT.squarify([5, 3], 0, 0, 100, -1) == []


def test_sad_a_folder_without_sizes_shows_the_message(monkeypatch):
    FT, view = _view([("empty", 0, False)])
    assert view.message == "Nothing with a size here."
    view.repaint()
    assert view.boxes == []


# -- edge ----------------------------------------------------------------------


def test_edge_one_two_and_lopsided_entries():
    FT = load()
    for sizes in ([7], [7, 7], [10**15, 1], [3, 2, 1, 1, 1, 1, 1, 1], [1e-300, 1e-300]):
        assert FT.squarify(sizes, 0, 0, 640, 480) == old_squarify(sizes, 0, 0, 640, 480)


def test_edge_new_entries_or_a_new_size_lay_out_again(monkeypatch):
    FT, view = _view([("a", 10, False), ("b", 5, False)], 400, 300)
    first = [box for box, _e in view.boxes]
    view.resize(600, 300)
    APP.processEvents()
    view.repaint()
    assert [box for box, _e in view.boxes] != first
    assert view.boxes[0][0].width() * view.boxes[0][0].height() == pytest.approx(
        600 * 300 * 10 / 15)
    view.set_entries([("c", 1, False), ("d", 1, False), ("e", 1, False)], True)
    view.repaint()
    assert [e[0] for _b, e in view.boxes] == ["c", "d", "e"]


# -- e2e -----------------------------------------------------------------------


def test_e2e_the_panel_draws_hovers_and_opens_a_folder_of_a_big_listing(tmp_path, monkeypatch):
    rnd = random.Random(7)
    entries = [(f"file{i}", rnd.randint(1, 10**7), False) for i in range(5000)]
    entries[0] = ("biggest_dir", 10**12, True)
    FT, view = _view(entries)
    assert len(view.boxes) == 5000
    box, entry = view.boxes[0]
    assert entry[0] == "biggest_dir"
    assert view.entry_at(box.center()) == entry
    opened = []

    class Ctx:
        backend = type("B", (), {"join": staticmethod(lambda a, b: f"{a}/{b}")})()
        folder = "/data"
        pane = type("P", (), {"navigate_async": staticmethod(opened.append)})()

    monkeypatch.setattr(FakeApi, "current", lambda self: Ctx())
    from PyQt6.QtTest import QTest

    QTest.mouseDClick(view, Qt.MouseButton.LeftButton, pos=box.center().toPoint())
    assert opened == ["/data/biggest_dir"]
    assert isinstance(view, QWidget) and view.entry_at(QPointF(-5, -5)) is None
