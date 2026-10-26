"""No garbage collection while Qt restyles every widget.

QApplication.setStyleSheet / setStyle / setPalette / setFont walk a copied
list of widgets and send each an event. A Python handler on one of them
(the script editor re-highlights on a palette change) allocates, which can
start Python's cyclic garbage collector, and the collector deletes widgets
that only Python owned - while Qt is still walking its list. Qt then
touches freed memory: a segfault on a theme switch, seen in the full test
suite after ~1500 tests had left their windows behind, and reproduced
here deterministically.

Each case runs in a child process: the failure is a crash.
"""

from __future__ import annotations

import gc
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

_PRELUDE = """
import gc, os, sys
os.environ["QT_QPA_PLATFORM"] = "offscreen"
sys.path.insert(0, {root!r})
from PyQt6.QtCore import QEvent
from PyQt6.QtWidgets import QApplication, QWidget

app = QApplication.instance() or QApplication([])


class Busy(QWidget):
    # Python work on every restyle event, as a syntax highlighter does: it
    # allocates cyclic objects, which is what starts an automatic collection.
    def event(self, event):
        if event.type() in (QEvent.Type.StyleChange, QEvent.Type.PaletteChange,
                            QEvent.Type.FontChange):
            junk = []
            for _ in range(3000):
                d = {{}}
                d["self"] = d
                junk.append(d)
        return super().event(event)


def make_garbage():
    busy = [Busy() for _ in range(40)]
    for b in busy:
        b.ensurePolished()
    for _ in range(300):
        w = QWidget()
        w.ensurePolished()
        w._cycle = w  # only the cyclic collector frees it
    return busy
"""


def _run(body: str) -> subprocess.CompletedProcess:
    script = textwrap.dedent(_PRELUDE).format(root=str(ROOT)) + textwrap.dedent(body)
    return subprocess.run(
        [sys.executable, "-c", script],
        capture_output=True,
        text=True,
        timeout=120,
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
    )


def test_sad_without_the_pause_the_restyle_crashes() -> None:
    """Control: the reproduction really reproduces on this Qt build."""
    done = _run(
        """
        app.setStyleSheet("QWidget { color: black; }")
        keep = make_garbage()
        app.setStyleSheet("QWidget { color: red; }")
        print("survived")
        """
    )
    if done.returncode == 0:
        pytest.skip("this Qt/Python build does not crash without the pause")
    assert done.returncode < 0, (done.returncode, done.stderr[-2000:])


def test_happy_the_pause_lets_the_restyle_finish() -> None:
    done = _run(
        """
        from ui import themes
        app.setStyleSheet("QWidget { color: black; }")
        keep = make_garbage()
        with themes.collection_paused():
            app.setStyleSheet("QWidget { color: red; }")
        print("survived")
        """
    )
    assert done.returncode == 0, (done.returncode, done.stderr[-2000:])
    assert "survived" in done.stdout


def test_happy_a_theme_switch_in_the_window_survives_garbage_widgets() -> None:
    done = _run(
        """
        from ui.main_window import MainWindow
        win = MainWindow()
        win._apply_theme("modern-dark")
        keep = make_garbage()
        win._apply_theme("modern-light")
        win._apply_theme("hacker")
        print("survived")
        """
    )
    assert done.returncode == 0, (done.returncode, done.stderr[-2000:])
    assert "survived" in done.stdout


def test_edge_a_font_size_change_in_the_window_survives_garbage_widgets() -> None:
    done = _run(
        """
        from ui.main_window import MainWindow
        win = MainWindow()
        win._apply_theme("modern-dark")
        keep = make_garbage()
        win._set_font_size(15)
        win._set_font_size(9)
        print("survived")
        """
    )
    assert done.returncode == 0, (done.returncode, done.stderr[-2000:])
    assert "survived" in done.stdout


def test_edge_the_pause_restores_the_collector_state_even_on_error() -> None:
    from ui import themes

    was = gc.isenabled()
    try:
        gc.enable()
        with pytest.raises(RuntimeError):
            with themes.collection_paused():
                assert not gc.isenabled()
                raise RuntimeError("boom")
        assert gc.isenabled()

        gc.disable()
        with themes.collection_paused():
            assert not gc.isenabled()
        assert not gc.isenabled()  # it was off before; it stays off
    finally:
        (gc.enable if was else gc.disable)()


# -- the pause costs no collection (2026-10-25) ---------------------------------------
#
# collection_paused ran gc.collect() before every restyle: 11-20 ms each, three
# while the window is built and one or two per theme switch (scripts/ui_bench.py,
# theme median 232-237 -> 196-198 ms without it). The safety is the paused
# collector, not the collection before: the reproduction above survives 5 of 5
# runs with gc.disable() alone and crashes 5 of 5 with neither.


def test_happy_the_pause_does_not_collect_up_front(monkeypatch) -> None:
    from ui import themes

    collected = []
    monkeypatch.setattr(themes.gc, "collect", lambda *a: collected.append(a) or 0)
    was = gc.isenabled()
    gc.enable()
    try:
        with themes.collection_paused():
            assert not gc.isenabled()
        assert gc.isenabled()
    finally:
        (gc.enable if was else gc.disable)()
    assert collected == []


def test_sad_garbage_from_before_the_restyle_survives_it_and_is_collected_later() -> None:
    done = _run(
        """
        import weakref
        from ui import themes
        app.setStyleSheet("QWidget { color: black; }")
        keep = make_garbage()
        probe = QWidget()
        probe._cycle = probe
        ref = weakref.ref(probe)
        del probe
        with themes.collection_paused():
            app.setStyleSheet("QWidget { color: red; }")
            assert ref() is not None  # not collected while Qt walks its widgets
        gc.collect()
        print("collected" if ref() is None else "alive")
        print("survived")
        """
    )
    assert done.returncode == 0, (done.returncode, done.stderr[-2000:])
    assert "survived" in done.stdout and "collected" in done.stdout


def test_edge_repeated_window_theme_switches_with_garbage_survive() -> None:
    done = _run(
        """
        from ui.main_window import MainWindow
        win = MainWindow()
        for theme in ("modern-dark", "modern-light", "hacker", "amber", "classic", "modern"):
            keep = make_garbage()
            win._apply_theme(theme)
        print("survived")
        """
    )
    assert done.returncode == 0, (done.returncode, done.stderr[-2000:])
    assert "survived" in done.stdout
