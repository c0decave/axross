"""Round 3: ui.markup_guard asked ``Qt.mightBeRichText`` of PyQt6.QtCore's
``Qt``, which carries it only once PyQt6.QtWidgets is imported (PyQt6
6.11 puts it there). A process that had imported QtCore or QtGui alone -
a test of the guard on its own, a child that draws with QtGui - failed
with AttributeError on its first label check, and so did every caller of
``bombs_layout`` / ``asks_for_resource`` / ``defuse`` there.

Each check runs in a fresh interpreter so no earlier import of
QtWidgets hides it.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _run(code: str) -> subprocess.CompletedProcess:
    env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
    return subprocess.run([sys.executable, "-c", textwrap.dedent(code)], cwd=str(ROOT),
                          env=env, capture_output=True, text=True, timeout=120)


def test_sad_the_guard_works_with_only_qtcore_imported():
    out = _run("""
        import PyQt6.QtCore
        from ui import markup_guard as MG
        assert MG.bombs_layout("<table><tr><td colspan=9>x</td></tr></table>")
        assert not MG.bombs_layout("<table><tr><td>x</td></tr></table>")
        assert MG.asks_for_resource('<img src="/dev/zero">')
        assert MG.defuse('<b>x</b><img src="/dev/zero">') != '<b>x</b><img src="/dev/zero">'
        assert MG.defuse("<b>bold</b>") == "<b>bold</b>"
        print("ok")
    """)
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.strip() == "ok"


def test_edge_plain_text_is_not_rich_with_only_qtgui_imported():
    out = _run("""
        import PyQt6.QtGui
        from ui import markup_guard as MG
        assert not MG._rich("a < 3 and 4 > 1")
        assert MG._rich("<b>bold</b>")
        print("ok")
    """)
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.strip() == "ok"


def test_happy_the_fallback_reads_texts_as_qt_does():
    out = _run("""
        from PyQt6.QtWidgets import QApplication
        from PyQt6.QtCore import Qt
        from ui import markup_guard as MG
        samples = ["", "plain", "  <b>x</b>", "<B>x", "a < b", "<x>y</x>", "<br/>",
                   "<!DOCTYPE html><p>", "&lt;b&gt;", "line\\n<b>x</b>", "<?xml v?> <p>x",
                   "<img src=/dev/zero>", "<! p>", "<p class=x>", "<1>", "<qt>x", "x <i>y</i>",
                   "<table border=1>", "<foo bar>", "< b>", "<b", "<h7>"]
        bad = [t for t in samples if MG._might_be_rich_text(t) != bool(Qt.mightBeRichText(t))]
        assert not bad, bad
        print("ok")
    """)
    assert out.returncode == 0, out.stderr[-2000:]
    assert out.stdout.strip() == "ok"
