"""Round-6 findings M3/M4: table spans froze the GUI thread.

Qt lays out the grid a table's spans make - rows times columns, with the
empty cells that fill a short row up to the widest one - and both guards
counted cells as written, regardless of their span:

* core/mail_html.py kept ``colspan`` / ``rowspan`` up to 99 and counted a
  cell as one: nested ``colspan=99 rowspan=99`` cells (a 4.7 KB mail) kept
  the safe view's GUI thread 34 s, a grid of them (43 KB) 43 s.
* ui/markup_guard.py let spans up to 100 through and counted at most 1000
  cells as written: an 841-byte label laid out for 31.7 s.

Now a span is at most MAX_SPAN (8) - cut to it in a mail, a label asking
for more is shown as written - and both count the cells of the grid (a
nested table's double for each table around it): core.mail_html.TableGrid.
The layouts run in a child with a timeout, so a regression fails instead
of hanging the run.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import mail_html as M  # noqa: E402
from core.mail_html import TableGrid, sanitise  # noqa: E402

T99 = "<table><tr><td>".replace("<td>", '<td colspan="99" rowspan="99">')
C99 = '<td colspan="99" rowspan="99">'

#: the mails of the report (pt-rev6-sec/content/mail/variants.py)
MAIL_BOMBS = {
    "nest_span": ('<table><tr><td colspan="99" rowspan="99">' * 6) + "x"
                 + ("</td></tr><tr>" + (C99 + "y</td>") * 20 + "</tr></table>") * 6,
    "grid99": "<table>" + ("<tr>" + (C99 + "x</td>") * 120 + "</tr>") * 10 + "</table>",
    "rowspan_col": "<table>" + '<tr><td rowspan="99">x</td></tr>' * 2000 + "</table>",
    # one wide row over many short ones: the short rows are filled up
    "pad": "<table><tr>" + "<td>x</td>" * 120 + "</tr>" + "<tr><td>y</td></tr>" * 1000 + "</table>",
}

#: the labels of the report (pt-rev6-sec/content/markup/)
LABEL_BOMBS = {
    "mailnest-841-bytes": ('<table><tr><td colspan="99" rowspan="99">' * 6) + "x"
                          + ("</td></tr><tr>" + (C99 + "y</td>") * 2 + "</tr></table>") * 6,
    "grid": "<table>" + ("<tr>" + "<td colspan=99 rowspan=99>x</td>" * 30 + "</tr>") * 10 + "</table>",
    "compact": ("<table><tr><td colspan=99 rowspan=99>") * 5
               + ("<tr><td colspan=99 rowspan=99></table>") * 5,
    "span8-nest": ("<table><tr><td colspan=8 rowspan=8>") * 6 + "x"
                  + ("</td></tr><tr>" + "<td colspan=8 rowspan=8>y</td>" * 20 + "</tr></table>") * 6,
    "pad": "<table><tr>" + "<td>x</td>" * 120 + "</tr>" + "<tr><td>y</td></tr>" * 800 + "</table>",
}


# -- the grid -------------------------------------------------------------------------------

def test_happy_the_grid_counts_rows_times_columns():
    grid = TableGrid()
    for _ in range(3):
        grid.new_row()
        grid.cell()
        grid.cell()
    assert grid.size == 6


def test_edge_spans_and_short_rows_count_their_grid_cells():
    grid = TableGrid()
    grid.new_row()
    for _ in range(120):
        grid.cell()
    for _ in range(1000):
        grid.new_row()
        grid.cell()
    assert grid.size == 120 * 1001          # the short rows are filled up
    grid = TableGrid()
    grid.cell(8, 8)                          # a cell before any <tr>: a row of its own
    assert (grid.rows, grid.cols) == (8, 8)
    grid.new_row()
    grid.cell(8, 1)                          # beside the rows the cell above still covers
    assert grid.cols == 16


# -- the mail view --------------------------------------------------------------------------

def test_sad_a_mail_s_spans_are_cut_to_the_limit():
    out = sanitise('<table><tr><td colspan="99" rowspan="1000000">x</td></tr></table>')
    assert f'colspan="{M.MAX_SPAN}" rowspan="{M.MAX_SPAN}"' in out
    assert M.MAX_SPAN == 8


def test_happy_a_mail_s_ordinary_spans_are_kept_and_broken_ones_dropped():
    out = sanitise('<table><tr><td colspan="2">a</td><th rowspan="3">b</th>'
                   '<td colspan="0" rowspan="x">c</td><td colspan="-4">d</td></tr></table>')
    assert '<td colspan="2">a</td>' in out and '<th rowspan="3">b</th>' in out
    assert "<td>c</td>" in out and "<td>d</td>" in out


@pytest.mark.parametrize("name", sorted(MAIL_BOMBS))
def test_sad_the_grid_a_mail_s_spans_make_is_capped(name):
    """Past the table work the tables end and the rest is text: the cells a
    span makes count, not only the cells written."""
    mail = MAIL_BOMBS[name]
    out = sanitise(mail)
    assert out.count("<table>") == out.count("</table>")
    assert not out.endswith("</table>"), "the tables did not end"
    assert out.count("<td") < mail.count("<td")


_LAYOUT = """
import sys, time
sys.path.insert(0, sys.argv[2])
from PyQt6.QtWidgets import QApplication
app = QApplication([])
import ui
from ui.mail_project import _safe_browser_class
view = _safe_browser_class()(); view.resize(900, 600); view.show(); app.processEvents()
text = open(sys.argv[1], encoding="utf-8").read()
start = time.perf_counter(); view.setHtml(text); app.processEvents()
print("TOOK", time.perf_counter() - start, flush=True)
"""


def _layout_seconds(html_text: str, tmp_path, limit: float = 30) -> float:
    page = tmp_path / "mail.html"
    page.write_text(html_text, encoding="utf-8")
    try:
        out = subprocess.run([sys.executable, "-c", _LAYOUT, str(page), str(ROOT)],
                             capture_output=True, text=True, timeout=limit, cwd=str(ROOT))
    except subprocess.TimeoutExpired:
        return float("inf")
    took = [line for line in out.stdout.splitlines() if line.startswith("TOOK ")]
    assert took, out.stderr[-2000:]
    return float(took[0].split()[1])


@pytest.mark.parametrize("name", ["nest_span", "grid99"])
def test_e2e_the_safe_view_lays_a_span_bomb_out_quickly(name, tmp_path):
    """34 s and 43 s on the GUI thread before."""
    assert _layout_seconds(sanitise(MAIL_BOMBS[name]), tmp_path) < 5.0


# -- labels, tooltips, message boxes --------------------------------------------------------

def test_sad_a_label_asking_for_a_large_span_or_grid_is_shown_as_written():
    from ui import markup_guard as MG

    assert MG.MAX_SPAN == 8
    for name, text in LABEL_BOMBS.items():
        assert MG.bombs_layout(text), name
        assert MG.defuse(text) != text, name
    assert MG.bombs_layout("<table><tr><td colspan=9>x</td></tr></table>")
    assert MG.bombs_layout("<table><tr><td rowspan=&#57;9>x</td></tr></table>")


def test_happy_labels_with_small_spans_and_tables_stay_rich_text():
    from ui import markup_guard as MG

    for text in ("<table><tr><td colspan=2><b>Error</b></td></tr>"
                 + "<tr><td>name</td><td>value</td></tr>" * 200 + "</table>",
                 "<table><tr><td colspan=8 rowspan=8>x</td></tr></table>",
                 "<font size=7>big</font>", "<hr size=4>"):
        assert not MG.bombs_layout(text), text[:80]
        assert MG.defuse(text) == text


def test_edge_a_nested_table_s_cells_count_double_per_table_around_it():
    from ui import markup_guard as MG

    row = "<tr>" + "<td>x</td>" * 10 + "</tr>"
    flat = "<table>" + row * 60 + "</table>"                      # 600 cells
    nested = "<table><tr><td><table>" + row * 60 + "</table></td></tr></table>"
    assert not MG.bombs_layout(flat)
    assert MG.bombs_layout(nested)


_LABEL = """
import sys, time
sys.path.insert(0, sys.argv[2])
from PyQt6.QtWidgets import QApplication, QLabel
app = QApplication([])
import ui
text = open(sys.argv[1], encoding="utf-8").read()
start = time.perf_counter(); label = QLabel(text); label.sizeHint()
print("TOOK", time.perf_counter() - start, flush=True)
"""


@pytest.mark.parametrize("name", ["mailnest-841-bytes", "grid", "compact"])
def test_e2e_a_label_span_bomb_lays_out_at_once(name, tmp_path):
    """31.7 s (841 bytes), 52 s and 2.4 s before."""
    page = tmp_path / "label.txt"
    page.write_text(LABEL_BOMBS[name], encoding="utf-8")
    started = time.monotonic()
    try:
        out = subprocess.run([sys.executable, "-c", textwrap.dedent(_LABEL), str(page), str(ROOT)],
                             capture_output=True, text=True, timeout=30, cwd=str(ROOT))
    except subprocess.TimeoutExpired:
        pytest.fail(f"the label took more than 30 s ({time.monotonic() - started:.0f} s)")
    took = [line for line in out.stdout.splitlines() if line.startswith("TOOK ")]
    assert took, out.stderr[-2000:]
    assert float(took[0].split()[1]) < 1.0
