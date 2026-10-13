"""Render a gallery of every common control under a theme and measure
how readable the text is (WCAG contrast of the dominant text colour
against the dominant background colour of the rendered pixels).

Shared by ``test_theme_contrast`` and usable standalone:
``python3 -m tests.theme_audit`` prints a table for every theme.
"""

from __future__ import annotations

import os
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

THEMES = ("modern-light", "modern-dark", "classic", "default", "hacker", "amber")


def _lin(c: int) -> float:
    v = c / 255
    return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4


def luminance(rgb: tuple[int, int, int]) -> float:
    r, g, b = rgb
    return 0.2126 * _lin(r) + 0.7152 * _lin(g) + 0.0722 * _lin(b)


def contrast(a: tuple[int, int, int], b: tuple[int, int, int]) -> float:
    la, lb = luminance(a), luminance(b)
    hi, lo = max(la, lb), min(la, lb)
    return (hi + 0.05) / (lo + 0.05)


def _hex(c) -> str:
    return "#%02x%02x%02x" % c


def _rgb(img, x: int, y: int) -> tuple[int, int, int]:
    c = img.pixelColor(x, y)
    return (c.red(), c.green(), c.blue())


def _best_text_pixel(img, bg, x0: int, y0: int, x1: int, y1: int):
    """Pixel in the crop with the highest contrast against *bg* (the
    solid core of a glyph stroke; anti-aliased edges score lower).
    This never under-reports a problem: it can only miss one when a
    decoration contrasts more than the text itself."""
    best, best_c = None, 0.0
    for y in range(max(0, y0), min(img.height(), y1)):
        for x in range(max(0, x0), min(img.width(), x1)):
            px = _rgb(img, x, y)
            c = contrast(px, bg)
            if c > best_c:
                best, best_c = px, c
    return best, best_c


def measure_widget(widget) -> tuple[float | None, str, str]:
    """(worst contrast, bg_hex, fg_hex) for a shown widget.

    Item views are judged row by row against that row's own background
    (rows alternate, selection differs); everything else against its
    dominant background colour. ``None`` when nothing was drawn.
    """
    from PyQt6.QtWidgets import QAbstractItemView

    if isinstance(widget, QAbstractItemView):
        img = widget.viewport().grab().toImage()
        model = widget.model()
        worst = (None, "", "")
        if model is None:
            return worst
        rows = []

        def collect(parent, depth=0):
            for r in range(model.rowCount(parent)):
                idx = model.index(r, 0, parent)
                rows.append(idx)
                if depth < 3 and hasattr(widget, "isExpanded") and widget.isExpanded(idx):
                    collect(idx, depth + 1)

        collect(widget.rootIndex() if hasattr(widget, "rootIndex") else model.index(-1, -1))
        for idx in rows[:10]:
            rect = widget.visualRect(idx)
            if rect.isEmpty() or rect.bottom() >= img.height():
                continue
            cy = rect.center().y()
            bg = _rgb(img, img.width() - 3, cy)
            fg, c = _best_text_pixel(
                img, bg, rect.left() + 24, rect.top() + 2, img.width() - 6, rect.bottom() - 1
            )
            if fg is None:
                continue
            if worst[0] is None or c < worst[0]:
                worst = (c, _hex(bg), _hex(fg))
        return worst

    img = widget.grab().toImage()
    counts: Counter = Counter()
    for y in range(img.height()):
        for x in range(img.width()):
            counts[_rgb(img, x, y)] += 1
    if not counts:
        return None, "", ""
    bg = counts.most_common(1)[0][0]
    fg, c = _best_text_pixel(img, bg, 4, 4, img.width() - 4, img.height() - 4)
    if fg is None or c < 1.05:
        return None, _hex(bg), ""
    return c, _hex(bg), _hex(fg)


def build_gallery(tmpdir: str | None = None):
    """name -> widget, each filled with sample content. With *tmpdir* the
    real archive pane (a zip written there) is part of the gallery."""
    from PyQt6.QtCore import Qt
    from PyQt6.QtGui import QStandardItem, QStandardItemModel
    from PyQt6.QtWidgets import (
        QCheckBox,
        QComboBox,
        QDateTimeEdit,
        QDoubleSpinBox,
        QGroupBox,
        QLabel,
        QLineEdit,
        QListView,
        QListWidget,
        QMenu,
        QPlainTextEdit,
        QProgressBar,
        QPushButton,
        QRadioButton,
        QSpinBox,
        QTableView,
        QTabWidget,
        QTextBrowser,
        QTextEdit,
        QToolButton,
        QTreeView,
        QTreeWidget,
        QTreeWidgetItem,
        QVBoxLayout,
        QWidget,
    )

    g: dict[str, QWidget] = {}

    tv = QTableView()
    m = QStandardItemModel(6, 3)
    m.setHorizontalHeaderLabels(["Name", "Size", "Modified"])
    for r in range(6):
        for c in range(3):
            m.setItem(r, c, QStandardItem(f"entry {r}-{c} report.txt"))
    tv.setModel(m)
    tv.setAlternatingRowColors(True)
    g["QTableView"] = tv
    tvs = QTableView()
    tvs.setModel(m)
    tvs.selectAll()
    g["QTableView (selected)"] = tvs

    tree = QTreeView()
    tm = QStandardItemModel()
    tm.setHorizontalHeaderLabels(["Name", "Size"])
    for i in range(3):
        parent = QStandardItem(f"folder_{i}")
        for j in range(3):
            parent.appendRow([QStandardItem(f"member_{i}_{j}.bin"), QStandardItem("12 KB")])
        tm.appendRow([parent, QStandardItem("")])
    tree.setModel(tm)
    tree.expandAll()
    tree.setAlternatingRowColors(True)
    g["QTreeView (archive-like)"] = tree
    trees = QTreeView()
    trees.setModel(tm)
    trees.expandAll()
    trees.selectAll()
    g["QTreeView (selected)"] = trees

    tw = QTreeWidget()
    tw.setHeaderLabels(["Name", "Value"])
    for i in range(5):
        QTreeWidgetItem(tw, [f"item {i}", f"value {i}"])
    tw.setAlternatingRowColors(True)
    g["QTreeWidget"] = tw

    lw = QListWidget()
    lw.addItems([f"list entry number {i}" for i in range(6)])
    lw.setAlternatingRowColors(True)
    g["QListWidget"] = lw
    lws = QListWidget()
    lws.addItems([f"list entry number {i}" for i in range(6)])
    lws.selectAll()
    g["QListWidget (selected)"] = lws

    lv = QListView()
    lm = QStandardItemModel()
    for i in range(6):
        lm.appendRow(QStandardItem(f"list view entry {i}"))
    lv.setModel(lm)
    lv.setAlternatingRowColors(True)
    g["QListView"] = lv

    te = QTextEdit()
    te.setPlainText("The quick brown fox jumps over the lazy dog.\n" * 5)
    g["QTextEdit"] = te
    pe = QPlainTextEdit()
    pe.setPlainText("The quick brown fox jumps over the lazy dog.\n" * 5)
    g["QPlainTextEdit"] = pe
    tb = QTextBrowser()
    tb.setHtml("<p>Some <b>rich</b> text and a <a href='x'>link</a> for the viewer.</p>" * 3)
    g["QTextBrowser"] = tb

    le = QLineEdit("single line input text")
    g["QLineEdit"] = le
    cb = QComboBox()
    cb.addItems(["first choice", "second choice"])
    g["QComboBox"] = cb
    sp = QSpinBox()
    sp.setValue(1234)
    g["QSpinBox"] = sp
    ds = QDoubleSpinBox()
    ds.setValue(3.14)
    g["QDoubleSpinBox"] = ds
    dt = QDateTimeEdit()
    g["QDateTimeEdit"] = dt

    btn = QPushButton("A Push Button")
    g["QPushButton"] = btn
    tbn = QToolButton()
    tbn.setText("Tool Button")
    g["QToolButton"] = tbn
    cbx = QCheckBox("A check box label")
    cbx.setChecked(True)
    g["QCheckBox"] = cbx
    rb = QRadioButton("A radio button label")
    g["QRadioButton"] = rb

    gb = QGroupBox("Group box title")
    lay = QVBoxLayout(gb)
    lay.addWidget(QLabel("label inside a group box"))
    g["QGroupBox"] = gb

    lbl = QLabel("A plain label with some text")
    g["QLabel"] = lbl
    ml = QLabel("A muted secondary label")
    ml.setProperty("role", "muted")
    g["QLabel (muted)"] = ml

    tabs = QTabWidget()
    tabs.addTab(QLabel("page one content"), "First tab")
    tabs.addTab(QLabel("page two content"), "Second tab")
    g["QTabWidget"] = tabs

    pb = QProgressBar()
    pb.setValue(45)
    g["QProgressBar"] = pb

    menu = QMenu()
    menu.addAction("Open")
    menu.addAction("Copy path")
    menu.addSeparator()
    dis = menu.addAction("Disabled entry")
    dis.setEnabled(False)
    g["QMenu"] = menu

    if tmpdir is not None:
        import zipfile

        from ui.archive_pane import ArchivePaneWidget

        zpath = str(Path(tmpdir) / "sample.zip")
        with zipfile.ZipFile(zpath, "w") as z:
            for name in ("docs/readme.txt", "docs/guide.md", "src/main.py", "src/util/helpers.py"):
                z.writestr(name, "content " * 20)
        pane = ArchivePaneWidget(zpath)
        pane._tree.expandAll()
        g["ArchivePaneWidget tree (real zip)"] = pane
    _ = Qt  # keep import used
    return g


def audit(
    theme: str, window, tmpdir: str | None = None
) -> dict[str, tuple[float | None, str, str]]:
    """Apply *theme* through the real main window and measure the gallery."""
    from PyQt6.QtWidgets import QApplication

    window._apply_theme(theme)
    app = QApplication.instance()
    results: dict[str, tuple[float | None, str, str]] = {}
    gallery = build_gallery(tmpdir)
    try:
        for name, widget in gallery.items():
            widget.resize(320, 160)
            widget.show()
            app.processEvents()
            results[name] = measure_widget(getattr(widget, "_tree", widget))
            widget.hide()
    finally:
        for widget in gallery.values():
            widget.deleteLater()
    return results


def main() -> None:  # pragma: no cover - manual tool
    import tempfile
    from unittest import mock

    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance() or QApplication([])
    home = tempfile.mkdtemp()
    with mock.patch("pathlib.Path.home", return_value=Path(home)):
        from ui.main_window import MainWindow

        win = MainWindow()
        names = None
        table: dict[str, dict] = {}
        for theme in THEMES:
            res = audit(theme, win, home)
            names = list(res)
            table[theme] = res
        print("%-26s" % "control", *("%-13s" % t for t in THEMES))
        for n in names:
            row = []
            for t in THEMES:
                ratio, _bg, _fg = table[t][n]
                row.append("%-13s" % ("-" if ratio is None else f"{ratio:5.1f}"))
            print("%-26s" % n, *row)
    _ = app


if __name__ == "__main__":
    main()
