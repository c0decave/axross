"""The hex view draws each byte from a prepared text, pixel for pixel what
it drew before, in a third of the time.

Measured 2026-10-25 (scripts/ui_bench.py ``hex_scroll_50_pages``): 543 ms
for 50 pages of a 30 MiB file, ~9 ms per repaint - HexWidget.paintEvent
laid out and drew two texts per byte with QPainter.drawText (32 per line).
The 256 hex pairs and 256 ASCII cells are now QStaticText prepared once
per font and drawn at the same pixel positions (drawStaticText), and the
pen changes only when the colour does. The reference below is the old
paintEvent, kept here as the oracle: the images must be identical.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets")
from PyQt6.QtCore import QRect, Qt  # noqa: E402
from PyQt6.QtGui import QImage, QPainter  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _reference_paint(self, event) -> None:
    """HexWidget.paintEvent as it was before 2026-10-25 (BYTES_PER_LINE 16)."""
    from ui.hex_editor import BYTES_PER_LINE

    painter = QPainter(self)
    painter.fillRect(self.rect(), self._bg_color)
    painter.setFont(self.font())
    visible = self._visible_lines()
    start_line = self._scroll_offset
    end_line = min(start_line + visible + 1, self._total_lines())
    for line_idx in range(start_line, end_line):
        y = (line_idx - start_line) * self._char_h
        offset = line_idx * BYTES_PER_LINE
        line_bytes = self._data[offset: offset + BYTES_PER_LINE]
        painter.setPen(self._offset_color)
        painter.drawText(0, y + self._fm.ascent(), f"{offset:08X}: ")
        painter.setPen(self._separator_color)
        sep_x = int(self._hex_start - self._char_w * 0.5)
        painter.drawLine(sep_x, y, sep_x, y + self._char_h)
        sep_x2 = int(self._ascii_start - self._char_w * 0.5)
        painter.drawLine(sep_x2, y, sep_x2, y + self._char_h)
        for i, byte in enumerate(line_bytes):
            byte_offset = offset + i
            is_cursor = byte_offset == self._cursor_pos
            is_selected = self._selection_start >= 0 and min(
                self._selection_start, self._selection_end
            ) <= byte_offset <= max(self._selection_start, self._selection_end)
            is_modified = byte_offset in self._modified_offsets
            hex_x = int(self._hex_start + i * 3 * self._char_w)
            if is_cursor and self._editing_hex:
                painter.fillRect(QRect(hex_x, y, int(self._char_w * 2), self._char_h),
                                 self._cursor_color)
            elif is_selected:
                painter.fillRect(QRect(hex_x, y, int(self._char_w * 2), self._char_h),
                                 self._selection_color)
            painter.setPen(self._modified_color if is_modified else self._text_color)
            painter.drawText(hex_x, y + self._fm.ascent(), f"{byte:02X}")
            ascii_x = int(self._ascii_start + i * self._char_w)
            ascii_char = chr(byte) if 32 <= byte < 127 else "."
            if is_cursor and not self._editing_hex:
                painter.fillRect(QRect(ascii_x, y, self._char_w, self._char_h),
                                 self._cursor_color)
            elif is_selected:
                painter.fillRect(QRect(ascii_x, y, self._char_w, self._char_h),
                                 self._selection_color)
            painter.setPen(self._modified_color if is_modified else self._ascii_color)
            painter.drawText(ascii_x, y + self._fm.ascent(), ascii_char)
    painter.end()


def _widget(data: bytes, width=900, height=500):
    from ui.hex_editor import HexWidget

    w = HexWidget()
    w.resize(width, height)
    w.set_data(data)
    w.show()
    APP.processEvents()
    return w


def _image(w) -> QImage:
    img = QImage(w.size(), QImage.Format.Format_ARGB32)
    img.fill(0)
    w.render(img)
    return img


def _reference_image(w, monkeypatch) -> QImage:
    from ui import hex_editor as HE

    with monkeypatch.context() as m:
        m.setattr(HE.HexWidget, "paintEvent", _reference_paint)
        return _image(w)


def _same_as_before(w, monkeypatch) -> None:
    new = _image(w)
    old = _reference_image(w, monkeypatch)
    assert new == old


class _CountingPainter(QPainter):
    texts = 0
    static = 0

    def drawText(self, *args):  # noqa: N802 - Qt
        type(self).texts += 1
        return super().drawText(*args)

    def drawStaticText(self, *args):  # noqa: N802 - Qt
        type(self).static += 1
        return super().drawStaticText(*args)


# -- happy ---------------------------------------------------------------------


def test_happy_a_page_draws_one_layout_per_line_not_one_per_byte(monkeypatch):
    from ui import hex_editor as HE

    w = _widget(bytes(range(256)) * 64)
    monkeypatch.setattr(HE, "QPainter", _CountingPainter)
    _CountingPainter.texts = _CountingPainter.static = 0
    w.repaint()
    lines = min(w._visible_lines() + 1, w._total_lines())
    assert _CountingPainter.texts == lines  # the offset column only
    assert _CountingPainter.static == lines * 32


def test_happy_every_byte_value_looks_as_before(monkeypatch):
    w = _widget(bytes(range(256)) * 8)
    _same_as_before(w, monkeypatch)
    w._scroll_offset = 40
    _same_as_before(w, monkeypatch)


# -- sad -----------------------------------------------------------------------


def test_sad_cursor_selection_and_modified_bytes_look_as_before(monkeypatch):
    w = _widget(bytes(range(256)) * 4)
    w._cursor_pos = 37
    w._selection_start, w._selection_end = 50, 130
    w._modified_offsets = {3, 38, 60, 61, 200}
    _same_as_before(w, monkeypatch)
    w._editing_hex = False
    w._selection_start, w._selection_end = 140, 90  # backwards
    _same_as_before(w, monkeypatch)


def test_sad_an_empty_file_looks_as_before(monkeypatch):
    _same_as_before(_widget(b""), monkeypatch)


# -- edge ----------------------------------------------------------------------


def test_edge_a_short_last_line_and_a_narrow_view_look_as_before(monkeypatch):
    w = _widget(b"hello world, this is the end" * 3 + b"\x00\xff", width=420, height=120)
    _same_as_before(w, monkeypatch)
    w._scroll_offset = w._total_lines() - 1
    _same_as_before(w, monkeypatch)


def test_edge_a_new_font_prepares_new_texts(monkeypatch):
    from PyQt6.QtGui import QFont

    w = _widget(bytes(range(64)))
    w.repaint()
    first = w._static_texts
    font = QFont(w.font())
    font.setPointSize(font.pointSize() + 4)
    w.setFont(font)
    w.repaint()
    assert w._static_texts is not first
    _same_as_before(w, monkeypatch)


# -- e2e -----------------------------------------------------------------------


def test_e2e_the_hex_dialog_scrolls_and_edits_and_looks_as_before(tmp_path, monkeypatch):
    from core.local_fs import LocalFS
    from ui.hex_editor import HexEditorDialog

    path = tmp_path / "data.bin"
    path.write_bytes(bytes(range(256)) * 300)
    dialog = HexEditorDialog(LocalFS(), str(path))
    try:
        dialog.resize(1000, 600)
        dialog.show()
        APP.processEvents()
        hexw = dialog._hex_widget
        dialog._scrollbar.setValue(200)
        APP.processEvents()
        hexw.setFocus()
        QTest.keyClicks(hexw, "ab")  # edits the byte at the cursor
        QTest.keyClick(hexw, Qt.Key.Key_Down)
        APP.processEvents()
        assert hexw.is_modified
        _same_as_before(hexw, monkeypatch)
    finally:
        dialog._hex_widget._modified_offsets.clear()
        dialog.reject()
        dialog.deleteLater()
        APP.processEvents()
