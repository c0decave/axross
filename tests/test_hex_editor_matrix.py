"""The hex editor end to end: keys, mouse, search, goto and save on a real
file, over a matrix of file sizes.

ui/hex_editor.py was at 57 % of its branches (docs/TEST_COVERAGE_MATRIX.md
of 2026-10-26): navigation, the mouse, search and goto, the "file changed
on the server" question of Save and every refusal of the dialog ran in no
test.

Bugs found while writing it:

* Enter in the Goto field jumped to the next search hit instead of the
  offset typed, and Enter in the Search field searched twice (skipping the
  first hit): "Find Next" was the dialog's default button, so Enter clicked
  it on top of the field's own action. No button of the window is a default
  button now.
* Tab did not switch between the hex and the ASCII column (the code for it
  never ran): Qt moved the focus to the Search field first. Tab switches
  now; Shift+Tab still leaves the view.
* Find Next never found the only match again from the match itself: the
  wrapped search ended before it ("Not found" for a pattern on screen).
* Page Down in an empty file put the cursor at offset -1: the status line
  read "Offset: 0x-0000001 (-1)".
* Goto with an offset past the end of the file did nothing and said
  nothing; the status line now says the offset is past the end.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QPoint, QPointF, Qt  # noqa: E402
from PyQt6.QtGui import QWheelEvent  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from ui.hex_editor import BYTES_PER_LINE, HexEditorDialog  # noqa: E402

APP = QApplication.instance() or QApplication([])
K = Qt.Key


@pytest.fixture
def make(tmp_path):
    opened = []

    def _make(data: bytes, *, read_only=False, background=False, name="blob.bin"):
        path = tmp_path / name
        path.write_bytes(data)
        dlg = HexEditorDialog(LocalFS(), str(path), read_only=read_only, background=background)
        opened.append(dlg)
        dlg.show()
        if background:
            end = time.time() + 10
            while dlg.loading and time.time() < end:
                APP.processEvents()
                time.sleep(0.01)
        dlg._hex_widget.setFocus()
        return dlg, path

    yield _make
    for dlg in opened:
        dlg._hex_widget._modified_offsets.clear()  # close without the question
        dlg.close()
        dlg.deleteLater()
    APP.processEvents()


def keys(dlg, *seq) -> None:
    for k in seq:
        if isinstance(k, str):
            QTest.keyClicks(dlg._hex_widget, k)
        elif isinstance(k, tuple):
            QTest.keyClick(dlg._hex_widget, k[0], k[1])
        else:
            QTest.keyClick(dlg._hex_widget, k)


def cursor(dlg) -> int:
    return dlg._hex_widget._cursor_pos


# ---------------------------------------------------------------- matrix
SIZES = [0, 1, BYTES_PER_LINE, BYTES_PER_LINE + 1, 4097]


@pytest.mark.parametrize("size", SIZES)
def test_edge_every_size_opens_navigates_and_closes(make, size):
    data = bytes(range(256)) * (size // 256 + 1)
    dlg, _ = make(data[:size])
    assert dlg.loaded and dlg._size_label.text() == f"{size:,} bytes"
    for k in (
        K.Key_End,
        K.Key_PageDown,
        K.Key_Down,
        K.Key_Right,
        (K.Key_End, Qt.KeyboardModifier.ControlModifier),
    ):
        keys(dlg, k)
        assert 0 <= cursor(dlg) <= max(0, size - 1), k
    keys(dlg, K.Key_PageUp, K.Key_Up, K.Key_Left, (K.Key_Home, Qt.KeyboardModifier.ControlModifier))
    assert cursor(dlg) == 0
    dlg._update_status()
    assert dlg._offset_label.text().startswith("Offset: 0x0")
    with mock.patch.object(QMessageBox, "question") as asked:
        dlg.close()
    asked.assert_not_called()


@pytest.mark.parametrize("background", [False, True])
def test_happy_e2e_type_hex_and_ascii_then_save_writes_the_file(make, background):
    dlg, path = make(b"\x00\x01\x02\x03hello", background=background)
    keys(dlg, "ab", K.Key_Tab, "Z")  # 0xAB at 0, then 'Z' at 1 in the ASCII column
    assert dlg._hex_widget.get_data()[:2] == b"\xabZ"
    dlg._update_status()
    assert dlg._status_label.text() == "Modified (2 bytes changed)"
    assert dlg._btn_save.isEnabled()
    saved = []
    dlg.saved.connect(lambda: saved.append(True))
    QTest.mouseClick(dlg._btn_save, Qt.MouseButton.LeftButton)
    assert path.read_bytes() == b"\xabZ\x02\x03hello"
    assert dlg._status_label.text() == "Saved" and saved == [True]
    assert not dlg._btn_save.isEnabled() and not dlg._hex_widget.is_modified


# --------------------------------------------------------------- happy
def test_happy_hex_nibbles_move_the_cursor_one_byte_per_two_digits(make):
    dlg, _ = make(b"\x00" * 4)
    keys(dlg, "1")
    assert (cursor(dlg), dlg._hex_widget._cursor_nibble) == (0, 1)
    keys(dlg, "2", "3")
    assert dlg._hex_widget.get_data()[:2] == b"\x12\x30"
    keys(dlg, K.Key_Left)
    assert (cursor(dlg), dlg._hex_widget._cursor_nibble) == (1, 0)
    keys(dlg, K.Key_Left)
    assert (cursor(dlg), dlg._hex_widget._cursor_nibble) == (0, 1)


def test_happy_home_end_and_lines(make):
    dlg, _ = make(bytes(40))
    keys(dlg, K.Key_Down, K.Key_Right, K.Key_Right)  # hex mode: two nibbles = one byte
    assert cursor(dlg) == BYTES_PER_LINE + 1
    keys(dlg, K.Key_End)
    assert cursor(dlg) == 2 * BYTES_PER_LINE - 1
    keys(dlg, K.Key_Home)
    assert cursor(dlg) == BYTES_PER_LINE
    keys(dlg, (K.Key_End, Qt.KeyboardModifier.ControlModifier))
    assert cursor(dlg) == 39


def test_happy_a_click_in_either_column_places_the_cursor_and_the_mode(make):
    dlg, _ = make(bytes(range(64)))
    w = dlg._hex_widget
    y = int(w._char_h * 1.5)  # second line
    x_hex = int(w._hex_start + 3 * w._char_w * 2 + 1)  # third byte of the hex column
    QTest.mouseClick(w, Qt.MouseButton.LeftButton, pos=QPoint(x_hex, y))
    assert (cursor(dlg), w._editing_hex) == (BYTES_PER_LINE + 2, True)
    x_ascii = int(w._ascii_start + w._char_w * 5 + 1)
    QTest.mouseClick(w, Qt.MouseButton.LeftButton, pos=QPoint(x_ascii, y))
    assert (cursor(dlg), w._editing_hex) == (BYTES_PER_LINE + 5, False)


def test_happy_the_wheel_scrolls_and_stops_at_the_end(make):
    dlg, _ = make(bytes(BYTES_PER_LINE * 400))
    w = dlg._hex_widget

    def wheel(dy):
        event = QWheelEvent(
            QPointF(10, 10),
            QPointF(10, 10),
            QPoint(0, 0),
            QPoint(0, dy),
            Qt.MouseButton.NoButton,
            Qt.KeyboardModifier.NoModifier,
            Qt.ScrollPhase.NoScrollPhase,
            False,
        )
        w.wheelEvent(event)

    wheel(-120)
    assert w._scroll_offset == 3
    for _ in range(500):
        wheel(-120)
    assert w._scroll_offset == w._total_lines() - w._visible_lines()
    wheel(120 * 1000)
    assert w._scroll_offset == 0


@pytest.mark.parametrize(
    "query, offset",
    [("FF 00", 6), ("ff,00", 6), ("text: AB", 2), ("B..", 3), ("AB", -1), ("xyz", -1)],
)
def test_happy_search_hex_or_text(make, query, offset):
    """Hex bytes first ("AB" is the byte 0xAB), text after "text:", and
    text as well when the query is no hex."""
    dlg, _ = make(b"..AB..\xff\x00..")
    dlg._search_edit.setText(query)
    QTest.keyClick(dlg._search_edit, K.Key_Return)
    if offset >= 0:
        assert cursor(dlg) == offset
        assert dlg._status_label.text() == f"Found at offset 0x{offset:08X}"
    else:
        assert dlg._status_label.text() == "Not found"


def test_sad_enter_in_the_goto_field_goes_to_the_offset_not_to_a_search_hit(make):
    dlg, _ = make(b"..AB..\xff\x00" + bytes(32))
    dlg._search_edit.setText("FF 00")
    dlg._goto_edit.setFocus()
    dlg._goto_edit.setText("3")
    QTest.keyClick(dlg._goto_edit, K.Key_Return)
    assert cursor(dlg) == 3


def test_sad_enter_in_the_search_field_searches_once(make):
    dlg, path = make(b"AB..AB..AB")
    dlg._search_edit.setFocus()
    dlg._search_edit.setText("text:AB")
    QTest.keyClick(dlg._search_edit, K.Key_Return)
    assert cursor(dlg) == 4  # the next hit after the cursor at 0, not the one after it
    QTest.keyClick(dlg._search_edit, K.Key_Return)
    assert cursor(dlg) == 8


def test_sad_enter_in_the_view_starts_nothing(make):
    dlg, path = make(b"AB..AB")
    dlg._search_edit.setText("text:AB")
    keys(dlg, K.Key_Return)
    assert cursor(dlg) == 0 and dlg._status_label.text() == "Loaded"
    assert not any(b.isDefault() or b.autoDefault() for b in dlg.findChildren(type(dlg._btn_save)))


def test_happy_tab_switches_between_the_hex_and_the_ascii_column(make):
    dlg, _ = make(b"\x00\x00")
    w = dlg._hex_widget
    dlg.activateWindow()
    w.setFocus()
    APP.processEvents()
    keys(dlg, K.Key_Tab)
    APP.processEvents()
    assert not w._editing_hex and APP.focusWidget() is w
    keys(dlg, "Z", K.Key_Tab, "4", "1")
    assert w.get_data() == b"ZA" and w._editing_hex


def test_edge_shift_tab_still_leaves_the_view(make):
    dlg, _ = make(b"\x00")
    dlg.activateWindow()
    dlg._hex_widget.setFocus()
    APP.processEvents()
    keys(dlg, (K.Key_Backtab, Qt.KeyboardModifier.ShiftModifier))
    APP.processEvents()
    assert dlg._hex_widget._editing_hex  # no mode switch
    assert APP.focusWidget() is not dlg._hex_widget


def test_edge_find_next_finds_the_only_match_again(make):
    dlg, _ = make(b"....needle....")
    dlg._search_edit.setText("text:needle")
    dlg._on_search()
    assert cursor(dlg) == 4
    dlg._on_search()
    assert cursor(dlg) == 4 and dlg._status_label.text() == "Found at offset 0x00000004"


def test_edge_search_wraps_around_to_the_start(make):
    dlg, _ = make(b"key....key....")
    dlg._search_edit.setText("text:key")
    dlg._on_search()
    assert cursor(dlg) == 7
    dlg._on_search()
    assert cursor(dlg) == 0  # past the last hit it starts over


def test_happy_goto_a_hex_offset(make):
    dlg, _ = make(bytes(0x200))
    dlg._goto_edit.setText("0x1A0")
    QTest.keyClick(dlg._goto_edit, K.Key_Return)
    assert cursor(dlg) == 0x1A0 and "0x000001A0" in dlg._offset_label.text()
    dlg._goto_edit.setText("10")  # hex, as the field says
    dlg._on_goto()
    assert cursor(dlg) == 0x10


# ----------------------------------------------------------------- sad
def test_sad_goto_garbage_or_past_the_end_says_so(make):
    dlg, _ = make(bytes(32))
    dlg._goto_edit.setText("zz")
    dlg._on_goto()
    assert dlg._status_label.text() == "Invalid offset"
    keys(dlg, K.Key_Right, K.Key_Right)
    dlg._goto_edit.setText("FFFF")
    dlg._on_goto()
    assert cursor(dlg) == 1  # stays
    assert dlg._status_label.text() == "Offset 0xFFFF is past the end (32 bytes)"


def test_sad_save_asks_when_the_file_changed_on_disk(make):
    dlg, path = make(b"original")
    keys(dlg, "00")
    path.write_bytes(b"changed elsewhere")
    with mock.patch.object(
        QMessageBox, "question", return_value=QMessageBox.StandardButton.No
    ) as q:
        dlg._save_file()
    q.assert_called_once()
    assert path.read_bytes() == b"changed elsewhere" and dlg._hex_widget.is_modified
    with mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
        dlg._save_file()
    assert path.read_bytes() == b"\x00riginal"


def test_sad_a_failed_save_says_why_and_keeps_the_edit(make):
    dlg, path = make(b"original")
    keys(dlg, "00")
    with (
        mock.patch(
            "core.atomic_io.atomic_write", side_effect=PermissionError(13, "Permission denied")
        ),
        mock.patch.object(QMessageBox, "critical") as critical,
    ):
        dlg._save_file()
    assert "Permission denied" in critical.call_args.args[2]
    assert path.read_bytes() == b"original"
    assert dlg._hex_widget.is_modified and dlg._btn_save.isEnabled()


def test_sad_reload_and_escape_ask_before_dropping_edits(make):
    dlg, _ = make(b"original")
    keys(dlg, "41")
    no = QMessageBox.StandardButton.No
    with mock.patch.object(QMessageBox, "question", return_value=no) as q:
        dlg._reload_file()
        keys(dlg, K.Key_Escape)
    assert q.call_count == 2
    assert dlg.isVisible() and dlg._hex_widget.get_data()[:1] == b"A"
    with mock.patch.object(QMessageBox, "question", return_value=QMessageBox.StandardButton.Yes):
        dlg._reload_file()
    assert dlg._hex_widget.get_data() == b"original" and not dlg._hex_widget.is_modified


def test_sad_an_unreadable_file_is_reported_and_the_window_does_not_open(tmp_path):
    with mock.patch.object(QMessageBox, "critical") as critical:
        dlg = HexEditorDialog(LocalFS(), str(tmp_path / "missing.bin"))
    critical.assert_called_once()
    assert not dlg.loaded and dlg.exec() == 0
    dlg.deleteLater()


def test_sad_a_file_over_the_open_limit_is_refused(make, tmp_path):
    path = tmp_path / "big.bin"
    path.write_bytes(bytes(2048))
    with (
        mock.patch("ui.hex_editor.max_open_bytes", return_value=1024),
        mock.patch.object(QMessageBox, "warning") as warning,
    ):
        dlg = HexEditorDialog(LocalFS(), str(path))
    assert "File Too Large" == warning.call_args.args[1]
    assert not dlg.loaded and dlg.exec() == 0
    dlg.deleteLater()


def test_sad_the_viewer_neither_edits_nor_offers_save(make):
    dlg, path = make(b"keepme", read_only=True)
    keys(dlg, "FF", K.Key_Tab, "zz")
    assert dlg._hex_widget.get_data() == b"keepme" and not dlg._btn_save.isVisible()


# ---------------------------------------------------------------- edge
def test_edge_page_down_in_an_empty_file_keeps_offset_zero(make):
    dlg, _ = make(b"")
    keys(dlg, K.Key_PageDown, K.Key_End, "AB", K.Key_Tab, "x")
    assert cursor(dlg) == 0 and dlg._hex_widget.get_data() == b""
    dlg._update_status()
    assert dlg._offset_label.text() == "Offset: 0x00000000 (0)"


def test_edge_the_last_byte_takes_both_nibbles_and_the_cursor_stays(make):
    dlg, path = make(b"\x00\x00")
    keys(dlg, (K.Key_End, Qt.KeyboardModifier.ControlModifier), "EF", "12")
    assert dlg._hex_widget.get_data() == b"\x00\x12" and cursor(dlg) == 1
    dlg._save_file()
    assert path.read_bytes() == b"\x00\x12"  # the size never changes


def test_edge_ctrl_letters_are_commands_not_bytes(make):
    dlg, _ = make(b"\x00\x00")
    keys(dlg, (K.Key_A, Qt.KeyboardModifier.ControlModifier))
    assert dlg._hex_widget.get_data() == b"\x00\x00" and not dlg._hex_widget.is_modified
