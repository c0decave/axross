#!/usr/bin/env python3
"""The chmod editor, extracted so two callers can share it.

``PermissionsDialog`` owned the checkbox grid, the octal field and the
preview line inline. The Properties dialog needs exactly that editor as
a tab, and a copy-paste would leave two implementations of a
security-relevant control to drift apart. The body moves into
``PermissionsWidget``; the dialog keeps its behaviour and just hosts
the widget.

The editor had no tests at all before this. It converts between three
representations of one value (nine checkboxes, an octal string, a
preview string) and writes the result through ``backend.chmod`` — the
sort of code where an off-by-one in the bit table is invisible until
someone's files end up world-writable.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from models.file_item import FileItem  # noqa: E402
from ui.permissions_dialog import PermissionsWidget  # noqa: E402

APP = QApplication.instance() or QApplication([])


class _RecordingBackend:
    """Minimal backend that records chmod calls."""

    def __init__(self, fail: Exception | None = None) -> None:
        self.calls: list[tuple[str, int]] = []
        self._fail = fail

    def chmod(self, path: str, mode: int) -> None:
        if self._fail is not None:
            raise self._fail
        self.calls.append((path, mode))


def _item(mode: int = 0o644, *, name: str = "a.txt", is_dir: bool = False) -> FileItem:
    return FileItem(
        name=name,
        size=10,
        modified=datetime(2026, 1, 1),
        permissions=mode,
        is_dir=is_dir,
        owner="alice",
        group="staff",
    )


@pytest.fixture()
def widget():
    def _make(mode: int = 0o644, backend=None, path: str = "/tmp/a.txt"):
        w = PermissionsWidget(backend or _RecordingBackend(), path, _item(mode))
        w.show()
        APP.processEvents()
        return w

    made: list = []

    def factory(*args, **kwargs):
        w = _make(*args, **kwargs)
        made.append(w)
        return w

    yield factory
    for w in made:
        w.close()
        w.deleteLater()
    APP.processEvents()


# --------------------------------------------------------------------------
# Happy path — the three representations agree
# --------------------------------------------------------------------------


def test_happy_checkboxes_reflect_the_incoming_mode(widget):
    w = widget(0o751)
    # rwx r-x --x
    assert [cb.isChecked() for cb in w._checks] == [
        True, True, True,
        True, False, True,
        False, False, True,
    ]


def test_happy_octal_field_shows_the_incoming_mode(widget):
    assert widget(0o644)._octal_edit.text() == "644"


def test_happy_typing_octal_updates_the_checkboxes(widget):
    w = widget(0o000)
    w._octal_edit.setText("755")
    assert w.selected_mode() == 0o755


def test_happy_toggling_a_checkbox_updates_the_octal_field(widget):
    w = widget(0o000)
    w._checks[0].setChecked(True)  # owner read
    assert w._octal_edit.text() == "400"
    assert w.selected_mode() == 0o400


def test_happy_apply_calls_chmod_with_the_selected_mode(widget):
    backend = _RecordingBackend()
    w = widget(0o644, backend=backend, path="/tmp/x")
    w._octal_edit.setText("600")
    assert w.apply() is None
    assert backend.calls == [("/tmp/x", 0o600)]


def test_happy_unchanged_mode_skips_the_chmod_call(widget):
    """Opening the editor and pressing OK must not issue a needless
    chmod — on some backends that is a write the user did not ask for."""
    backend = _RecordingBackend()
    w = widget(0o644, backend=backend)
    assert w.apply() is None
    assert backend.calls == []


# --------------------------------------------------------------------------
# Edge cases
# --------------------------------------------------------------------------


def test_edge_high_bits_are_preserved_when_deciding_no_op(widget):
    """A setuid file (04755) whose rwx bits are untouched must still
    count as unchanged — comparing the full mode instead of the low 9
    bits would issue a chmod that silently drops the setuid bit."""
    backend = _RecordingBackend()
    w = widget(0o4755, backend=backend)
    assert w.apply() is None
    assert backend.calls == []


def test_edge_octal_above_777_is_rejected(widget):
    w = widget(0o644)
    w._octal_edit.setText("7777")
    # Ignored: the checkboxes keep the previous value.
    assert w.selected_mode() == 0o644


def test_edge_non_octal_text_is_ignored(widget):
    w = widget(0o644)
    w._octal_edit.setText("zz")
    assert w.selected_mode() == 0o644


def test_edge_preview_matches_the_selection(widget):
    w = widget(0o640)
    assert "rw-r-----" in w._preview.text()
    assert "0640" in w._preview.text()


def test_edge_directory_preview_uses_the_directory_type_char():
    w = PermissionsWidget(_RecordingBackend(), "/tmp/d", _item(0o755, name="d", is_dir=True))
    assert w._preview.text().startswith("Preview: d")
    w.deleteLater()


# --------------------------------------------------------------------------
# Sad path
# --------------------------------------------------------------------------


def test_sad_chmod_failure_returns_the_error_text(widget):
    backend = _RecordingBackend(fail=OSError("read-only filesystem"))
    w = widget(0o644, backend=backend)
    w._octal_edit.setText("600")
    assert w.apply() == "read-only filesystem"


def test_sad_backend_without_chmod_returns_the_error_text(widget):
    class _NoChmod:
        def chmod(self, path, mode):
            raise OSError("chmod not supported by this backend")

    w = widget(0o644, backend=_NoChmod())
    w._octal_edit.setText("600")
    assert w.apply() == "chmod not supported by this backend"


# --------------------------------------------------------------------------
# The dialog still works after the extraction
# --------------------------------------------------------------------------


def test_dialog_still_exposes_the_editor_and_applies(widget):
    from ui.permissions_dialog import PermissionsDialog

    backend = _RecordingBackend()
    dlg = PermissionsDialog(backend, "/tmp/y", _item(0o644))
    dlg.show()
    APP.processEvents()
    dlg._widget._octal_edit.setText("640")
    dlg._apply()
    assert backend.calls == [("/tmp/y", 0o640)]
    dlg.deleteLater()
    APP.processEvents()
