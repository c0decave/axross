#!/usr/bin/env python3
"""Two ways the chmod editor wrote a mode the user never chose.

* A symlink. The pane lists a link with its lstat mode (0777 on Linux),
  but ``chmod`` follows the link, so unticking "Others: write" on a link
  to a 0600 key wrote 0775 onto the KEY. A link's own mode cannot be
  changed on Linux and means nothing elsewhere, so the editor is
  read-only for a link and ``apply()`` never calls chmod for it.
* A four-digit octal mode. The field accepted four characters but the
  handler applied every prefix as the user typed and then ignored the
  complete value as "above 0o777": typing 1777 wrote 0177, 4755 wrote
  0475. The field now takes the full 0o7777 range; anything that is not
  an octal mode marks the field invalid and the hosts disable OK.
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

from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialogButtonBox  # noqa: E402

from models.file_item import FileItem  # noqa: E402
from ui.permissions_dialog import PermissionsDialog, PermissionsWidget  # noqa: E402

APP = QApplication.instance() or QApplication([])

POSIX = pytest.mark.skipif(not hasattr(os, "geteuid"), reason="POSIX modes")


class _RecordingBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[str, int]] = []

    def chmod(self, path: str, mode: int) -> None:
        self.calls.append((path, mode))


def _item(mode: int = 0o644, *, is_link: bool = False, is_dir: bool = False) -> FileItem:
    return FileItem(
        name="f",
        size=1,
        modified=datetime(2026, 1, 1),
        permissions=mode,
        is_dir=is_dir,
        is_link=is_link,
        link_target="/target" if is_link else "",
        owner="u",
        group="g",
    )


@pytest.fixture()
def make():
    made: list = []

    def _make(mode: int = 0o644, *, backend=None, is_link: bool = False, is_dir: bool = False):
        w = PermissionsWidget(
            backend or _RecordingBackend(), "/x/f", _item(mode, is_link=is_link, is_dir=is_dir)
        )
        w.show()
        APP.processEvents()
        made.append(w)
        return w

    yield _make
    for w in made:
        w.close()
        w.deleteLater()
    APP.processEvents()


def _type(widget: PermissionsWidget, text: str) -> None:
    """Type *text* into the octal field the way a user does: key by key."""
    widget._octal_edit.selectAll()
    QTest.keyClicks(widget._octal_edit, text)
    APP.processEvents()


# --------------------------------------------------------------------------
# Symlinks: the editor never writes through the link
# --------------------------------------------------------------------------


def test_edge_symlink_editor_is_read_only(make):
    w = make(0o777, is_link=True)
    assert all(not cb.isEnabled() for cb in w._checks)
    assert not w._octal_edit.isEnabled()
    assert "link" in w._link_note.text().lower()
    assert not w._link_note.isHidden()


def test_happy_regular_file_editor_is_editable(make):
    w = make(0o644)
    assert all(cb.isEnabled() for cb in w._checks)
    assert w._octal_edit.isEnabled()
    assert w._link_note.isHidden()


def test_sad_symlink_apply_never_calls_chmod(make):
    """Even a change made behind the disabled controls is refused."""
    backend = _RecordingBackend()
    w = make(0o777, backend=backend, is_link=True)
    w._checks[7].setChecked(False)  # others write
    error = w.apply()
    assert error is not None and "link" in error.lower()
    assert backend.calls == []


def test_happy_symlink_unchanged_apply_is_a_quiet_no_op(make):
    backend = _RecordingBackend()
    w = make(0o777, backend=backend, is_link=True)
    assert w.apply() is None
    assert backend.calls == []


@POSIX
def test_edge_properties_on_a_real_symlink_leaves_the_target_mode(tmp_path):
    """The review's reproducer, end to end with LocalFS."""
    from core.local_fs import LocalFS
    from ui.properties_dialog import PropertiesDialog

    key = tmp_path / "id_ed25519"
    key.write_text("PRIVATE")
    key.chmod(0o600)
    link = tmp_path / "deploy_key"
    link.symlink_to(key)
    fs = LocalFS()
    item = next(i for i in fs.list_dir(str(tmp_path)) if i.name == "deploy_key")
    dlg = PropertiesDialog(fs, str(link), item)
    try:
        dlg._permissions._checks[7].setChecked(False)
        with pytest.MonkeyPatch.context() as mp:
            shown: list = []
            mp.setattr(
                "ui.properties_dialog.QMessageBox.critical",
                lambda *a, **k: shown.append(a),
            )
            dlg._on_accept()
        assert os.stat(key).st_mode & 0o7777 == 0o600
    finally:
        dlg.deleteLater()
        APP.processEvents()


# --------------------------------------------------------------------------
# Four-digit octal modes
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("typed", "expected"),
    [("1777", 0o1777), ("4755", 0o4755), ("2775", 0o2775), ("7777", 0o7777)],
)
def test_happy_typed_four_digit_mode_is_written(make, typed, expected):
    backend = _RecordingBackend()
    w = make(0o755, backend=backend, is_dir=True)
    _type(w, typed)
    assert w._octal_edit.text() == typed
    assert w.is_valid()
    assert w.apply() is None
    assert backend.calls == [("/x/f", expected)]


def test_happy_leading_zero_clears_the_special_bits(make):
    """``0750`` on a setuid file means: no setuid. That is how chmod(1)
    reads a four-digit mode, and the only way to clear the bit here."""
    backend = _RecordingBackend()
    w = make(0o4755, backend=backend)
    _type(w, "0750")
    assert w.apply() is None
    assert backend.calls == [("/x/f", 0o750)]


def test_edge_three_digits_keep_the_files_special_bits(make):
    backend = _RecordingBackend()
    w = make(0o2775, backend=backend, is_dir=True)
    _type(w, "770")
    assert w.apply() is None
    assert backend.calls == [("/x/f", 0o2770)]


def test_edge_field_and_preview_show_special_bits(make):
    w = make(0o4755)
    assert w._octal_edit.text() == "4755"
    assert "rwsr-xr-x" in w._preview.text()
    assert "(4755)" in w._preview.text()
    _type(w, "1754")
    assert "rwxr-xr-T" in w._preview.text()


def test_edge_checkbox_toggle_keeps_the_typed_special_bits(make):
    backend = _RecordingBackend()
    w = make(0o755, backend=backend, is_dir=True)
    _type(w, "1777")
    w._checks[7].setChecked(False)  # others write
    assert w._octal_edit.text() == "1775"
    assert w.apply() is None
    assert backend.calls == [("/x/f", 0o1775)]


@pytest.mark.parametrize("typed", ["9", "78", "8888", "zz", "12a"])
def test_sad_invalid_octal_marks_the_field_invalid_and_never_chmods(make, typed):
    backend = _RecordingBackend()
    w = make(0o644, backend=backend)
    _type(w, typed)
    assert not w.is_valid()
    error = w.apply()
    assert error is not None and "octal" in error.lower()
    assert backend.calls == []


@pytest.mark.parametrize("text", ["8888", "7-7", "zz"])
def test_sad_invalid_whole_value_leaves_the_checkboxes(make, text):
    w = make(0o644)
    before = [cb.isChecked() for cb in w._checks]
    w._octal_edit.setText(text)
    assert not w.is_valid()
    assert [cb.isChecked() for cb in w._checks] == before


def test_sad_empty_field_is_invalid(make):
    w = make(0o644)
    w._octal_edit.clear()
    assert not w.is_valid()


def test_edge_validity_signal_follows_the_field(make):
    w = make(0o644)
    seen: list[bool] = []
    w.validity_changed.connect(seen.append)
    _type(w, "9")
    _type(w, "640")
    assert seen[0] is False
    assert seen[-1] is True
    assert w.is_valid()


def test_sad_dialog_ok_is_disabled_while_the_field_is_invalid():
    dlg = PermissionsDialog(_RecordingBackend(), "/x/f", _item(0o644))
    try:
        ok = dlg.findChild(QDialogButtonBox).button(QDialogButtonBox.StandardButton.Ok)
        _type(dlg._widget, "9")
        assert not ok.isEnabled()
        _type(dlg._widget, "600")
        assert ok.isEnabled()
    finally:
        dlg.deleteLater()
        APP.processEvents()


def test_sad_properties_ok_is_disabled_while_the_field_is_invalid():
    from ui.properties_dialog import PropertiesDialog

    class _B(_RecordingBackend):
        name = "Fake"

    dlg = PropertiesDialog(_B(), "/x/f", _item(0o644))
    try:
        ok = dlg.findChild(QDialogButtonBox).button(QDialogButtonBox.StandardButton.Ok)
        _type(dlg._permissions, "8")
        assert not ok.isEnabled()
        _type(dlg._permissions, "644")
        assert ok.isEnabled()
    finally:
        dlg.deleteLater()
        APP.processEvents()


@POSIX
def test_edge_dialog_writes_a_typed_sticky_mode_to_disk(tmp_path):
    from core.local_fs import LocalFS

    d = tmp_path / "shared"
    d.mkdir()
    d.chmod(0o755)
    fs = LocalFS()
    dlg = PermissionsDialog(fs, str(d), fs.stat(str(d)))
    try:
        _type(dlg._widget, "1777")
        dlg.findChild(QDialogButtonBox).button(QDialogButtonBox.StandardButton.Ok).click()
        assert os.stat(d).st_mode & 0o7777 == 0o1777
    finally:
        dlg.deleteLater()
        APP.processEvents()
