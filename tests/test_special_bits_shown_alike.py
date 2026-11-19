"""setuid, setgid and sticky are shown alike everywhere: the file pane's
Permissions column, Properties and the Permissions dialog (current and
preview) all write ``-rwsr-xr-x  (4755)`` as ``ls -l`` does - before,
Properties and the dialog's "Current" showed ``rwxr-xr-x`` and only the
preview had the ``s``."""
from __future__ import annotations

import os
from datetime import datetime

import pytest

from models.file_item import FileItem, permission_string

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
_APP = None


@pytest.mark.parametrize("mode, text", [
    (0o4755, "rwsr-xr-x"), (0o4644, "rwSr--r--"), (0o2750, "rwxr-s---"),
    (0o2640, "rw-r-S---"), (0o1777, "rwxrwxrwt"), (0o1776, "rwxrwxrwT"),
    (0o0644, "rw-r--r--"), (0o7777, "rwsrwsrwt"),
])
def test_happy_the_string_marks_the_special_bits(mode, text):
    assert permission_string(mode) == text
    item = FileItem(name="f", permissions=mode)
    assert item.permissions_str == text and item.mode_str == "-" + text


def test_happy_properties_and_permissions_say_the_same(tmp_path):
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication, QLabel

    from core.local_fs import LocalFS
    from ui import properties_dialog as PD
    from ui.permissions_dialog import PermissionsWidget

    global _APP
    _APP = QApplication.instance() or QApplication([])  # kept: a dropped one aborts Qt
    path = tmp_path / "tool"
    path.write_text("x")
    os.chmod(path, 0o4755)
    item = FileItem(name="tool", permissions=0o4755, modified=datetime.now())
    widget = PermissionsWidget(LocalFS(), str(path), item)
    try:
        labels = [w.text() for w in widget.findChildren(QLabel)]
        assert "-rwsr-xr-x  (4755)" in labels
        assert any(t.endswith("-rwsr-xr-x  (4755)") for t in labels if "Preview" in t)
    finally:
        widget.deleteLater()
    dialog = PD.PropertiesDialog(LocalFS(), str(path), LocalFS().stat(str(path)))
    try:
        assert dialog._compute_field("Permissions") == "-rwsr-xr-x  (4755)"
    finally:
        dialog.deleteLater()
