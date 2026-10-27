"""Save As never replaces a file whose existence it could not check.

ui/editor_window.py save_as() asked ``backend.exists(path)`` (and
``is_dir`` for an existing one) before writing, and on an OSError set
``exists = folder = False`` - "the write below says what is wrong". A
timeout or a refused permission on the probe was read as "the name is
free", so the confirmation was skipped and the write replaced the
existing file. Unknown is not "absent": the save is refused with a
message and nothing is written.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtGui import QAction  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core.ram_fs import RamFsSession  # noqa: E402

APP = QApplication.instance() or QApplication([])
YES = QMessageBox.StandardButton.Yes


class _FlakyProbe(RamFsSession):
    """A remote whose first existence probe of one path fails (a timeout
    on the wire); later probes, reads and writes go through - the save's
    own write then succeeds and replaces whatever is there."""

    def __init__(self, *, fail_exists=(), fail_is_dir=()):
        super().__init__()
        self.fail_exists = set(fail_exists)
        self.fail_is_dir = set(fail_is_dir)

    def exists(self, path):
        if path in self.fail_exists:
            self.fail_exists.discard(path)
            raise TimeoutError(f"probe of {path} timed out")
        return super().exists(path)

    def is_dir(self, path):
        if path in self.fail_is_dir:
            self.fail_is_dir.discard(path)
            raise PermissionError(f"probe of {path} refused")
        return super().is_dir(path)


def _write(ram, path, data):
    with ram.open_write(path) as fh:
        fh.write(data)


def _read(ram, path):
    with ram.open_read(path) as fh:
        return fh.read()


@pytest.fixture
def window():
    from ui.editor_window import EditorWindow

    win = EditorWindow()
    win.show()
    yield win
    with mock.patch("ui.editor_window.QMessageBox.question",
                    return_value=QMessageBox.StandardButton.Discard):
        win.close()
    win.deleteLater()
    APP.processEvents()


def _remote(**fail):
    ram = _FlakyProbe(**fail)
    _write(ram, "/dir/a.txt", b"mine\n")
    _write(ram, "/dir/b.txt", b"theirs\n")
    return ram


def test_happy_a_free_name_saves_without_asking(window):
    ram = _remote()
    tab = window.open_file(ram, "/dir/a.txt")
    with mock.patch("ui.editor_window.QInputDialog.getText", return_value=("/dir/c.txt", True)), \
            mock.patch("ui.editor_window.QMessageBox.question") as asked:
        assert window.save_as() is True
    assert not asked.called
    assert _read(ram, "/dir/c.txt") == b"mine\n" and tab.path == "/dir/c.txt"


def test_sad_a_failed_existence_probe_writes_nothing(window):
    ram = _remote(fail_exists={"/dir/b.txt"})
    tab = window.open_file(ram, "/dir/a.txt")
    with mock.patch("ui.editor_window.QInputDialog.getText", return_value=("/dir/b.txt", True)), \
            mock.patch("ui.editor_window.QMessageBox.question", return_value=YES) as asked, \
            mock.patch("ui.editor_window.QMessageBox.critical") as said:
        assert window.save_as() is False
    said.assert_called_once()
    assert "b.txt" in said.call_args.args[2]
    assert not asked.called
    assert _read(ram, "/dir/b.txt") == b"theirs\n"
    assert tab.path == "/dir/a.txt"


def test_edge_a_failed_folder_probe_of_an_existing_name_writes_nothing(window):
    ram = _remote(fail_is_dir={"/dir/b.txt"})
    tab = window.open_file(ram, "/dir/a.txt")
    with mock.patch("ui.editor_window.QInputDialog.getText", return_value=("/dir/b.txt", True)), \
            mock.patch("ui.editor_window.QMessageBox.question", return_value=YES), \
            mock.patch("ui.editor_window.QMessageBox.critical") as said:
        assert window.save_as() is False
    said.assert_called_once()
    assert _read(ram, "/dir/b.txt") == b"theirs\n"
    assert tab.path == "/dir/a.txt"


def test_e2e_file_menu_save_as_with_a_failing_probe_keeps_the_file(window):
    """Through the window's own File > Save As action."""
    ram = _remote(fail_exists={"/dir/b.txt"})
    window.open_file(ram, "/dir/a.txt")
    action = next(a for a in window.findChildren(QAction)
                  if a.text().replace("&", "").startswith("Save As"))
    with mock.patch("ui.editor_window.QInputDialog.getText", return_value=("/dir/b.txt", True)), \
            mock.patch("ui.editor_window.QMessageBox.question", return_value=YES), \
            mock.patch("ui.editor_window.QMessageBox.critical") as said:
        action.trigger()
        APP.processEvents()
    said.assert_called_once()
    assert _read(ram, "/dir/b.txt") == b"theirs\n"
