"""Right-click > Create XLink… end to end: the real dialog, typed into with
QTest, on a real folder.

Before this file the feature had no end-to-end test: the pane test of it
(tests/test_pane_create_stale_folder.py) replaces the dialog's exec and
accessors, and the dialog's own checks (an unsafe name, a URL whose scheme
is not allowed, empty fields) ran in no test at all.

Bug found while writing it: a name whose ``.axlink`` already existed was
replaced without a question - New Folder and New File refuse an existing
name with "Path already exists", Create XLink wrote over it (core.xlink
writes through atomic_write, which replaces). It now refuses the same way
and leaves the existing link as it was.
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

from PyQt6.QtCore import Qt, QTimer  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QApplication,
    QComboBox,
    QDialogButtonBox,
    QLabel,
    QLineEdit,
)

from core import xlink as XL  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])


def wait_until(cond, timeout: float = 8.0) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.02)
    return cond()


@pytest.fixture
def folder(tmp_path) -> Path:
    root = tmp_path / "work"
    root.mkdir()
    (root / "notes.txt").write_text("n")
    return root


@pytest.fixture
def pane(folder):
    from ui.file_pane import FilePaneWidget

    p = FilePaneWidget(LocalFS())
    p.resize(700, 400)
    p.show()
    p.navigate(str(folder))
    yield p
    p.close()
    p.deleteLater()
    APP.processEvents()


def listed(pane) -> set[str]:
    proxy = pane._table.model()
    return {proxy.index(r, 0).data() for r in range(proxy.rowCount())}


def fields(dlg):
    name, url, display = dlg.findChildren(QLineEdit)
    errors = [lbl for lbl in dlg.findChildren(QLabel) if "c0392b" in lbl.styleSheet()]
    return name, url, display, dlg.findChild(QComboBox), errors[0]


def click(dlg, which) -> None:
    box = dlg.findChild(QDialogButtonBox)
    QTest.mouseClick(box.button(which), Qt.MouseButton.LeftButton)


def run_dialog(pane, steps) -> list[str]:
    """Open Create XLink… from the pane's right-click menu and let *steps*
    drive the dialog once it is up; returns the inline errors it showed."""
    from ui.create_xlink_dialog import CreateXlinkDialog

    seen: list[str] = []

    def drive() -> None:
        dlg = APP.activeModalWidget()
        if not isinstance(dlg, CreateXlinkDialog):
            QTimer.singleShot(20, drive)
            return
        steps(dlg, seen)

    action = next(a for a in pane._build_context_menu().actions() if a.text() == "Create XLink…")
    QTimer.singleShot(0, drive)
    action.trigger()
    return seen


def type_and_ok(name="", url="", display="", then_cancel=False):
    def steps(dlg, seen):
        n, u, d, _combo, err = fields(dlg)
        QTest.keyClicks(n, name)
        QTest.keyClicks(u, url)
        QTest.keyClicks(d, display)
        click(dlg, QDialogButtonBox.StandardButton.Ok)
        seen.append(err.text())
        if dlg.isVisible():
            click(dlg, QDialogButtonBox.StandardButton.Cancel)

    return steps


# ---------------------------------------------------------------- happy
def test_happy_e2e_create_xlink_from_the_menu_writes_the_link_and_lists_it(pane, folder):
    errors = run_dialog(pane, type_and_ok("jump", "sftp://host/srv/data", "Data share"))
    assert errors == [""]
    assert wait_until(lambda: "jump.axlink" in listed(pane))
    link = XL.read_xlink(LocalFS(), str(folder / "jump.axlink"))
    assert (link.target_url, link.display_name) == ("sftp://host/srv/data", "Data share")


def test_happy_picking_a_scheme_fills_an_empty_url_field(pane, folder):
    def steps(dlg, seen):
        n, u, _d, combo, _err = fields(dlg)
        QTest.keyClicks(n, "bucket")
        combo.setFocus()
        start = combo.currentIndex()
        QTest.keyClick(combo, Qt.Key.Key_Down)
        seen.append(u.text())
        seen.append(combo.itemText(start + 1))
        QTest.keyClicks(u, "my-bucket/key")
        click(dlg, QDialogButtonBox.StandardButton.Ok)

    url, scheme = run_dialog(pane, steps)
    assert url == f"{scheme}://"
    assert wait_until(lambda: "bucket.axlink" in listed(pane))
    assert XL.target_of(LocalFS(), str(folder / "bucket.axlink")) == f"{scheme}://my-bucket/key"


def test_happy_a_typed_url_is_kept_when_a_scheme_is_picked_afterwards(pane):
    def steps(dlg, seen):
        _n, u, _d, combo, _err = fields(dlg)
        QTest.keyClicks(u, "smb://server/share")
        combo.setFocus()
        QTest.keyClick(combo, Qt.Key.Key_Down)
        seen.append(u.text())
        click(dlg, QDialogButtonBox.StandardButton.Cancel)

    assert run_dialog(pane, steps) == ["smb://server/share"]


# ------------------------------------------------------------------ sad
@pytest.mark.parametrize(
    "url, message",
    [
        ("javascript:alert(1)", "not in the allow-list"),
        ("file:///etc/passwd", "not in the allow-list"),
        ("no-scheme-here", "has no scheme"),
    ],
)
def test_sad_a_url_axross_cannot_follow_is_refused_in_the_dialog(pane, folder, url, message):
    errors = run_dialog(pane, type_and_ok("bad", url))
    assert message in errors[0]
    APP.processEvents()
    assert not list(folder.glob("bad*"))


@pytest.mark.parametrize("name", ["../escape", "sub/dir", ".."])
def test_sad_an_unsafe_name_is_refused_and_nothing_is_written(pane, folder, name):
    errors = run_dialog(pane, type_and_ok(name, "sftp://h/x"))
    assert errors[0].startswith("Unsafe link name")
    APP.processEvents()
    assert sorted(p.name for p in folder.parent.rglob("*.axlink")) == []


def test_sad_empty_fields_say_what_is_missing(pane, folder):
    assert run_dialog(pane, type_and_ok("", "sftp://h/x")) == ["Name is required."]
    assert run_dialog(pane, type_and_ok("x", "")) == ["Target URL is required."]
    assert not list(folder.glob("*.axlink"))


def test_sad_an_existing_link_is_not_replaced_without_a_question(pane, folder):
    XL.create_xlink(LocalFS(), str(folder / "jump"), "sftp://old/target")
    before = (folder / "jump.axlink").read_bytes()
    with mock.patch("ui.file_pane.QMessageBox.warning") as warning:
        run_dialog(pane, type_and_ok("jump", "s3://new/target"))
    warning.assert_called_once()
    assert "already exists" in warning.call_args.args[2]
    assert (folder / "jump.axlink").read_bytes() == before


def test_sad_a_failed_write_is_reported_and_leaves_no_file(pane, folder):
    with (
        mock.patch(
            "core.atomic_io.atomic_write", side_effect=PermissionError(13, "Permission denied")
        ),
        mock.patch("ui.file_pane.QMessageBox.critical") as critical,
    ):
        run_dialog(pane, type_and_ok("jump", "sftp://h/x"))
    critical.assert_called_once()
    assert "Permission denied" in critical.call_args.args[2]
    assert not list(folder.glob("jump*"))


def test_sad_cancel_writes_nothing(pane, folder):
    def steps(dlg, seen):
        n, u, _d, _c, _e = fields(dlg)
        QTest.keyClicks(n, "jump")
        QTest.keyClicks(u, "sftp://h/x")
        click(dlg, QDialogButtonBox.StandardButton.Cancel)

    run_dialog(pane, steps)
    APP.processEvents()
    assert not list(folder.glob("jump*"))


# ----------------------------------------------------------------- edge
def test_edge_a_name_that_already_ends_in_axlink_is_not_doubled(pane, folder):
    run_dialog(pane, type_and_ok("jump.axlink", "webdav://h/x"))
    assert wait_until(lambda: "jump.axlink" in listed(pane))
    assert not (folder / "jump.axlink.axlink").exists()


def test_edge_an_empty_display_name_falls_back_to_the_link_name(pane, folder):
    run_dialog(pane, type_and_ok("jump", "ax-cas://sha256:" + "a" * 64))
    assert wait_until(lambda: "jump.axlink" in listed(pane))
    assert XL.read_xlink(LocalFS(), str(folder / "jump.axlink")).display_name == "jump"


def test_edge_a_unicode_name_and_spaces_round_trip(pane, folder):
    run_dialog(pane, type_and_ok("Übersicht Q3", "https://dav.example/Übersicht"))
    assert wait_until(lambda: "Übersicht Q3.axlink" in listed(pane))
    target = XL.target_of(LocalFS(), str(folder / "Übersicht Q3.axlink"))
    assert target == "https://dav.example/Übersicht"


def test_edge_an_existing_file_without_the_suffix_does_not_block_the_link(pane, folder):
    # "notes.txt" exists; the link is notes.txt.axlink, a different name
    run_dialog(pane, type_and_ok("notes.txt", "sftp://h/x"))
    assert wait_until(lambda: "notes.txt.axlink" in listed(pane))
    assert (folder / "notes.txt").read_text() == "n"
