#!/usr/bin/env python3
"""Properties dialog — the file/directory info sheet behind Alt+Enter.

Every field shown here already existed on ``FileItem``; nothing but the
window was missing. Alt+Enter was bound to the permissions editor alone,
which is why the app felt like it had no properties view at all — that
binding now opens this dialog, with the permissions editor as its second
tab.

Two behaviours are worth pinning:

* A field the backend cannot supply renders as an em dash, never
  disappears. Which metadata a protocol carries is itself information
  the user wants (S3 has no owner; IMAP has no mode bits), and a
  silently absent row reads as "this file has no owner".
* Directory size is computed automatically only where walking a tree is
  cheap. On a remote backend a recursive walk is an unbounded number of
  round trips, so the dialog must open instantly and let the user ask
  for the number.
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
from ui.properties_dialog import PropertiesDialog  # noqa: E402

APP = QApplication.instance() or QApplication([])

DASH = "—"


class _FakeBackend:
    """Backend stub with a small in-memory tree."""

    supports_symlinks = True

    def __init__(self, tree: dict[str, list[FileItem]] | None = None, *, cheap: bool = False):
        self._tree = tree or {}
        self.walks = 0
        if cheap:
            self.has_cheap_recursive_walk = True

    @property
    def name(self) -> str:
        return "Fake"

    def join(self, a: str, b: str) -> str:
        return f"{a.rstrip('/')}/{b}"

    def list_dir(self, path: str) -> list[FileItem]:
        self.walks += 1
        return self._tree.get(path, [])

    def chmod(self, path: str, mode: int) -> None:
        pass


def _f(name, **kw) -> FileItem:
    kw.setdefault("modified", datetime(2026, 3, 4, 5, 6, 7))
    return FileItem(name=name, **kw)


def _open(backend, path, item):
    dlg = PropertiesDialog(backend, path, item)
    dlg.show()
    APP.processEvents()
    return dlg


@pytest.fixture()
def opened():
    made: list = []

    def factory(backend, path, item):
        dlg = _open(backend, path, item)
        made.append(dlg)
        return dlg

    yield factory
    for dlg in made:
        dlg.close()
        dlg.deleteLater()
    APP.processEvents()


# --------------------------------------------------------------------------
# Happy path — the fields the user asked for
# --------------------------------------------------------------------------


def test_happy_shows_owner_group_permissions_and_size(opened):
    item = _f("report.pdf", size=2048, permissions=0o644, owner="alice", group="staff")
    fields = opened(_FakeBackend(), "/data/report.pdf", item).general_fields()

    assert fields["Owner"] == "alice"
    assert fields["Group"] == "staff"
    assert fields["Permissions"].startswith("rw-r--r--")
    assert "644" in fields["Permissions"]
    assert "2048" in fields["Size"]


def test_happy_size_is_shown_in_both_exact_and_human_form(opened):
    item = _f("big.bin", size=1536)
    size = opened(_FakeBackend(), "/big.bin", item).general_fields()["Size"]
    assert "1536" in size          # exact byte count, for the pedantic case
    assert "1.5 KB" in size or "1.5 KiB" in size


def test_happy_path_and_backend_are_shown(opened):
    fields = opened(_FakeBackend(), "/srv/data/x.txt", _f("x.txt")).general_fields()
    assert fields["Path"] == "/srv/data/x.txt"
    assert fields["Backend"] == "Fake"


def test_happy_type_reflects_file_dir_and_symlink(opened):
    b = _FakeBackend()
    assert opened(b, "/a", _f("a")).general_fields()["Type"] == "File"
    assert opened(b, "/d", _f("d", is_dir=True)).general_fields()["Type"] == "Directory"
    link = _f("l", is_link=True, link_target="/elsewhere")
    fields = opened(b, "/l", link).general_fields()
    assert fields["Type"] == "Symlink"
    assert fields["Link target"] == "/elsewhere"


def test_happy_has_a_permissions_tab_wired_to_the_same_file(opened):
    item = _f("a.txt", permissions=0o600)
    dlg = opened(_FakeBackend(), "/a.txt", item)
    assert [dlg._tabs.tabText(i) for i in range(dlg._tabs.count())] == [
        "General",
        "Permissions",
    ]
    assert dlg._permissions.selected_mode() == 0o600


# --------------------------------------------------------------------------
# Missing metadata renders as a dash, never vanishes
# --------------------------------------------------------------------------


def test_edge_backend_without_owner_shows_a_dash(opened):
    """S3, IMAP, Dropbox and friends report no owner. The row stays."""
    fields = opened(_FakeBackend(), "/o", _f("o", owner="", group="")).general_fields()
    assert fields["Owner"] == DASH
    assert fields["Group"] == DASH


def test_edge_zero_mode_shows_a_dash_not_000(opened):
    """permissions == 0 means "the protocol did not tell us", not
    "nobody may read this". Rendering it as --------- would be a lie."""
    assert opened(_FakeBackend(), "/o", _f("o", permissions=0)).general_fields()[
        "Permissions"
    ] == DASH


def test_edge_absent_atime_and_ctime_show_dashes(opened):
    fields = opened(_FakeBackend(), "/o", _f("o")).general_fields()
    assert fields["Accessed"] == DASH
    assert fields["Created"] == DASH


def test_edge_present_atime_and_ctime_are_rendered(opened):
    item = _f("o", accessed=datetime(2026, 1, 2, 3, 4, 5), created=datetime(2025, 12, 31))
    fields = opened(_FakeBackend(), "/o", item).general_fields()
    assert "2026-01-02" in fields["Accessed"]
    assert "2025-12-31" in fields["Created"]


def test_edge_non_symlink_has_no_link_target_row(opened):
    assert "Link target" not in opened(_FakeBackend(), "/a", _f("a")).general_fields()


# --------------------------------------------------------------------------
# Directory size: cheap walk automatic, expensive walk on request
# --------------------------------------------------------------------------


def _dir_tree() -> dict[str, list[FileItem]]:
    return {
        "/d": [_f("a", size=100), _f("sub", is_dir=True)],
        "/d/sub": [_f("b", size=23)],
    }


def test_happy_local_directory_size_is_computed_automatically(opened):
    backend = _FakeBackend(_dir_tree(), cheap=True)
    dlg = opened(backend, "/d", _f("d", is_dir=True))
    dlg.wait_for_size()
    assert "123" in dlg.general_fields()["Size"]
    assert backend.walks > 0


def test_edge_remote_directory_size_waits_for_the_user(opened):
    backend = _FakeBackend(_dir_tree())  # no cheap-walk marker
    dlg = opened(backend, "/d", _f("d", is_dir=True))
    assert backend.walks == 0, "a remote dialog must not walk the tree on open"
    assert dlg.general_fields()["Size"] == DASH
    assert dlg._calc_btn.isVisible()


def test_edge_remote_directory_size_computes_when_asked(opened):
    backend = _FakeBackend(_dir_tree())
    dlg = opened(backend, "/d", _f("d", is_dir=True))
    dlg._calc_btn.click()
    dlg.wait_for_size()
    assert "123" in dlg.general_fields()["Size"]


def test_edge_plain_file_has_no_calculate_button(opened):
    dlg = opened(_FakeBackend(cheap=True), "/a", _f("a", size=5))
    assert not dlg._calc_btn.isVisible()


# --------------------------------------------------------------------------
# Sad path
# --------------------------------------------------------------------------


def test_sad_unreadable_subdirectory_does_not_break_the_dialog(opened):
    class _Boom(_FakeBackend):
        def list_dir(self, path):
            self.walks += 1
            if path == "/d/sub":
                raise OSError("permission denied")
            return _dir_tree().get(path, [])

    backend = _Boom(cheap=True)
    dlg = opened(backend, "/d", _f("d", is_dir=True))
    dlg.wait_for_size()
    # The readable part is still counted and reported.
    assert "100" in dlg.general_fields()["Size"]


def test_sad_backend_without_chmod_still_opens(opened):
    class _NoChmod(_FakeBackend):
        def chmod(self, path, mode):
            raise OSError("not supported")

    dlg = opened(_NoChmod(), "/a", _f("a", permissions=0o644))
    assert dlg._tabs.count() == 2


# --------------------------------------------------------------------------
# Wiring: Alt+Enter and the context menu
# --------------------------------------------------------------------------


def test_local_backend_advertises_a_cheap_recursive_walk():
    """The auto-vs-on-demand decision reads this marker, following the
    same ``getattr(backend, "...", False)`` idiom the pane already uses
    for supports_symlinks / supports_hardlinks."""
    from core.local_fs import LocalFS

    assert getattr(LocalFS, "has_cheap_recursive_walk", False) is True


def _pane(tmp_path):
    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    pane = FilePaneWidget(LocalFS())
    pane.resize(600, 400)
    pane.show()
    APP.processEvents()
    pane.navigate(str(tmp_path))
    APP.processEvents()
    return pane


def _select(pane, name: str) -> None:
    """Select the row holding *name*.

    Never select by index: row 0 is the ``..`` parent entry, which
    ``selected_file_items()`` deliberately filters out, so a test that
    picks row 0 silently exercises an empty selection.
    """
    for row in range(pane._proxy.rowCount()):
        if pane._proxy.index(row, 0).data() == name:
            pane._table.selectRow(row)
            APP.processEvents()
            return
    raise AssertionError(f"{name!r} not in pane rows")


def test_alt_enter_opens_properties_not_just_permissions(tmp_path, monkeypatch):
    """Alt+Enter used to open the chmod editor alone — which is why the
    app looked like it had no properties view."""
    from PyQt6.QtCore import QEvent, Qt
    from PyQt6.QtGui import QKeyEvent

    (tmp_path / "a.txt").write_text("x")
    pane = _pane(tmp_path)
    try:
        _select(pane, "a.txt")

        called: list[str] = []
        monkeypatch.setattr(pane, "_show_properties", lambda: called.append("properties"))

        event = QKeyEvent(
            QEvent.Type.KeyPress,
            Qt.Key.Key_Return,
            Qt.KeyboardModifier.AltModifier,
        )
        assert pane.eventFilter(pane._table, event) is True
        assert called == ["properties"]
    finally:
        pane.close()
        pane.deleteLater()
        APP.processEvents()


def test_context_menu_offers_properties(tmp_path):
    (tmp_path / "a.txt").write_text("x")
    pane = _pane(tmp_path)
    try:
        _select(pane, "a.txt")
        texts = [a.text() for a in pane._build_context_menu().actions()]
        assert any("Properties" in t for t in texts), texts
    finally:
        pane.close()
        pane.deleteLater()
        APP.processEvents()


# --------------------------------------------------------------------------
# Multi-selection: Ctrl+A then Properties
#
# The dialog took items[0] and described whichever entry happened to be
# first, silently ignoring the rest of the selection. What is wanted is
# one summary — and it has to be honest about entries it could not read,
# because a total that quietly omits an unreadable subtree UNDER-reports,
# and somebody checking whether a copy will fit is told yes.
# --------------------------------------------------------------------------


def _dir_backend():
    return _FakeBackend(
        {
            "/d": [_f("a.txt", size=100), _f("sub", is_dir=True)],
            "/d/sub": [_f("b.txt", size=23)],
        },
        cheap=True,
    )


def test_happy_multi_selection_reports_a_summary_not_the_first_item(opened):
    from ui.properties_dialog import PropertiesDialog

    items = [_f("a.txt", size=100), _f("sub", is_dir=True)]
    dlg = PropertiesDialog(_dir_backend(), "/d", items)
    dlg.show()
    APP.processEvents()
    try:
        dlg.wait_for_size()
        fields = dlg.general_fields()
        assert fields["Selection"].startswith("2 items")
        assert "123" in fields["Size"], fields["Size"]
    finally:
        dlg.close()
        dlg.deleteLater()
        APP.processEvents()


def test_happy_single_selection_keeps_the_per_file_sheet(opened):
    """One item must still show the detailed sheet, not a summary."""
    dlg = opened(_FakeBackend(), "/a.txt", _f("a.txt", size=5, owner="alice"))
    fields = dlg.general_fields()
    assert "Selection" not in fields
    assert fields["Owner"] == "alice"


def test_sad_unreadable_entries_are_reported_not_silently_dropped(opened):
    from ui.properties_dialog import PropertiesDialog

    class _Denying(_FakeBackend):
        def list_dir(self, path):
            self.walks += 1
            if path == "/d/locked":
                raise PermissionError("permission denied")
            return {"/d": [_f("ok", size=10)]}.get(path, [])

    backend = _Denying(cheap=True)
    items = [_f("ok", size=10), _f("locked", is_dir=True)]
    dlg = PropertiesDialog(backend, "/d", items)
    dlg.show()
    APP.processEvents()
    try:
        dlg.wait_for_size()
        fields = dlg.general_fields()
        assert "could not be read" in fields["Selection"], fields["Selection"]
        # And the total must not pretend to be exact.
        assert "at least" in fields["Size"].lower(), fields["Size"]
    finally:
        dlg.close()
        dlg.deleteLater()
        APP.processEvents()


def test_edge_multi_selection_has_no_permissions_tab(opened):
    """chmod applies to one file. Offering the tab for a mixed
    selection would invite applying one mode to all of them."""
    from ui.properties_dialog import PropertiesDialog

    items = [_f("a.txt", size=1), _f("b.txt", size=2)]
    dlg = PropertiesDialog(_FakeBackend(cheap=True), "/d", items)
    dlg.show()
    APP.processEvents()
    try:
        assert [dlg._tabs.tabText(i) for i in range(dlg._tabs.count())] == ["General"]
    finally:
        dlg.close()
        dlg.deleteLater()
        APP.processEvents()


def test_edge_remote_multi_selection_waits_for_the_button(opened):
    from ui.properties_dialog import PropertiesDialog

    backend = _FakeBackend({"/d/sub": [_f("b.txt", size=23)]})  # not cheap
    items = [_f("a.txt", size=100), _f("sub", is_dir=True)]
    dlg = PropertiesDialog(backend, "/d", items)
    dlg.show()
    APP.processEvents()
    try:
        assert backend.walks == 0, "a remote summary must not walk on open"
        assert dlg._calc_btn.isVisible()
    finally:
        dlg.close()
        dlg.deleteLater()
        APP.processEvents()
