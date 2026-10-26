"""Enter in a dialog's text field does what that field is for - once, and
without closing the dialog.

Found with the hex editor (tests/test_hex_editor_matrix.py): a field that
runs its action on Enter (returnPressed) in a dialog that also has a
default button runs both. The same pattern, measured in every dialog of
ui/ that connects returnPressed:

* Agent dock > Access…: Enter in the host field added the host and then
  pressed OK - the dialog closed (accepted) after the first host;
* Find in Index, Find Files, Add MCP Server from Catalog: one Enter started
  the search twice (the catalog asked every registry twice).
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

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QDialog  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _show(dlg, field):
    dlg.show()
    dlg.activateWindow()
    field.setFocus()
    APP.processEvents()


def _enter(field) -> None:
    QTest.keyClick(field, Qt.Key.Key_Return)
    APP.processEvents()


# ------------------------------------------------------------ agent access
@pytest.fixture
def access_dialog():
    from core import agent_access as X
    from ui.agent_access_dialog import SessionAccessDialog

    dlg = SessionAccessDialog(
        None, "tab", X.SessionAccess(network="hosts"), [], ceiling=None, sandbox=None
    )
    _show(dlg, dlg.editor.host_edit)
    yield dlg
    dlg.close()
    dlg.deleteLater()


def _hosts(dlg) -> list[str]:
    lst = dlg.editor.hosts_list
    return [lst.item(i).text() for i in range(lst.count())]


def test_happy_e2e_enter_adds_hosts_one_after_another_and_ok_keeps_them(access_dialog):
    dlg, edit = access_dialog, access_dialog.editor.host_edit
    QTest.keyClicks(edit, "db.example:5432")
    _enter(edit)
    QTest.keyClicks(edit, "[2001:db8::1]:443")
    _enter(edit)
    assert _hosts(dlg) == ["db.example:5432", "[2001:db8::1]:443"]
    assert dlg.isVisible() and edit.text() == ""
    dlg.accept()
    assert dlg.result() == QDialog.DialogCode.Accepted
    assert dlg.editor.access().hosts == ("db.example:5432", "[2001:db8::1]:443")


def test_sad_enter_on_an_invalid_host_says_why_and_keeps_the_dialog_open(access_dialog):
    dlg, edit = access_dialog, access_dialog.editor.host_edit
    QTest.keyClicks(edit, "no-port-here")
    _enter(edit)
    assert dlg.isVisible() and _hosts(dlg) == []
    assert dlg.editor.host_note.text() != "" and edit.text() == "no-port-here"


def test_edge_enter_on_an_empty_host_field_closes_nothing(access_dialog):
    _enter(access_dialog.editor.host_edit)
    assert access_dialog.isVisible() and _hosts(access_dialog) == []


def test_edge_the_same_host_twice_is_listed_once(access_dialog):
    edit = access_dialog.editor.host_edit
    for _ in range(2):
        QTest.keyClicks(edit, "db.example:5432")
        _enter(edit)
    assert _hosts(access_dialog) == ["db.example:5432"]


# -------------------------------------------------------- searches: once
def _find_in_index():
    from ui import metadata_search_dialog as M

    return (
        M.MetadataSearchDialog,
        "_do_search",
        lambda: M.MetadataSearchDialog(None),
        "_needle_edit",
    )


def _find_files():
    from ui import find_files_dialog as F

    return F.FindFilesDialog, "start_search", lambda: F.FindFilesDialog([]), "name_edit"


def _find_files_contains():
    from ui import find_files_dialog as F

    return F.FindFilesDialog, "start_search", lambda: F.FindFilesDialog([]), "contains_edit"


def _mcp_catalog():
    from core import mcp_catalog as MC
    from ui import mcp_catalog_dialog as D

    sources = MC.CatalogSources(builtin=False, dockerhub=False, c0decave=False, discover=False)
    return (
        D.McpCatalogDialog,
        "search",
        lambda: D.McpCatalogDialog(sources=sources, search_now=False),
        "search_edit",
    )


@pytest.mark.parametrize(
    "spec",
    [_find_in_index, _find_files, _find_files_contains, _mcp_catalog],
    ids=["find-in-index", "find-files-name", "find-files-contains", "mcp-catalog"],
)
def test_sad_one_enter_starts_one_search(spec):
    cls, slot, make, field_name = spec()
    with mock.patch.object(cls, slot) as search:
        dlg = make()
        field = getattr(dlg, field_name)
        _show(dlg, field)
        search.reset_mock()
        field.setText("needle")
        _enter(field)
        assert search.call_count == 1
        _enter(field)
        assert search.call_count == 2
        assert dlg.isVisible()
        dlg.close()
        dlg.deleteLater()


def test_happy_e2e_enter_in_find_files_searches_a_real_folder_once(tmp_path):
    """The real search, not a stand-in: one Enter, each hit listed once."""
    import time

    from core.local_fs import LocalFS
    from ui import find_files_dialog as F

    (tmp_path / "needle-1.txt").write_text("x")
    (tmp_path / "other.txt").write_text("x")
    dlg = F.FindFilesDialog([F.ScopeChoice(LocalFS(), str(tmp_path), label=str(tmp_path))])
    _show(dlg, dlg.name_edit)
    with mock.patch.object(F.FS, "run_search", wraps=F.FS.run_search) as engine:
        QTest.keyClicks(dlg.name_edit, "needle*")
        _enter(dlg.name_edit)
        end = time.time() + 10
        while (dlg.is_running or dlg.table.rowCount() == 0) and time.time() < end:
            APP.processEvents()
            time.sleep(0.01)
    assert engine.call_count == 1
    names = [dlg.table.item(r, 0).text() for r in range(dlg.table.rowCount())]
    assert names == ["needle-1.txt"]
    dlg.close()
    dlg.deleteLater()
