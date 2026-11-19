"""Find Files, the Duplicate Finder, its history and Find on Network Hosts
open within a 1024x600 screen - in English and in German.

Found in review (round 1 of the 2026-11 reviews, UI shell; repro: every
menu window opened with the screen set to 1024x600): Find Files opened at
1100x760 and could not get narrower than 1040 px (its Options row and six
columns of Types side by side with Look in), the Duplicate Finder at
1100x650 with a minimum of 1043 px - its Show list grew to the longest
scan label, so a scan of a deep folder made the window as wide as that
path - Duplicate Index & History at 1000x420 and Find on Network Hosts at
1000x640: their right edge, and the Find Files buttons, off the screen.
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

from PyQt6.QtCore import QRect, QSize  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import cas as CAS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])
SMALL = QRect(0, 0, 1024, 600)
#: What a window may take of it with its title bar and frame drawn.
LIMIT = QSize(984, 560)
LONG = "/".join(["a-rather-long-folder-name"] * 12)


def _fits(size: QSize) -> bool:
    return size.width() <= LIMIT.width() and size.height() <= LIMIT.height()


@pytest.fixture(params=["en", "de"])
def small_screen(request, monkeypatch, tmp_path):
    from core import i18n
    from ui import screen_fit

    monkeypatch.setattr(screen_fit, "available_geometry", lambda widget=None: QRect(SMALL))
    monkeypatch.setattr(CAS, "_DEFAULT_DB", tmp_path / "cas.sqlite")
    i18n.install(request.param)
    yield tmp_path
    i18n.install(i18n.DEFAULT_LANGUAGE)


def _check(dialog) -> None:
    try:
        dialog.show()
        APP.processEvents()
        for what, size in (("size", dialog.size()), ("minimum hint", dialog.minimumSizeHint()),
                           ("minimum", dialog.minimumSize())):
            assert _fits(size), (type(dialog).__name__, what, size)
    finally:
        dialog.close()
        dialog.deleteLater()
        APP.processEvents()


def _scan_of_a_deep_folder(tmp_path: Path) -> Path:
    deep = tmp_path / LONG
    deep.mkdir(parents=True)
    (deep / "one.txt").write_bytes(b"same\n")
    (deep / "two.txt").write_bytes(b"same\n")
    CAS.rebuild(LocalFS(), str(deep), backend_id="LocalFS:Local")
    return deep


# -- happy ---------------------------------------------------------------------


def test_happy_find_files_fits(small_screen):
    from ui.find_files_dialog import FindFilesDialog, ScopeChoice

    _check(FindFilesDialog([ScopeChoice(LocalFS(), str(small_screen / LONG))]))


def test_happy_duplicate_index_history_fits(small_screen):
    from ui.cas_history_dialog import CasHistoryDialog

    _scan_of_a_deep_folder(small_screen)
    _check(CasHistoryDialog(backends=[LocalFS()]))


def test_happy_find_on_network_hosts_fits(small_screen):
    from ui.network_search_dialog import NetworkSearchDialog

    _check(NetworkSearchDialog())


# -- sad -----------------------------------------------------------------------


def test_sad_a_scan_of_a_deep_folder_does_not_widen_the_duplicate_finder(small_screen):
    from ui.cas_dialog import CasDuplicatesDialog

    deep = _scan_of_a_deep_folder(small_screen)

    class _Pane:
        backend = LocalFS()
        current_path = str(deep)

    _check(CasDuplicatesDialog(_Pane()))


def test_sad_a_long_tag_name_does_not_widen_find_files(small_screen, monkeypatch):
    from core import tags as TG
    from ui.find_files_dialog import FindFilesDialog

    class _Tag:
        name = "a tag with a name much longer than anyone would type " * 3

    monkeypatch.setattr(TG.store(), "tags", lambda: [_Tag()])
    _check(FindFilesDialog([]))


# -- edge ----------------------------------------------------------------------


def test_edge_a_large_screen_keeps_the_roomy_sizes(monkeypatch):
    from ui import screen_fit
    from ui.find_files_dialog import FindFilesDialog

    monkeypatch.setattr(screen_fit, "available_geometry",
                        lambda widget=None: QRect(0, 0, 1920, 1080))
    dialog = FindFilesDialog([])
    try:
        assert dialog.size() == QSize(1100, 760)
    finally:
        dialog.deleteLater()
