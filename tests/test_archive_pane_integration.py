"""Integration smoke tests for the archive-preview dock wiring (Task A4).

The headless Qt platform MUST be selected BEFORE PyQt6 is imported,
otherwise instantiating widgets on a box with no display aborts the
process. A single shared :class:`QApplication` is created for the whole
module (Qt forbids more than one).

What is covered headless
------------------------
* ``MainWindow.open_archive_pane`` creates a single reusable
  ``QDockWidget`` hosting an ``ArchivePaneWidget`` with a clean
  ``load_error`` (and reuses the same dock on a second call).
* ``MainWindow._extract_single_member`` extracts ONE member of a zip to
  a fresh temp dir and tracks it for cleanup.
* The ``extract_selected`` handler shows an info message (not a crash)
  on an empty selection and on the 7z/RAR ``NotImplementedError`` path.

What is NOT covered here (manual UI)
------------------------------------
* The actual modal viewer opened by ``_archive_open_member`` (image /
  hex / text dialog ``.exec()`` blocks an offscreen event loop) — the
  extraction half is tested via ``_extract_single_member`` instead.
* The full extract-with-progress dialog interaction (``QProgressDialog``
  + Cancel button) — the underlying ``core.archive`` extractors already
  have dedicated tests.
"""

from __future__ import annotations

import os

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import zipfile

import pytest
from PyQt6.QtWidgets import QApplication, QDockWidget, QMessageBox

from ui.archive_pane import ArchivePaneWidget
from ui.main_window import MainWindow

# One QApplication for the module; reuse any pre-existing instance.
APP = QApplication.instance() or QApplication([])


@pytest.fixture
def sample_zip(tmp_path):
    """A small multi-member zip with a nested directory."""
    zp = tmp_path / "sample.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("top.txt", "hello world")
        zf.writestr("sub/inner.txt", "nested payload")
    return str(zp)


@pytest.fixture
def window():
    win = MainWindow()
    yield win
    win._cleanup_archive_tempdirs()
    win.close()


def _archive_docks(win) -> list[QDockWidget]:
    return [
        dk
        for dk in win.findChildren(QDockWidget)
        if isinstance(dk.widget(), ArchivePaneWidget)
    ]


def test_open_archive_pane_creates_dock(window, sample_zip):
    window.open_archive_pane(sample_zip)
    docks = _archive_docks(window)
    assert len(docks) == 1
    dock = docks[0]
    assert dock.windowTitle() == "Archive: sample.zip"
    pane = dock.widget()
    assert isinstance(pane, ArchivePaneWidget)
    assert pane.load_error is None


def test_open_archive_pane_reuses_single_dock(window, sample_zip, tmp_path):
    window.open_archive_pane(sample_zip)
    second = tmp_path / "second.zip"
    with zipfile.ZipFile(second, "w") as zf:
        zf.writestr("only.txt", "x")
    window.open_archive_pane(str(second))
    docks = _archive_docks(window)
    # Reused, not duplicated; retargeted to the new archive.
    assert len(docks) == 1
    assert docks[0].windowTitle() == "Archive: second.zip"
    assert docks[0].widget().load_error is None


def test_extract_single_member_to_tempdir(window, sample_zip):
    extracted = window._extract_single_member(sample_zip, "sub/inner.txt")
    assert extracted is not None
    assert os.path.isfile(extracted)
    with open(extracted) as fh:
        assert fh.read() == "nested payload"
    assert len(window._archive_member_tempdirs) == 1
    # Cleanup removes the temp dir.
    window._cleanup_archive_tempdirs()
    assert not os.path.exists(extracted)
    assert window._archive_member_tempdirs == []


def test_extract_selected_empty_shows_info(window, sample_zip, monkeypatch):
    """Empty selection → info message, no extraction, no crash."""
    calls: list[tuple] = []
    monkeypatch.setattr(
        QMessageBox,
        "information",
        lambda *a, **k: calls.append(a) or QMessageBox.StandardButton.Ok,
    )
    window._archive_extract_selected(sample_zip, [])
    assert len(calls) == 1  # the "no selection" info was shown


def test_extract_selected_notimplemented_shows_info(window, monkeypatch, tmp_path):
    """A 7z/RAR partial-extract NotImplementedError surfaces as an info
    message (use 'Alles extrahieren'), never an unhandled exception."""
    # Build a real .zip but force extract_members to raise
    # NotImplementedError, simulating the 7z/RAR partial path without
    # needing the optional codecs installed.
    zp = tmp_path / "fake.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("a.txt", "a")

    import core.archive as ARCH

    def _boom(*_a, **_k):
        raise NotImplementedError("partial extraction not supported for 7z/RAR")

    monkeypatch.setattr(ARCH, "extract_members", _boom)

    infos: list[str] = []
    monkeypatch.setattr(
        QMessageBox,
        "information",
        lambda _self, _title, text, *a, **k: infos.append(text)
        or QMessageBox.StandardButton.Ok,
    )
    # Must not raise.
    window._archive_extract_selected(str(zp), ["a.txt"])
    assert infos, "expected an info message on NotImplementedError"
    assert "7z/RAR" in infos[0]


def test_extract_single_member_notimplemented(window, monkeypatch, tmp_path):
    """_extract_single_member returns None + info on NotImplementedError."""
    zp = tmp_path / "fake2.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        zf.writestr("a.txt", "a")

    import core.archive as ARCH

    monkeypatch.setattr(
        ARCH,
        "extract_members",
        lambda *_a, **_k: (_ for _ in ()).throw(NotImplementedError()),
    )
    infos: list[str] = []
    monkeypatch.setattr(
        QMessageBox,
        "information",
        lambda _self, _title, text, *a, **k: infos.append(text)
        or QMessageBox.StandardButton.Ok,
    )
    result = window._extract_single_member(str(zp), "a.txt")
    assert result is None
    assert infos and "7z/RAR" in infos[0]


def test_single_member_tempdirs_dont_grow(window, sample_zip):
    """Fix 2 (resource leak): opening a second single member reaps the
    PREVIOUS member's temp dir, so the tracking list stays bounded and
    the first temp dir is gone after the second open."""
    first = window._extract_single_member(sample_zip, "top.txt")
    assert first is not None and os.path.isfile(first)
    first_dir = window._archive_last_member_tempdir
    assert first_dir is not None and os.path.isdir(first_dir)
    assert len(window._archive_member_tempdirs) == 1

    # Second open: the first temp dir must be reaped (not pulled out from
    # under a viewer mid-use — reaping happens on the NEXT open, here).
    second = window._extract_single_member(sample_zip, "sub/inner.txt")
    assert second is not None and os.path.isfile(second)
    # First temp dir is gone; list did not grow unboundedly.
    assert not os.path.exists(first_dir)
    assert len(window._archive_member_tempdirs) == 1
    assert window._archive_last_member_tempdir != first_dir
    assert os.path.isdir(window._archive_last_member_tempdir)


def test_populate_dock_view_menu_keeps_archive_toggle(window, sample_zip):
    """Fix 1 (latent bug): rebuilding the Panels menu must re-add the
    lazily-created archive-dock toggle exactly once — no drop, no
    duplicate. Matched on the dock's reused ``toggleViewAction``
    identity (its text is synced by Qt to the dock window title)."""

    def _archive_toggle_count() -> int:
        dock = window._archive_dock
        if dock is None:
            return 0
        toggle = dock.toggleViewAction()
        return sum(1 for act in window._dock_view_menu.actions() if act is toggle)

    # No archive dock yet → toggle absent.
    assert _archive_toggle_count() == 0

    window.open_archive_pane(sample_zip)
    assert _archive_toggle_count() == 1

    # A full rebuild (as triggered elsewhere) must preserve it, once.
    window._populate_dock_view_menu()
    assert _archive_toggle_count() == 1

    # A second rebuild still must not duplicate it.
    window._populate_dock_view_menu()
    assert _archive_toggle_count() == 1
