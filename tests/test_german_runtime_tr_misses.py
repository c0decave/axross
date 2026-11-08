"""Every text the German window asks ``tr()`` for has a German entry.

UX review round 4 wrapped ``core.i18n.Translator.tr`` during a German walk
of the window and found 133 texts without a catalogue entry: the type
check boxes of Find Files ("Documents", "Archives", ...), the group and
column names of Help > Features, the OAuth set-up steps of Connect to
Server, Qt's own tab-bar buttons ("Scroll Left"), and German texts that
were translated a second time. tests/test_german_ui_coverage.py compares
what is visible; this test catches every ``tr()`` call that finds nothing,
visible or not yet.

The walk: the main window and every menu (as it opens), every Settings
page and sub-page, Connect to Server with each protocol and the proxy
group, Find Files, Help > Features, Keyboard Shortcuts, About, the
conflict prompt and the Transfers dock with a failed job. A text counts as
a miss when the German catalogue has no entry and it carries a word of
three letters or more. ALLOWED holds what is data or a name, not a label.
"""

from __future__ import annotations

import collections
import os
import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QDialog, QMenu, QWidget  # noqa: E402

from tests.settings_testkit import app, isolate  # noqa: E402

APP = app()

#: Names and data that pass through tr() and need no entry, with why.
ALLOWED = frozenset({
    # Python's log level names: the Log dock filters by them, the log
    # lines carry them.
    "DEBUG", "INFO", "WARNING", "ERROR",
    # Protocol and product names (core.backend_registry, Help > About).
    "SFTP", "FTP", "FTPS", "WebDAV", "NFS", "Rsync", "SMB / CIFS", "iSCSI", "Dropbox",
    "Google Drive", "OneDrive", "SharePoint", "Azure Blob", "Azure Files", "MongoDB GridFS",
    "NNTP / Usenet", "ADB (Android)", "Exchange (EWS)", "IMAP (Mail)", "Telnet (Shell)",
    "WinRM (PowerShell-Remoting)", "SFTP / SCP", "FTP / FTPS", "IMAP / POP3",
    "Azure Blob / Files", "OneDrive / SharePoint", "Google Drive, Dropbox",
    # Sandbox and container runtimes, sound servers: program names.
    "podman", "docker", "bubblewrap", "PipeWire", "PulseAudio",
    # External programs of Help > Features (core.features.TOOLS) and an
    # optional package named by its protocol.
    "ripgrep", "rsync", "FFmpeg", "Subversion", "open-iscsi", "qemu-img", "The Sleuth Kit",
    "TestDisk / PhotoRec", "VirtualBox (VBoxManage)", "SNMP",
    # An agent mode id, shown next to its translated description.
    "bypass",
    # The path kind of a Windows share: an acronym.
    "UNC",
})


def pump(seconds: float = 0.1) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def _menu(menu: QMenu, depth: int = 0) -> None:
    if depth > 6:
        return
    menu.aboutToShow.emit()
    for action in menu.actions():
        if action.menu() is not None:
            _menu(action.menu(), depth + 1)


def _new_tops(before: set[int]) -> list[QWidget]:
    return [t for t in APP.topLevelWidgets() if id(t) not in before and t.isVisible()]


def walk(stores) -> tuple[collections.Counter, int]:
    """The German texts tr() found no entry for, with how often, and how
    many tr() calls the walk made."""
    from unittest import mock

    from PyQt6.QtWidgets import QFileDialog, QInputDialog

    from core import i18n
    from core.transfer_conflicts import TransferConflict
    from ui.connection_dialog import ConnectionDialog
    from ui.qt_translations import install_qt_translator
    from ui.shortcuts_dialog import ShortcutsDialog
    from ui.transfer_conflict_dialog import TransferConflictDialog

    missed: collections.Counter = collections.Counter()
    calls = [0]
    original = i18n.Translator.tr

    def recording(self, text):
        result = original(self, text)
        calls[0] += 1
        if (self.language != "en" and result == text and text not in self._entries
                and re.search(r"[A-Za-z]{3,}", text or "")):
            missed[text] += 1
        return result

    def fake_exec(dialog, *a, **k):
        dialog.show()
        pump(0.05)
        dialog.hide()
        return 0

    patches = [
        mock.patch.object(i18n.Translator, "tr", recording),
        mock.patch.object(QDialog, "exec", fake_exec),
        mock.patch.object(QMenu, "exec", lambda self, *a, **k: (self.aboutToShow.emit(), None)[1]),
        mock.patch.object(QFileDialog, "getOpenFileName", staticmethod(lambda *a, **k: ("", ""))),
        mock.patch.object(QFileDialog, "getExistingDirectory", staticmethod(lambda *a, **k: "")),
        mock.patch.object(QInputDialog, "getText", staticmethod(lambda *a, **k: ("", False))),
    ]
    i18n.install("de")
    translator = install_qt_translator(APP)
    for patch in patches:
        patch.start()
    try:
        win = stores.make_window()
        win.resize(1280, 800)
        win.show()
        pump(0.4)
        for top in win.menuBar().actions():
            if top.menu() is not None:
                _menu(top.menu())
        for pane in getattr(win, "_panes", [])[:1]:
            builder = getattr(pane, "_build_context_menu", None)
            if callable(builder):
                _menu(builder())

        settings = stores.settings_dialog(win)
        settings.show()
        pump(0.2)
        for page_id in list(settings._items):
            settings.show_page(page_id)
            item = settings._items[page_id]
            for c in range(item.childCount()):
                settings.tree.setCurrentItem(item.child(c))
            pump(0.05)
        settings.reject()

        connect = ConnectionDialog(win._profile_manager, parent=win)
        stores.dialogs.append(connect)
        connect.show()
        combo = connect._protocol_combo
        for i in range(combo.count()):
            combo.setCurrentIndex(i)
            pump(0.02)
        connect._proxy_group.setChecked(True)
        pump(0.05)
        connect.reject()

        for opener in (win._open_find_files, win._show_features, win._show_shortcuts):
            before = {id(t) for t in APP.topLevelWidgets()}
            opener()
            pump(0.3)
            features = getattr(win, "_features_dialog", None)
            if opener == win._show_features and features is not None:
                # The features are collected off the GUI thread.
                end = time.time() + 20
                while not features._loaded and time.time() < end:
                    pump(0.1)
                features.missing_only.setChecked(True)
                features.missing_only.setChecked(False)
            for top in _new_tops(before):
                if top is not win:
                    top.close()
        shortcuts = ShortcutsDialog(win)
        stores.dialogs.append(shortcuts)
        win.about_html()

        conflict = TransferConflict(
            name="f.txt", source_path="/a/f.txt", dest_path="/b/f.txt", dest_dir="/b",
            source_is_dir=False, dest_is_dir=False,
            source_size=3, dest_size=1536, source_mtime=2.0e9, dest_mtime=1.0e9,
        )
        for remaining in (0, 1, 3):
            dialog = TransferConflictDialog(conflict, remaining, win)
            stores.dialogs.append(dialog)
        return missed, calls[0]
    finally:
        for patch in reversed(patches):
            patch.stop()
        stores.restore()
        stores.dialogs, stores.windows = [], []
        if translator is not None:
            APP.removeTranslator(translator)
        i18n.install(i18n.DEFAULT_LANGUAGE)


@pytest.fixture(scope="module")
def misses(tmp_path_factory):
    mp = pytest.MonkeyPatch()
    try:
        stores = isolate(tmp_path_factory.mktemp("tr-misses-de"), mp)
        return walk(stores)
    finally:
        mp.undo()


def test_happy_every_german_tr_call_finds_an_entry(misses):
    missed, calls = misses
    assert calls > 2500, calls  # the whole window was walked
    left = sorted(text for text in missed if text not in ALLOWED)
    report = "\n".join(f"  {text[:120]!r}" for text in left)
    assert left == [], f"{len(left)} texts have no German entry:\n{report}"


def test_sad_the_recorder_sees_a_missing_text(monkeypatch):
    """The wrapper counts a text without an entry - and not a translated one."""
    from core import i18n

    original = i18n.Translator.tr
    seen = []

    def recording(self, text):
        result = original(self, text)
        if result == text and text not in self._entries:
            seen.append(text)
        return result

    monkeypatch.setattr(i18n.Translator, "tr", recording)
    i18n.install("de")
    try:
        assert i18n.tr("Cancel") != "Cancel"
        i18n.tr("A sentence no catalogue has, for this test")
    finally:
        i18n.install(i18n.DEFAULT_LANGUAGE)
    assert seen == ["A sentence no catalogue has, for this test"]


def test_edge_the_allow_list_holds_only_names(misses):
    """Each allowed text is a name or data, not a sentence of the UI: no
    allowed text has more than four words, and none ends with a stop."""
    for text in ALLOWED:
        assert len(text.split()) <= 4 and not text.endswith((".", ":")), text
