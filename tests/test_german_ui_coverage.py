"""The German window speaks German: menus, toolbars, docks, Settings pages,
Connect to Server and Keyboard Shortcuts.

Review round 3 ran the window offscreen in German and harvested every
visible text and tooltip: 1,205 of 2,406 were still English, although every
string that went through ``tr()`` had a German entry. They never went
through ``tr()`` - toolbar tooltips ("Close active pane (Ctrl+W)"), the
pane's buttons and status line ("0 items", "Free: 2.9 GB / 4.0 GB (27%
used)", the SOURCE / TARGET badge), the transfer dock's headers and buttons,
every field of Connect to Server, the Keyboard Shortcuts list, the window
corners ("Close (Esc)", "Maximize (Ctrl+M)").

This test builds the window twice, in English and in German, collects the
texts and tooltips of both and counts a German text as untranslated when
the English window shows it verbatim and it carries an English word. Names
stay as they are and are not counted: products, protocols, paths, numbers,
identifiers, acronyms and the IT terms ``tests/test_i18n.py`` keeps English.
It fails when more than a small share of the German texts stays English.
"""

from __future__ import annotations

import os
import re
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtWidgets import (  # noqa: E402
    QAbstractButton,
    QAbstractItemView,
    QComboBox,
    QDockWidget,
    QGroupBox,
    QLabel,
    QLineEdit,
    QListWidget,
    QMenu,
    QPlainTextEdit,
    QTabWidget,
    QTextEdit,
    QToolBar,
    QTreeWidget,
    QWidget,
)

from tests.settings_testkit import app, isolate  # noqa: E402
from tests.test_i18n import KEEP_ENGLISH  # noqa: E402

APP = app()

#: At most this share of the German texts may still be English.
MAX_ENGLISH_SHARE = 0.005

#: Words that mark a text as English. German shares none of them (no
#: "in", "an", "so", "Name", "Status", "Filter", "Host", "Start" ...).
ENGLISH_WORDS = frozenset("""
the and of to for with from this that these those your you is are was were be been on or not
all any show hide open add new file files folder folders select selected selection run copy move
delete remove edit save saved none setting settings clear close connect connected disconnected
search find size type date path view help about when what which every only here there it its by
at as can cannot will has have use used using read write list page window button click key keys
local remote free total speed progress direction level messages message items item jobs job
enter choose before after first last next previous back forward again also more less than
then into out over under each other another one two both same left right up down top bottom
yes until while should must may might do does done failed error errors warning cancel cancelled
retry finished pending active skipped names value values default custom automatic manual
password passwords login user users server servers connection connections import export
refresh reload loading load stop running create created check checked
directory home parent current target source destination transfer transfers queue drag drop
""".split())

#: Kept English on purpose (tests/test_i18n.py); never a sign of a missing
#: translation.
_KEPT = frozenset(term.casefold() for term in KEEP_ENGLISH for term in term.split())

#: A word of code or data: an identifier, a path, an address, a file name.
_CODE = re.compile(r"[._/\\@:=<>{}\[\]#~$%*|]|^\d|^-")

#: Visible texts that are the user's data or a key, not labels, with why.
ALLOWED = {
    # The terminal dock's session key: also the restore key in session.json.
    "Local Shell",
    # A product name (Microsoft's), as the connection list names it.
    "Azure Files",
    # Tool group ids, as the agent and its settings name them (core.agent_profiles).
    "remote", "transfer",
}

#: The MCP catalogue's categories, as the catalogue names them (data).
CATALOGUE_CATEGORIES = re.compile(r"^(Security: .*|Files & Dev|Web & Data|Knowledge & Reasoning|Testing)$")


def pump(seconds: float = 0.1) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def english_words(text: str) -> list[str]:
    """The English words of *text* that are no name, code or kept term."""
    found = []
    for token in re.sub(r"<[^>]+>", " ", text.replace("&", "")).split():
        if _CODE.search(token):
            continue
        for word in re.findall(r"[A-Za-z]+", token):
            if word.isupper() and len(word) > 1:  # an acronym: SFTP, DEBUG, API
                continue
            low = word.casefold()
            if low in ENGLISH_WORDS and low not in _KEPT:
                found.append(word)
    return found


def _add(out: list, kind: str, text) -> None:
    if text is None:
        return
    text = str(text).strip()
    if text and re.search(r"[A-Za-z]{2,}", text):
        out.append((kind, text))


def _menu(out: list, menu: QMenu) -> None:
    menu.aboutToShow.emit()
    for action in menu.actions():
        if action.isSeparator():
            continue
        _add(out, "menu", action.text())
        tip = action.toolTip()
        if tip and tip.replace("&", "") != action.text().replace("&", "").split("\t")[0]:
            _add(out, "menutip", tip)
        if action.menu() is not None:
            _menu(out, action.menu())


def _widgets(out: list, root: QWidget) -> None:
    for w in [root, *root.findChildren(QWidget)]:
        if isinstance(w, QMenu):
            continue
        _add(out, "tooltip", w.toolTip())
        if isinstance(w, QLabel):
            _add(out, "label", w.text())
        elif isinstance(w, QAbstractButton):
            _add(out, "button", w.text())
        if isinstance(w, QGroupBox):
            _add(out, "group", w.title())
        if isinstance(w, (QLineEdit, QPlainTextEdit, QTextEdit)):
            _add(out, "placeholder", w.placeholderText())
        if isinstance(w, QComboBox):
            for i in range(w.count()):
                _add(out, "combo", w.itemText(i))
        if isinstance(w, QTabWidget):
            for i in range(w.count()):
                _add(out, "tab", w.tabText(i))
                _add(out, "tabtip", w.tabToolTip(i))
        if isinstance(w, QDockWidget) or w is root:
            _add(out, "title", w.windowTitle())
        if isinstance(w, QAbstractItemView) and w.model() is not None:
            model = w.model()
            try:
                columns = model.columnCount()
            except TypeError:  # a list model's columnCount() is private
                columns = 1
            for c in range(columns):
                _add(out, "header", model.headerData(c, Qt.Orientation.Horizontal))
            if isinstance(w, (QTreeWidget, QListWidget)):
                for r in range(model.rowCount()):
                    index = model.index(r, 0)
                    text = model.data(index)
                    _add(out, "item", text)
                    # The API browser's tooltips are the docstrings of the
                    # code its rows name - reference text, not labels.
                    if not (text and _CODE.search(str(text).strip())):
                        _add(out, "itemtip", model.data(index, Qt.ItemDataRole.ToolTipRole))
                    for k in range(model.rowCount(index)):
                        child = model.index(k, 0, index)
                        _add(out, "item", model.data(child))
                        _add(out, "item", model.data(model.index(k, 1, index)))
    for toolbar in root.findChildren(QToolBar):
        for action in toolbar.actions():
            if not action.isSeparator():
                _add(out, "toolbar", action.text())
                _add(out, "toolbartip", action.toolTip())


def collect(stores, language: str) -> list[tuple[str, str]]:
    """(kind, text) of the window, its menus and docks, every Settings page,
    Connect to Server and Keyboard Shortcuts - in *language*."""
    from core import i18n
    from ui.connection_dialog import ConnectionDialog
    from ui.qt_translations import install_qt_translator
    from ui.shortcuts_dialog import ShortcutsDialog

    i18n.install(language)
    translator = install_qt_translator(APP)
    out: list[tuple[str, str]] = []
    try:
        win = stores.make_window()
        win.resize(1280, 800)
        win.show()
        pump(0.4)
        for top in win.menuBar().actions():
            _add(out, "menu", top.text())
            _menu(out, top.menu())
        _widgets(out, win)

        settings = stores.settings_dialog(win)
        settings.show()
        pump(0.2)
        for page_id in list(settings._items):
            settings.show_page(page_id)
            item = settings._items[page_id]
            for c in range(item.childCount()):
                settings.tree.setCurrentItem(item.child(c))
            pump(0.05)
        _widgets(out, settings)
        settings.reject()

        connect = ConnectionDialog(win._profile_manager, parent=win)
        stores.dialogs.append(connect)
        _widgets(out, connect)
        shortcuts = ShortcutsDialog(win)
        stores.dialogs.append(shortcuts)
        _widgets(out, shortcuts)
        return out
    finally:
        stores.restore()
        stores.dialogs, stores.windows = [], []
        if translator is not None:
            APP.removeTranslator(translator)
        i18n.install(i18n.DEFAULT_LANGUAGE)


@pytest.fixture(scope="module")
def texts(tmp_path_factory):
    found = {}
    for language in ("en", "de"):
        mp = pytest.MonkeyPatch()
        try:
            stores = isolate(tmp_path_factory.mktemp(f"ui-{language}"), mp)
            found[language] = collect(stores, language)
        finally:
            mp.undo()
    return found


def untranslated(found) -> tuple[list[tuple[str, str]], int]:
    """The German texts the English window shows verbatim and that carry an
    English word, and how many German texts there are."""
    english = {text for _kind, text in found["en"]}
    german = found["de"]
    left = [(kind, text) for kind, text in german
            if text in english and text not in ALLOWED and not CATALOGUE_CATEGORIES.match(text)
            and english_words(text)]
    return left, len(german)


def _classifier_works() -> None:
    """Names and code are no English; a label is."""
    assert english_words("SFTP") == []
    assert english_words("  axross.copy") == []
    assert english_words("bulk_rename") == []
    assert english_words("/mnt/iscsi") == []
    assert english_words("Pane schließen") == []  # a kept term (tests/test_i18n.py)
    assert english_words("DEBUG") == []
    assert english_words("Close active pane (Ctrl+W)") == ["Close", "active"]
    found = {"en": [("button", "Cancel All"), ("label", "SFTP")],
             "de": [("button", "Cancel All"), ("label", "SFTP")]}
    assert untranslated(found) == ([("button", "Cancel All")], 2)


def test_happy_the_german_window_is_german(texts):
    _classifier_works()
    left, total = untranslated(texts)
    unique = sorted({text for _kind, text in left})
    report = "\n".join(f"  {text[:110]!r}" for text in unique)
    assert total > 2000, total  # the whole window was walked, not an empty one
    assert len(left) <= MAX_ENGLISH_SHARE * total, (
        f"{len(left)} of {total} German texts are English ({len(unique)} different):\n{report}")


def test_happy_the_areas_the_review_named_are_translated(texts):
    """One text of each area the review listed, by what it shows in German."""
    german = {text for _kind, text in texts["de"]}
    for expected in (
        "Aktives Pane schließen (Strg+W)",          # toolbar tooltip
        "Mit Server verbinden",                     # Connect to Server
        "Dateioperationen",                         # Keyboard Shortcuts section
        "Strg+Umschalt+H",                          # a key, the German way
        "Richtung",                                 # transfer dock header
        "Fehlgeschlagene wiederholen",              # transfer dock button
        "In die Dock-Leiste legen (ein Klick auf seinen Namen dort holt es zurück)",
    ):
        assert expected in german, expected
