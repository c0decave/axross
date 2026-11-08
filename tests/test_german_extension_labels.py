"""The bundled extensions speak German too: their Extensions-menu entries,
right-click entries and panel titles, and the texts of their windows.

Review 4 (features/extensions): in German, "Agent Stats", "Markdown
Preview", "Entropy Heatmap…", the Forensic Tools entries and the Drives
panel ("Refresh", "Show system and memory mounts", "Select a drive") were
English. ui/extension_host.py put the labels on screen as given and the
extensions never passed their texts through tr().
"""

from __future__ import annotations

import ast
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMainWindow, QMenu  # noqa: E402

from tests.test_i18n import kept_terms_missing  # noqa: E402

APP = QApplication.instance() or QApplication([])
CATALOGUE = json.loads((ROOT / "resources" / "i18n" / "de.json").read_text(encoding="utf-8"))
REGISTERING = {"add_menu_action", "add_context_action", "add_dock"}


def _labels() -> list[tuple[str, str]]:
    """(extension file, label) of every literal label a bundled extension
    registers - bare or in tr()."""
    found = []
    for path in sorted((ROOT / "resources" / "extensions").glob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not (isinstance(node, ast.Call) and node.args):
                continue
            name = getattr(node.func, "attr", getattr(node.func, "id", ""))
            if name not in REGISTERING:
                continue
            arg = node.args[0]
            if isinstance(arg, ast.Call) and getattr(arg.func, "id", "") == "tr" and arg.args:
                arg = arg.args[0]
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                found.append((path.name, arg.value))
    return found


#: Names that are the same in German.
SAME = {"IRC", "XMPP", "Matrix", "Bluetooth", "Arcade…"}


def test_happy_every_bundled_extension_label_has_a_german_entry():
    labels = _labels()
    assert len(labels) >= 25, labels   # the scan found the registrations
    missing = [(f, label) for f, label in labels if label not in CATALOGUE and label not in SAME]
    assert missing == []
    lost = [(label, CATALOGUE[label]) for _f, label in labels
            if label in CATALOGUE and kept_terms_missing(label, CATALOGUE[label])]
    assert lost == []


@pytest.fixture
def german_host(tmp_path, monkeypatch):
    from core import extensions as EX
    from core import i18n
    from ui.extension_host import ExtensionHost

    monkeypatch.setattr(EX, "_SAFE_MODE", False)
    i18n.install("de")
    window = QMainWindow()
    host = ExtensionHost(window, window.menuBar().addMenu("Extensions"))
    try:
        yield window, host
    finally:
        for ext_id in list(getattr(host, "_loaded", {})):
            host.set_enabled(ext_id, False)
        i18n.install(i18n.DEFAULT_LANGUAGE)
        window.deleteLater()
        APP.processEvents()
        APP.sendPostedEvents(None, QEvent.Type.DeferredDelete)


class _Pane:
    """What the host's right-click entries read of a file pane."""

    def __init__(self, folder: Path, name: str):
        from core.local_fs import LocalFS

        self.backend = LocalFS()
        self.current_path = str(folder)
        self._item = next(i for i in self.backend.list_dir(str(folder)) if i.name == name)

    def selected_file_items(self):
        return [self._item]

    def selected_items(self):
        return [os.path.join(self.current_path, self._item.name)]


def _menu_texts(menu: QMenu) -> list[str]:
    return [a.text() for a in menu.actions() if not a.isSeparator()]


def test_happy_menu_context_and_panel_labels_show_in_german(german_host, tmp_path):
    window, host = german_host
    for ext_id in ("bundled:agent_stats", "bundled:entropy_heatmap", "bundled:forensic_tools",
                   "bundled:markdown_preview", "bundled:drives_overview"):
        host.set_enabled(ext_id, True)
    APP.processEvents()
    menu = window.menuBar().actions()[0].menu()
    texts = []
    stack = [menu]
    while stack:
        m = stack.pop()
        texts += _menu_texts(m)
        stack += [a.menu() for a in m.actions() if a.menu() is not None]
    assert "Agenten-Statistik" in texts and "Agent Stats" not in texts

    (tmp_path / "disk.img").write_bytes(b"\0" * 4096)
    pane = _Pane(tmp_path, "disk.img")
    context = QMenu()
    host.add_context_actions(pane, context)
    labels = _menu_texts(context)
    assert "Entropie-Heatmap…" in labels
    assert "Image hashen (MD5, SHA-1, SHA-256)" in labels
    assert not any(label in labels for label in ("Entropy Heatmap…", "Carve Files (PhotoRec)"))
    context.deleteLater()

    titles = {d.windowTitle() for ext in ("bundled:markdown_preview", "bundled:drives_overview")
              for d in host.docks(ext)}
    assert "Markdown-Preview" in titles


def test_sad_the_drives_panel_and_the_stats_window_are_german(german_host):
    window, host = german_host
    host.set_enabled("bundled:drives_overview", True)
    host.set_enabled("bundled:agent_stats", True)
    panel = host.docks("bundled:drives_overview")[0].widget()
    assert panel.refresh_button.text() == "Aktualisieren"
    assert panel.show_system.text() == "System- und Speicher-Mounts anzeigen"
    headers = [panel.table.horizontalHeaderItem(c).text() for c in range(panel.table.columnCount())]
    assert "Gerät" in headers and "Mount" in headers
    stats = host.module("bundled:agent_stats").WINDOW
    assert stats.windowTitle() == "Agenten-Statistik" and stats.state.text() == "Untätig"


def test_edge_a_label_without_a_catalogue_entry_stays_as_given(german_host):
    from ui.extension_host import _tr

    assert _tr("My Own Extension Entry") == "My Own Extension Entry"
    assert _tr("Agent Stats") == "Agenten-Statistik"


def test_edge_the_entropy_verdicts_are_german(german_host):
    sys.path.insert(0, str(ROOT))
    from resources.extensions import entropy_heatmap as EH

    assert EH.verdict([]) == "leere Datei"
    assert EH.verdict([8.0] * 10) == "durchgehend komprimiert oder verschlüsselt"
    assert EH.verdict([4.0] * 10).startswith("niedrige Entropie")
