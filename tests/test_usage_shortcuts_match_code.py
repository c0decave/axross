"""The user guides name the keys the window really binds.

Found in review (round 3, config; reproduced by pressing the keys): the
guides said Ctrl+N opens the Connection Manager (it opens Quick Connect;
the manager is Ctrl+Shift+N), Ctrl+T adds a pane (bound nowhere in the
main window - inside the Agent dock it opens an agent tab) and Ctrl+Tab
cycles panes (it does nothing; Tab / Shift+Tab in a file list do). The
German handbook also called F2 "refresh" (F2 renames, Ctrl+R refreshes).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GUIDES = ["docs/USAGE.md", "docs/USAGE_de.md", "docs/USAGE_es.md", "docs/HANDBUCH.md"]
MAIN_WINDOW = (ROOT / "ui" / "main_window.py").read_text(encoding="utf-8")
FILE_PANE = (ROOT / "ui" / "file_pane.py").read_text(encoding="utf-8")


def _shortcut(action: str) -> str:
    m = re.search(rf'\b{action}\.setShortcut\(QKeySequence\("([^"]+)"\)\)', MAIN_WINDOW)
    assert m, action
    return m.group(1)


def _text(guide: str) -> str:
    return (ROOT / guide).read_text(encoding="utf-8")


def _without_agent_dock(text: str) -> str:
    """Ctrl+T is real inside the Agent dock; drop those sentences."""
    return "\n".join(line for line in text.splitlines() if '"+"' not in line and "„+" not in line)


def test_happy_the_bindings_the_guides_rely_on():
    assert _shortcut("quick_connect_action") == "Ctrl+N"
    assert _shortcut("connect_action") == "Ctrl+Shift+N"
    assert "Key_Tab and no_mods" in FILE_PANE and "Key_Backtab" in FILE_PANE


@pytest.mark.parametrize("guide", GUIDES)
def test_sad_connection_manager_is_not_ctrl_n(guide):
    text = _text(guide)
    assert not re.search(r"Connection[- ]Manager[^\n]{0,12}\((Ctrl|Strg)\+N\)", text)
    assert not re.search(r"(Ctrl|Strg)\+N`? +öffnet den Connection", text)
    assert "Ctrl+Shift+N" in text or "Strg+Shift+N" in text


@pytest.mark.parametrize("guide", GUIDES)
def test_sad_no_ctrl_t_for_panes_and_no_ctrl_tab(guide):
    text = _without_agent_dock(_text(guide))
    assert not re.search(r"\b(Ctrl|Strg)\+T\b(?!ab)", text), guide
    assert not re.search(r"\b(Ctrl|Strg)\+Tab\b", text), guide


@pytest.mark.parametrize("guide", ["docs/USAGE.md", "docs/USAGE_de.md", "docs/USAGE_es.md"])
def test_edge_tab_cycling_is_documented(guide):
    assert re.search(r"\*\*Tab\*\*\s*/\s*\*\*Shift\+Tab\*\*", _text(guide)), guide


def test_edge_handbook_f2_renames():
    text = _text("docs/HANDBUCH.md")
    assert not re.search(r"F2\*?\*?`? *(→|\|) *(Pane|Aktives Pane) aktualisieren", text)
    assert re.search(r"`F2` +\| *Umbenennen", text)
