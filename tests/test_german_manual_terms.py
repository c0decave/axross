"""The German manual, the German catalogue and the German tour narration
name things the way the German window does - one term per thing.

Found in review round 3 (UX, German):

- docs/USAGE_de.md wrote *Edit → Settings…*, *Help → Features…*, *View >
  Tagged Files…* and some 70 more English menu paths, for a window whose
  menus read *Bearbeiten → Einstellungen…*, *Hilfe → Funktionen…*.
- The same thing had two names: the dock *Übertragungen* was the
  "Transfer-Warteschlange" in the tours and "Transfers" in the manual;
  *Dateien finden* was "Find Files"; the *Produktion* box "Production";
  modifier keys were "Ctrl+", "Strg+Shift+" and "Strg+Umschalt+".
- docs/HANDBUCH.md was a second German manual, older than USAGE_de.md
  (the one F1 shows), and the READMEs sent German readers there.
- Wording: the menu "Actions" stayed English, "View &Media…" and
  "Tagged F&iles…" were half English, "An den Agent senden" (Agenten),
  "Aktualisieren" stood for both Refresh and Update to…, "Nach 0.5 s"
  (decimal comma), "Konflikte werden gefragt", "dieses Release".
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

GUIDE = ROOT / "docs" / "USAGE_de.md"
CATALOGUE = ROOT / "resources" / "i18n" / "de.json"
NARRATION = ROOT / "scripts" / "tour_narration.json"


def _german() -> dict[str, str]:
    return json.loads(CATALOGUE.read_text(encoding="utf-8"))


def _bare(label: str) -> str:
    """A menu label as shown: mnemonic "&" gone, "&&" one "&", no shortcut."""
    return label.replace("&&", "\0").replace("&", "").replace("\0", "&").split("\t")[0]


def _prose(text: str) -> str:
    """*text* without fenced code blocks, its whitespace runs made one space
    (a menu path may wrap)."""
    lines, fenced = [], False
    for line in text.splitlines():
        if line.startswith("```"):
            fenced = not fenced
            continue
        if not fenced:
            lines.append(line)
    return " ".join(" ".join(lines).split())


def _narration_de() -> list[str]:
    data = json.loads(NARRATION.read_text(encoding="utf-8"))
    found: list[str] = []

    def walk(node, key=""):
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, k)
        elif isinstance(node, list):
            for v in node:
                walk(v, key)
        elif key == "de" and isinstance(node, str):
            found.append(node)

    walk(data)
    return found


# --------------------------------------------------------------------------
# Menu paths in the German manual
# --------------------------------------------------------------------------

ENGLISH_PATH = re.compile(
    r"(?<![\w-])(File|Edit|Actions|View|Help|Settings|Agent Settings)\s*(→|>)\s*\*?\w")


def test_sad_the_german_manual_names_no_english_menu_path():
    hits = [m.group(0) for m in ENGLISH_PATH.finditer(_prose(GUIDE.read_text(encoding="utf-8")))]
    assert hits == [], hits


def test_happy_the_german_manual_names_the_entries_the_german_menus_have():
    """Each "<menu> → <entry>" of the manual names an entry of that menu in
    the German window (or the start of one: "Ansicht → Zoom")."""
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtCore import QEvent
    from PyQt6.QtWidgets import QApplication

    from core import i18n

    app = QApplication.instance() or QApplication([])
    previous = i18n._ACTIVE
    i18n._ACTIVE = i18n.Translator("de")
    try:
        from ui.main_window import MainWindow

        win = MainWindow()
        win._reconnect_timer.stop()
        menus: dict[str, list[str]] = {}
        for top in win.menuBar().actions():
            top.menu().aboutToShow.emit()
            menus[_bare(top.text())] = [_bare(a.text()) for a in top.menu().actions()
                                        if not a.isSeparator() and a.text()]
        win.close()
        win.deleteLater()
        app.sendPostedEvents(None, QEvent.Type.DeferredDelete)
    finally:
        i18n._ACTIVE = previous
    assert "Bearbeiten" in menus and "Hilfe" in menus, list(menus)
    # "Pane" is also the noun ("Rechtsklick auf das Pane → ..."), and the
    # Text Editor has a File menu of its own (Datei → Neu).
    menus.pop("Pane", None)
    menus.setdefault("Datei", []).append("Neu")
    # A bundled extension's entry is in the Extensions menu only while the
    # extension is on: take the labels its source adds.
    de = _german()
    for source in (ROOT / "resources" / "extensions").glob("*.py"):
        for label in re.findall(r'add_menu_action\(\s*(?:tr\()?"([^"]+)"',
                                source.read_text(encoding="utf-8")):
            menus.setdefault("Extensions", []).append(_bare(de.get(label, label)))
    body = _prose(GUIDE.read_text(encoding="utf-8"))
    top = re.compile(r"(?<![\w-])(%s) → " % "|".join(map(re.escape, menus)))
    wrong, consumed, pos = [], 0, 0
    while (m := top.search(body, pos)):
        pos = m.end()
        if m.start() < consumed:  # "Workspace → Neuer Workspace → Mit ..."
            continue
        rest = body[m.end():]
        segment = re.split(r"\*| \(|,|;|\)| →", rest, maxsplit=1)[0].strip()
        entry = next((e for e in menus[m.group(1)]
                      if rest.startswith(e) or e.startswith(segment)), None)
        if entry is None or not segment:
            wrong.append(f"{m.group(1)} → {rest[:40]}")
        else:
            consumed = m.end() + len(entry)
    assert wrong == [], wrong


# --------------------------------------------------------------------------
# One manual
# --------------------------------------------------------------------------


def test_happy_handbuch_only_points_to_the_german_manual():
    text = (ROOT / "docs" / "HANDBUCH.md").read_text(encoding="utf-8")
    assert "(USAGE_de.md)" in text
    assert len(text.splitlines()) < 40 and "\n## " not in text


@pytest.mark.parametrize("name", ["README.md", "README_de.md", "README_es.md",
                                  "docs/USAGE.md", "docs/USAGE_de.md", "docs/USAGE_es.md"])
def test_sad_no_reader_is_sent_to_the_old_handbook(name):
    text = (ROOT / name).read_text(encoding="utf-8")
    assert "HANDBUCH.md" not in text, name
    if name.startswith("README"):
        assert "(docs/USAGE_de.md)" in text, name


# --------------------------------------------------------------------------
# One term per thing
# --------------------------------------------------------------------------


def test_sad_modifier_keys_are_spelt_as_on_a_german_keyboard():
    """Strg and Umschalt, as Qt's German shortcut texts say - not Ctrl,
    Shift or a mix ("Strg+Shift+N")."""
    english = re.compile(r"(?<![\w-])(Ctrl|Shift)\+\S")
    guide = english.findall(_prose(GUIDE.read_text(encoding="utf-8")))
    catalogue = {k: v for k, v in _german().items() if english.search(v)}
    narration = [t for t in _narration_de() if english.search(t)]
    assert guide == [] and catalogue == {} and narration == [], (guide, catalogue, narration)


def test_happy_the_ui_names_are_the_ones_used_everywhere():
    de = _german()
    assert de["Transfers"] == "Übertragungen"
    assert _bare(de["&Find Files…"]) == "Dateien finden…" == de["Find Files"] + "…"
    assert de["Features…"] == "Funktionen…"
    assert de["Production (confirm destructive operations with a countdown)"].startswith(
        "Produktion ")
    guide = _prose(GUIDE.read_text(encoding="utf-8"))
    narration = " ".join(_narration_de())
    for text, where in ((guide, "USAGE_de.md"), (narration, "tour_narration.json"),
                        (" ".join(de.values()), "de.json")):
        for stale in ("Transfer-Warteschlange", "Transfer-Queue", "{Transfer}-",
                      "Find Files", "{Find Files}", "Tagged Files", "Features-Fenster",
                      "Features…", "Production"):
            assert stale not in text, (where, stale)
    assert "\n## Übertragungen\n" in GUIDE.read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# The wording the review named
# --------------------------------------------------------------------------


def test_sad_the_menu_labels_are_german():
    de = _german()
    assert _bare(de["&Actions"]) == "Aktionen"
    assert _bare(de["&View Media…"]) == de["View Media…"] == "Medien ansehen…"
    assert "Tagged" not in de["Tagged &Files…"] and "Files" not in de["Tagged &Files…"]
    assert de["Send to Agent"] == "An den Agenten senden"
    assert de["Ask the Agent"] == "Den Agenten fragen"


def test_sad_refresh_and_update_are_two_words():
    de = _german()
    refresh = _bare(de["Refresh"]).split()[0]
    for update in ("Update to…", "Update to {version}…"):
        assert refresh.casefold() not in de[update].casefold(), (refresh, de[update])


def test_sad_no_weak_noun_or_genitive_is_left_uninflected():
    """der Agent, den/dem Agenten; das Release, des Releases."""
    agent = re.compile(r"\b(den|dem|einen|einem)\s+Agent\b(?![-\w])", re.I)
    release = re.compile(r"\b(dieses|des|seines|eines|jedes)\s+\{?Release\}?(?![-\w])")
    texts = list(_german().values()) + _narration_de() + [GUIDE.read_text(encoding="utf-8")]
    bad = [m.group(0) for t in texts for p in (agent, release) for m in p.finditer(t)]
    assert bad == [], bad
    assert not any("werden gefragt" in v for v in _german().values())


def test_edge_seconds_get_a_decimal_comma_in_german(monkeypatch):
    """Settings > General > Activate a pane read "Nach 0.5 s im Pane"."""
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from core import i18n
    from ui import settings_dialog

    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))
    assert settings_dialog._decimal(0.5) == "0,5"
    assert settings_dialog._decimal(2) == "2"
    # Round 6: "Nach 0,5 s im Pane" said little - the choice names the mouse.
    assert i18n.tr("When the mouse rests on it for {n} s").format(
        n=settings_dialog._decimal(0.5)) == "Wenn die Maus 0,5 s darauf ruht"
    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("en"))
    assert settings_dialog._decimal(0.5) == "0.5"
