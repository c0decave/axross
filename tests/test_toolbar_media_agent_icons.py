"""Toolbar icons: a music note for the Media Player, the equalizer for a new
"Audio & Video Settings" button, the Agent button with the Agent's robot,
and a gate on every toolbar button without a real icon.

Operator: *„das media player icon sieht eher aus wie ein icon fuer music
equializer und sollte sowas oder music / video settings aufmachen, während
wir z.b. ein svg mit einer note fuer den musicplayer brauchen."* and
*„ich glaube es fehlt noch imemr das agent doc icon svg in der icon menu
bar."*

Measured on 0.13.121 (source tree and dist/axross-full, offscreen, with the
operator's own session.json): the Agent button IS in the Tools bar and its
icon renders (269 painted pixels at 22 px). What it showed was a speech
bubble with a plus ("agent" in ui/icon_provider.py) - while the Agent dock's
title bar and the "Send to Agent" entry show the robot ("bot"). The button
for the Agent did not look like the Agent anywhere else; now it is the
same robot.

The frozen check runs the built binary: ``AXROSS_FROZEN_BINARY=dist/axross-full``.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtGui import QIcon  # noqa: E402
from PyQt6.QtWidgets import QLabel, QToolBar, QWidget  # noqa: E402

from tests.settings_testkit import app, isolate  # noqa: E402
from ui import icon_provider as IP  # noqa: E402

APP = app()
ROOT = Path(__file__).resolve().parents[1]
BINARY = os.environ.get("AXROSS_FROZEN_BINARY", "")
#: The equalizer sliders the Media Player button had until now.
EQUALIZER = '<path d="M1 14h6M9 8h6M17 16h6"/>'
#: Fewer painted pixels than this at 22 px is no icon a user can see.
MIN_PAINTED = 40


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


@pytest.fixture
def stores(tmp_path, monkeypatch):
    s = isolate(tmp_path, monkeypatch)
    yield s
    s.restore()


@pytest.fixture
def win(stores):
    w = stores.make_window()
    w.show()
    pump()
    return w


def _bars(win) -> list[QToolBar]:
    return [tb for title in ("Main", "Tools") for tb in win.findChildren(QToolBar)
            if tb.windowTitle() == title]


def _by_icon(win) -> dict:
    return {a.property("axIcon"): a for bar in _bars(win) for a in bar.actions()
            if a.property("axIcon")}


def _painted(icon: QIcon, size: int = 22) -> int:
    image = icon.pixmap(size, size).toImage()
    return sum(1 for x in range(image.width()) for y in range(image.height())
               if image.pixelColor(x, y).alpha() > 0)


def toolbar_icon_problems(win) -> list[str]:
    """Every button of the Main and Tools bars without a real icon: no
    ``axIcon`` name, a name the icon set does not have (it would draw the
    question-mark placeholder), a null icon, or one that paints (next to)
    nothing."""
    problems = []
    for bar in _bars(win):
        for action in bar.actions():
            if action.isSeparator():
                continue
            name = action.property("axIcon")
            label = f"{bar.windowTitle()}: {action.text()!r}"
            if not name:
                problems.append(f"{label} has no axIcon")
            elif not IP.has_icon(str(name)):
                problems.append(f"{label} names the unknown icon {name!r}")
            elif action.icon().isNull():
                problems.append(f"{label} ({name}) has a null icon")
            elif _painted(action.icon()) < MIN_PAINTED:
                problems.append(f"{label} ({name}) paints {_painted(action.icon())} pixels")
    return problems


def _opened_on(win, trigger) -> list[tuple[str, str]]:
    """(page id, page title) the Settings dialog opens on when *trigger* runs."""
    from ui.settings_dialog import SettingsDialog

    seen = []

    def fake_exec(dialog) -> int:
        dialog.show()
        APP.processEvents()
        seen.append((dialog.current_page_id(), dialog.title_label.text()))
        return 0

    with mock.patch.object(SettingsDialog, "exec", fake_exec):
        trigger()
    return seen


class _AudioPage(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.marker = QLabel("test audio page", self)


@pytest.fixture
def audio_page():
    from ui import settings_dialog as SD

    # Its own title: the real Audio page (ui.audio_settings_page) is there too.
    SD.register_page("test-audio", "Test Audio", lambda parent, window: _AudioPage(parent))
    yield
    SD.unregister_page("test-audio")


# --- happy ------------------------------------------------------------------


def test_happy_the_media_player_icon_is_a_music_note() -> None:
    svg = IP.ICONS["media-player"]
    assert EQUALIZER not in svg
    assert "<circle" in svg or "<ellipse" in svg  # the note head
    assert 'viewBox="0 0 24 24"' in svg and 'stroke="currentColor"' in svg
    assert IP._ICON_COLORS.get("media-player")
    assert _painted(IP.icon("media-player")) >= MIN_PAINTED


def test_happy_the_equalizer_is_the_audio_and_video_settings_icon() -> None:
    svg = IP.ICONS["audio-settings"]
    assert EQUALIZER in svg
    assert 'stroke="currentColor"' in svg
    colour = IP._ICON_COLORS.get("audio-settings")
    assert colour and colour != IP._ICON_COLORS["media-player"]
    assert "audio-settings" in IP.available_icons()


def test_happy_the_audio_and_video_button_sits_beside_the_media_player(win) -> None:
    tools = next(b for b in _bars(win) if b.windowTitle() == "Tools")
    names = [a.property("axIcon") for a in tools.actions() if not a.isSeparator()]
    assert names.index("audio-settings") == names.index("media-player") + 1
    action = _by_icon(win)["audio-settings"]
    assert action is win._av_settings_action
    assert "Audio & Video Settings" in action.toolTip()
    # In the menus as well, as the same action (Tools, beside the other
    # entries that open Settings on their page).
    tools_menu = next(a.menu() for a in win.menuBar().actions() if a.text() == "&Tools")
    assert action in tools_menu.actions()
    assert action.text().replace("&&", "\0").replace("&", "").replace("\0", "&") == \
        "Audio & Video Settings…"


def test_happy_e2e_audio_and_video_settings_opens_the_page_it_names(win, audio_page,
                                                                    monkeypatch) -> None:
    monkeypatch.setattr(type(win), "AUDIO_SETTINGS_TITLE", "Test Audio")
    assert _opened_on(win, _by_icon(win)["audio-settings"].trigger) == [("test-audio", "Test Audio")]


def test_happy_open_settings_by_title(win, audio_page) -> None:
    assert _opened_on(win, lambda: win.open_settings(title="Test Audio")) == [
        ("test-audio", "Test Audio")]
    # A built-in page by its (English) title as well.
    assert _opened_on(win, lambda: win.open_settings(title="Appearance"))[0][0] == "appearance"


def test_happy_the_agent_button_shows_the_agents_robot(win) -> None:
    # The Agent dock's title bar and "Send to Agent" show "bot"; the button
    # showed a speech bubble with a plus that nothing else used.
    assert IP.ICONS["agent"] == IP.ICONS["bot"]
    from ui.file_pane import CONTEXT_COMMANDS

    assert CONTEXT_COMMANDS["send-to-agent"][0] in ("bot", "agent")
    agent = _by_icon(win)["agent"]
    assert agent is win._agent_dock.toggleViewAction()
    assert IP._ICON_COLORS.get("agent")
    assert _painted(agent.icon()) >= MIN_PAINTED


def test_happy_every_toolbar_button_has_a_real_icon(win) -> None:
    assert toolbar_icon_problems(win) == []


# --- sad --------------------------------------------------------------------


def test_sad_without_a_page_of_that_title_the_dialog_opens_on_its_first_page(win,
                                                                             monkeypatch) -> None:
    monkeypatch.setattr(type(win), "AUDIO_SETTINGS_TITLE", "No Such Page")
    assert _opened_on(win, _by_icon(win)["audio-settings"].trigger) == [("general", "General")]


@pytest.mark.parametrize("title", ["", "No Such Page", "audio "])
def test_sad_show_page_titled_reports_a_miss_and_keeps_the_page(stores, win, title) -> None:
    dialog = stores.settings_dialog(win, "network")
    assert dialog.show_page_titled(title) is False
    assert dialog.current_page_id() == "network"


def test_sad_the_icon_gate_catches_a_button_without_an_icon(win) -> None:
    # Negative controls: the gate is not blind.
    agent = _by_icon(win)["agent"]
    agent.setIcon(QIcon())
    assert any("has a null icon" in p and "agent" in p for p in toolbar_icon_problems(win))
    agent.setProperty("axIcon", "no-such-icon")
    assert any("unknown icon 'no-such-icon'" in p for p in toolbar_icon_problems(win))
    agent.setProperty("axIcon", None)
    assert any("has no axIcon" in p for p in toolbar_icon_problems(win))


# --- edge -------------------------------------------------------------------


def test_edge_every_theme_and_monochrome_keep_every_toolbar_icon(win) -> None:
    theme = win._current_theme
    try:
        for name in ("hacker", "amber", "modern-light", "default", "modern"):
            try:
                win._apply_theme(name)
            except KeyError:
                continue
            pump()
            assert toolbar_icon_problems(win) == [], name
        win.set_monochrome_icons(True, store=False)
        pump()
        assert toolbar_icon_problems(win) == [], "monochrome"
    finally:
        win.set_monochrome_icons(False, store=False)
        win._apply_theme(theme)


def test_edge_the_first_of_two_pages_with_one_title_wins(stores, win, audio_page) -> None:
    from ui import settings_dialog as SD

    SD.register_page("test-audio-2", "Test Audio", lambda parent, window: QWidget(parent))
    try:
        dialog = stores.settings_dialog(win)
        assert dialog.show_page_titled("Test Audio") is True
        assert dialog.current_page_id() == "test-audio"
    finally:
        SD.unregister_page("test-audio-2")


def test_edge_a_title_matches_in_the_interface_language(stores, win, monkeypatch) -> None:
    from core import i18n

    german = i18n.Translator(i18n.DEFAULT_LANGUAGE)
    german._entries = {"Appearance": "Darstellung"}
    monkeypatch.setattr(i18n, "_ACTIVE", german)
    dialog = stores.settings_dialog(win)
    assert dialog.show_page_titled("Appearance") is True
    assert dialog.current_page_id() == "appearance"
    assert dialog.show_page_titled("Darstellung") is True


def test_edge_the_note_and_the_equalizer_differ_from_the_neighbours() -> None:
    for other in ("music", "speaker", "headphones", "media-view"):
        assert IP.ICONS["media-player"] != IP.ICONS[other], other
    assert IP.ICONS["audio-settings"] != IP.ICONS["settings"]


# --- the built binary -------------------------------------------------------

_FROZEN_PROBE = r'''
import json, os, sys
from PyQt6.QtWidgets import QApplication, QToolBar
app = QApplication.instance() or QApplication(["probe"])
from ui import icon_provider as IP
from ui.main_window import MainWindow
win = MainWindow()
win._reconnect_timer.stop()
win.show()
for _ in range(20):
    app.processEvents()

def painted(icon, size=22):
    image = icon.pixmap(size, size).toImage()
    return sum(1 for x in range(image.width()) for y in range(image.height())
               if image.pixelColor(x, y).alpha() > 0)

out = {"frozen": bool(getattr(sys, "frozen", False)), "buttons": [],
       "agent_is_robot": IP.ICONS.get("agent") == IP.ICONS.get("bot")}
for bar in win.findChildren(QToolBar):
    if bar.windowTitle() not in ("Main", "Tools"):
        continue
    for a in bar.actions():
        if a.isSeparator():
            continue
        name = a.property("axIcon")
        out["buttons"].append({"bar": bar.windowTitle(), "text": a.text(), "icon": name,
                               "known": bool(name) and IP.has_icon(str(name)),
                               "null": a.icon().isNull(), "painted": painted(a.icon())})
with open(os.environ["PROBE_OUT"], "w") as fh:
    json.dump(out, fh)
win.close()
os._exit(0)
'''


@pytest.mark.skipif(not BINARY, reason="set AXROSS_FROZEN_BINARY to a built axross-full/slim")
@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="Linux one-file bundle")
def test_frozen_every_toolbar_button_has_a_real_icon_in_the_binary() -> None:
    with tempfile.TemporaryDirectory(prefix="axross-toolbar-probe-") as tmp:
        home = Path(tmp) / "home"
        (home / "run").mkdir(parents=True)
        os.chmod(home / "run", 0o700)
        script, out = Path(tmp) / "probe.py", Path(tmp) / "out.json"
        script.write_text(_FROZEN_PROBE)
        env = {"HOME": str(home), "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
               "XDG_CONFIG_HOME": str(home / ".config"), "XDG_RUNTIME_DIR": str(home / "run"),
               "QT_QPA_PLATFORM": "offscreen", "PROBE_OUT": str(out),
               "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring"}
        r = subprocess.run([os.path.abspath(BINARY), "--script", str(script)], cwd=tmp, env=env,
                           capture_output=True, text=True, timeout=300)
        assert out.exists(), f"the probe wrote nothing (rc {r.returncode}): {r.stderr[-1500:]}"
        data = json.loads(out.read_text())
    assert data["frozen"] is True
    names = [b["icon"] for b in data["buttons"]]
    assert "agent" in names and "media-player" in names, names
    bad = [b for b in data["buttons"]
           if not b["known"] or b["null"] or b["painted"] < MIN_PAINTED]
    assert bad == [], bad
    assert data["agent_is_robot"], "the binary's Agent button is not the Agent's robot"


def test_happy_e2e_audio_and_video_settings_opens_the_real_audio_page(win) -> None:
    """With the Audio page of ui.audio_settings_page present (no test page):
    the toolbar button lands on it."""
    assert _opened_on(win, _by_icon(win)["audio-settings"].trigger) == [("audio", "Audio")]
