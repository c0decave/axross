"""Every setting really works - one table, one row per setting.

Operator: *„prüfen ob alle settings wirklich funktionieren, matrix tests."*
Each row of ``ROWS`` names a setting, its page in Edit > Settings…, its
store, the values to try, hand-edited values that are not valid, and how
its effect is seen. For every row:

1. ``test_set_store_reload_effect`` - set through the page's real widgets,
   OK (``apply``) -> the store holds it -> a fresh load shows it (a new
   Settings dialog; a new window where the window holds the value) -> the
   effect is observable (a pane listing, the stylesheet, a refused file, a
   hover timer, a connection through a fake proxy, ...);
2. ``test_back_to_the_default`` - setting the default again stores it;
3. ``test_cancel_keeps_the_store`` - Cancel writes nothing;
4. ``test_hand_edited_value_falls_back`` - an invalid stored value starts
   without an error and reads as the default (the security mode fails
   closed to paranoid instead - deliberately, see core.security_mode).

Cross effects (paranoid x sudo, x extensions, x proxy, x network search,
theme x compact, show x highlight hidden) and the compatibility of old
settings files follow the table.
"""

from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import textwrap
from dataclasses import dataclass, field
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QPointF, Qt  # noqa: E402
from PyQt6.QtGui import QColor, QEnterEvent  # noqa: E402
from PyQt6.QtWidgets import QMessageBox  # noqa: E402

from core import extensions as EX  # noqa: E402
from core import i18n  # noqa: E402
from core import metadata_tools as MT  # noqa: E402
from core import open_limits as OL  # noqa: E402
from core import pane_activation as PA  # noqa: E402
from core import proxy_settings as PS  # noqa: E402
from core import ramfs_settings as RS  # noqa: E402
from core import remote_sweep as RW  # noqa: E402
from core import security_mode as SM  # noqa: E402
from core import sudo_password as SP  # noqa: E402
from core import voice_settings as VS  # noqa: E402
from tests.proxy_testkit import EchoServer, FakeSocks5Server, allow_loopback_proxy  # noqa: E402
from tests.settings_testkit import app, isolate  # noqa: E402
from ui import themes, window_prefs  # noqa: E402

APP = app()
MIB = 1024 * 1024
EXT_ID = "user:matrixext"
EXT_MENU_ENTRY = "Matrix Extension Entry"


# ---------------------------------------------------------------------------
# The context of one test
# ---------------------------------------------------------------------------


@dataclass
class Ctx:
    stores: object
    monkeypatch: object
    tmp_path: Path
    socks: FakeSocks5Server
    echo: EchoServer
    win: object = None
    extras: dict = field(default_factory=dict)

    def dialog(self, win=None):
        return self.stores.settings_dialog(win or self.win)


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    stores = isolate(tmp_path, monkeypatch)
    echo = EchoServer(banner=b"HI\n")
    socks = FakeSocks5Server(routes={("db.internal", 5432): ("127.0.0.1", echo.port)})
    # An extension to switch on (the user's folder is in the temporary home).
    folder = EX.extensions_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "matrixext.py").write_text(
        'EXTENSION = {"name": "Matrix", "version": "1.0", "description": "test"}\n\n'
        + textwrap.dedent(
            f"""
            def activate(api):
                api.add_menu_action({EXT_MENU_ENTRY!r}, lambda: None)
            """
        )
    )
    c = Ctx(stores, monkeypatch, tmp_path, socks, echo)
    c.win = stores.make_window()
    yield c
    stores.restore()
    socks.close()
    echo.close()


# ---------------------------------------------------------------------------
# Store helpers (hand edits go through json, like a user's editor would)
# ---------------------------------------------------------------------------


def _read_json(path: Path):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def _edit_settings(ctx, key, value) -> None:
    data = _read_json(ctx.stores.settings) or {}
    data[key] = value
    ctx.stores.settings.write_text(json.dumps(data))


def _edit_window(ctx, key, value) -> None:
    data = _read_json(ctx.stores.session) or {}
    data.setdefault("window", {})[key] = value
    ctx.stores.session.write_text(json.dumps(data))


def _edit_ramfs(ctx, key, value) -> None:
    data = _read_json(ctx.stores.ramfs) or {}
    data[key] = value
    ctx.stores.ramfs.write_text(json.dumps(data))
    RS.reload_settings()


def _window_pref(ctx, attr):
    data = _read_json(ctx.stores.session) or {}
    return getattr(window_prefs.parse(data.get("window")), attr)


def _ramfs(attr):
    return getattr(RS.RamFsSettings.load(), attr)


# ---------------------------------------------------------------------------
# Effects
# ---------------------------------------------------------------------------


def _enter(pane) -> None:
    p = QPointF(10, 10)
    APP.sendEvent(pane, QEnterEvent(p, p, p))


def _listing(ctx, win) -> list[str]:
    folder = ctx.tmp_path / "listing"
    folder.mkdir(exist_ok=True)
    (folder / ".dotfile").write_text("d")
    (folder / "plain.txt").write_text("p")
    pane = win._active_pane
    pane.navigate(str(folder))
    APP.processEvents()
    proxy = pane._proxy
    return sorted(proxy.data(proxy.index(r, 0)) for r in range(proxy.rowCount()))


def _ram_session():
    from core.connection_manager import ConnectionManager
    from core.profiles import ConnectionProfile

    return ConnectionManager()._create_session(
        ConnectionProfile(name="ws", protocol="ramfs"), "", "", None
    )


def effect_language(ctx, win, value) -> None:
    ctx.stores.close_windows()
    i18n.install(i18n.detect_language(configured=i18n.stored_language(), env={}, timezone=None))
    fresh = ctx.win = ctx.stores.make_window()
    titles = [a.text() for a in fresh.menuBar().actions()]
    assert ("&Datei" if value == "de" else "&File") in titles, titles


def effect_restore(ctx, win, value) -> None:
    from PyQt6.QtCore import Qt as _Qt

    win._split_pane(_Qt.Orientation.Horizontal)
    ctx.stores.close_windows()  # closing saves the layout
    fresh = ctx.win = ctx.stores.make_window()
    assert fresh.restore_layout_on_start() is value


def effect_activation(ctx, win, value) -> None:
    pane = win._active_pane
    pane._hover_timer.stop()
    _enter(pane)
    if value == PA.CLICK:
        assert not pane._hover_timer.isActive()
    else:
        assert pane._hover_timer.isActive()
        assert pane._hover_timer.interval() == int(value * 1000)
    pane._hover_timer.stop()


def effect_theme(ctx, win, value) -> None:
    assert win._current_theme == value
    assert APP.styleSheet() == themes.stylesheet_for(value, themes.system_scheme(), compact=False)


def effect_compact(ctx, win, value) -> None:
    css = themes.stylesheet_for(win._current_theme, themes.system_scheme(), compact=value)
    assert APP.styleSheet() == css
    assert (themes.COMPACT_CSS.strip() in APP.styleSheet()) is value


def effect_monochrome(ctx, win, value) -> None:
    from ui.icon_provider import is_monochrome

    assert is_monochrome() is value


def effect_font(ctx, win, value) -> None:
    from ui import main_window as MW

    expected = MW._desktop_font_size() if value is None else value
    assert APP.font().pointSize() == expected


def effect_highlight(ctx, win, value) -> None:
    assert [p._model.highlight_hidden for p in win._panes] == [value] * len(win._panes)


def effect_colour(ctx, win, value) -> None:
    assert [p._model.hidden_color for p in win._panes] == [value] * len(win._panes)


def effect_show_hidden(ctx, win, value) -> None:
    names = _listing(ctx, win)
    assert (".dotfile" in names) is value and "plain.txt" in names


def effect_open_limit(ctx, win, value) -> None:
    pane = win._active_pane
    assert pane._is_editable_file("notes.txt", value * MIB)
    assert not pane._is_editable_file("notes.txt", value * MIB + 1)  # refused: too big


def effect_ramfs_enabled(ctx, win, value) -> None:
    if value:
        assert _ram_session() is not None
    else:
        with pytest.raises(OSError, match="disabled"):
            _ram_session()


def effect_ramfs_max(ctx, win, value) -> None:
    assert _ram_session()._max_bytes == value * MIB


def effect_ramfs_reserve(ctx, win, value) -> None:
    assert _ram_session()._system_reserve == value * MIB


def effect_tmpfs(ctx, win, value) -> None:
    from core import tmpfs_detect

    ram = ctx.tmp_path / "ram"
    ram.mkdir(exist_ok=True)
    ctx.monkeypatch.delenv("TMPDIR", raising=False)
    ctx.monkeypatch.setattr(tmpfs_detect, "preferred_tmpfs_dir", lambda: str(ram))
    ctx.monkeypatch.setattr(tempfile, "tempdir", tempfile.tempdir)
    assert tmpfs_detect.apply_tempdir_preference() == (str(ram) if value else None)


def effect_proxy(ctx, win, value) -> None:
    from core.proxy import create_proxy_socket

    cfg = PS.resolve("default", None, "db.internal", 5432).config
    if value == "none":
        assert cfg is None
        return
    assert (cfg.proxy_type, cfg.host, cfg.port) == (value, "127.0.0.1", ctx.socks.port)
    if value != "socks5":
        return  # the fake speaks SOCKS5; the route chosen is the effect here
    with allow_loopback_proxy():
        sock = create_proxy_socket(cfg, "db.internal", 5432, timeout=5)
    try:
        assert sock.recv(3) == b"HI\n"
    finally:
        sock.close()
    assert ("db.internal", 5432) in ctx.socks.connects


def effect_llm(ctx, win, value) -> None:
    dock = win._analysis_dock
    dock.refresh_profiles()
    assert (dock._profile.name if dock._profile else "") == value


def effect_agent_steps(ctx, win, value) -> None:
    assert win._agent_dock.agent_settings.max_steps == value


def effect_agent_mode(ctx, win, value) -> None:
    assert win._agent_dock.agent_settings.mode == value


def _edit_voice(ctx, key, value) -> None:
    path = VS.settings_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _read_json(path) or {}
    data[key] = value
    path.write_text(json.dumps(data))


def _voice_effect(field):
    """The Agent dock's voice works with the value - and shows it where the
    setting has a visible effect."""

    def effect(ctx, win, value) -> None:
        dock = win._agent_dock  # the Voice page's save reloads it
        assert dock.voice.settings.get(field) == value
        tab = dock.current_tab()
        if field == "output_enabled":
            assert tab.speaker_button.isChecked() is value
        elif field == "input_mode":
            assert tab.mic_button.isCheckable() is (value != "push_to_talk")
        elif field == "hotkey":
            assert value in tab.mic_button.toolTip()
        elif field == "gender":
            assert VS.voice_for("de", dock.voice.settings.gender) == (
                "piper-de-kerstin" if value == "female" else "piper-de-thorsten")
        elif field == "language":
            answer = "The file is there and it is fine."
            assert VS.spoken_language(dock.voice.settings.language, answer) == (
                "en" if value == "auto" else value)
        elif field == "after_recognition":
            tab.input.clear()
            tab.on_voice_text("zeig die logs")
            if value == "insert":
                assert tab.input.toPlainText() == "zeig die logs"
            else:  # sent: without an LLM profile the tab says so
                assert "No LLM profile is active." in tab.transcript.toPlainText()
            tab.input.clear()
        elif field == "silence_seconds":
            from core import voice_audio as VA

            detector = VA.SilenceDetector(dock.voice.settings.silence_seconds)
            assert detector.silence_seconds == value

    return effect


def _voice_row(field, values, set_ui, shown, bad):
    return Row(f"voice_{field}", "voice", f"agent/voice.json {field}", values,
               VS.VoiceSettings().get(field), set_ui, shown,
               lambda c: VS.VoiceSettings.load().get(field),
               lambda c, v: _edit_voice(c, field, v), bad, _voice_effect(field))


def _set_hotkey(ctx, dialog, value) -> None:
    from PyQt6.QtGui import QKeySequence

    dialog.page("voice").hotkey_edit.setKeySequence(QKeySequence(value))


def _shown_hotkey(dialog) -> str:
    from PyQt6.QtGui import QKeySequence

    return dialog.page("voice").hotkey_edit.keySequence().toString(
        QKeySequence.SequenceFormat.PortableText)


def effect_metadata_mode(ctx, win, value) -> None:
    from core.local_fs import LocalFS
    from tests import metadata_testkit as K

    folder = ctx.tmp_path / "meta"
    folder.mkdir(exist_ok=True)
    photo = K.write(folder / "photo.jpg", K.jpeg_bytes())
    ctx.monkeypatch.setenv("HOME", str(ctx.stores.home))
    result = MT.remove_metadata(LocalFS(), str(photo))  # the mode comes from the setting
    assert result.mode == value
    if value == MT.MODE_COPY:
        assert result.output == str(folder / "photo.clean.jpg")


def effect_metadata_confirm(ctx, win, value) -> None:
    from ui import metadata_dialog as MD

    with mock.patch.object(MD.QMessageBox, "question",
                           return_value=QMessageBox.StandardButton.No) as asked:
        go = MD._ask_to_remove(None, 1)
    assert asked.called is value
    assert go is (not value)


def effect_parallel(ctx, win, value) -> None:
    assert RW.SweepConfig(targets="10.0.0.1", username="u", password="p").parallel == value


def effect_paranoid(ctx, win, value) -> None:
    assert SM.is_paranoid() is value
    assert SM.current_policy().allow_scripts is (not value)
    if value:
        with pytest.raises(OSError):
            SM.require_protocol_allowed("ftp")
    else:
        SM.require_protocol_allowed("ftp")


def effect_remember(ctx, win, value) -> None:
    SP.forget()
    SP.remember("pw")
    assert SP.remembered() == ("pw" if value else None)
    SP.forget()


def effect_extension(ctx, win, value) -> None:
    host = win.extension_host
    assert (host.module(EXT_ID) is not None) is value
    labels = [a.text() for a in win.extensions_menu.actions()]
    assert (EXT_MENU_ENTRY in labels) is value


# ---------------------------------------------------------------------------
# Driving the pages (real widgets)
# ---------------------------------------------------------------------------


def _combo_data(combo, value) -> None:
    index = combo.findData(value)
    assert index >= 0, value
    combo.setCurrentIndex(index)


def set_colour(ctx, dialog, value) -> None:
    page = dialog.page("appearance")
    if value is None:
        page.theme_colour_radio.click()
        return
    with mock.patch("ui.settings_dialog.QColorDialog.getColor", return_value=QColor(value)), \
            mock.patch("ui.settings_dialog.QMessageBox.question",
                       return_value=QMessageBox.StandardButton.Yes):
        page.colour_button.click()


def set_font(ctx, dialog, value) -> None:
    spin = dialog.page("appearance").font_spin
    spin.setValue(spin.minimum() if value is None else value)


def set_proxy(ctx, dialog, value) -> None:
    page = dialog.page("network")
    if value == "none":
        page._type.setCurrentIndex(0)
        return
    _combo_data(page._type, value)
    page._host.setText("127.0.0.1")
    page._port.setValue(ctx.socks.port)


def shown_proxy(dialog) -> str:
    return dialog.page("network").collect().proxy_type


def stored_proxy(ctx) -> str:
    return PS.load().proxy_type


def set_llm(ctx, dialog, value) -> None:
    page = dialog.page("llm")
    if not value:
        while page._settings.profiles:
            page.profile_list.setCurrentRow(0)
            page.delete_profile()
        return
    page.add_profile()
    page.name_edit.setText(value)


def shown_llm(dialog) -> str:
    page = dialog.page("llm")
    active = next((p for p in page._settings.profiles if id(p) == page._active_id), None)
    return active.name if active else ""


def set_extension(ctx, dialog, value) -> None:
    page = dialog.page("extensions")
    row = page.row_of(EXT_ID)
    assert row >= 0
    page.set_checked(row, value)
    APP.processEvents()


def shown_extension(dialog) -> bool:
    page = dialog.page("extensions")
    return page.is_checked(page.row_of(EXT_ID))


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Row:
    id: str
    page: str
    store: str
    values: tuple
    default: object
    set_ui: object  # (ctx, dialog, value)
    shown: object  # (dialog) -> value
    stored: object  # (ctx) -> value read back through the real reader
    write_bad: object  # (ctx, bad)
    bad: tuple
    effect: object  # (ctx, window, value)
    #: The window holds the value: a fresh load is a new window.
    new_window: bool = False
    #: What a hand-edited value reads as (default: the default).
    bad_reads_as: object = "default"

    def expected_for_bad(self):
        return self.default if self.bad_reads_as == "default" else self.bad_reads_as


def _page_attr(page_id, attr, method="isChecked"):
    return lambda d: getattr(getattr(d.page(page_id), attr), method)()


def _set_check(page_id, attr):
    return lambda ctx, d, v: getattr(d.page(page_id), attr).setChecked(v)


def _set_spin(page_id, attr):
    return lambda ctx, d, v: getattr(d.page(page_id), attr).setValue(v)


def _set_combo(page_id, attr):
    return lambda ctx, d, v: _combo_data(getattr(d.page(page_id), attr), v)


def _combo_shown(page_id, attr):
    return lambda d: getattr(d.page(page_id), attr).currentData()


ROWS = [
    Row("language", "general", "session.json window.language", ("de",), "",
        _set_combo("general", "language_combo"), _combo_shown("general", "language_combo"),
        lambda c: i18n.stored_language() or "",
        lambda c, v: _edit_window(c, "language", v), ("klingon", 5, None, ["de"]),
        effect_language),
    Row("restore_layout_on_start", "general", "session.json window.restore_layout_on_start",
        (False,), True,
        _set_check("general", "restore_check"), _page_attr("general", "restore_check"),
        lambda c: _window_pref(c, "restore_layout_on_start"),
        lambda c, v: _edit_window(c, window_prefs.RESTORE_ON_START_KEY, v), ("no", 0, None),
        effect_restore, new_window=True),
    Row("pane_activation", "general", "settings.json pane_activation", (PA.CLICK, 2), 0.5,
        _set_combo("general", "activation_combo"), _combo_shown("general", "activation_combo"),
        lambda c: PA.activation(),
        lambda c, v: _edit_settings(c, PA.SETTING, v), (7, "x", True, 2.0, None),
        effect_activation),
    Row("theme", "appearance", "session.json window.ui_theme", ("hacker", "modern-light"),
        "modern",
        _set_combo("appearance", "theme_combo"), _combo_shown("appearance", "theme_combo"),
        lambda c: _window_pref(c, "theme") or "modern",
        lambda c, v: _edit_window(c, window_prefs.THEME_KEY, v), ("neon", 5),
        effect_theme, new_window=True),
    Row("compact", "appearance", "session.json window.compact", (True,), False,
        _set_check("appearance", "compact_check"), _page_attr("appearance", "compact_check"),
        lambda c: _window_pref(c, "compact"),
        lambda c, v: _edit_window(c, window_prefs.COMPACT_KEY, v), ("yes", 1),
        effect_compact, new_window=True),
    Row("monochrome_icons", "appearance", "session.json window.monochrome_icons", (True,), False,
        _set_check("appearance", "monochrome_check"), _page_attr("appearance", "monochrome_check"),
        lambda c: _window_pref(c, "monochrome_icons"),
        lambda c, v: _edit_window(c, window_prefs.MONOCHROME_KEY, v), ("no", 1),
        effect_monochrome, new_window=True),
    Row("font_size", "appearance", "session.json window.font_size", (14, 8), None,
        set_font, lambda d: d.page("appearance").font_size(),
        lambda c: _window_pref(c, "font_size"),
        lambda c, v: _edit_window(c, window_prefs.FONT_SIZE_KEY, v), (99, "12", True, 5),
        effect_font, new_window=True),
    Row("highlight_hidden", "appearance", "session.json window.highlight_hidden", (False,), True,
        _set_check("appearance", "highlight_check"), _page_attr("appearance", "highlight_check"),
        lambda c: _window_pref(c, "highlight_hidden"),
        lambda c, v: _edit_window(c, window_prefs.HIGHLIGHT_HIDDEN_KEY, v), ("nope", 0),
        effect_highlight, new_window=True),
    Row("hidden_color", "appearance", "session.json window.hidden_color", ("#12ab34",), None,
        set_colour, lambda d: d.page("appearance").colour(),
        lambda c: _window_pref(c, "hidden_color"),
        lambda c, v: _edit_window(c, window_prefs.HIDDEN_COLOR_KEY, v), ("#12", 7, "red"),
        effect_colour, new_window=True),
    Row("show_hidden", "files", "session.json window.show_hidden", (False,), True,
        _set_check("files", "show_hidden_check"), _page_attr("files", "show_hidden_check"),
        lambda c: _window_pref(c, "show_hidden"),
        lambda c, v: _edit_window(c, window_prefs.SHOW_HIDDEN_KEY, v), ("no", 0),
        effect_show_hidden, new_window=True),
    Row("max_open_mb", "files", "settings.json max_open_mb", (1, 100), OL.DEFAULT_MAX_OPEN_MB,
        _set_spin("files", "open_limit_spin"), _page_attr("files", "open_limit_spin", "value"),
        lambda c: OL.max_open_mb(),
        lambda c, v: _edit_settings(c, "max_open_mb", v), (0, 99999, True, "8"),
        effect_open_limit),
    Row("ramfs_enabled", "files", "ramfs.json ramfs_enabled", (False,), True,
        _set_check("files", "ramfs_check"), _page_attr("files", "ramfs_check"),
        lambda c: _ramfs("ramfs_enabled"),
        lambda c, v: _edit_ramfs(c, "ramfs_enabled", v), ("no", 0),
        effect_ramfs_enabled),
    Row("ramfs_max_bytes", "files", "ramfs.json ramfs_max_bytes (MiB in the page)", (64,), 256,
        _set_spin("files", "ramfs_max_spin"), _page_attr("files", "ramfs_max_spin", "value"),
        lambda c: _ramfs("ramfs_max_bytes") // MIB,
        lambda c, v: _edit_ramfs(c, "ramfs_max_bytes", v), (True, -1, "x", 2**50),
        effect_ramfs_max),
    Row("ramfs_system_reserve_bytes", "files", "ramfs.json ramfs_system_reserve_bytes",
        (128,), 256,
        _set_spin("files", "ramfs_reserve_spin"),
        _page_attr("files", "ramfs_reserve_spin", "value"),
        lambda c: _ramfs("ramfs_system_reserve_bytes") // MIB,
        lambda c, v: _edit_ramfs(c, "ramfs_system_reserve_bytes", v), (False, -5, "1"),
        effect_ramfs_reserve),
    Row("tmpfs_enabled", "files", "ramfs.json tmpfs_enabled (applies at start)", (True,), False,
        _set_check("files", "tmpfs_check"), _page_attr("files", "tmpfs_check"),
        lambda c: _ramfs("tmpfs_enabled"),
        lambda c, v: _edit_ramfs(c, "tmpfs_enabled", v), ("yes", 1),
        effect_tmpfs),
    Row("default_proxy", "network", "proxy.json proxy_type/host/port", ("socks5", "http"), "none",
        set_proxy, shown_proxy, stored_proxy,
        lambda c, v: c.stores.proxy.write_text(json.dumps({"proxy_type": v, "port": "x"})),
        ("bogus", 7, "socks9"),
        effect_proxy),
    Row("llm_profile", "llm", "llm.json profiles + active", ("local-qwen",), "",
        set_llm, shown_llm, lambda c: __import__("core.llm_profiles").llm_profiles
        .LLMSettings.load().active,
        lambda c, v: c.stores.llm.write_text(v), ("{not json", "[1, 2]", '{"profiles": 5}'),
        effect_llm),
    Row("agent_max_steps", "agent", "agent/settings.json max_steps", (42,), 20,
        _set_spin("agent", "steps_spin"), _page_attr("agent", "steps_spin", "value"),
        lambda c: __import__("core.agent_settings").agent_settings.AgentSettings.load().max_steps,
        lambda c, v: (c.stores.agent.parent.mkdir(parents=True, exist_ok=True),
                      c.stores.agent.write_text(json.dumps({"max_steps": v}))),
        ("x", 0, 999, True),
        effect_agent_steps),
    Row("agent_mode", "agent", "agent/settings.json mode", ("plan", "auto"), "ask",
        _set_combo("agent", "mode_combo"), _combo_shown("agent", "mode_combo"),
        lambda c: __import__("core.agent_settings").agent_settings.AgentSettings.load().mode,
        lambda c, v: (c.stores.agent.parent.mkdir(parents=True, exist_ok=True),
                      c.stores.agent.write_text(json.dumps({"mode": v}))),
        ("bypass", "yolo", 3),
        effect_agent_mode),
    _voice_row("output_enabled", (True,), _set_check("voice", "output_check"),
               _page_attr("voice", "output_check"), ("yes", 1, None)),
    _voice_row("language", ("de", "en"), _set_combo("voice", "language_combo"),
               _combo_shown("voice", "language_combo"), ("fr", 5, None)),
    _voice_row("gender", ("female",), _set_combo("voice", "gender_combo"),
               _combo_shown("voice", "gender_combo"), ("robot", True)),
    _voice_row("input_mode", ("toggle", "conversation"), _set_combo("voice", "mode_combo"),
               _combo_shown("voice", "mode_combo"), ("always", 2)),
    _voice_row("hotkey", ("Ctrl+Shift+V", "F7"), _set_hotkey, _shown_hotkey, ("A", "", 9)),
    _voice_row("after_recognition", ("send",), _set_combo("voice", "after_combo"),
               _combo_shown("voice", "after_combo"), ("print", False)),
    _voice_row("silence_seconds", (2.5, 0.5), _set_spin("voice", "silence_spin"),
               _page_attr("voice", "silence_spin", "value"), (0.1, 99, "1", True)),
    Row("metadata_write_mode", "metadata", "settings.json metadata_write_mode", (MT.MODE_COPY,),
        MT.MODE_IN_PLACE,
        lambda c, d, v: (d.page("metadata").copy_radio if v == MT.MODE_COPY
                         else d.page("metadata").in_place_radio).setChecked(True),
        lambda d: d.page("metadata")._chosen()[0],
        lambda c: MT.write_mode(),
        lambda c, v: _edit_settings(c, "metadata_write_mode", v), ("bogus", 1),
        effect_metadata_mode),
    Row("metadata_confirm_remove", "metadata", "settings.json metadata_confirm_remove", (True,),
        False,
        _set_check("metadata", "confirm_box"), _page_attr("metadata", "confirm_box"),
        lambda c: MT.confirm_before_remove(),
        lambda c, v: _edit_settings(c, "metadata_confirm_remove", v), ("yes", 1),
        effect_metadata_confirm),
    Row("remote_sweep_parallel", "search", "settings.json remote_sweep_parallel", (9, 64), 4,
        _set_spin("search", "parallel_spin"), _page_attr("search", "parallel_spin", "value"),
        lambda c: RW.parallel_hosts(),
        lambda c, v: _edit_settings(c, RW.PARALLEL_SETTING, v), (0, 65, True, "8"),
        effect_parallel),
    Row("security_mode", "security", "settings.json security_mode", (True,), False,
        _set_check("security", "paranoid_check"), _page_attr("security", "paranoid_check"),
        lambda c: SM.stored_mode() == "paranoid",
        lambda c, v: _edit_settings(c, SM.SETTING, v), ("paranoia", 1, True),
        effect_paranoid, new_window=True, bad_reads_as=True),
    Row("remember_sudo_password", "security", "settings.json remember_sudo_password", (False,),
        True,
        _set_check("security", "remember_check"), _page_attr("security", "remember_check"),
        lambda c: SP.remember_setting(),
        lambda c, v: _edit_settings(c, SP.SETTING, v), ("no", 0),
        effect_remember),
    Row("extension_enabled", "extensions", "extensions.json enabled", (True,), False,
        set_extension, shown_extension, lambda c: EXT_ID in EX.enabled_ids(),
        lambda c, v: c.stores.extensions.write_text(v), ("{", '{"enabled": "user:matrixext"}'),
        effect_extension, new_window=True),
]


def _start(ctx, *, closed: bool = False):
    """A restart of axross: the window closes (unless *closed* already),
    main.py applies the stored security mode, then builds the window."""
    if not closed:
        ctx.stores.close_windows()
    SM._CURRENT = None
    SM.apply_stored_mode()
    ctx.win = ctx.stores.make_window()
    return ctx.win


def _reload(ctx, row):
    """A fresh load: a new start where the window holds the value; else
    the stores are read again by a new Settings dialog of the same window."""
    return _start(ctx) if row.new_window else ctx.win


# ---------------------------------------------------------------------------
# The matrix
# ---------------------------------------------------------------------------

ROW_PARAMS = [pytest.param(row, id=row.id) for row in ROWS]


def test_every_category_has_rows_and_every_row_its_page(ctx) -> None:
    dialog = ctx.dialog()
    assert {row.page for row in ROWS} == set(dialog.page_ids())


@pytest.mark.parametrize("row", ROW_PARAMS)
def test_set_store_reload_effect(ctx, row) -> None:
    """Cancel writes nothing; each value: set on the page -> OK -> stored ->
    a fresh load shows it -> its effect; then the default again."""
    before = ctx.stores.files()
    dialog = ctx.dialog()
    assert row.shown(dialog) == row.default  # a fresh home shows the default
    row.set_ui(ctx, dialog, row.values[0])
    dialog.reject()
    assert ctx.stores.files() == before, "Cancel wrote a store"
    assert row.stored(ctx) == row.default
    for value in (*row.values, row.default):
        dialog = ctx.dialog()
        row.set_ui(ctx, dialog, value)
        assert dialog.dirty_page_ids() == [row.page], value
        assert dialog.apply(), dialog.error_text()
        assert row.stored(ctx) == value, value  # persisted in its store
        win = _reload(ctx, row)
        assert row.shown(ctx.dialog(win)) == value, value  # a fresh load shows it
        row.effect(ctx, win, value)  # and it does what it says


@pytest.mark.parametrize("row", ROW_PARAMS)
def test_hand_edited_value_falls_back(ctx, row) -> None:
    expected = row.expected_for_bad()
    for bad in row.bad:
        if row.new_window:
            ctx.stores.close_windows()  # its close must not write over the edit
        row.write_bad(ctx, bad)
        assert row.stored(ctx) == expected, bad
        win = _start(ctx, closed=True) if row.new_window else ctx.win  # starts without an error
        assert row.shown(ctx.dialog(win)) == expected, bad
        row.effect(ctx, win, expected)


# ---------------------------------------------------------------------------
# Cross effects
# ---------------------------------------------------------------------------


def test_cross_paranoid_forgets_the_sudo_password_and_keeps_the_choice(ctx) -> None:
    SP.remember("pw")
    dialog = ctx.dialog()
    security = dialog.page("security")
    security.paranoid_check.setChecked(True)
    assert not security.remember_check.isEnabled() and not security.remember_check.isChecked()
    assert dialog.apply()
    assert SP.remembered() is None and not SP.remember_enabled()
    SP.remember("again")
    assert SP.remembered() is None  # paranoid never remembers
    assert SP.remember_setting() is True  # the stored choice is untouched
    security.paranoid_check.setChecked(False)
    assert security.remember_check.isEnabled() and security.remember_check.isChecked()
    assert dialog.apply()
    effect_remember(ctx, ctx.win, True)


def test_cross_paranoid_unloads_extensions_and_greys_their_switches(ctx) -> None:
    dialog = ctx.dialog()
    set_extension(ctx, dialog, True)
    assert dialog.apply()
    effect_extension(ctx, ctx.win, True)
    dialog.page("security").paranoid_check.setChecked(True)
    assert dialog.apply()
    effect_extension(ctx, ctx.win, False)
    assert EXT_ID in EX.enabled_ids()  # still switched on, only not loaded
    page = ctx.dialog().page("extensions")
    item = page.table.item(page.row_of(EXT_ID), 0)
    assert not item.flags() & Qt.ItemFlag.ItemIsEnabled
    assert not page._blocked.isHidden()
    again = ctx.dialog()
    again.page("security").paranoid_check.setChecked(False)
    assert again.apply()
    effect_extension(ctx, ctx.win, True)


def test_cross_paranoid_refuses_a_private_default_proxy_even_when_allowed(ctx) -> None:
    from core.proxy import create_proxy_socket

    dialog = ctx.dialog()
    set_proxy(ctx, dialog, "socks5")
    assert dialog.apply()
    ctx.monkeypatch.setenv("AXROSS_ALLOW_PRIVATE_PROXY", "1")
    cfg = PS.resolve("default", None, "db.internal", 5432).config
    create_proxy_socket(cfg, "db.internal", 5432, timeout=5).close()  # normal: allowed
    dialog.page("security").paranoid_check.setChecked(True)
    assert dialog.apply()
    with pytest.raises((ConnectionError, OSError, socket.error)):
        create_proxy_socket(cfg, "db.internal", 5432, timeout=5)


def test_cross_paranoid_blocks_find_on_network_hosts(ctx) -> None:
    dialog = ctx.dialog()
    dialog.page("security").paranoid_check.setChecked(True)
    assert dialog.apply()
    config = RW.SweepConfig(targets="10.0.0.1", username="u", password="p")
    with pytest.raises(PermissionError):
        RW.sweep(config, on_hit=lambda hit: None, on_status=lambda *a: None)


def test_cross_theme_and_compact_in_one_ok(ctx) -> None:
    dialog = ctx.dialog()
    page = dialog.page("appearance")
    _combo_data(page.theme_combo, "amber")
    page.compact_check.setChecked(True)
    assert dialog.apply()
    assert APP.styleSheet() == themes.stylesheet_for("amber", themes.system_scheme(), compact=True)
    stored = json.loads(ctx.stores.session.read_text())["window"]
    assert stored["ui_theme"] == "amber" and stored["compact"] is True


def test_cross_show_and_highlight_hidden_are_independent(ctx) -> None:
    dialog = ctx.dialog()
    dialog.page("appearance").highlight_check.setChecked(False)
    assert dialog.apply()
    assert ".dotfile" in _listing(ctx, ctx.win)  # highlight changes the look only
    dialog.page("files").show_hidden_check.setChecked(False)
    assert dialog.apply()
    assert ".dotfile" not in _listing(ctx, ctx.win)
    effect_highlight(ctx, ctx.win, False)


def test_cross_the_ctrl_h_switch_and_the_settings_page_agree(ctx) -> None:
    ctx.win._hidden_action.trigger()  # Ctrl+H: off, stored at once
    assert _window_pref(ctx, "show_hidden") is False
    assert not ctx.dialog().page("files").show_hidden_check.isChecked()


def test_cross_view_theme_menu_and_zoom_store_like_the_page(ctx) -> None:
    ctx.win._theme_actions["hacker"].trigger()
    assert _window_pref(ctx, "theme") == "hacker"
    assert ctx.win._theme_actions["hacker"].isChecked()
    assert ctx.dialog().page("appearance").theme_combo.currentData() == "hacker"
    before = APP.font().pointSize()
    ctx.win._change_font_size(2)
    assert _window_pref(ctx, "font_size") == before + 2
    assert ctx.dialog().page("appearance").font_size() == before + 2


# ---------------------------------------------------------------------------
# Old settings files load unchanged
# ---------------------------------------------------------------------------


def test_compat_old_files_load_unchanged_and_unrelated_keys_survive_a_save(ctx) -> None:
    window = {
        "width": 900, "height": 600, "ui_theme": "hacker", "compact": True,
        "monochrome_icons": True, "show_hidden": False, "highlight_hidden": False,
        "hidden_color": "#abcdef", "restore_layout_on_start": False, "language": "sv",
        "viewers": {"image": {"x": 1, "y": 2, "width": 300, "height": 200, "maximized": False}},
    }
    session = {"window": window, "splitter": {"type": "splitter", "children": []}}
    settings = {
        "max_open_mb": 64, "pane_activation": 2, "metadata_write_mode": "copy",
        "metadata_confirm_remove": True, "remember_sudo_password": False,
        "remote_sweep_parallel": 8, "some_future_key": [1, 2, 3],
    }
    ctx.stores.close_windows()
    ctx.stores.session.write_text(json.dumps(session))
    ctx.stores.settings.write_text(json.dumps(settings))
    win = _start(ctx, closed=True)
    dialog = ctx.dialog(win)
    shown = {
        "theme": dialog.page("appearance").theme_combo.currentData(),
        "compact": dialog.page("appearance").compact_check.isChecked(),
        "mono": dialog.page("appearance").monochrome_check.isChecked(),
        "highlight": dialog.page("appearance").highlight_check.isChecked(),
        "colour": dialog.page("appearance").colour(),
        "show_hidden": dialog.page("files").show_hidden_check.isChecked(),
        "restore": dialog.page("general").restore_check.isChecked(),
        "language": dialog.page("general").language_combo.currentData(),
        "open_limit": dialog.page("files").open_limit_spin.value(),
        "activation": dialog.page("general").activation_combo.currentData(),
        "copy": dialog.page("metadata").copy_radio.isChecked(),
        "confirm": dialog.page("metadata").confirm_box.isChecked(),
        "remember": dialog.page("security").remember_check.isChecked(),
        "parallel": dialog.page("search").parallel_spin.value(),
    }
    assert shown == {
        "theme": "hacker", "compact": True, "mono": True, "highlight": False,
        "colour": "#abcdef", "show_hidden": False, "restore": False, "language": "sv",
        "open_limit": 64, "activation": 2, "copy": True, "confirm": True,
        "remember": False, "parallel": 8,
    }
    assert dialog.dirty_page_ids() == []
    dialog.page("search").parallel_spin.setValue(9)
    assert dialog.apply()
    assert json.loads(ctx.stores.settings.read_text()) == {**settings, "remote_sweep_parallel": 9}
    assert json.loads(ctx.stores.session.read_text()) == session  # nothing else was written
