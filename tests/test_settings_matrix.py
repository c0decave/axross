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
x the update check at start; theme x compact, show x highlight hidden,
monochrome x icon colours, toolbar tint x category colours, parallel
transfers x the jobs that run at once, update check x automatic download)
and the compatibility of old settings files follow the table.

The table goes on in tests/test_settings_matrix_network_llm.py (Network &
Proxy, the fields of an LLM profile) and tests/test_settings_matrix_agent*.py
(every tab of the Agent page). Operator: *„alle bereiche der tools plus neue
matrix tests auch bei den einstellungen. wir brauchen eine saubere abdeckung
aller hauptfeatures.“* **Completeness:** every input widget of every page
(check box, combo box, spin box, slider, line and text edit, key sequence,
list and table) is driven by a row (Row.widgets) or named in NOT_STORED with
the reason; a setting added without a row fails
test_every_stored_input_widget_has_a_row_or_a_reason.
"""

from __future__ import annotations

import dataclasses
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
from PyQt6.QtWidgets import (  # noqa: E402
    QAbstractItemView,
    QAbstractSpinBox,
    QCheckBox,
    QComboBox,
    QDial,
    QKeySequenceEdit,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QRadioButton,
    QSlider,
    QSpinBox,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from core import analysis_settings as ANS  # noqa: E402
from core import audio_settings as AS  # noqa: E402
from core import extensions as EX  # noqa: E402
from core import i18n  # noqa: E402
from core import metadata_tools as MT  # noqa: E402
from core import open_limits as OL  # noqa: E402
from core import pane_activation as PA  # noqa: E402
from core import proxy_settings as PS  # noqa: E402
from core import ramfs_settings as RS  # noqa: E402
from core import remote_sweep as RW  # noqa: E402
from core import self_update as SU  # noqa: E402
from core import security_mode as SM  # noqa: E402
from core import sudo_password as SP  # noqa: E402
from core import transfer_pool as TP  # noqa: E402
from core import voice_settings as VS  # noqa: E402
from tests.proxy_testkit import EchoServer, FakeSocks5Server, allow_loopback_proxy  # noqa: E402
from tests.settings_testkit import app, isolate  # noqa: E402
from ui import themes, window_prefs  # noqa: E402
from ui import toolbar_categories as TC  # noqa: E402

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
    for close in reversed(c.extras.get("closers", [])):  # servers a row started
        close()


def keep_open(ctx, server):
    """*server* (anything with close()) is closed when the test ends."""
    ctx.extras.setdefault("closers", []).append(server.close)
    return server


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


def _toolbar_style(ctx):
    data = _read_json(ctx.stores.session) or {}
    return TC.parse_style(data.get("window"))


def _tools_bar(win):
    from PyQt6.QtWidgets import QToolBar

    return next(tb for tb in win.findChildren(QToolBar) if tb.windowTitle() == "Tools")


def effect_toolbar_grouping(ctx, win, value) -> None:
    assert win.toolbar_style().grouping is value
    ids = [a.property("axToolId") for a in _tools_bar(win).actions() if not a.isSeparator()]
    # Grouped, the Tools bar starts with the Media group; plain, with the Agent.
    assert ids[0] == ("thumbnails" if value else "agent")


def effect_toolbar_tint(ctx, win, value) -> None:
    assert win.toolbar_style().tint is value
    assert bool(_tools_bar(win).styleSheet()) is value


def effect_toolbar_colours(ctx, win, value) -> None:
    assert win.toolbar_style().colour_map() == {**TC.default_colours(), **value}
    css = _tools_bar(win).styleSheet()
    for category, colours in win.toolbar_button_colours().items():
        assert f'[axCategory="{category}"] {{\n    background-color: {colours.normal};' in css


def set_toolbar_colours(ctx, dialog, value) -> None:
    page = dialog.page("toolbar")
    page.reset_button.click()
    for category, colour in value.items():
        with mock.patch("ui.settings_dialog.QColorDialog.getColor",
                        return_value=QColor(colour)):
            page.colour_buttons[category].click()


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


def effect_parallel_transfers(ctx, win, value) -> None:
    manager = win._transfer_manager
    assert manager.max_parallel == value  # jobs that start from now on
    assert len(manager._pool) >= value


def effect_tmpfs(ctx, win, value) -> None:
    from core import tmpfs_detect

    ram = ctx.tmp_path / "ram"
    ram.mkdir(exist_ok=True)
    ctx.monkeypatch.delenv("TMPDIR", raising=False)
    ctx.monkeypatch.setattr(tmpfs_detect, "preferred_tmpfs_dir", lambda: str(ram))
    ctx.monkeypatch.setattr(tempfile, "tempdir", tempfile.tempdir)
    assert tmpfs_detect.apply_tempdir_preference() == (str(ram) if value else None)


def refused_unknown_proxy_type(ctx, win, bad) -> None:
    """A stored proxy_type axross does not know: no connection at all (fail
    closed, core.proxy_settings._known_type); an absent one connects directly."""
    if bad is None:
        assert PS.resolve("default", None, "db.internal", 5432).config is None
        return
    with pytest.raises(PS.ProxyResolutionError):
        PS.resolve("default", None, "db.internal", 5432)


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
        elif field in ("voice_de", "voice_en"):
            assert dock.voice.settings.voice(field[-2:]) == value
        elif field == "tuning":
            for voice_id in (v for ids in VS.VOICES.values() for v in ids):
                assert dock.voice.settings.tuning_for(voice_id) == value.get(
                    voice_id, VS.default_tuning())
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


def _set_voice_combo(lang):
    return lambda ctx, d, v: _combo_data(d.page("voice").voice_combos[lang], v)


def _voice_combo_shown(lang):
    return lambda d: d.page("voice").voice_combos[lang].currentData()


def _set_tuning(ctx, dialog, value) -> None:
    """Every voice's sliders to *value* (voice id -> tuning; the defaults
    for a voice it leaves out), the chosen voices unchanged."""
    page = dialog.page("voice")
    for lang, combo in page.voice_combos.items():
        chosen = combo.currentData()
        for voice_id in VS.VOICES[lang]:
            _combo_data(combo, voice_id)
            tuning = value.get(voice_id, VS.default_tuning())
            for name, slider in page.sliders[lang].items():
                slider.setValue(round(tuning[name] / VS.TUNING[name].step))
        _combo_data(combo, chosen)


def _tuning_shown(dialog):
    return dialog.page("voice").values()["tuning"]


def _voice_row(field, values, set_ui, shown, bad, widgets):
    return Row(f"voice_{field}", "voice", f"agent/voice.json {field}", values,
               VS.VoiceSettings().get(field), set_ui, shown,
               lambda c: VS.VoiceSettings.load().get(field),
               lambda c, v: _edit_voice(c, field, v), bad, _voice_effect(field),
               widgets=tuple(f"voice.{w}" for w in widgets))


def _edit_audio(ctx, key, value) -> None:
    path = AS.settings_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _read_json(path) or {}
    data[key] = value
    path.write_text(json.dumps(data))


def _audio_effect(field):
    """What the players read (core.audio_route) and, for the backend, what
    main() hands Qt as QT_AUDIO_BACKEND at the next start."""

    def effect(ctx, win, value) -> None:
        from core import audio_route as AR
        from core import multimedia_env as ME

        AR.forget()
        assert AR.settings().get(field) == value
        if field == "backend":
            ctx.monkeypatch.setattr(ME, "_SET_BY_AXROSS", set())
            env: dict = {}
            AS.apply_saved_backend(env)
            assert env.get(ME.AUDIO_BACKEND_VAR) == (None if value == "auto" else value)
        elif field == "output_volume":
            assert AR.output_gain() == value / 100
        elif field == "input_volume":
            assert AR.input_gain() == value / 100
        else:  # the device the players open; "" is the system's default (None)
            kind = field.split("_")[0]
            device = getattr(AR, f"{kind}_device")()
            assert (AR.device_id(device) if device is not None else "") == value

    return effect


def _audio_row(field, values, set_ui, shown, bad, widget, *, setup=None):
    return Row(f"audio_{field}", "audio", f"audio.json {field}", values,
               AS.AudioSettings().get(field), set_ui, shown,
               lambda c: AS.AudioSettings.load().get(field),
               lambda c, v: _edit_audio(c, field, v), bad, _audio_effect(field),
               widgets=(f"audio.{widget}",), setup=setup)


def _edit_analysis(ctx, key, value) -> None:
    path = ANS.settings_file()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _read_json(path) or {}
    data[key] = value
    path.write_text(json.dumps(data))


def _analysis_effect(field):
    """What the open Analysis dock runs with (the dialog told it after the
    save) and what a fresh load of analysis.json gives."""

    def effect(ctx, win, value) -> None:
        dock = win._analysis_dock
        assert dock._analysis.get(field) == value
        assert ANS.AnalysisSettings.load().get(field) == value
        if field in dock._options():
            assert dock._options()[field] == value

    return effect


def _analysis_value(field):
    return lambda d: d.page("analysis").values()[field]


def _set_analysis_mb(ctx, dialog, value) -> None:
    dialog.page("analysis").max_bytes_spin.setValue(value // 1_000_000)


def _set_analysis_seconds(ctx, dialog, value) -> None:
    dialog.page("analysis").time_spin.setValue(round(value))


def _set_analysis_profile(ctx, dialog, value) -> None:
    dialog.page("analysis")._select_profile(value)


def _set_analysis_categories(ctx, dialog, value) -> None:
    dialog.page("analysis").categories_edit.setPlainText("\n".join(value))


def _analysis_row(field, values, set_ui, bad, widget):
    return Row(f"analysis_{field}", "analysis", f"analysis.json {field}", values,
               ANS.AnalysisSettings().get(field), set_ui, _analysis_value(field),
               lambda c: ANS.AnalysisSettings.load().get(field),
               lambda c, v: _edit_analysis(c, field, v), bad, _analysis_effect(field),
               widgets=(f"analysis.{widget}",))


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


def _run_update_check(win, *, auto_install=None):
    """A fresh start's check (a new controller) against the local fake
    GitHub; returns (requests made, the controller)."""
    import time as _time

    from PyQt6.QtWidgets import QApplication

    from tests.fake_github import (
        FakeGitHub,
        FakeHttpsHandler,
        FakeRelease,
        newer_than,
        trusted_test_key,
    )
    from ui.update_ui import UpdateController

    from axross._version import __version__

    data = b"new axross"
    server = FakeGitHub(FakeRelease(newer_than(__version__), {"axross-full": data}))
    try:
        with trusted_test_key():  # the fake release is signed with the test key
            controller = UpdateController(win)
            controller.opener_factory = lambda: SU.build_opener(
                handlers=[FakeHttpsHandler(server.port)])
            controller.install_info = auto_install or SU.detect_install(frozen=False)
            controller.start_check()
            end = _time.time() + 10
            while _time.time() < end and (controller.state in ("checking", "downloading")
                                           or controller._check_job.running
                                           or controller._download_job.running):
                QApplication.instance().processEvents()
                _time.sleep(0.01)
            return server.api_requests(), controller
    finally:
        server.close()


def effect_update_check(ctx, win, value) -> None:
    requests, _controller = _run_update_check(win)
    assert requests == (1 if value else 0)


def effect_update_auto(ctx, win, value) -> None:
    folder = Path(tempfile.mkdtemp(prefix="axross-matrix-update-"))
    exe = folder / "axross-full"
    exe.write_bytes(b"old axross")
    exe.chmod(0o755)
    inst = SU.detect_install(frozen=True, executable=str(exe), bundle_dir=None,
                             platform="linux", machine="x86_64")
    _requests, controller = _run_update_check(win, auto_install=inst)
    assert (exe.read_bytes() == b"new axross") is value
    assert controller.state == ("installed" if value else "available")
    import shutil

    shutil.rmtree(folder, ignore_errors=True)


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


def _seed_hacker_theme(ctx) -> None:
    """Hacker has an icon tint of its own: "theme" and "coloured" differ."""
    _edit_window(ctx, window_prefs.THEME_KEY, "hacker")


def set_icon_colours(ctx, dialog, value) -> None:
    page = dialog.page("appearance")
    mode, colour = value
    _combo_data(page.icon_colours_combo, mode)
    if mode == "one":
        assert page.icon_colour_button.isEnabled()
        with mock.patch("ui.settings_dialog.QColorDialog.getColor", return_value=QColor(colour)):
            page.icon_colour_button.click()


def _edit_icon_colours(ctx, bad) -> None:
    _edit_window(ctx, window_prefs.ICON_COLOURS_KEY, bad[0])
    _edit_window(ctx, window_prefs.ICON_COLOUR_KEY, bad[1])


def effect_icon_colours(ctx, win, value) -> None:
    """The colour every icon is drawn in now (ui.icon_provider)."""
    from ui import icon_provider

    mode, colour = value
    hacker = themes.icon_tint_for(themes.resolve("hacker", themes.system_scheme()))
    assert hacker  # else "theme" and "coloured" could not be told apart here
    expected = {"theme": hacker, "coloured": None, "one": colour}[mode]
    assert win._current_theme == "hacker"
    assert icon_provider.get_tint() == expected
    folder_own = icon_provider._ICON_COLORS["folder"]
    assert icon_provider.stroke_colour("folder") == (expected or folder_own)


#: The devices the audio probe of the matrix finds (core.multimedia_probe).
AUDIO_DEVICES = {
    "output": (("usb.headset.sink", "USB Headset"), ("hdmi.sink", "HDMI")),
    "input": (("usb.headset.mic", "USB Headset Microphone"),),
}


class _FakeAudioDevice:
    """A QAudioDevice as core.audio_route reads it: its id."""

    def __init__(self, device_id: str) -> None:
        self._id = device_id

    def id(self) -> bytes:
        return self._id.encode()


def _seed_audio_devices(ctx) -> None:
    """The audio probe answered ok with AUDIO_DEVICES; Qt lists the same."""
    from core import audio_route as AR
    from core import multimedia_probe as MPROBE

    infos = {kind: tuple(MPROBE.AudioDeviceInfo(i, d) for i, d in devices)
             for kind, devices in AUDIO_DEVICES.items()}
    ctx.monkeypatch.setattr(MPROBE, "_result", MPROBE.ProbeResult(
        ok=True, outputs=len(infos["output"]), inputs=len(infos["input"]),
        output_devices=infos["output"], input_devices=infos["input"]))
    for kind, devices in AUDIO_DEVICES.items():
        listed = [_FakeAudioDevice(i) for i, _d in devices]
        ctx.monkeypatch.setattr(AR, f"_{kind}s", lambda listed=listed: listed)


def _set_audio_device(kind):
    return lambda ctx, d, v: _combo_data(getattr(d.page("audio"), f"{kind}_combo"), v)


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
    #: The input widgets of the page this row drives, as "page.attribute"
    #: (test_every_stored_input_widget_has_a_row_or_a_reason holds them).
    widgets: tuple = ()
    #: (ctx) -> None: what the stores hold before the row starts (an MCP
    #: server whose timeout the row sets, a theme the effect needs); axross
    #: then starts again on them.
    setup: object = None
    #: A hand-edited store is read at the next start (the Agent dock keeps
    #: what it read): the hand-edit step starts axross again. A save on the
    #: page still takes effect at once (step 1 checks that).
    edit_needs_start: bool = False
    #: (ctx, window, bad) -> None: the effect of a hand-edited value when it is
    #: not "the default again" - a proxy type axross does not know fails
    #: closed (no connection) instead of connecting directly.
    bad_effect: object = None

    def expected_for_bad(self):
        return self.default if self.bad_reads_as == "default" else self.bad_reads_as


@dataclass(frozen=True)
class Secret:
    """A password-like field: typed, it goes to the keyring and is never
    shown again; left empty, the stored one stays (check_secret)."""

    id: str
    page: str
    widgets: tuple
    setup: object  # (ctx) -> None: what the secret belongs to
    type_in: object  # (ctx, dialog, value): typed on the page
    kept: object  # (ctx) -> the value in the keyring ("" for none)
    field: object  # (dialog) -> the text the field shows
    effect: object  # (ctx, window, value): the credential is used


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
    Row("toolbar_grouping", "toolbar", "session.json window.toolbar_grouping", (False,), True,
        _set_check("toolbar", "grouping_check"), _page_attr("toolbar", "grouping_check"),
        lambda c: _toolbar_style(c).grouping,
        lambda c, v: _edit_window(c, TC.GROUPING_KEY, v), ("no", 0, None),
        effect_toolbar_grouping, new_window=True),
    Row("toolbar_category_tint", "toolbar", "session.json window.toolbar_category_tint",
        (False,), True,
        _set_check("toolbar", "tint_check"), _page_attr("toolbar", "tint_check"),
        lambda c: _toolbar_style(c).tint,
        lambda c, v: _edit_window(c, TC.TINT_KEY, v), ("off", 0),
        effect_toolbar_tint, new_window=True),
    Row("toolbar_category_colors", "toolbar", "session.json window.toolbar_category_colors",
        ({"media": "#ff0000"}, {"llm": "#00ff00", "files": "#123456"}), {},
        set_toolbar_colours, lambda d: d.page("toolbar").colour_overrides(),
        lambda c: _toolbar_style(c).overrides(),
        lambda c, v: _edit_window(c, TC.COLORS_KEY, v),
        ("red", 5, {"media": "#12"}, {"nope": "#ffffff"}, ["#ffffff"]),
        effect_toolbar_colours, new_window=True),
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
    Row("parallel_transfers", "files", "settings.json parallel_transfers", (3, 8), 1,
        _set_spin("files", "parallel_transfers_spin"),
        _page_attr("files", "parallel_transfers_spin", "value"),
        lambda c: TP.parallel_transfers(),
        lambda c, v: _edit_settings(c, TP.PARALLEL_SETTING, v), (0, 9, True, "4"),
        effect_parallel_transfers),
    Row("default_proxy", "network", "proxy.json proxy_type/host/port", ("socks5", "http"), "none",
        set_proxy, shown_proxy, stored_proxy,
        lambda c, v: c.stores.proxy.write_text(json.dumps({"proxy_type": v, "port": "x"})),
        ("bogus", 7, "socks9"),
        effect_proxy, bad_effect=refused_unknown_proxy_type),
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
               _page_attr("voice", "output_check"), ("yes", 1, None), ("output_check",)),
    _voice_row("language", ("de", "en"), _set_combo("voice", "language_combo"),
               _combo_shown("voice", "language_combo"), ("fr", 5, None), ("language_combo",)),
    _voice_row("voice_de", ("piper-de-kerstin",), _set_voice_combo("de"),
               _voice_combo_shown("de"), ("piper-en-ryan", "robot", 5), ("voice_combos[de]",)),
    _voice_row("voice_en", ("piper-en-lessac",), _set_voice_combo("en"),
               _voice_combo_shown("en"), ("piper-de-thorsten", None), ("voice_combos[en]",)),
    _voice_row("tuning", ({"piper-de-thorsten": {**VS.default_tuning(), "speed": 1.5,
                                                 "pitch": -2.0},
                           "piper-en-lessac": {**VS.default_tuning(), "volume": 0.5,
                                               "pause": 1.0}},),
               _set_tuning, _tuning_shown,
               ("x", [1], {"piper-en-ryan": {"speed": 9}}, {"nope": {"speed": 1.5}}),
               tuple(f"sliders[{lang}][{name}]" for lang in VS.VOICES for name in VS.TUNING)),
    _voice_row("input_mode", ("toggle", "conversation"), _set_combo("voice", "mode_combo"),
               _combo_shown("voice", "mode_combo"), ("always", 2), ("mode_combo",)),
    _voice_row("hotkey", ("Ctrl+Shift+V", "F7"), _set_hotkey, _shown_hotkey, ("A", "", 9),
               ("hotkey_edit",)),
    _voice_row("after_recognition", ("send",), _set_combo("voice", "after_combo"),
               _combo_shown("voice", "after_combo"), ("print", False), ("after_combo",)),
    _voice_row("silence_seconds", (2.5, 0.5), _set_spin("voice", "silence_spin"),
               _page_attr("voice", "silence_spin", "value"), (0.1, 99, "1", True),
               ("silence_spin",)),
    _audio_row("backend", ("pulseaudio", "pipewire"), _set_combo("audio", "backend_combo"),
               _combo_shown("audio", "backend_combo"), ("alsa", 1, None), "backend_combo"),
    _audio_row("output_volume", (40, 0), _set_spin("audio", "output_slider"),
               _page_attr("audio", "output_slider", "value"), (101, -1, "50", True, 50.5),
               "output_slider"),
    _audio_row("input_volume", (75,), _set_spin("audio", "input_slider"),
               _page_attr("audio", "input_slider", "value"), (200, "loud", False),
               "input_slider"),
    _audio_row("output_device", ("usb.headset.sink", "hdmi.sink"), _set_audio_device("output"),
               _combo_shown("audio", "output_combo"), (5, None, ["usb.headset.sink"]),
               "output_combo", setup=_seed_audio_devices),
    _audio_row("input_device", ("usb.headset.mic",), _set_audio_device("input"),
               _combo_shown("audio", "input_combo"), (7, False), "input_combo",
               setup=_seed_audio_devices),
    _analysis_row("auto_analyse", (False,), _set_check("analysis", "auto_check"), ("no", 0),
                  "auto_check"),
    _analysis_row("llm_profile", ("sift-model",), _set_analysis_profile, (5, None),
                  "profile_combo"),
    _analysis_row("max_bytes", (1_000_000, 2_000_000), _set_analysis_mb,
                  (0, -5, "big", True), "max_bytes_spin"),
    _analysis_row("time_budget", (5.0, 3600.0), _set_analysis_seconds, (0, 3601, "60", True),
                  "time_spin"),
    _analysis_row("vision", (False,), _set_check("analysis", "vision_check"), ("no", 1),
                  "vision_check"),
    _analysis_row("context_tokens", (8192, 256), _set_spin("analysis", "context_spin"),
                  (100, -1, "8k"), "context_spin"),
    _analysis_row("tags", (5, 32), _set_spin("analysis", "tags_spin"), (33, -1, True),
                  "tags_spin"),
    _analysis_row("categories", (["Invoices", "Contracts"],), _set_analysis_categories,
                  ("Invoices", ["a", "A"], [3]), "categories_edit"),
    _analysis_row("cache", (False,), _set_check("analysis", "cache_check"), ("off", 0),
                  "cache_check"),
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
    Row("update_check_at_start", "updates", "settings.json update_check_at_start", (False,),
        True,
        _set_check("updates", "check_box"), _page_attr("updates", "check_box"),
        lambda c: SU.check_at_start(),
        lambda c, v: _edit_settings(c, SU.SETTING_CHECK, v), ("no", 0, None),
        effect_update_check),
    Row("update_auto_download", "updates", "settings.json update_auto_download", (True,),
        False,
        _set_check("updates", "auto_box"), _page_attr("updates", "auto_box"),
        lambda c: SU.auto_download(),
        lambda c, v: _edit_settings(c, SU.SETTING_AUTO, v), ("yes", 1),
        effect_update_auto),
    Row("extension_enabled", "extensions", "extensions.json enabled", (True,), False,
        set_extension, shown_extension, lambda c: EXT_ID in EX.enabled_ids(),
        lambda c, v: c.stores.extensions.write_text(v), ("{", '{"enabled": "user:matrixext"}'),
        effect_extension, new_window=True),
    Row("icon_colours", "appearance", "session.json window.icon_colours + icon_colour",
        (("coloured", None), ("one", "#3366ff")), ("theme", None),
        set_icon_colours, lambda d: d.page("appearance").icon_colours(),
        lambda c: (_window_pref(c, "icon_colours"), _window_pref(c, "icon_colour")),
        _edit_icon_colours, (("sparkly", None), ("one", None), ("one", "red"), (5, "#ffffff")),
        effect_icon_colours, new_window=True,
        widgets=("appearance.icon_colours_combo",), setup=_seed_hacker_theme),
]

#: The input widgets each plain row of ROWS drives (the factories name their own).
_ROW_WIDGETS = {
    "language": ("general.language_combo",),
    "restore_layout_on_start": ("general.restore_check",),
    "pane_activation": ("general.activation_combo",),
    "theme": ("appearance.theme_combo",),
    "compact": ("appearance.compact_check",),
    "monochrome_icons": ("appearance.monochrome_check",),
    "font_size": ("appearance.font_spin",),
    "highlight_hidden": ("appearance.highlight_check",),
    "hidden_color": ("appearance.theme_colour_radio", "appearance.own_colour_radio"),
    "toolbar_grouping": ("toolbar.grouping_check",),
    "toolbar_category_tint": ("toolbar.tint_check",),
    "toolbar_category_colors": (),  # colour buttons: push buttons, not input widgets
    "show_hidden": ("files.show_hidden_check",),
    "max_open_mb": ("files.open_limit_spin",),
    "ramfs_enabled": ("files.ramfs_check",),
    "ramfs_max_bytes": ("files.ramfs_max_spin",),
    "ramfs_system_reserve_bytes": ("files.ramfs_reserve_spin",),
    "tmpfs_enabled": ("files.tmpfs_check",),
    "parallel_transfers": ("files.parallel_transfers_spin",),
    "default_proxy": ("network._type", "network._host", "network._port"),
    "llm_profile": ("llm.name_edit",),
    "agent_max_steps": ("agent.steps_spin",),
    "agent_mode": ("agent.mode_combo",),
    "metadata_write_mode": ("metadata.in_place_radio", "metadata.copy_radio"),
    "metadata_confirm_remove": ("metadata.confirm_box",),
    "remote_sweep_parallel": ("search.parallel_spin",),
    "security_mode": ("security.paranoid_check",),
    "remember_sudo_password": ("security.remember_check",),
    "update_check_at_start": ("updates.check_box",),
    "update_auto_download": ("updates.auto_box",),
    "extension_enabled": ("extensions.table",),
}
ROWS = [row if row.widgets or row.id not in _ROW_WIDGETS
        else dataclasses.replace(row, widgets=_ROW_WIDGETS[row.id]) for row in ROWS]


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


def _set_up(ctx, row) -> None:
    """The stores the row starts from (Row.setup), then a start on them;
    the window is closed first so that its close writes nothing over them."""
    if row.setup is not None:
        ctx.stores.close_windows()
        row.setup(ctx)
        _start(ctx, closed=True)


def check_set_store_reload_effect(ctx, row) -> None:
    """Cancel writes nothing; each value: set on the page -> OK -> stored ->
    a fresh load shows it -> its effect; then the default again."""
    _set_up(ctx, row)
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


def check_hand_edited_value_falls_back(ctx, row) -> None:
    _set_up(ctx, row)
    expected = row.expected_for_bad()
    restart = row.new_window or row.edit_needs_start
    for bad in row.bad:
        if restart:
            ctx.stores.close_windows()  # its close must not write over the edit
        row.write_bad(ctx, bad)
        assert row.stored(ctx) == expected, bad
        win = _start(ctx, closed=True) if restart else ctx.win  # starts without an error
        assert row.shown(ctx.dialog(win)) == expected, bad
        if row.bad_effect is not None:
            row.bad_effect(ctx, win, bad)
        else:
            row.effect(ctx, win, expected)


def test_every_category_has_rows_and_every_row_its_page(ctx) -> None:
    dialog = ctx.dialog()
    assert {row.page for row in all_rows()} == set(dialog.page_ids())


@pytest.mark.parametrize("row", ROW_PARAMS)
def test_set_store_reload_effect(ctx, row) -> None:
    check_set_store_reload_effect(ctx, row)


@pytest.mark.parametrize("row", ROW_PARAMS)
def test_hand_edited_value_falls_back(ctx, row) -> None:
    check_hand_edited_value_falls_back(ctx, row)


# ---------------------------------------------------------------------------
# Completeness: every input widget that stores a value has a row
# ---------------------------------------------------------------------------

#: The modules whose tables continue ROWS (one file each, so that they run
#: side by side). Their secrets tables (SECRETS) name the password fields.
ROW_MODULES = ("tests.test_settings_matrix_network_llm", "tests.test_settings_matrix_agent")

#: Input widgets that store nothing themselves, each with the reason.
NOT_STORED = {
    "network._test_host": "the target host of Test proxy; a probe, not stored",
    "network._test_port": "the target port of Test proxy; a probe, not stored",
    "llm.profile_list": "chooses the profile the form edits; the profiles are the rows",
    "agent.agent_profile_list": "chooses the agent profile the form edits",
    "agent.agent_profile_preview": "read-only: what a tab gets from the profile",
    "agent.agent_profile_missing": "read-only: what the profile misses (Install from Catalog)",
    "agent.prompt_list": "chooses the prompt profile the form edits",
    "agent.sandbox_list": "chooses the sandbox profile the form edits",
    "agent.host_edit": "the host typed for Add host; hosts_list holds what is stored",
    "agent.server_list": "chooses the MCP server the form edits",
    "agent.detected_list": "an action: a tick adds the detected server to MCP Servers, "
                           "whose fields are the rows",
    "agent.detected_details": "read-only: what was detected",
    "agent.session_list": "chooses the tab the Sessions form edits",
    "agent.session_editor.host_edit": "the host typed for Add host; hosts_list holds it",
    "agent.agent_profile_access.host_edit": "the host typed for Add host; hosts_list holds it",
    "agent.agent_profile_access.folders_table": "hidden: an agent profile has no folders "
                                                "(AccessEditor(folders=False))",
}

#: What an input widget is: a value typed, ticked, chosen or slid. A widget
#: inside another (a spin box's line edit, a combo in a table cell) belongs
#: to that one; scroll bars move a view.
INPUT_CLASSES = (QCheckBox, QRadioButton, QComboBox, QAbstractSpinBox, QSlider, QDial,
                 QLineEdit, QKeySequenceEdit, QPlainTextEdit, QTextEdit, QAbstractItemView)


def _names(obj, prefix: str, out: dict, depth: int = 0) -> None:
    """id(widget) -> its name on *obj*: "attr", "attr[key]", "attr[k1][k2]",
    and "owner.attr" inside a non-input widget held as an attribute."""
    if depth > 3:
        return
    for attr, value in list(vars(obj).items()):
        key = prefix + attr
        if isinstance(value, QWidget):
            out.setdefault(id(value), key)
            if not isinstance(value, INPUT_CLASSES):
                _names(value, key + ".", out, depth + 1)
        elif isinstance(value, dict):
            for k, v in value.items():
                if isinstance(v, QWidget):
                    out.setdefault(id(v), f"{key}[{k}]")
                elif isinstance(v, dict):
                    for k2, v2 in v.items():
                        if isinstance(v2, QWidget):
                            out.setdefault(id(v2), f"{key}[{k}][{k2}]")


def input_widgets(page) -> dict:
    """name -> widget for every input widget of *page*; an unnamed one is
    "?<Class>#<n>" (it fails the completeness test: name it)."""
    names: dict = {}
    _names(page, "", names)
    out, unnamed = {}, 0
    for widget in page.findChildren(QWidget):
        if not isinstance(widget, INPUT_CLASSES):
            continue
        parent = widget.parentWidget()
        while parent is not None and parent is not page and not isinstance(parent, INPUT_CLASSES):
            parent = parent.parentWidget()
        if parent is not None and parent is not page:
            continue  # part of another input widget
        name = names.get(id(widget)) or widget.objectName()
        if not name:
            name = f"?{type(widget).__name__}#{unnamed}"
            unnamed += 1
        out[name] = widget
    return out


def all_rows() -> list:
    """ROWS and the tables of ROW_MODULES."""
    import importlib

    rows = list(ROWS)
    for name in ROW_MODULES:
        rows += importlib.import_module(name).ROWS
    return rows


def mapped_widgets() -> dict:
    """"page.attr" -> the row (or secret) ids that drive it."""
    import importlib

    out: dict = {}
    for row in all_rows():
        for key in row.widgets:
            out.setdefault(key, []).append(row.id)
    for name in ROW_MODULES:
        for secret in importlib.import_module(name).SECRETS:
            for key in secret.widgets:
                out.setdefault(key, []).append(secret.id)
    return out


def unmapped_widgets(dialog, mapped=None, allowed=None) -> tuple[list, list]:
    """(input widgets of every page with no row and no reason, mapped or
    allowed names no page has)."""
    mapped = mapped_widgets() if mapped is None else mapped
    allowed = NOT_STORED if allowed is None else allowed
    found = {f"{pid}.{name}" for pid in dialog.page_ids()
             for name in input_widgets(dialog.page(pid))}
    missing = sorted(found - set(mapped) - set(allowed))
    stale = sorted((set(mapped) | set(allowed)) - found)
    return missing, stale


def test_every_stored_input_widget_has_a_row_or_a_reason(ctx) -> None:
    """A setting added to a page without a row in the matrix fails here."""
    dialog = ctx.dialog()
    missing, stale = unmapped_widgets(dialog)
    assert not missing, f"input widgets without a matrix row or a NOT_STORED reason: {missing}"
    assert not stale, f"rows or reasons name widgets no page has: {stale}"
    both = sorted(set(mapped_widgets()) & set(NOT_STORED))
    assert not both, f"a row drives them, yet NOT_STORED says they store nothing: {both}"
    assert all(reason.strip() for reason in NOT_STORED.values())


def test_the_completeness_check_sees_a_new_unmapped_setting(ctx) -> None:
    """Negative control: a page with a new check box and an unnamed spin box
    is reported, and so is a reason for a widget that is gone."""
    from ui import settings_dialog as SD

    class _NewPage(QWidget):
        def __init__(self, parent=None) -> None:
            super().__init__(parent)
            layout = QVBoxLayout(self)
            self.brand_new_check = QCheckBox("A brand-new setting")
            layout.addWidget(self.brand_new_check)
            layout.addWidget(QSpinBox())

    SD.register_page("matrixprobe", "Matrix Probe", lambda parent, window: _NewPage(parent))
    try:
        dialog = ctx.dialog()
        missing, stale = unmapped_widgets(dialog, allowed={**NOT_STORED, "matrixprobe.gone": "x"})
    finally:
        SD.unregister_page("matrixprobe")
    probe = "matrixprobe."
    assert [m for m in missing if m.startswith(probe)] == [
        "matrixprobe.?QSpinBox#0", "matrixprobe.brand_new_check"]
    assert [m for m in stale if m.startswith(probe)] == ["matrixprobe.gone"]


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


def test_cross_paranoid_mode_stops_the_update_check_at_start(ctx) -> None:
    """Paranoid x Updates: the switch "check at start" stays on, but no
    request leaves at start (core.self_update.start_check_allowed), and
    the Updates page says why; back to normal, the check runs again."""
    dialog = ctx.dialog()
    dialog.page("security").paranoid_check.setChecked(True)
    assert dialog.apply()
    assert SU.check_at_start() is True
    allowed, reason = SU.start_check_allowed()
    assert not allowed and "paranoid" in reason
    note = ctx.dialog().page("updates").start_note
    assert not note.isHidden() and "paranoid" in note.text()
    assert _run_update_check(ctx.win)[0] == 0  # the fake GitHub saw nothing
    dialog = ctx.dialog()
    dialog.page("security").paranoid_check.setChecked(False)
    assert dialog.apply()
    assert SU.start_check_allowed() == (True, "")
    assert ctx.dialog().page("updates").start_note.isHidden()
    assert _run_update_check(ctx.win)[0] == 1


def test_cross_update_check_off_wins_over_auto_download(ctx) -> None:
    """Edge: "download automatically" on, "check at start" off - nothing is
    asked, so nothing is downloaded."""
    dialog = ctx.dialog()
    page = dialog.page("updates")
    page.check_box.setChecked(False)
    page.auto_box.setChecked(True)
    assert dialog.apply()
    folder = Path(tempfile.mkdtemp(prefix="axross-matrix-update-"))
    exe = folder / "axross-full"
    exe.write_bytes(b"old axross")
    inst = SU.detect_install(frozen=True, executable=str(exe), bundle_dir=None,
                             platform="linux", machine="x86_64")
    requests, controller = _run_update_check(ctx.win, auto_install=inst)
    assert requests == 0 and exe.read_bytes() == b"old axross" and controller.state == "idle"
    import shutil

    shutil.rmtree(folder, ignore_errors=True)


def test_cross_parallel_transfers_bound_the_jobs_that_run_at_once(ctx) -> None:
    """Files & Panes > Parallel transfers x the window's transfer manager:
    with 3, never more than 3 jobs read at once (and more than one does);
    with 1 again, the next jobs run one after the other."""
    from core.local_fs import LocalFS
    from tests.test_transfer_parallel import FINAL, SlowLocal, make_files, pump_until

    manager = ctx.win._transfer_manager

    def run(count: int, batch: str) -> int:
        dialog = ctx.dialog()
        dialog.page("files").parallel_transfers_spin.setValue(count)
        if dialog.dirty_page_ids():
            assert dialog.apply()
        assert manager.max_parallel == count
        source = SlowLocal(open_delay=0.08)
        target = ctx.tmp_path / f"to-{batch}"
        target.mkdir()
        jobs = manager.transfer_files(source, LocalFS(), make_files(ctx.tmp_path / batch, 9),
                                      str(target))
        assert pump_until(lambda: all(j.status in FINAL for j in jobs), 30)
        assert sorted(p.name for p in target.iterdir()) == [f"f{i:03d}.bin" for i in range(9)]
        return source.max_inflight

    assert 2 <= run(3, "three") <= 3
    assert run(1, "one") == 1


def test_cross_monochrome_icons_override_the_icon_colours(ctx) -> None:
    """Monochrome x Icon colours: the choice is greyed out and kept, and
    every icon takes the theme's single colour while monochrome is on."""
    from ui import icon_provider

    dialog = ctx.dialog()
    page = dialog.page("appearance")
    set_icon_colours(ctx, dialog, ("one", "#3366ff"))
    page.monochrome_check.setChecked(True)
    assert not page.icon_colours_combo.isEnabled() and not page.icon_colour_button.isEnabled()
    assert dialog.apply()
    assert icon_provider.get_tint() != "#3366ff"
    assert _window_pref(ctx, "icon_colours") == "one"  # kept for later
    dialog = ctx.dialog()
    dialog.page("appearance").monochrome_check.setChecked(False)
    assert dialog.apply()
    assert icon_provider.get_tint() == "#3366ff"


def test_cross_toolbar_tint_off_greys_out_the_category_colours(ctx) -> None:
    dialog = ctx.dialog()
    page = dialog.page("toolbar")
    page.tint_check.setChecked(False)
    assert not page.colours_box.isEnabled()
    assert dialog.apply()
    assert _tools_bar(ctx.win).styleSheet() == ""
    page.tint_check.setChecked(True)
    assert page.colours_box.isEnabled()


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
