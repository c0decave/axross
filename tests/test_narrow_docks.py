"""Panels in a narrow dock (~340 px) and the two close buttons of a title bar.

The product review docked the panels at 366 px: the Audio Mixer needed
496 px and scrolled sideways, the Media Player was cut off on the right
(its error text with it), and the title bar's "Close" and "Close all
panels in this area" were the same red X right next to each other.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QDockWidget, QMainWindow, QSpacerItem  # noqa: E402

from core import audio_route as AR  # noqa: E402

APP = QApplication.instance() or QApplication([])
NARROW = 340


def pump(seconds: float = 0.1) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def _load(name: str, file: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "resources" / "extensions" / file)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


MIX = _load("bundled_audio_mixer_narrow_docks", "audio_mixer.py")
MP = _load("bundled_media_player_narrow_docks", "media_player.py")


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    AR.forget()
    yield tmp_path
    AR.forget()


def test_happy_the_audio_mixer_fits_a_narrow_dock(home):
    long_names = [("alsa_output.pci-0000_00_1f.3.analog-stereo", "Built-in Audio Analog Stereo"),
                  ("bluez_output.AA_BB_CC_DD_EE_07.1", "WH-1000XM4 Wireless Headset")]
    panel = MIX.MixerPanel(settings_path=home / "audio.json", device_lister=lambda: long_names)
    try:
        panel.resize(NARROW, 600)
        panel.show()
        pump()
        assert panel.minimumSizeHint().width() <= NARROW
        assert panel.width() == NARROW
        for channel in (panel.master, *panel.channels.values()):
            # each still has all of its controls, none squeezed away
            assert channel.slider.width() >= 100
            assert channel.output.isVisible() and channel.mute.isVisible()
            assert channel.output.geometry().right() <= channel.output.parentWidget().width()
        # a device name longer than the box is still listed whole
        assert panel.master.output.findText("WH-1000XM4 Wireless Headset") >= 0
    finally:
        panel.shutdown()
        panel.close()
        panel.deleteLater()


def test_happy_the_media_player_and_its_error_fit_a_narrow_dock(home):
    from core.multimedia_probe import ProbeResult

    reason = ("Qt Multimedia failed: ImportError: libpulse.so.0: cannot open shared object "
              "file: No such file or directory")
    panel = MP.PlayerPanel(audio_probe=lambda: ProbeResult(False, reason),
                           open_mixer=lambda: None, open_audio_settings=lambda: None)
    try:
        panel.resize(NARROW, 700)
        panel.show()
        pump()
        assert panel.minimumSizeHint().width() <= NARROW
        assert panel.width() == NARROW
        status = panel.audio_status
        assert status.isVisible() and reason in status.text()
        # the error wraps inside the panel instead of running off its edge
        assert status.geometry().right() <= panel.width()
        assert status.height() > status.fontMetrics().height() * 2
        for button in (panel.play_button, panel.mute_button, panel.sound_button):
            assert button.geometry().right() <= panel.width()
    finally:
        panel.close()
        panel.deleteLater()


def test_happy_close_all_looks_unlike_close_and_stands_apart():
    from ui.dock_titlebar import DockTitleBar

    window = QMainWindow()
    dock = QDockWidget("Panel", window)
    bar = DockTitleBar("Panel", "terminal", dock)
    dock.setTitleBarWidget(bar)
    try:
        close, close_all = bar._close_btn, bar._close_all_btn
        one = close.icon().pixmap(16, 16).toImage()
        many = close_all.icon().pixmap(16, 16).toImage()
        assert one != many
        assert close.toolTip() != close_all.toolTip()
        assert "ALL" in close_all.toolTip()
        layout = bar.layout()
        between = [layout.itemAt(i) for i in range(layout.indexOf(close) + 1,
                                                    layout.indexOf(close_all))]
        assert any(isinstance(item, QSpacerItem) and item.sizeHint().width() >= 8
                   for item in between), "no gap between the two close buttons"
    finally:
        window.deleteLater()


def test_edge_the_two_icons_have_their_own_colours():
    from ui.icon_provider import _ICON_COLORS as ICON_COLOURS

    assert ICON_COLOURS["close-all-panes"] != ICON_COLOURS["close-pane"]
