"""Switching the Arcade extension off lets its window and its sound go.

``deactivate`` only called ``close()`` on the Arcade window - a child of
the main window, without WA_DeleteOnClose - so the window, its views and
its ArcadeAudio (still connected to the Audio Mixer's notifier) lived on
until axross ended: one more of each with every switch on and off.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QEvent, QObject  # noqa: E402
from PyQt6.QtWidgets import QApplication, QMainWindow  # noqa: E402

APP = QApplication.instance() or QApplication([])


class FakeIO:
    def write(self, data):
        return len(data)


class FakeSink(QObject):
    def bytesFree(self):  # noqa: N802 - Qt API
        return 0

    def setVolume(self, v):  # noqa: N802 - Qt API
        self.volume = v

    def stop(self):
        pass


def _flush_deletes() -> None:
    APP.processEvents()
    APP.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)


@pytest.fixture
def ext(tmp_path, monkeypatch):
    from ui import arcade_audio as AA

    monkeypatch.setattr(AA, "CACHE", tmp_path / "cache")
    monkeypatch.setattr(AA, "open_sink", lambda rate, dev, vol, buf: (FakeSink(), FakeIO()))
    return importlib.import_module("resources.extensions.arcade")


def test_sad_switching_off_deletes_the_window_and_its_sound(ext):
    from core import audio_route as AR
    from ui.arcade_audio import ArcadeAudio
    from ui.arcade_window import ArcadeWindow

    main = QMainWindow()

    class Api:
        window = main

        def add_menu_action(self, *_a, **_k):
            pass
    api = Api()
    signal = AR.notifier().changed
    listeners = AR.notifier().receivers(signal)
    for _ in range(3):
        ext.activate(api)
        win = ext.show_window(main)
        win.audio._ensure_sink()                    # the sound is on: on the mixer's notifier
        assert AR.notifier().receivers(signal) == listeners + 1
        ext.deactivate(api)
        _flush_deletes()
        assert sip.isdeleted(win)
        assert AR.notifier().receivers(signal) == listeners     # off the notifier again
    alive = [w for w in main.findChildren(ArcadeWindow) if not sip.isdeleted(w)]
    assert alive == [] and main.findChildren(ArcadeAudio) == []
    main.deleteLater()
    _flush_deletes()


def test_edge_switching_off_twice_or_without_a_window_is_harmless(ext):
    class Api:
        window = None

        def add_menu_action(self, *_a, **_k):
            pass
    api = Api()
    ext.activate(api)
    ext.deactivate(api)                             # never opened
    win = ext.show_window(None)
    ext.deactivate(api)
    ext.deactivate(api)
    _flush_deletes()
    assert sip.isdeleted(win)
    assert ext.show_window(None) is not win         # switched on again: a new window
    ext.deactivate(api)
    _flush_deletes()
