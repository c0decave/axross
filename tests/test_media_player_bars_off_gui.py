"""The spectrum's FFT runs in the equalizer thread, not on every GUI tick.

Reported: the spectrometer got much slower under load (transfers, I/O).
Profiled: with two threads busy in Python, a visualizer tick that worked
out the FFT on the GUI thread took ~75 ms (0.55 ms idle) - every numpy
call gives the GIL away and waits up to the switch interval to get it
back - so 30 frames a second could not be kept. With the bars worked out
in the equalizer thread the tick takes them: ~0.2 ms busy or not.
"""

from __future__ import annotations

import importlib.util
import os
import sys
import time
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
np = pytest.importorskip("numpy")

_spec = importlib.util.spec_from_file_location(
    "media_player_bars",
    Path(__file__).resolve().parent.parent / "resources/extensions/media_player.py")
MP = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(MP)


def _engine(state="playing"):
    rng = np.random.default_rng(3)
    return SimpleNamespace(state=state, rate=48000, _bars=None, _bars_wanted=0, _bars_asked=0.0,
                           _recent=(rng.standard_normal((4096, 2)) * 0.3).astype(np.float32))


def _calls(monkeypatch):
    calls = []
    real = MP.spectrum_bars

    def counting(*a, **k):
        calls.append(1)
        return real(*a, **k)

    monkeypatch.setattr(MP, "spectrum_bars", counting)
    return calls


def test_happy_while_playing_the_gui_takes_the_equalizer_threads_bars(monkeypatch):
    eng = _engine()
    calls = _calls(monkeypatch)
    first = MP.EqEngine.current_bars(eng, 32)  # the first ask works them out
    assert len(first) == 32 and len(calls) == 1
    eng._bars = (eng._bars[0], time.monotonic() - 1.0)  # old: the eq thread is due
    MP.EqEngine._update_bars(eng)  # the equalizer thread
    assert len(calls) == 2
    MP.EqEngine.current_bars(eng, 32)
    MP.EqEngine.current_bars(eng, 32)
    assert len(calls) == 2  # the GUI ticks took them, no FFT of their own


def test_edge_paused_another_count_or_stale_bars_are_worked_out_here(monkeypatch):
    eng = _engine()
    calls = _calls(monkeypatch)
    MP.EqEngine.current_bars(eng, 32)
    MP.EqEngine.current_bars(eng, 64)  # another bar count
    assert len(calls) == 2
    eng._bars = (eng._bars[0], time.monotonic() - MP.BARS_FRESH - 0.05)
    MP.EqEngine.current_bars(eng, 64)  # the equalizer thread fell behind
    assert len(calls) == 3
    eng.state = "paused"
    MP.EqEngine.current_bars(eng, 64)
    assert len(calls) == 4


def test_sad_nobody_watching_means_no_fft_in_the_equalizer_thread(monkeypatch):
    eng = _engine()
    calls = _calls(monkeypatch)
    MP.EqEngine._update_bars(eng)  # never asked
    assert calls == []
    MP.EqEngine.current_bars(eng, 32)
    eng._bars_asked = time.monotonic() - MP.BARS_WANTED_FOR - 0.1  # the face went away
    eng._bars = (eng._bars[0], 0.0)
    MP.EqEngine._update_bars(eng)
    assert len(calls) == 1
