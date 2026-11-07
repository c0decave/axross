"""core.arcade.sound (the synthesiser, the composer) and ui/arcade_audio
(mixing onto one output, silent without sound) - with a fake output."""

from __future__ import annotations

import array
import io
import os
import sys
import time
import wave
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.arcade import sound as S  # noqa: E402


@pytest.mark.parametrize("name", sorted(S.EFFECTS))
def test_happy_every_effect_renders_audible_16_bit_pcm(name):
    pcm = S.render(S.EFFECTS[name])
    samples = array.array("h")
    samples.frombytes(pcm)
    assert 0.02 < len(samples) / S.RATE < 2.0
    assert max(abs(x) for x in samples) > 8000          # audible, normalised
    assert max(abs(x) for x in samples) <= 30000        # never clipped


def test_happy_tunes_are_composed_from_the_seed_and_loop_exactly():
    a, b, c = S.compose(1), S.compose(1), S.compose(2)
    assert a.notes == b.notes and a.notes != c.notes
    pcm = S.render_tune(a)
    beat = 60 / a.tempo
    assert len(pcm) == int(a.bars * 4 * beat * S.RATE) * 2
    with wave.open(io.BytesIO(S.wav(pcm))) as w:
        assert (w.getnchannels(), w.getsampwidth(), w.getframerate()) == (1, 2, S.RATE)
    melody = [n for n in a.notes if n[4] == 0.22]
    assert melody and all(S.SCALES[a.scale].count((n[2] - a.root) % 12) for n in melody)   # in key


@pytest.fixture(autouse=True)
def _own_cache(tmp_path_factory, monkeypatch):
    """Rendered effects go to a cache of the test session, not ~/.cache."""
    from ui import arcade_audio as AA

    monkeypatch.setattr(AA, "CACHE", tmp_path_factory.getbasetemp() / "arcade-cache")


class FakeIO:
    def __init__(self):
        self.chunks = []

    def write(self, data):
        self.chunks.append(bytes(data))


class FakeSink:
    def stop(self):
        pass


def _audio():
    from PyQt6.QtWidgets import QApplication

    from ui.arcade_audio import ArcadeAudio

    app = QApplication.instance() or QApplication([])
    fio = FakeIO()
    audio = ArcadeAudio(sink_factory=lambda: (FakeSink(), fio))
    end = time.monotonic() + 60
    while len(audio._effects) < len(S.EFFECTS) and time.monotonic() < end:
        time.sleep(0.02)
    return app, audio, fio


def _loud(chunks):
    s = array.array("h")
    for c in chunks:
        s.frombytes(c)
    return max((abs(x) for x in s), default=0)


def test_happy_effects_are_mixed_onto_the_output():
    _app, audio, fio = _audio()
    audio.play("key")
    audio.play("bit")
    for _ in range(20):
        audio._pump()
    assert fio.chunks and _loud(fio.chunks) > 3000
    audio.muted = True
    fio.chunks.clear()
    audio.play("crash")
    audio._pump()
    assert _loud(fio.chunks) == 0
    audio.stop()


def test_happy_music_loops_from_the_cache(tmp_path, monkeypatch):
    from ui import arcade_audio as AA

    monkeypatch.setattr(AA, "CACHE", tmp_path)
    _app, audio, fio = _audio()
    audio.music(5)
    end = time.monotonic() + 30
    while audio._music is None and time.monotonic() < end:
        time.sleep(0.05)
    assert audio._music is not None and list(tmp_path.glob("*.pcm"))
    audio._ensure_sink()
    for _ in range(10):
        audio._pump()
    assert _loud(fio.chunks) > 1000
    audio.music(None)
    assert audio._music is None
    audio.stop()


def test_sad_without_sound_everything_is_silent_and_nothing_fails():
    from PyQt6.QtWidgets import QApplication

    from ui.arcade_audio import ArcadeAudio

    QApplication.instance() or QApplication([])

    def broken():
        raise OSError("no audio server")
    audio = ArcadeAudio(sink_factory=broken)
    end = time.monotonic() + 10
    while not audio._effects and time.monotonic() < end:
        time.sleep(0.02)
    audio.play("bit")
    audio.play("bit")
    assert audio._failed and audio._sink is None
    audio.stop()


def test_happy_the_arcade_has_its_own_mixer_channel():
    from core import audio_route as AR
    from core.audio_settings import AudioSettings

    assert "games" in AR.SOURCES and AR.SOURCE_LABELS["games"] == "Arcade"
    s = AudioSettings.from_dict({"games_volume": 40, "games_muted": True})
    assert (s.games_volume, s.games_muted) == (40, True)


def test_happy_every_game_has_its_own_title_jingle():
    jingles = {k: S.render(S.EFFECTS[f"intro-{k}"]) for k in ("chase", "tilt", "rockfall", "trails")}
    assert len(set(jingles.values())) == 4
    for pcm in jingles.values():
        assert 1.0 < len(pcm) / 2 / S.RATE < 2.0                # a jingle, not a beep - and short


def test_happy_tunes_have_drums_and_a_seamless_loop():
    tune = S.compose(9101, mood="dorian")
    assert {"kick", "snare", "hat"} <= {n[3] for n in tune.notes}
    pcm = array.array("h")
    pcm.frombytes(S.render_tune(tune))
    steps = [abs(pcm[i + 1] - pcm[i]) for i in range(len(pcm) - 1)]
    # the seam (end -> start) is no bigger a jump than the tune makes anyway
    assert abs(pcm[0] - pcm[-1]) <= max(steps)
