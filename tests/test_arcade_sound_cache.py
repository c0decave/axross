"""The Arcade's sound cache (~/.cache/axross/arcade): a damaged file costs
nothing.

The effects and the music loops were written straight to their cache
file and read back without a look at the length. A write cut short (a
full disk, a killed process) left an odd number of bytes;
``array.frombytes`` then raised in the render thread on every start - one
damaged effect file silenced every effect after it, for good, and a
damaged music file the world's music. Also one effect that failed to
render ended the thread for all the others.
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

from core.arcade import sound as S  # noqa: E402
from ui import arcade_audio as AA  # noqa: E402


def _no_sink():
    raise OSError("no sink in the tests")


def _effect_path(cache: Path, name: str) -> Path:
    key = hashlib.sha256(f"{AA.SOUND_VERSION}:{S.RATE}:{S.EFFECTS[name]!r}".encode()).hexdigest()[:24]
    return cache / "sfx" / f"{key}.pcm"


def _wait(cond, seconds: float = 60) -> bool:
    end = time.monotonic() + seconds
    while not cond() and time.monotonic() < end:
        time.sleep(0.05)
    return cond()


@pytest.fixture
def cache(tmp_path, monkeypatch):
    monkeypatch.setattr(AA, "CACHE", tmp_path)
    return tmp_path


def test_sad_an_odd_length_effect_file_is_deleted_and_rendered_again(cache):
    first = next(iter(S.EFFECTS))
    path = _effect_path(cache, first)
    path.parent.mkdir(parents=True)
    path.write_bytes(b"\x00" * 1001)                 # a write cut short
    audio = AA.ArcadeAudio(sink_factory=_no_sink)
    assert _wait(lambda: len(audio._effects) == len(S.EFFECTS)), "every effect still loads"
    assert path.read_bytes() == S.render(S.EFFECTS[first])     # the cache is whole again
    audio.stop()


def test_sad_an_odd_length_music_file_is_rendered_again(cache):
    name = hashlib.sha256(f"{AA.SOUND_VERSION}:5:".encode()).hexdigest()[:24]
    (cache / f"{name}.pcm").write_bytes(b"\x01" * 777)
    audio = AA.ArcadeAudio(sink_factory=_no_sink)
    audio.music(5)
    assert _wait(lambda: audio._music is not None), "the music still plays"
    assert len(audio._music) > 1000 and (cache / f"{name}.pcm").stat().st_size % 2 == 0
    audio.stop()


def test_edge_a_write_cut_short_leaves_no_half_cache_file(cache, monkeypatch):
    """The cache is written to a temporary name and renamed: a failed
    write leaves nothing a later start would read."""
    real = Path.write_bytes

    def half_then_full(self, data):
        real(self, data[: len(data) // 2 + 1])      # odd: what a full disk leaves
        raise OSError(28, "No space left on device")
    monkeypatch.setattr(Path, "write_bytes", half_then_full)
    audio = AA.ArcadeAudio(sink_factory=_no_sink)
    assert _wait(lambda: len(audio._effects) == len(S.EFFECTS))    # played from memory anyway
    audio.stop()
    left = [p for p in cache.rglob("*") if p.is_file()]
    assert left == [], f"half files left behind: {left}"


def test_sad_one_effect_that_fails_does_not_cost_the_others(cache, monkeypatch):
    names = list(S.EFFECTS)
    bad = S.EFFECTS[names[1]]
    real = S.render

    def render(effect, *a, **kw):
        if effect is bad:
            raise ValueError("a broken effect")
        return real(effect, *a, **kw)
    monkeypatch.setattr(S, "render", render)
    audio = AA.ArcadeAudio(sink_factory=_no_sink)
    assert _wait(lambda: len(audio._effects) == len(S.EFFECTS) - 1)
    assert names[1] not in audio._effects and names[-1] in audio._effects
    audio.stop()
