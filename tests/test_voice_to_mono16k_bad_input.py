"""core.voice_audio.to_mono16k with what a broken device or file reports.

What was wrong: a sample rate of 0 or less divided by zero (or made a
negative length) when the audio was resampled, and a NaN float sample went
through ``numpy.clip`` unchanged and became whatever ``astype(int16)`` makes
of NaN - a garbage sample (a click) instead of silence. Now a rate <= 0 is
refused with ValueError and NaN is silence (0); an infinity is full scale.
"""

from __future__ import annotations

import array
import math
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import voice_audio as VA  # noqa: E402


@pytest.mark.parametrize("rate", [0, -48000, float("nan")])
@pytest.mark.parametrize("fmt", ["float", "int16"])
def test_sad_a_rate_of_zero_or_less_is_refused(rate, fmt):
    data = struct.pack("<ff", 0.5, 0.5) if fmt == "float" else struct.pack("<hh", 100, 100)
    with pytest.raises(ValueError, match="sample rate"):
        VA.to_mono16k(data * 16, rate, 1, fmt)


def test_sad_nan_is_silence_in_its_channel_only_and_infinity_is_full_scale():
    frames = struct.pack("<" + "ff" * 16, *([math.nan, 0.5] * 16))
    values = array.array("h", VA.to_mono16k(frames, 16000, 2, "float"))
    assert set(values) == {8192}                         # (0 + 0.5) / 2
    nans = struct.pack("<" + "f" * 96, *([math.nan] * 96))
    for rate in (16000, 48000):
        assert set(array.array("h", VA.to_mono16k(nans, rate, 1, "float"))) == {0}
    inf = array.array("h", VA.to_mono16k(struct.pack("<ff", math.inf, -math.inf) * 8, 16000, 1, "float"))
    assert set(inf) == {32767, -32768}


def test_edge_the_pure_python_path_does_the_same(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def no_numpy(name, *args, **kwargs):
        if name == "numpy":
            raise ImportError("no numpy here")
        return real_import(name, *args, **kwargs)
    monkeypatch.setattr(builtins, "__import__", no_numpy)
    data = struct.pack("<" + "f" * 32, *([math.nan] * 32))
    assert set(array.array("h", VA.to_mono16k(data, 48000, 1, "float"))) == {0}
    with pytest.raises(ValueError, match="sample rate"):
        VA.to_mono16k(data, 0, 1, "float")
