"""Audio helpers of the microphone and the speaker (core.voice_audio):
level, end of speech, and conversion of what a sound card delivers to
16 kHz mono int16 for recognition."""

from __future__ import annotations

import array
import math
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import voice_audio as VA  # noqa: E402


def tone(seconds: float, amplitude: int, rate: int = 16000, freq: float = 440.0) -> bytes:
    n = int(seconds * rate)
    return array.array("h", (int(amplitude * math.sin(2 * math.pi * freq * i / rate))
                             for i in range(n))).tobytes()


def silence(seconds: float, rate: int = 16000) -> bytes:
    return b"\0\0" * int(seconds * rate)


# -- level -------------------------------------------------------------------------------------


def test_happy_level_of_loud_and_quiet():
    assert VA.level(tone(0.1, 20000)) > 0.5
    assert VA.level(silence(0.1)) == 0.0


def test_edge_level_of_nothing_and_odd_bytes():
    assert VA.level(b"") == 0.0
    assert VA.level(b"\x01") == 0.0


# -- end of speech -------------------------------------------------------------------------------


def test_happy_speech_then_silence_ends_the_input():
    det = VA.SilenceDetector(silence_seconds=0.5)
    assert not det.feed(silence(0.3))
    assert not det.feed(tone(0.6, 8000))
    assert not det.feed(silence(0.3))
    assert det.feed(silence(0.3))
    assert det.heard_speech


def test_sad_silence_alone_never_ends_the_input():
    det = VA.SilenceDetector(silence_seconds=0.5)
    for _ in range(20):
        assert not det.feed(silence(0.2))
    assert not det.heard_speech


def test_edge_a_noisy_room_raises_the_threshold():
    det = VA.SilenceDetector(silence_seconds=0.4)
    noise = tone(0.4, 900, freq=97.0)
    assert not det.feed(noise)  # the first 0.3 s set the noise floor
    assert not det.feed(noise * 3)  # steady noise is no speech
    assert not det.heard_speech
    assert not det.feed(tone(0.5, 12000))
    assert det.heard_speech
    assert det.feed(noise * 2)


def test_edge_a_short_click_is_no_speech():
    det = VA.SilenceDetector(silence_seconds=0.3)
    det.feed(silence(0.3))
    det.feed(tone(0.03, 20000))
    assert not det.feed(silence(1.0))
    assert not det.heard_speech


# -- conversion ------------------------------------------------------------------------------------


def test_happy_16k_mono_int16_passes_through():
    pcm = tone(0.05, 1000)
    assert VA.to_mono16k(pcm, 16000, 1, "int16") == pcm


def test_happy_48k_stereo_float_becomes_16k_mono_int16():
    n = 4800  # 0.1 s
    frames = b"".join(struct.pack("<ff", 0.5, 0.5) for _ in range(n))
    out = VA.to_mono16k(frames, 48000, 2, "float")
    values = array.array("h", out)
    assert abs(len(values) - 1600) <= 1
    assert all(16000 <= v <= 16500 for v in values)


def test_edge_int32_and_uint8():
    out = VA.to_mono16k(struct.pack("<i", 2**30) * 16, 16000, 1, "int32")
    assert array.array("h", out)[0] == 2**14
    out8 = VA.to_mono16k(bytes([255]) * 16, 16000, 1, "uint8")
    assert array.array("h", out8)[0] > 32000


def test_sad_unknown_format_is_refused():
    with pytest.raises(ValueError):
        VA.to_mono16k(b"\0" * 8, 16000, 1, "int24")


def test_edge_partial_frames_are_dropped():
    assert len(VA.to_mono16k(b"\0" * 7, 16000, 2, "int16")) == 2 * 1


def test_happy_seconds_of_pcm():
    assert VA.seconds(silence(1.5)) == pytest.approx(1.5)
    assert VA.seconds(b"\0\0" * 22050, rate=22050) == pytest.approx(1.0)


def test_happy_resample_changes_the_length_by_the_rate_ratio():
    pcm = tone(0.1, 8000, rate=22050)
    out = VA.resample(pcm, 22050, 48000)
    assert abs(len(out) // 2 - int(len(pcm) // 2 * 48000 / 22050)) <= 1
    assert VA.level(out) == pytest.approx(VA.level(pcm), rel=0.05)


def test_edge_resample_same_rate_or_nothing_is_unchanged():
    pcm = tone(0.01, 1000)
    assert VA.resample(pcm, 16000, 16000) == pcm
    assert VA.resample(b"", 22050, 48000) == b""
    assert VA.resample(b"\x01", 22050, 48000) == b""


def test_sad_resample_with_a_bad_rate_returns_the_input():
    pcm = tone(0.01, 1000)
    assert VA.resample(pcm, 0, 48000) == pcm


# -- pitch (the voice settings' "higher / lower") ------------------------------------------


def dominant_hz(pcm: bytes, rate: int) -> float:
    """The strongest frequency of *pcm* (FFT peak, parabolic interpolation)."""
    import numpy as np

    audio = np.frombuffer(pcm, dtype="<i2").astype(np.float64)
    spectrum = np.abs(np.fft.rfft(audio * np.hanning(len(audio))))
    k = int(np.argmax(spectrum[1:])) + 1
    a, b, c = spectrum[k - 1], spectrum[k], spectrum[k + 1]
    shift = 0.5 * (a - c) / (a - 2 * b + c)
    return (k + shift) * rate / len(audio)


@pytest.mark.parametrize("semitones", [12.0, 5.0, 0.5, -3.0, -12.0])
def test_happy_pitch_shift_moves_the_tone_by_semitones_and_the_length_by_the_same_factor(
        semitones):
    rate, hz = 22050, 220.0
    pcm = tone(1.0, 12000, rate=rate, freq=hz)
    out = VA.pitch_shift(pcm, semitones)
    factor = 2 ** (semitones / 12)
    assert abs(dominant_hz(out, rate) - hz * factor) < 1.0
    assert abs(len(out) // 2 - round(rate / factor)) <= 1
    assert VA.pitch_factor(semitones) == pytest.approx(factor)


def test_happy_pitch_shift_keeps_the_loudness():
    pcm = tone(0.5, 12000, rate=22050, freq=300.0)
    assert VA.rms(VA.pitch_shift(pcm, 4.0)) == pytest.approx(VA.rms(pcm), rel=0.03)


def test_happy_shifting_up_leaves_no_alias_of_a_tone_above_the_new_nyquist():
    """A 9 kHz tone an octave up is above 11 kHz: it is filtered out, not
    folded back down into the audible band."""
    rate = 22050
    pcm = tone(0.5, 12000, rate=rate, freq=9000.0)
    assert VA.rms(VA.pitch_shift(pcm, 12.0)) < 200


@pytest.mark.parametrize("bad", [24.5, -30, float("nan"), float("inf"), "2", None, True])
def test_sad_pitch_shift_refuses_what_is_no_sensible_shift(bad):
    with pytest.raises(ValueError):
        VA.pitch_shift(tone(0.1, 1000, rate=22050), bad)


def test_edge_pitch_shift_of_nothing_zero_and_odd_bytes():
    pcm = tone(0.1, 1000, rate=22050)
    assert VA.pitch_shift(pcm, 0) == pcm
    assert VA.pitch_shift(b"", 5.0) == b""
    assert VA.pitch_shift(b"\x01", 5.0) == b""
    assert len(VA.pitch_shift(pcm + b"\x01", 0.0)) == len(pcm)
    assert len(VA.pitch_shift(b"\x10\x00", 12.0)) == 2  # one sample stays one sample


def test_edge_pitch_shift_of_a_full_scale_square_does_not_wrap_around():
    import numpy as np

    square = np.where(np.arange(22050) % 100 < 50, 32767, -32768).astype("<i2").tobytes()
    out = np.frombuffer(VA.pitch_shift(square, -5.0), dtype="<i2")
    # Ringing at the edges is clipped, never wrapped to the other sign.
    assert out.max() <= 32767 and out.min() >= -32768
    assert np.mean(np.abs(out.astype(np.int64))) > 20000
