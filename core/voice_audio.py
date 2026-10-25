"""Audio helpers of the Agent dock's microphone and speaker, without Qt:
the level of a piece of PCM, the end of speech (toggle and conversation
input end on silence), conversion of what a sound card delivers into
16 kHz mono int16 for recognition, and the pitch of a voice. Audio is only
ever held in memory.
"""

from __future__ import annotations

import array
import math
import struct

RATE = 16000
#: Least level a voice has in a quiet room (RMS of int16, 0..32767).
MIN_SPEECH_RMS = 700
#: Speech is this many times louder than the room's noise.
NOISE_FACTOR = 3.0
#: The first seconds measure the room's noise.
NOISE_SECONDS = 0.3
#: Speech shorter than this (a click, a knock) does not count.
MIN_SPEECH_SECONDS = 0.15


def _samples(pcm: bytes) -> array.array:
    values = array.array("h")
    values.frombytes(pcm[: len(pcm) // 2 * 2])
    return values


def rms(pcm: bytes) -> float:
    values = _samples(pcm)
    if not values:
        return 0.0
    return math.sqrt(sum(v * v for v in values) / len(values))


def level(pcm: bytes) -> float:
    """0..1: how loud *pcm* (int16) is, for a level meter and a pulse."""
    return min(1.0, rms(pcm) / 12000.0)


def seconds(pcm: bytes, rate: int = RATE) -> float:
    return len(pcm) // 2 / float(rate)


def resample(pcm: bytes, from_rate: int, to_rate: int) -> bytes:
    """Mono int16 *pcm* at *to_rate* (linear interpolation). Played at
    *from_rate* instead, the result sounds slower and lower when *to_rate*
    is higher - the same as playing *pcm* at a lower rate."""
    pcm = pcm[: len(pcm) // 2 * 2]
    if from_rate == to_rate or not pcm or from_rate <= 0 or to_rate <= 0:
        return pcm
    try:
        import numpy as np
    except ImportError:  # pragma: no cover - numpy comes with the voice packages
        values = _samples(pcm)
        n = int(len(values) * to_rate / from_rate)
        return array.array("h", (values[min(len(values) - 1, int(i * from_rate / to_rate))]
                                 for i in range(n))).tobytes()
    audio = np.frombuffer(pcm, dtype="<i2").astype(np.float64)
    n = int(len(audio) * to_rate / from_rate)
    out = np.interp(np.linspace(0, len(audio) - 1, n), np.arange(len(audio)), audio)
    return np.clip(np.round(out), -32768, 32767).astype("<i2").tobytes()


#: Semitones :func:`pitch_shift` moves at most (two octaves).
PITCH_LIMIT = 24.0


def pitch_factor(semitones: float) -> float:
    return 2.0 ** (semitones / 12.0)


def pitch_shift(pcm: bytes, semitones: float) -> bytes:
    """Mono int16 *pcm* *semitones* higher (lower when negative), and
    shorter (longer) by the same factor: band-limited resampling at the
    same rate (FFT; shifting up drops what would pass the Nyquist frequency
    instead of folding it back). Piper has no pitch of its own: the voice
    worker asks it for speech that much slower first (length_scale), so the
    speech keeps its length. Raises ValueError beyond :data:`PITCH_LIMIT`."""
    if (not isinstance(semitones, (int, float)) or isinstance(semitones, bool)
            or not math.isfinite(semitones) or abs(semitones) > PITCH_LIMIT):
        raise ValueError(f"no pitch shift of {semitones!r} semitones")
    pcm = pcm[: len(pcm) // 2 * 2]
    if not semitones or not pcm:
        return pcm
    n = len(pcm) // 2
    m = max(1, int(round(n / pitch_factor(semitones))))
    try:
        import numpy as np
    except ImportError:  # pragma: no cover - numpy comes with the voice packages
        return resample(pcm, n, m)
    spectrum = np.fft.rfft(np.frombuffer(pcm, dtype="<i2").astype(np.float64))
    bins = m // 2 + 1
    if bins <= len(spectrum):
        spectrum = spectrum[:bins]
    else:
        spectrum = np.concatenate([spectrum, np.zeros(bins - len(spectrum), complex)])
    out = np.fft.irfft(spectrum, m) * (m / n)
    return np.clip(np.round(out), -32768, 32767).astype("<i2").tobytes()


class SilenceDetector:
    """Feed 16 kHz int16 pieces; :meth:`feed` is True once speech was heard
    and then *silence_seconds* passed without it."""

    def __init__(self, silence_seconds: float = 1.2, rate: int = RATE) -> None:
        self.silence_seconds = silence_seconds
        self.rate = rate
        self.heard_speech = False
        self._noise: list[float] = []
        self._noise_seconds = 0.0
        self._threshold = float(MIN_SPEECH_RMS)
        self._loud = 0.0
        self._quiet = 0.0

    def feed(self, pcm: bytes) -> bool:
        duration = seconds(pcm, self.rate)
        if not duration:
            return False
        loudness = rms(pcm)
        if self._noise_seconds < NOISE_SECONDS:
            self._noise.append(loudness)
            self._noise_seconds += duration
            self._threshold = max(MIN_SPEECH_RMS, NOISE_FACTOR * max(self._noise))
            return False
        if loudness >= self._threshold:
            self._loud += duration
            self._quiet = 0.0
            if self._loud >= MIN_SPEECH_SECONDS:
                self.heard_speech = True
            return False
        self._quiet += duration
        if not self.heard_speech:
            self._loud = 0.0
        return self.heard_speech and self._quiet >= self.silence_seconds


_FORMATS = {"int16": ("<h", 32768.0, 0), "int32": ("<i", 2147483648.0, 0),
            "float": ("<f", 1.0, 0), "uint8": ("<B", 128.0, 128)}


def to_mono16k(data: bytes, rate: int, channels: int, sample_format: str) -> bytes:
    """*data* (interleaved, *channels*, *rate*, *sample_format*) as 16 kHz
    mono int16."""
    if sample_format not in _FORMATS:
        raise ValueError(f"unsupported sample format {sample_format!r}")
    if sample_format == "int16" and rate == RATE and channels == 1:
        return data[: len(data) // 2 * 2]
    code, scale, offset = _FORMATS[sample_format]
    width = struct.calcsize(code)
    frame = width * max(1, channels)
    data = data[: len(data) // frame * frame]
    try:
        import numpy as np
    except ImportError:  # pragma: no cover - numpy comes with the voice packages
        np = None
    if np is not None:
        dtype = {"<h": "<i2", "<i": "<i4", "<f": "<f4", "<B": "u1"}[code]
        audio = (np.frombuffer(data, dtype=dtype).astype(np.float64) - offset) / scale
        audio = audio.reshape(-1, max(1, channels)).mean(axis=1)
        if rate != RATE and len(audio):
            n = int(len(audio) * RATE / rate)
            audio = np.interp(np.linspace(0, len(audio) - 1, n), np.arange(len(audio)), audio)
        return (np.clip(audio, -1.0, 32767 / 32768) * 32768).astype("<i2").tobytes()
    values = [(v[0] - offset) / scale for v in struct.iter_unpack(code, data)]
    mono = [sum(values[i:i + channels]) / channels for i in range(0, len(values), channels)]
    if rate != RATE and mono:
        n = int(len(mono) * RATE / rate)
        mono = [mono[min(len(mono) - 1, int(i * rate / RATE))] for i in range(n)]
    return array.array("h", (int(max(-1.0, min(32767 / 32768, v)) * 32768)
                             for v in mono)).tobytes()
