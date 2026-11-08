"""One equalizer for everything axross plays.

Ten bands, presets, and the setting that goes with them - kept in the audio
settings (core.audio_settings: ``eq_enabled``, ``eq_preset``,
``eq_gains``), so the Audio Mixer and the Media Player's own equalizer row
show and change the same thing. :class:`Equalizer` is the filter (short-time
FFT with 50 % overlap-add, numpy); the Media Player runs it in its engine,
:func:`equalize_int16` runs it over a piece of int16 PCM (the Agent's
voice). Without numpy nothing is equalized and nothing fails: the setting
stays, the sound goes out as it is.
"""

from __future__ import annotations

import importlib.util

#: numpy, imported the first time something is equalized (:func:`_numpy`):
#: it costs about 170 ms and 20 MB, and a Media Player or Audio Mixer that
#: is only switched on equalizes nothing. None until then, and for good
#: when numpy is missing (the equalizer needs it; playback does not).
np = None
_NUMPY_STATE = {"tried": False}


def _numpy():
    """numpy (imported on the first call), or None when it is missing."""
    global np
    if np is None and not _NUMPY_STATE["tried"]:
        _NUMPY_STATE["tried"] = True
        try:
            import numpy
        except ImportError:  # pragma: no cover - depends on the install
            return None
        np = numpy
    return np

#: Centre frequencies of the ten bands (Hz).
BANDS = (31, 62, 125, 250, 500, 1000, 2000, 4000, 8000, 16000)
MAX_GAIN_DB = 12.0
PRESETS = {
    "Flat": [0.0] * 10,
    "Bass boost": [8.0, 7.0, 5.0, 3.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    "Treble boost": [0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 3.0, 5.0, 7.0, 8.0],
    "Vocal": [-3.0, -2.0, -1.0, 1.0, 4.0, 5.0, 4.0, 2.0, 0.0, -1.0],
    "Loudness": [6.0, 5.0, 2.0, 0.0, -1.0, -1.0, 0.0, 2.0, 4.0, 5.0],
    "Rock": [5.0, 4.0, 2.0, -1.0, -2.0, -1.0, 2.0, 4.0, 5.0, 5.0],
}
#: The preset name of gains that match no preset.
CUSTOM = "Custom"
#: The filter's FFT frame and hop (its latency is one hop).
FRAME = 2048
HOP = FRAME // 2


def available() -> bool:
    """Whether sound can be equalized here (numpy is installed) - without
    importing numpy."""
    if np is not None:
        return True
    if _NUMPY_STATE["tried"]:
        return False
    try:
        return importlib.util.find_spec("numpy") is not None
    except (ImportError, ValueError):
        return False


def gains_ok(value) -> bool:
    """Ten numbers within +-MAX_GAIN_DB."""
    return (isinstance(value, (list, tuple)) and len(value) == len(BANDS)
            and all(isinstance(g, (int, float)) and not isinstance(g, bool)
                    and -MAX_GAIN_DB <= g <= MAX_GAIN_DB for g in value))


def clean_gains(value) -> list[float]:
    """*value* as ten floats held to +-MAX_GAIN_DB (ValueError when it is
    not ten numbers)."""
    if not isinstance(value, (list, tuple)) or len(value) != len(BANDS):
        raise ValueError(f"{len(BANDS)} band gains, not {value!r}")
    out = []
    for g in value:
        if isinstance(g, bool) or not isinstance(g, (int, float)) or g != g:
            raise ValueError(f"not a gain: {g!r}")
        out.append(float(max(-MAX_GAIN_DB, min(MAX_GAIN_DB, g))))
    return out


def preset_of(gains) -> str:
    """The name of the preset *gains* are, else CUSTOM."""
    gains = [float(g) for g in gains]
    for name, values in PRESETS.items():
        if all(abs(a - b) < 0.05 for a, b in zip(gains, values)):
            return name
    return CUSTOM


def is_flat(gains) -> bool:
    return all(abs(float(g)) < 1e-9 for g in gains)


def equalize_int16(pcm: bytes, rate: int, gains, channels: int = 1) -> bytes:
    """*pcm* (int16, *channels* interleaved, at *rate*) through the
    equalizer at *gains*: as long as it was, the filter's latency taken
    off, clipped to int16. Unchanged without numpy, for flat gains or for
    nothing to do."""
    if not pcm or is_flat(gains) or rate <= 0 or _numpy() is None:
        return pcm
    samples = np.frombuffer(pcm[: len(pcm) - len(pcm) % (2 * channels)], dtype="<i2")
    if not len(samples):
        return pcm
    block = samples.astype(np.float32).reshape(-1, channels) / 32768.0
    eq = Equalizer(rate, channels)
    eq.set_gains(clean_gains(gains))
    out = np.concatenate([eq.process(block), eq.flush()])[eq.latency:eq.latency + len(block)]
    clipped = np.clip(out * 32768.0, -32768, 32767).astype("<i2")
    return clipped.tobytes()


def _gain_curve(gains_db, rate: int, n_fft: int):
    """Linear gain per rfft bin: the band gains interpolated over the log of
    the frequency, flat beyond the outer bands."""
    _numpy()
    freqs = np.fft.rfftfreq(n_fft, 1.0 / rate)
    logf = np.log10(np.maximum(freqs, BANDS[0]))
    db = np.interp(logf, np.log10(BANDS), gains_db)
    return (10.0 ** (db / 20.0)).astype(np.float32)


class Equalizer:
    """Ten bands by short-time FFT with 50 % overlap-add: sqrt-Hann before
    and after, so unity gains give back the input exactly, delayed by
    :attr:`latency` samples, whatever the block sizes."""

    def __init__(self, rate: int = 44100, channels: int = 2) -> None:
        if _numpy() is None:
            raise RuntimeError("the equalizer needs numpy (pip install numpy)")
        self.rate = rate
        self.channels = channels
        n = np.arange(FRAME)
        hann = 0.5 - 0.5 * np.cos(2 * np.pi * n / FRAME)  # periodic: sums to 1 at 50 %
        self._window = np.sqrt(hann).astype(np.float32)[:, None]
        self.latency = HOP
        self.gains_db = [0.0] * 10
        self._curve = _gain_curve(self.gains_db, rate, FRAME)[:, None]
        self.reset()

    def reset(self) -> None:
        self._in = np.zeros((HOP, self.channels), np.float32)  # the pre-pad: latency
        self._acc = np.zeros((FRAME, self.channels), np.float32)

    def set_gains(self, gains_db) -> None:
        if len(gains_db) != len(BANDS):
            raise ValueError(f"{len(BANDS)} band gains, not {len(gains_db)}")
        self.gains_db = [float(max(-MAX_GAIN_DB, min(MAX_GAIN_DB, g))) for g in gains_db]
        self._curve = _gain_curve(self.gains_db, self.rate, FRAME)[:, None]

    @property
    def flat(self) -> bool:
        return all(g == 0.0 for g in self.gains_db)

    def process(self, block):
        """Filtered samples for *block* (frames x channels); as many as are
        complete, so the output lags by :attr:`latency` overall."""
        block = np.asarray(block, np.float32).reshape(-1, self.channels)
        self._in = np.concatenate([self._in, block])
        count = (len(self._in) - FRAME) // HOP + 1 if len(self._in) >= FRAME else 0
        if count <= 0:
            return np.zeros((0, self.channels), np.float32)
        # All complete frames at once: a fixed number of numpy calls per
        # block, not per frame. Each call lets go of the GIL, and getting it
        # back from a busy thread costs up to sys.getswitchinterval() (5 ms):
        # next to a GUI thread busy in Python, playback in one feed thread
        # ran at x0.70 frame by frame and at x0.87 batched (measured).
        starts = np.arange(count) * HOP
        frames = self._in[starts[:, None] + np.arange(FRAME)] * self._window
        spectra = np.fft.rfft(frames, axis=1) * self._curve
        shaped = np.fft.irfft(spectra, n=FRAME, axis=1).astype(np.float32) * self._window
        # 50 % overlap-add: each hop out is a frame's first half plus the
        # previous frame's second half (the first one's is kept in _acc).
        previous = np.concatenate([self._acc[None, :HOP], shaped[:-1, HOP:]])
        out = (shaped[:, :HOP] + previous).reshape(-1, self.channels)
        self._acc = np.zeros((FRAME, self.channels), np.float32)
        self._acc[:HOP] = shaped[-1, HOP:]
        self._in = self._in[count * HOP:]
        return out

    def flush(self):
        """The rest, as if silence followed."""
        tail = self.process(np.zeros((FRAME, self.channels), np.float32))
        self.reset()
        return tail


__all__ = ["BANDS", "CUSTOM", "Equalizer", "FRAME", "HOP", "MAX_GAIN_DB", "PRESETS",
           "available", "clean_gains", "equalize_int16", "gains_ok", "is_flat", "preset_of"]
