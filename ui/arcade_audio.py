"""The Arcade's sound: core.arcade.sound's effects and each world's music,
mixed in software and pushed to one QAudioSink on the Audio Mixer's
"Arcade" channel (its volume, mute and output; Edit > Settings > Audio).

Never in the way: Qt Multimedia is touched only after axross's multimedia
probe answered ok (as the voice does - a hanging audio server must not
freeze the window); without sound everything here is silent and nothing
fails. While the probe is still running the sink is tried again a moment
later (it used to give up for the whole session on the first effect).

Latency - why effects came late: the old pump wrote 20 ms every 20 ms
into a sink opened with the voice's 250 ms buffer, open loop. Nothing
looked at how much was queued: the audio server only starts a stream
once its buffer is full, every GUI hiccup (a level being built, a slow
frame) made it run dry and fill up again, and the queue then stayed full -
every effect waited behind up to a quarter second of music or silence.
Now the sink gets a small buffer (:data:`LEAD_MS`) of its own and a
precise 5 ms pump tops it up to exactly that from the sink's own
``bytesFree()`` - closed loop: an effect is heard after at most one
buffer, a stall of the GUI thread shorter than the buffer is no gap, and
a longer one is caught up on the next pump instead of piling up.
:meth:`ArcadeAudio.play` pumps at once, so an effect does not even wait
for the timer. Mixing is a few hundred samples per pump; while nothing
sounds nothing is written - the sink runs dry and the next effect goes
out at the front of an empty buffer.

Effects are rendered in a thread and kept in ~/.cache/axross/arcade/ (so
the next start has them at once); one asked for before they are ready
still plays if it is fresh. Music loops are rendered in a thread and
cached the same way.
"""

from __future__ import annotations

import array
import hashlib
import logging
import threading
import time
from pathlib import Path

from PyQt6.QtCore import QObject, Qt, QTimer

from core import audio_route as AR
from core.arcade import sound as S

log = logging.getLogger(__name__)

CACHE = Path.home() / ".cache" / "axross" / "arcade"
SOUND_VERSION = "v2"
LEAD_MS = 50                    # the sink's buffer: what an effect waits at most
PUMP_MS = 5                     # how often it is topped up
CHUNK = S.RATE // 50            # 20 ms: what a pump writes to a sink that does not tell its fill
MAX_VOICES = 12
FRESH_S = 1.5                   # an effect asked for before rendering ended still plays if this fresh
RETRY_MS = 700                  # the multimedia probe is still running: try the sink again


def lead_bytes(rate: int = S.RATE) -> int:
    """The sink buffer in bytes (16-bit mono) for :data:`LEAD_MS`."""
    return int(rate * LEAD_MS / 1000) * 2


def open_sink(rate: int, device_id: str | None, volume: float, buffer_bytes: int):
    """(QAudioSink, its QIODevice) for mono int16 at *rate* with a buffer
    of *buffer_bytes* - ui.voice opens its sink with 250 ms, far too much
    for a game."""
    from PyQt6.QtMultimedia import QAudio, QAudioFormat, QAudioSink, QMediaDevices

    from core.multimedia_env import prime_notify_lookups
    from ui.voice import _audio_ready

    _audio_ready()
    device = AR.output_device(device_id) or QMediaDevices.defaultAudioOutput()
    if device.isNull():
        raise OSError("no audio output")
    fmt = QAudioFormat()
    fmt.setSampleRate(rate)
    fmt.setChannelCount(1)
    fmt.setSampleFormat(QAudioFormat.SampleFormat.Int16)
    if not device.isFormatSupported(fmt):
        raise OSError(f"the output does not take {rate} Hz mono")
    sink = QAudioSink(device, fmt)
    prime_notify_lookups(sink)
    sink.setBufferSize(buffer_bytes)
    sink.setVolume(volume)
    io = sink.start()
    if io is None or sink.error() != QAudio.Error.NoError:
        sink.deleteLater()
        raise OSError("the audio output could not be opened")
    log.debug("Arcade: sink open, buffer %d bytes asked, %d given", buffer_bytes, sink.bufferSize())
    return sink, io


def _limit(x: float) -> int:
    """A soft knee above ~0.7 of full scale instead of hard clipping when
    many voices sound together."""
    a = abs(x)
    if a <= 23000:
        return int(x)
    soft = 23000 + (a - 23000) / (1 + (a - 23000) / 9000)
    return int(min(32767, soft) if x > 0 else -min(32767, soft))


class ArcadeAudio(QObject):
    def __init__(self, parent=None, *, sink_factory=None):
        super().__init__(parent)
        self._sink_factory = sink_factory
        self._sink = self._io = None
        self._failed = False
        self._effects: dict[str, array.array] = {}
        self._waiting: list[tuple[str, float, float]] = []   # (name, gain, asked at)
        self._playing: list[list] = []         # [samples, position, gain]
        self._music: array.array | None = None
        self._music_pos = 0
        self._music_gain = 0.5
        self._music_key = None
        self.muted = False
        self.written = 0                       # frames handed to the sink (tests, diagnostics)
        self._mixer_connected = False
        self._lock = threading.Lock()
        self._timer = QTimer(self)
        self._timer.setTimerType(Qt.TimerType.PreciseTimer)
        self._timer.timeout.connect(self._pump)
        self._retry = QTimer(self)
        self._retry.setSingleShot(True)
        self._retry.timeout.connect(self._ensure_sink)
        threading.Thread(target=self._render_effects, daemon=True, name="arcade-sfx").start()

    # -- rendering -----------------------------------------------------------------------------

    def _render_effects(self) -> None:
        done = {}
        for name, effect in S.EFFECTS.items():
            key = hashlib.sha256(f"{SOUND_VERSION}:{S.RATE}:{effect!r}".encode()).hexdigest()[:24]
            path = CACHE / "sfx" / f"{key}.pcm"
            try:
                pcm = path.read_bytes()
            except OSError:
                pcm = S.render(effect)
                try:
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(pcm)
                except OSError:
                    pass
            samples = array.array("h")
            samples.frombytes(pcm)
            done[name] = samples
            with self._lock:                   # each one usable as soon as it is there
                self._effects = dict(done)

    def music(self, seed: int | None, mood: str = "") -> None:
        """Start the world's loop (None: no music)."""
        key = None if seed is None else (seed, mood)
        if key == self._music_key:
            return
        self._music_key = key
        with self._lock:
            self._music, self._music_pos = None, 0
        if key is None:
            return
        threading.Thread(target=self._render_music, args=(key,), daemon=True, name="arcade-music").start()
        self._ensure_sink()

    def _render_music(self, key) -> None:
        seed, mood = key
        name = hashlib.sha256(f"{SOUND_VERSION}:{seed}:{mood}".encode()).hexdigest()[:24]
        path = CACHE / f"{name}.pcm"
        try:
            pcm = path.read_bytes()
        except OSError:
            pcm = S.render_tune(S.compose(seed, mood=mood))
            try:
                CACHE.mkdir(parents=True, exist_ok=True)
                path.write_bytes(pcm)
            except OSError:
                pass
        samples = array.array("h")
        samples.frombytes(pcm)
        with self._lock:
            if self._music_key == key:
                self._music, self._music_pos = samples, 0

    # -- playing -------------------------------------------------------------------------------

    def play(self, name: str, gain: float = 1.0) -> None:
        with self._lock:
            samples = self._effects.get(name)
            if samples is None:
                if name in S.EFFECTS:          # not rendered yet: played when it is, if still fresh
                    self._waiting.append((name, gain, time.monotonic()))
                    del self._waiting[:-MAX_VOICES]
            else:
                self._start_voice(samples, gain)
        self._ensure_sink()
        if samples is not None:
            self._pump()                       # into the sink now, not on the next timer

    def _start_voice(self, samples, gain) -> None:
        if len(self._playing) >= MAX_VOICES:
            self._playing.pop(0)
        self._playing.append([samples, 0, gain])

    def stop(self) -> None:
        self._timer.stop()
        self._retry.stop()
        with self._lock:
            self._playing.clear()
            self._waiting.clear()
            self._music = None
            self._music_key = None
        if self._sink is not None:
            try:
                self._sink.stop()
            except Exception:  # noqa: BLE001
                pass
        self._sink = self._io = None

    def _ensure_sink(self) -> None:
        if self._sink is not None or self._failed:
            return
        try:
            if self._sink_factory is not None:
                self._sink, self._io = self._sink_factory()
            else:
                from ui.voice import AudioPending

                try:
                    self._sink, self._io = open_sink(S.RATE, AR.source_output_id("games"),
                                                     AR.source_gain("games"), lead_bytes())
                except AudioPending:
                    log.debug("Arcade: audio still starting, trying again")
                    if not self._retry.isActive():
                        self._retry.start(RETRY_MS)
                    return
                if not self._mixer_connected:
                    AR.notifier().changed.connect(self._mixer_changed)
                    self._mixer_connected = True
        except Exception as exc:  # noqa: BLE001 - no sound: the games run silent
            log.info("Arcade: no sound (%s)", exc)
            self._failed = True
            return
        self._timer.start(PUMP_MS)

    def _mixer_changed(self, *_args) -> None:
        """The Audio Mixer's Arcade volume / mute reach the running sink."""
        if self._sink is not None:
            try:
                self._sink.setVolume(AR.source_gain("games"))
            except Exception:  # noqa: BLE001 - the sink went away
                pass

    # -- the pump ------------------------------------------------------------------------------

    def _frames_wanted(self) -> int:
        """How many frames the sink takes now: its free space (closed loop),
        or one chunk for a sink that does not tell."""
        sink = self._sink
        free = getattr(sink, "bytesFree", None)
        if free is None:
            return CHUNK
        try:
            return max(0, int(free()) // 2)
        except Exception:  # noqa: BLE001 - the device went away
            return 0

    def _pump(self) -> None:
        if self._io is None:
            return
        if not (self._playing or self._waiting or self._music is not None):
            return                             # nothing sounds: let the sink run dry, the next effect starts at once
        n = self._frames_wanted()
        if n <= 0:
            return
        out = self.mix(n)
        try:
            self._io.write(out.tobytes())
        except Exception:  # noqa: BLE001 - the device went away
            self.stop()
            self._failed = True
            return
        self.written += n

    def mix(self, n: int) -> array.array:
        """The next *n* frames: every playing effect and the music."""
        mix = [0.0] * n
        now = time.monotonic()
        with self._lock:
            if self._waiting:
                still = []
                for name, gain, asked in self._waiting:
                    samples = self._effects.get(name)
                    if samples is not None:
                        if now - asked < FRESH_S:
                            self._start_voice(samples, gain)
                    elif now - asked < FRESH_S:
                        still.append((name, gain, asked))
                self._waiting = still
            keep = []
            for voice in self._playing:
                samples, pos, gain = voice
                end = min(len(samples), pos + n)
                g = gain * 0.6
                seg = samples[pos:end]
                for i, s in enumerate(seg):
                    mix[i] += s * g
                voice[1] = end
                if end < len(samples):
                    keep.append(voice)
            self._playing = keep
            m = self._music
            if m is not None and len(m):
                p, g = self._music_pos, self._music_gain
                length = len(m)
                i = 0
                while i < n:
                    take = min(n - i, length - p)
                    for k, s in enumerate(m[p:p + take]):
                        mix[i + k] += s * g
                    i += take
                    p = (p + take) % length
                self._music_pos = p
        if self.muted:
            return array.array("h", bytes(2 * n))
        return array.array("h", [_limit(x) for x in mix])
