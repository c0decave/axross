"""The Media Player keeps real time while the GUI thread is busy.

Reported: "Media Player: The sound card plays at x0.19 speed through
PulseAudio (measured over 3 s) instead of x1.00. Choose PulseAudio (or
another output) in Edit > Settings… > Audio." - with PulseAudio in use.

Measured: the sound card was not slow. The equalizer engine's feed
(QAudioDecoder -> equalizer -> QAudioSink) ran on the GUI thread, and Qt's
FFmpeg decoder hands out its next buffer only after the last one was read:
read() asks the renderer thread for one more frame, which comes back as a
queued signal (qffmpegaudiodecoder.cpp read() -> nextBuffer() ->
Renderer::doForceStep()). So the decoder delivered one buffer (about 22 ms
of a 48 kHz MP3) per GUI event-loop iteration: with the GUI loop busy for
130 ms per iteration (painting, other work) playback ran at x0.18, with
40 ms at x0.52, and the sound card always had room - the feed starved. The
monitor counted frames written and blamed the sound card, suggesting the
backend that was already in use.

Now the feed runs in threads of its own - the decoder's, the equalizer's
and the one that writes to the sound card; the GUI thread only sends
commands and reads the position and the samples - and the monitor tells
"the sound card takes audio slower than real time" (its buffer full) from
"the Media Player could not deliver audio fast enough" (its buffer had
room, nothing was ready); only the first suggests another backend or
output, and never the backend in use.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import threading
import time
import wave
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

np = pytest.importorskip("numpy")
pytest.importorskip("PyQt6.QtMultimedia", reason="QtMultimedia not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])

_spec = importlib.util.spec_from_file_location(
    "media_player_feed_thread_ext", ROOT / "resources" / "extensions" / "media_player.py")
MP = importlib.util.module_from_spec(_spec)
sys.modules["media_player_feed_thread_ext"] = MP
_spec.loader.exec_module(MP)

#: How long one GUI event-loop iteration stays busy: the reported x0.19.
BUSY_SECONDS = 0.13
#: One long stall of the GUI thread during playback.
STALL_SECONDS = 2.0


# -- fixtures -------------------------------------------------------------------------------

def tone_wav(path: Path, seconds: float, rate: int = MP.RATE, channels: int = 2) -> Path:
    n = int(seconds * rate)
    t = np.arange(n) / rate
    pcm = (np.sin(2 * np.pi * 440 * t) * 0.3 * 32767).astype("<i2")
    with wave.open(str(path), "wb") as w:
        w.setnchannels(channels)
        w.setsampwidth(2)
        w.setframerate(rate)
        w.writeframes(np.repeat(pcm, channels).tobytes())
    return path


class PacedSink(MP.MemorySink):
    """A sound card: plays *rate* frames per second out of a 250 ms buffer.
    Run dry it plays silence - that time is lost, nothing catches up - and
    :attr:`dry` counts it (from its first call on: the start is in it)."""

    def __init__(self, rate: int = MP.RATE, bpf: int = 8) -> None:
        super().__init__()
        self.rate = rate
        self.bpf = bpf
        self.capacity = rate // 4
        self.level = 0.0
        self.dry = 0.0
        self.writer_threads: set[int] = set()
        #: Per write, taken in the writing (audio) thread: (time, frames
        #: written so far, frames buffered after it).
        self.writes: list[tuple[float, int, float]] = []
        self._last: float | None = None
        self._lock = threading.Lock()

    def _advance(self) -> None:
        now = time.monotonic()
        last, self._last = self._last, now
        if last is None or not self.running:
            return
        due = (now - last) * self.rate
        if due > self.level:
            self.dry += (due - self.level) / self.rate
            self.level = 0.0
        else:
            self.level -= due

    def bytes_free(self) -> int:
        with self._lock:
            self._advance()
            return int(self.capacity - self.level) * self.bpf if self.running else 0

    def write(self, data: bytes) -> int:
        with self._lock:
            self._advance()
            self.writer_threads.add(threading.get_ident())
            room = max(0, int(self.capacity - self.level)) * self.bpf
            taken = min(len(data), room)
            self.level += taken / self.bpf
            self.data += data[:taken]
            self.writes.append((self._last, len(self.data) // self.bpf, self.level))
            return taken

    def frames(self) -> int:
        return len(self.data) // self.bpf


def busy(seconds: float, how: str) -> None:
    """Keep the GUI thread busy: asleep ("sleep": work in C++ that lets go
    of the GIL) or running pure Python all the time ("python": it holds
    the GIL; the interpreter hands it over every sys.getswitchinterval())."""
    if how == "sleep":
        time.sleep(seconds)
        return
    end = time.perf_counter() + seconds
    x = 0
    while time.perf_counter() < end:
        x += 1


def run_busy_gui(seconds: float, how: str, probe=None) -> list:
    """A GUI loop that is busy for BUSY_SECONDS per iteration; *probe()*
    sampled with the time after each iteration."""
    samples = []
    start = time.monotonic()
    while time.monotonic() - start < seconds:
        APP.processEvents()
        busy(BUSY_SECONDS, how)
        if probe is not None:
            samples.append((time.monotonic() - start, probe()))
    return samples


def speed_between(samples, rate: int, t0: float) -> float:
    first = next(s for s in samples if s[0] >= t0)
    last = samples[-1]
    return (last[1] - first[1]) / (last[0] - first[0]) / rate


# -- 1. the regression: real time with a busy GUI thread -------------------------------------

def worker_speed(sink: PacedSink, t0: float, t1: float) -> tuple[float, float, float]:
    """From the writes the audio thread made between *t0* and *t1*
    (monotonic): frames written per second of wall clock against real
    time, the longest gap between two writes (s), and how long the card
    ran dry meanwhile (s)."""
    writes = [w for w in sink.writes if t0 <= w[0] <= t1]
    (first_t, first_n, first_level), (last_t, last_n, last_level) = writes[0], writes[-1]
    # Frames played = written minus what the buffer gained (it is kept full).
    played = (last_n - first_n) - (last_level - first_level)
    speed = played / (last_t - first_t) / sink.rate
    gap = max(b[0] - a[0] for a, b in zip(writes, writes[1:]))
    return speed, gap, sink.dry


@pytest.mark.parametrize("how", ["sleep", "python"])
def test_happy_e2e_playback_keeps_real_time_while_the_gui_thread_is_busy(tmp_path, how):
    """The reported case and worse: the GUI loop busy for 130 ms per
    iteration, and once stalled for 2 s, asleep or running pure Python.
    Measured in the audio thread, from its writes: x0.97-1.03, never a gap
    between writes as long as the card's buffer, the card never dry."""
    sink = PacedSink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    try:
        engine.load(str(tone_wav(tmp_path / "t.wav", 10.0)))
        engine.play()
        run_busy_gui(1.0, how)  # the start (decoding ahead, the first writes)
        t0, dry0 = time.monotonic(), sink.dry
        run_busy_gui(2.0, how)
        busy(STALL_SECONDS, how)  # one long stall
        run_busy_gui(2.0, how)
        t1 = time.monotonic()
        speed, gap, dry = worker_speed(sink, t0, t1)
        buffer_seconds = sink.capacity / sink.rate
        assert 0.97 <= speed <= 1.03, f"x{speed:.3f} with the GUI busy ({how})"
        assert gap < buffer_seconds, f"{gap:.3f} s between two writes ({how})"
        assert dry - dry0 < 0.005, f"the sound card ran dry for {dry - dry0:.3f} s ({how})"
        assert engine.error == ""
    finally:
        engine.close()


def test_happy_the_feed_runs_off_the_gui_thread(tmp_path):
    sink = PacedSink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    try:
        assert engine._decoder.thread() is not APP.thread()
        engine.load(str(tone_wav(tmp_path / "t.wav", 2.0)))
        engine.play()
        run_busy_gui(0.5, "sleep")
        assert sink.writer_threads, "nothing was written"
        assert threading.main_thread().ident not in sink.writer_threads
    finally:
        engine.close()


def test_happy_controls_still_answer_at_once(tmp_path):
    """Play, pause, seek and stop take effect before they return, as they
    did on the GUI thread (the panel reads the state right after)."""
    sink = PacedSink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    try:
        engine.load(str(tone_wav(tmp_path / "t.wav", 6.0)))
        engine.play()
        assert engine.state == "playing"
        engine.pause()
        assert engine.state == "paused"
        engine.seek(3000)
        assert engine.position_ms() == 3000 and engine.state == "paused"
        engine.play()
        assert engine.state == "playing"
        engine.stop()
        assert engine.state == "stopped" and engine.position_ms() == 0
    finally:
        engine.close()


def test_sad_a_command_that_fails_raises_in_the_caller():
    engine = MP.EqEngine(sink_factory=lambda fmt: PacedSink())
    try:
        with pytest.raises(ValueError):
            engine.set_gains([1.0, 2.0])  # ten bands, not two
    finally:
        engine.close()


def test_edge_close_stops_and_later_calls_do_nothing(tmp_path):
    sink = PacedSink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    engine.load(str(tone_wav(tmp_path / "t.wav", 4.0)))
    engine.play()
    run_busy_gui(0.3, "sleep")
    engine.close()
    assert engine.state == "stopped" and not sink.running
    written = sink.frames()
    engine.play()  # nothing: closed
    engine.seek(1000)
    engine.close()  # twice is fine
    run_busy_gui(0.3, "sleep")
    assert engine.state == "stopped" and sink.frames() == written


def test_edge_the_position_does_not_wait_for_a_slow_step(tmp_path, monkeypatch):
    """The GUI asks for the position several times a second: it gets the
    one after the audio thread's last step, also while a step takes long."""
    sink = PacedSink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    try:
        engine.load(str(tone_wav(tmp_path / "t.wav", 4.0)))
        engine.play()
        run_busy_gui(0.3, "sleep")
        original = MP.Equalizer.process
        monkeypatch.setattr(MP.Equalizer, "process",
                            lambda self, block: (time.sleep(0.3), original(self, block))[1])
        time.sleep(0.05)  # a pump is inside the slow equalizer now
        worst = 0.0
        for _ in range(10):
            start = time.perf_counter()
            position = engine.position_ms()
            worst = max(worst, time.perf_counter() - start)
            time.sleep(0.02)
        assert worst < 0.05, f"position_ms() waited {worst:.3f} s"
        assert position > 0
    finally:
        monkeypatch.undo()
        engine.close()


def test_edge_the_exit_handler_closes_engines_and_ends_the_threads(tmp_path):
    engine = MP.EqEngine(sink_factory=lambda fmt: PacedSink())
    engine.load(str(tone_wav(tmp_path / "t.wav", 4.0)))
    engine.play()
    threads = [MP.media_thread(name) for name in (MP.AUDIO_THREAD, MP.DECODER_THREAD,
                                                   MP.EQUALIZER_THREAD)]
    assert MP.end_media_threads() is True
    assert engine.closed and engine.state == "stopped"
    assert all(t.isFinished() for t in threads)
    assert MP.end_media_threads() is True  # nothing left: a no-op
    engine.play()  # closed: nothing, no hang
    # A later engine starts the threads anew and plays.
    sink = PacedSink()
    later = MP.EqEngine(sink_factory=lambda fmt: sink)
    try:
        later.load(str(tone_wav(tmp_path / "u.wav", 2.0)))
        later.play()
        run_busy_gui(0.4, "sleep")
        assert sink.frames() > 0 and later.state == "playing"
    finally:
        later.close()


def test_edge_a_deleted_engine_stops_its_feed(tmp_path):
    """The engine object deleted while it plays (its panel went): the audio
    thread stops feeding, no exception reaches Qt."""
    from PyQt6 import sip

    sink = PacedSink()
    engine = MP.EqEngine(sink_factory=lambda fmt: sink)
    engine.load(str(tone_wav(tmp_path / "t.wav", 6.0)))
    engine.play()
    run_busy_gui(0.3, "sleep")
    sip.delete(engine)
    time.sleep(0.2)
    written = sink.frames()
    run_busy_gui(0.5, "sleep")
    assert sink.frames() == written


# -- 2. the monitor: sound card or feed --------------------------------------------------------

def feed_monitor(monitor, speed, starved, backend="", seconds=4.0, rate=44100, step=0.05):
    """*starved*: a bool for every update, or a share (0..1) of them."""
    t, frames, n, problem = 0.0, 0, 0, None
    while t <= seconds:
        flag = starved if isinstance(starved, bool) else (n % 10) < starved * 10
        problem = monitor.update(t, frames, backend, starved=flag) or problem
        t += step
        frames += int(rate * speed * step)
        n += 1
    return problem


@pytest.mark.parametrize("backend, other", [("PulseAudio", "PipeWire"),
                                            ("PipeWire", "PulseAudio")])
def test_happy_a_slow_sound_card_suggests_the_other_backend_only(backend, other):
    problem = feed_monitor(MP.PlaybackMonitor(44100), 0.5, False, backend)
    assert problem is not None and "x0.50" in problem and "sound card" in problem
    assert f"through {backend}" in problem
    assert f"Choose the {other} backend or another output device" in problem
    assert f"Choose the {backend}" not in problem and f"{backend} backend" not in problem


def test_edge_the_backends_named_are_the_ones_settings_offers():
    from core import multimedia_env

    assert set(MP.BACKEND_LABELS) == set(multimedia_env.AUDIO_BACKENDS)
    for label in MP.BACKEND_LABELS.values():
        assert label not in MP.output_hint(label)


def test_happy_an_unknown_backend_names_both():
    problem = feed_monitor(MP.PlaybackMonitor(44100), 0.5, False, "")
    assert "PulseAudio or PipeWire" in problem and "another output device" in problem


def test_sad_a_starved_feed_is_not_blamed_on_the_sound_card():
    """The report's numbers: x0.18 while the sound card had room."""
    problem = feed_monitor(MP.PlaybackMonitor(44100), 0.18, True, "PulseAudio")
    assert problem is not None
    assert "could not deliver audio fast enough" in problem and "x0.18" in problem
    assert "The sound card is not the cause" in problem
    assert "Choose" not in problem and "plays at" not in problem


def test_sad_a_feed_that_delivers_nothing_says_so():
    problem = feed_monitor(MP.PlaybackMonitor(44100), 0.0, True, "PipeWire")
    assert problem is not None and "delivered no audio" in problem
    assert "Choose" not in problem and "takes no audio" not in problem


def test_sad_a_full_sound_card_that_takes_nothing_still_suggests_another_output():
    problem = feed_monitor(MP.PlaybackMonitor(44100), 0.0, False, "PulseAudio")
    assert "takes no audio" in problem and "Choose the PipeWire backend" in problem


def test_edge_too_fast_is_the_sound_card_whatever_the_feed_did():
    problem = feed_monitor(MP.PlaybackMonitor(44100), 2.0, True, "PipeWire")
    assert "x2.00" in problem and "Choose the PulseAudio backend" in problem


@pytest.mark.parametrize("share, feed", [(0.3, False), (0.4, False), (0.7, True)])
def test_edge_the_feed_is_blamed_only_when_most_of_the_window_starved(share, feed):
    problem = feed_monitor(MP.PlaybackMonitor(44100), 0.5, share, "PulseAudio")
    assert problem is not None
    assert ("could not deliver" in problem) is feed


def test_edge_real_time_is_no_problem_even_when_starved_now_and_then():
    assert feed_monitor(MP.PlaybackMonitor(44100), 1.0, 0.3, "PulseAudio") is None


# -- 3. the monitor through the engine and the panel -----------------------------------------

def _slow_equalizer(monkeypatch, factor: float) -> None:
    """The equalizer takes *factor* times the length of what it is given."""
    original = MP.Equalizer.process

    def process(self, block):
        time.sleep(len(block) / self.rate * factor)
        return original(self, block)

    monkeypatch.setattr(MP.Equalizer, "process", process)


def test_sad_e2e_a_slow_feed_is_reported_as_the_media_players(tmp_path, monkeypatch):
    """The equalizer step made slower than real time: the sound card has
    room and waits - the message says so and suggests no other output."""
    monkeypatch.setattr(MP, "MONITOR_WINDOW_SECONDS", 1.0)
    monkeypatch.setattr(MP, "_backend_name", lambda: "PulseAudio")
    _slow_equalizer(monkeypatch, 2.5)  # x0.4
    problems = []
    engine = MP.EqEngine(sink_factory=lambda fmt: PacedSink())
    engine.playback_problem.connect(problems.append)
    try:
        engine.load(str(tone_wav(tmp_path / "t.wav", 6.0)))
        engine.play()
        end = time.monotonic() + 4
        while not problems and time.monotonic() < end:
            APP.processEvents()
            time.sleep(0.01)
    finally:
        engine.close()
    assert problems, "no problem reported"
    assert "could not deliver audio fast enough" in problems[0], problems[0]
    assert "Choose" not in problems[0]


def test_sad_e2e_a_full_sound_card_never_suggests_the_backend_in_use(tmp_path, monkeypatch):
    class DeafSink(MP.MemorySink):
        def bytes_free(self):
            return 0

    monkeypatch.setattr(MP, "MONITOR_WINDOW_SECONDS", 0.6)
    monkeypatch.setattr(MP, "_backend_name", lambda: "PulseAudio")
    problems = []
    engine = MP.EqEngine(sink_factory=lambda fmt: DeafSink())
    engine.playback_problem.connect(problems.append)
    try:
        engine.load(str(tone_wav(tmp_path / "t.wav", 3.0)))
        engine.play()
        end = time.monotonic() + 3
        while not problems and time.monotonic() < end:
            APP.processEvents()
            time.sleep(0.01)
    finally:
        engine.close()
    assert problems and "takes no audio through PulseAudio" in problems[0]
    assert "Choose the PipeWire backend" in problems[0]
    assert "Choose the PulseAudio" not in problems[0]


def test_e2e_the_panel_shows_a_slow_feed_and_its_shutdown_closes_the_engine(
        tmp_path, monkeypatch):
    monkeypatch.setattr(MP, "MONITOR_WINDOW_SECONDS", 1.0)
    _slow_equalizer(monkeypatch, 2.5)
    sink = PacedSink()
    notices = []
    panel = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: sink))
    try:
        panel.engine_failed.connect(notices.append)
        panel.add_files([str(tone_wav(tmp_path / "t.wav", 6.0))])
        panel.play_item(panel.playlist.item(0))
        end = time.monotonic() + 4
        while not notices and time.monotonic() < end:
            APP.processEvents()
            time.sleep(0.01)
        assert notices and "could not deliver audio fast enough" in notices[0]
        assert "could not deliver audio fast enough" in panel.note.text()
        panel.shutdown()
        assert panel.engine.closed and not sink.running
    finally:
        panel.close()


# -- 4. real sound servers: a null sink, the GUI busy ------------------------------------------

def _runtime() -> str:
    for folder in (os.environ.get("XDG_RUNTIME_DIR"), f"/run/user/{os.getuid()}"):
        if folder and os.path.exists(os.path.join(folder, "pipewire-0")):
            return folder
    return ""


RUNTIME = _runtime()
FROZEN = os.environ.get("AXROSS_FROZEN_BINARY", "")
_BUSY_SPEED = """\
import os, sys, time, importlib.util
sys.path.insert(0, {root!r})
from PyQt6.QtWidgets import QApplication
app = QApplication.instance() or QApplication(["x"])
import core
ext = os.path.join(os.path.dirname(os.path.dirname(core.__file__)), "resources", "extensions",
                   "media_player.py")
spec = importlib.util.spec_from_file_location("mpx", ext); MPX = importlib.util.module_from_spec(spec)
sys.modules["mpx"] = MPX; spec.loader.exec_module(MPX)
from PyQt6.QtMultimedia import QMediaDevices
from core import audio_route
dev = next(d for d in QMediaDevices.audioOutputs() if d.description() == {sink!r})
audio_route.output_device = lambda *a: dev
eng = MPX.default_engine()
problems = []
# EqEngine (numpy, full) reports playback_problem; SimpleEngine (QMediaPlayer, slim) failed.
(getattr(eng, "playback_problem", None) or eng.failed).connect(problems.append)
print("ENGINE", type(eng).__name__, flush=True)
eng.load({track!r}); eng.play()
def gui(seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents(); time.sleep({busy!r})  # the GUI thread busy
gui(1.0)  # the start
p0 = (eng.position_ms(), time.monotonic())
gui(2.0)
time.sleep({stall!r})  # one long stall
gui(2.0)
p1 = (eng.position_ms(), time.monotonic())
line = "SPEED %s %r %r" % ((p1[0] - p0[0]) / 1000 / (p1[1] - p0[1]), eng.error, problems)
if hasattr(eng, "close"):
    eng.close()
if os.environ.get("SPEED_OUT"):
    open(os.environ["SPEED_OUT"], "w").write(line)
else:
    print(line)
"""


@pytest.fixture
def null_sink():
    if not RUNTIME:
        pytest.skip("no PipeWire server")
    env = {**os.environ, "XDG_RUNTIME_DIR": RUNTIME}
    if subprocess.run(["pactl", "info"], env=env, capture_output=True, timeout=20).returncode:
        pytest.skip("pactl cannot reach the server")
    name = f"axbusy{os.getpid()}"
    out = subprocess.run(["pactl", "load-module", "module-null-sink", f"sink_name={name}",
                          "format=s16le", "rate=48000", "channels=2",
                          f"sink_properties=device.description={name}"],
                         env=env, capture_output=True, text=True, timeout=20)
    if out.returncode:
        pytest.skip(f"no null sink: {out.stderr.strip()}")
    yield env, name
    subprocess.run(["pactl", "unload-module", out.stdout.strip()], env=env,
                   capture_output=True, timeout=20)


def _run_script(code: str, env: dict, tmp_path) -> str:
    """*code* with this tree's Python, or in the built binary
    (AXROSS_FROZEN_BINARY) through --script."""
    if not FROZEN:
        return subprocess.run([sys.executable, "-c", code], env=env, capture_output=True,
                              text=True, timeout=90).stdout
    script, out = tmp_path / "busy_speed.py", tmp_path / "busy_speed.out"
    script.write_text(code)
    out.unlink(missing_ok=True)
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    subprocess.run([FROZEN, "--script", str(script)],
                   env={**env, "HOME": str(home), "SPEED_OUT": str(out)},
                   capture_output=True, timeout=150)
    return out.read_text() if out.exists() else ""


@pytest.mark.parametrize("backend", ["pulseaudio", "pipewire"])
def test_e2e_real_time_on_a_null_sink_while_the_gui_thread_is_busy(tmp_path, null_sink, backend):
    """The operator's case on a real server: 48 kHz mono, the GUI loop busy
    130 ms per iteration and once stalled for 2 s. Before: x0.18 and a
    message blaming the sound card."""
    env, name = null_sink
    track = tone_wav(tmp_path / "t.wav", 10.0, rate=48000, channels=1)
    env = {**env, "QT_AUDIO_BACKEND": backend, "QT_QPA_PLATFORM": "offscreen"}
    env.pop("DISPLAY", None)
    code = _BUSY_SPEED.format(root=str(ROOT), sink=name, track=str(track), busy=BUSY_SECONDS,
                              stall=STALL_SECONDS)
    out = _run_script(code, env, tmp_path)
    line = next((ln for ln in out.splitlines() if ln.startswith("SPEED")), "SPEED 0 none")
    speed = float(line.split()[1])
    assert 0.97 <= speed <= 1.03, f"{backend}: {line}"
    assert line.endswith("'' []"), f"{backend}: {line}"


# -- 5. the end of the process ---------------------------------------------------------------

_EXIT = """\
import os, sys, time, importlib.util, wave
sys.path.insert(0, {root!r})
from PyQt6.QtWidgets import QApplication
app = QApplication.instance() or QApplication(["x"])
if {orderly!r}:
    from core import qt_exit
    qt_exit.install_orderly_qt_exit()
spec = importlib.util.spec_from_file_location("mpx", {ext!r}); MPX = importlib.util.module_from_spec(spec)
sys.modules["mpx"] = MPX; spec.loader.exec_module(MPX)
class RealTimeSink(MPX.MemorySink):
    def bytes_free(self):
        return 441 * 8 if self.running else 0  # 10 ms per 10 ms tick: real time

if {late!r}:
    probe = MPX.EqEngine(sink_factory=lambda fmt: MPX.MemorySink())  # handler registered first
    from core import qt_exit
    qt_exit.install_orderly_qt_exit()  # runs before it
engines = []
for _ in range(3):
    eng = MPX.EqEngine(sink_factory=lambda fmt: RealTimeSink())
    eng.load({track!r}); eng.play()
    engines.append(eng)
end = time.monotonic() + 0.5
while time.monotonic() < end:
    app.processEvents(); time.sleep(0.01)
print("PLAYING", [e.state for e in engines])
"""


@pytest.mark.parametrize("orderly, late", [(False, False), (True, False), (False, True)])
def test_edge_exit_while_playing_ends_cleanly(tmp_path, orderly, late):
    """Engines left playing at the exit, without core.qt_exit, with it
    installed before the Media Player's exit handler (it runs after it) and
    after it (it runs first and deletes the engines): the threads end, no
    "QThread: Destroyed while thread is still running" abort, no crash."""
    track = tone_wav(tmp_path / "t.wav", 30.0)
    code = _EXIT.format(root=str(ROOT), ext=str(ROOT / "resources" / "extensions" /
                                                "media_player.py"),
                        track=str(track), orderly=orderly, late=late)
    for _ in range(3):
        done = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                              timeout=60, env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
        assert done.returncode == 0, (done.returncode, done.stderr[-2000:])
        assert "PLAYING ['playing', 'playing', 'playing']" in done.stdout
        assert "Destroyed while thread" not in done.stderr
