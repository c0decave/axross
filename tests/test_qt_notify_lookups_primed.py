"""Qt Multimedia objects axross builds never make a Qt thread wait for the GIL.

Incident (core dump of a hung test run): the main thread held the GIL in
QMediaPlayer.stop() and waited for a Qt signal-slot lock. Qt FFmpeg's audio
renderer thread held that lock - QObject::~QObject() calls the sender's
disconnectNotify() while it holds its own lock (qtbase qobject.cpp) - and its
sender was the QAudioOutput axross made. A PyQt-made object is a sip
subclass: its disconnectNotify() first asks Python whether it is
reimplemented, which takes the GIL (sip_core.c, sip_api_is_py_method). The
renderer waited for the GIL, the main thread for the lock: a deadlock.

sip skips that question for good once it found no reimplementation
(``*pymc = 1``, "Use the fast track in future"), per object. So every such
object asks once on the GUI thread, right after it is made
(core.multimedia_env.prime_notify_lookups). The flag is observable: an
instance attribute named like the virtual is only called while sip still
looks it up.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QCoreApplication, QEvent, QObject, pyqtSignal  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import multimedia_env as ME  # noqa: E402

app = QApplication.instance() or QApplication([])


def _looked_up(obj: QObject) -> list[str]:
    """The notify virtuals sip still asks Python about for *obj*."""
    seen: list[str] = []
    obj.connectNotify = lambda method: seen.append("connectNotify")
    obj.disconnectNotify = lambda method: seen.append("disconnectNotify")

    def slot(*_args):
        pass

    obj.destroyed.connect(slot)
    obj.destroyed.disconnect(slot)
    del obj.connectNotify, obj.disconnectNotify
    return seen


class _Sender(QObject):
    ping = pyqtSignal()


# -- the helper -------------------------------------------------------------------------------

def test_happy_a_primed_object_is_never_asked_again():
    obj = _Sender()
    ME.prime_notify_lookups(obj)
    assert _looked_up(obj) == []


def test_happy_the_observable_sees_an_unprimed_object():
    """Without priming sip asks Python on each connect and disconnect - the
    question a Qt thread would need the GIL for."""
    assert set(_looked_up(_Sender())) == {"connectNotify", "disconnectNotify"}


def test_edge_priming_leaves_no_connection_and_can_be_repeated():
    obj = _Sender()
    for _ in range(10):
        ME.prime_notify_lookups(obj)
    # PyQt's slot proxies go with the next deferred delete
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    assert obj.receivers(obj.destroyed) == 0
    assert _looked_up(obj) == []


def test_sad_a_deleted_or_missing_object_is_ignored():
    from PyQt6 import sip

    obj = _Sender()
    sip.delete(obj)
    ME.prime_notify_lookups(obj)  # no exception
    ME.prime_notify_lookups(None)


def test_edge_a_real_qaudiooutput_is_primed():
    from PyQt6.QtMultimedia import QAudioOutput

    out = QAudioOutput()
    ME.prime_notify_lookups(out)
    assert _looked_up(out) == []


# -- every multimedia object axross makes -----------------------------------------------------

def _media_player_module():
    import importlib.util

    path = ROOT / "resources" / "extensions" / "media_player.py"
    spec = importlib.util.spec_from_file_location("mp_notify_primed", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules["mp_notify_primed"] = module
    spec.loader.exec_module(module)
    return module


def test_e2e_the_qmediaplayer_engine_primes_its_player_and_output():
    MP = _media_player_module()
    engine = MP.SimpleEngine()
    try:
        assert _looked_up(engine._player) == []
        assert _looked_up(engine._output) == []
    finally:
        engine.deleteLater()


def test_e2e_the_equalizer_engine_primes_its_decoder_and_sink():
    pytest.importorskip("numpy")
    MP = _media_player_module()
    engine = MP.EqEngine()
    try:
        assert _looked_up(engine._decoder) == []
        sink = MP.QtSink(MP.qt_format(MP.RATE, 2, "Float"))
        assert _looked_up(sink._sink) == []
    finally:
        engine.deleteLater()


def test_e2e_the_equalizer_engine_primes_what_its_threads_make(tmp_path):
    """The decoder, the timers, the sound card's QAudioSink and the
    objects that run work in the Media Player's own threads are made there,
    not on the GUI thread - and primed there."""
    np = pytest.importorskip("numpy")
    import wave

    MP = _media_player_module()
    track = tmp_path / "t.wav"
    with wave.open(str(track), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(MP.RATE)
        w.writeframes(np.zeros(MP.RATE, "<i2").tobytes())
    made = []

    def sink_factory(fmt):
        made.append(MP.QtSink(fmt))
        return made[-1]

    engine = MP.EqEngine(sink_factory=sink_factory, negotiate=lambda fmt: fmt)
    try:
        engine.load(str(track))
        engine.play()
        assert made, "no sink was made"
        objects = [engine._decoder, engine._timer, engine._eq_timer, engine._feed, engine._decode,
                   engine._eq, made[0]._sink]
        for obj in objects:
            assert obj.thread() is not app.thread(), type(obj).__name__
            assert _looked_up(obj) == [], type(obj).__name__
    finally:
        engine.close()


def test_e2e_the_media_preview_primes_its_player_and_output():
    from core.local_fs import LocalFS
    from ui import media_viewer as MV

    viewer = MV.MediaViewer(LocalFS())
    try:
        viewer._ensure_player()
        assert _looked_up(viewer._player) == []
        assert _looked_up(viewer._audio) == []
    finally:
        viewer.close()
        viewer.deleteLater()


_VOICE = """\
import json, os, sys
sys.path.insert(0, {root!r})
from PyQt6.QtCore import QCoreApplication, QEvent
from PyQt6.QtWidgets import QApplication
app = QApplication(["x"])
QCoreApplication.sendEvent(app, QEvent(QEvent.Type.User))
from core import multimedia_probe as MPROBE
assert MPROBE.probe(timeout=30).ok
from PyQt6.QtMultimedia import QMediaDevices
from ui import voice as V
sys.path.insert(0, {tests!r})
from test_qt_notify_lookups_primed import _looked_up
out = next(d for d in QMediaDevices.audioOutputs() if d.description() == {sink!r})
src = next(d for d in QMediaDevices.audioInputs() if d.description() == {source!r})
sink, io, rate = V._qt_sink(16000, device_id=bytes(out.id()).decode())
recorder = V.QtRecorder(device_id=bytes(src.id()).decode(), volume=1.0)
recorder.start()
result = {{"sink": _looked_up(sink), "source": _looked_up(recorder._source)}}
recorder.stop(); sink.stop()
print("RESULT " + json.dumps(result), flush=True)
os._exit(0)
"""


def test_e2e_the_voice_speaker_and_microphone_prime_their_audio_objects(tmp_path):
    """Real devices (a null sink and a source remapped from another one's
    monitor) on the user's PipeWire server, in a child: _qt_sink and
    QtRecorder only make their objects when a device is there."""
    import json
    import shutil
    import subprocess

    runtime = next((d for d in (os.environ.get("XDG_RUNTIME_DIR"), f"/run/user/{os.getuid()}")
                    if d and os.path.exists(os.path.join(d, "pipewire-0"))), "")
    if not (runtime and shutil.which("pactl")):
        pytest.skip("needs a PipeWire server and pactl")
    env = {**os.environ, "XDG_RUNTIME_DIR": runtime}
    tag = f"axprime{os.getpid()}"
    modules = []

    def load(*args):
        out = subprocess.run(["pactl", "load-module", *args], env=env, capture_output=True,
                             text=True, timeout=20)
        if out.returncode:
            pytest.skip(f"pactl: {out.stderr.strip()}")
        modules.append(out.stdout.strip())

    try:
        load("module-null-sink", f"sink_name={tag}_out", f"sink_properties=device.description={tag}_out")
        load("module-null-sink", f"sink_name={tag}_feed",
             f"sink_properties=device.description={tag}_feed")
        load("module-remap-source", f"master={tag}_feed.monitor", f"source_name={tag}_mic",
             f"source_properties=device.description={tag}_mic")
        script = tmp_path / "voice.py"
        script.write_text(_VOICE.format(root=str(ROOT), tests=str(ROOT / "tests"),
                                        sink=f"{tag}_out", source=f"{tag}_mic"))
        home = tmp_path / "home"
        home.mkdir()
        run_env = {**env, "HOME": str(home), "XDG_CONFIG_HOME": str(home / ".config"),
                   "QT_QPA_PLATFORM": "offscreen"}
        run_env.pop("DISPLAY", None)
        out = subprocess.run([sys.executable, str(script)], env=run_env, capture_output=True,
                             text=True, timeout=120)
    finally:
        for module in reversed(modules):
            subprocess.run(["pactl", "unload-module", module], env=env, capture_output=True,
                           timeout=20)
    line = next((ln for ln in out.stdout.splitlines() if ln.startswith("RESULT ")), "")
    assert line, out.stderr[-3000:]
    assert json.loads(line[len("RESULT "):]) == {"sink": [], "source": []}
