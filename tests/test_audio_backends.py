"""PulseAudio and PipeWire: the audio settings, the backend Qt uses, the
probe that finds a working one, and the device lists it reports.

Measured on the release binary (Qt 6.10): Qt Multimedia's PipeWire backend
deadlocked in the probe child - the child's main thread held the GIL inside
QMediaDevices.audioOutputs() and waited for PipeWire's loop lock, while the
PipeWire thread held that lock and waited for the GIL in PyQt's
QGuiApplication.notify() (sip checks once per object whether Python
overrides notify, and caches the answer). A fresh app had never delivered
an event, so the check was still due; in the running app it had long been
made. One event sent before the first multimedia object removes it.

QT_AUDIO_BACKEND (Qt 6.10 and 6.11, measured): unset - PipeWire when its
daemon runs, else PulseAudio; "pipewire"; "pulseaudio"; anything else -
PulseAudio.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import audio_settings as AS  # noqa: E402
from core import multimedia_env as ME  # noqa: E402
from core import multimedia_probe as MP  # noqa: E402
from core import subprocess_env as SE  # noqa: E402

VAR = "QT_AUDIO_BACKEND"


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.delenv(VAR, raising=False)
    ME._SET_BY_AXROSS.discard(VAR)
    MP.reset()
    monkeypatch.setattr(MP, "_active_backend", None)
    yield
    # probe() sets the variable itself; monkeypatch.delenv only restores a
    # value that was there before, so a set one leaked into later tests (an
    # app started from them took it as the user's own choice).
    os.environ.pop(VAR, None)
    ME._SET_BY_AXROSS.discard(VAR)
    MP.reset()


# -- the settings --------------------------------------------------------------

def test_happy_defaults_follow_the_system(tmp_path):
    s = AS.AudioSettings.load(tmp_path / "audio.json")
    assert (s.backend, s.output_device, s.input_device) == ("auto", "", "")
    assert (s.output_volume, s.input_volume) == (100, 100)


def test_happy_settings_round_trip_privately(tmp_path):
    path = tmp_path / "cfg" / "audio.json"
    s = AS.AudioSettings()
    s.set("backend", "pulseaudio")
    s.set("output_device", "alsa_output.pci-0000_00_05.0.analog-stereo")
    s.set("input_volume", 35)
    s.save(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    again = AS.AudioSettings.load(path)
    assert again == s
    assert json.loads(path.read_text())["version"] == 1


def test_sad_invalid_values_are_refused_and_keep_their_default(tmp_path):
    s = AS.AudioSettings()
    for name, value in (("backend", "PipeWire"), ("backend", "alsa"), ("output_volume", 101),
                        ("input_volume", -1), ("output_volume", True), ("output_device", 7)):
        with pytest.raises(ValueError):
            s.set(name, value)
    with pytest.raises(KeyError):
        s.set("colour", "red")
    path = tmp_path / "audio.json"
    path.write_text(json.dumps({"backend": "jack", "output_volume": 400, "input_device": "mic"}))
    loaded = AS.AudioSettings.load(path)
    assert (loaded.backend, loaded.output_volume, loaded.input_device) == ("auto", 100, "mic")


def test_edge_a_file_that_is_no_json_is_the_defaults(tmp_path):
    path = tmp_path / "audio.json"
    path.write_text("{not json")
    assert AS.AudioSettings.load(path) == AS.AudioSettings()
    path.write_text("[1, 2]")
    assert AS.AudioSettings.load(path) == AS.AudioSettings()


# -- the backend in the environment ----------------------------------------------

def test_happy_a_chosen_backend_is_set_for_qt():
    env = {}
    assert ME.apply_audio_backend("pipewire", env) == "pipewire"
    assert env[VAR] == "pipewire" and VAR in ME.set_by_axross()


def test_happy_auto_leaves_the_choice_to_qt():
    env = {}
    assert ME.apply_audio_backend("auto", env) is None
    assert VAR not in env


def test_sad_the_users_own_variable_wins():
    env = {VAR: "pulseaudio"}
    assert ME.apply_audio_backend("pipewire", env) is None
    assert env[VAR] == "pulseaudio" and VAR not in ME.set_by_axross()


def test_sad_an_unknown_backend_name_is_refused():
    with pytest.raises(ValueError):
        ME.apply_audio_backend("PipeWire", {})


def test_edge_what_axross_set_may_be_replaced_but_never_reaches_host_programs():
    env = {}
    ME.apply_audio_backend("pipewire", env)
    assert ME.apply_audio_backend("pulseaudio", env) == "pulseaudio"  # the probe's fallback
    assert env[VAR] == "pulseaudio"
    assert VAR not in SE.clean_child_env(env)
    assert SE.worker_env(env)[VAR] == "pulseaudio"  # axross's own children keep it


# -- which backends the probe tries ------------------------------------------------

def test_happy_auto_prefers_pulseaudio_where_a_pulse_server_answers():
    """Measured: PulseAudio (also through pipewire-pulse) played on every
    sink tried; Qt's PipeWire backend left mono sinks silent."""
    assert MP.backend_order("auto", {}, platform="linux", pipewire=True,
                            pulse=True) == ["pulseaudio", "pipewire"]


def test_happy_auto_takes_pipewire_first_without_a_pulse_server():
    assert MP.backend_order("auto", {}, platform="linux", pipewire=True,
                            pulse=False) == ["pipewire", "pulseaudio"]


def test_happy_auto_tries_pulseaudio_only_without_pipewire():
    assert MP.backend_order("auto", {}, platform="linux", pipewire=False,
                            pulse=True) == ["pulseaudio"]
    assert MP.backend_order("auto", {}, platform="linux", pipewire=False,
                            pulse=False) == ["pulseaudio"]


def test_edge_a_pulse_server_is_found_by_its_socket_or_variable(tmp_path):
    assert not MP.pulse_running({"XDG_RUNTIME_DIR": str(tmp_path)})
    (tmp_path / "pulse").mkdir()
    (tmp_path / "pulse" / "native").write_text("")
    assert MP.pulse_running({"XDG_RUNTIME_DIR": str(tmp_path)})
    assert MP.pulse_running({"PULSE_SERVER": "unix:/x", "XDG_RUNTIME_DIR": "/nowhere"})


def test_sad_a_backend_that_lists_no_output_falls_back_to_the_next(monkeypatch):
    dev = MP.AudioDeviceInfo("alsa_output.x", "Speakers", True)
    calls = _fake_runs(monkeypatch, {
        "pulseaudio": MP.ProbeResult(True, "", 0.1, 0, 0, backend="pulseaudio"),
        "pipewire": MP.ProbeResult(True, "", 0.1, 1, 0, backend="pipewire", output_devices=(dev,)),
    })
    result = MP.probe()
    assert calls == ["pulseaudio", "pipewire"]
    assert result.backend == "pipewire"


def test_edge_the_last_backend_with_no_output_is_still_the_answer(monkeypatch):
    _fake_runs(monkeypatch, {"pulseaudio": MP.ProbeResult(True, "", 0.1, 0, 0, backend="pulseaudio")})
    result = MP.probe()
    assert result.ok and result.backend == "pulseaudio" and result.outputs == 0


def test_sad_an_explicit_choice_is_the_only_one_tried():
    assert MP.backend_order("pipewire", {}, platform="linux", pipewire=True) == ["pipewire"]
    assert MP.backend_order("pulseaudio", {}, platform="linux", pipewire=True) == ["pulseaudio"]


def test_sad_the_users_own_variable_is_the_only_one_tried():
    env = {VAR: "pipewire"}
    assert MP.backend_order("pulseaudio", env, platform="linux", pipewire=True) == ["pipewire"]


def test_edge_other_platforms_leave_the_backend_to_qt():
    assert MP.backend_order("auto", {}, platform="darwin", pipewire=False) == [""]
    assert MP.backend_order("pulseaudio", {}, platform="win32", pipewire=False) == [""]


def test_edge_pipewire_is_found_by_its_socket(tmp_path):
    assert not MP.pipewire_running({"XDG_RUNTIME_DIR": str(tmp_path)})
    (tmp_path / "pipewire-0").write_text("")
    assert MP.pipewire_running({"XDG_RUNTIME_DIR": str(tmp_path)})
    assert MP.pipewire_running({"PIPEWIRE_REMOTE": "/some/socket", "XDG_RUNTIME_DIR": "/nowhere"})


# -- the probe: fallback and device lists ---------------------------------------------

def _fake_runs(monkeypatch, answers):
    calls = []

    def fake(timeout=None, *, command=None, env=None, backend=""):
        calls.append(backend)
        return answers[backend]

    monkeypatch.setattr(MP, "run_probe", fake)
    monkeypatch.setattr(MP, "backend_order", lambda *a, **k: list(answers))
    return calls


def test_happy_a_hung_backend_falls_back_to_the_next(monkeypatch):
    dev = MP.AudioDeviceInfo("alsa_output.x", "Built-in Audio", True)
    calls = _fake_runs(monkeypatch, {
        "pipewire": MP.ProbeResult(False, "Qt Multimedia did not answer within 15 s", 15.0,
                                   step="audio devices"),
        "pulseaudio": MP.ProbeResult(True, "", 0.1, 1, 0, backend="pulseaudio",
                                     output_devices=(dev,)),
    })
    result = MP.probe()
    assert calls == ["pipewire", "pulseaudio"]
    assert result.ok and result.backend == "pulseaudio"
    assert result.output_devices == (dev,)
    assert os.environ[VAR] == "pulseaudio"  # the GUI process uses what answered


def test_sad_every_backend_failing_names_each_one(monkeypatch):
    _fake_runs(monkeypatch, {
        "pipewire": MP.ProbeResult(False, "it hung", 15.0, step="audio devices"),
        "pulseaudio": MP.ProbeResult(False, "no server", 0.2, step="audio output"),
    })
    result = MP.probe()
    assert not result.ok
    assert "PipeWire: it hung" in result.reason and "PulseAudio: no server" in result.reason
    assert VAR not in os.environ


def test_sad_a_hang_before_any_audio_step_is_not_retried_with_another_backend(monkeypatch):
    """The GPU drivers hang in the decoder step whatever the audio backend."""
    calls = _fake_runs(monkeypatch, {
        "pipewire": MP.ProbeResult(False, "it hung while starting its media backend", 15.0,
                                   step="decoder"),
        "pulseaudio": MP.ProbeResult(True, "", 0.1, 1, 1, backend="pulseaudio"),
    })
    result = MP.probe()
    assert calls == ["pipewire"]
    assert not result.ok and "starting its media backend" in result.reason


def test_edge_the_step_a_child_stopped_at_is_kept(monkeypatch):
    assert MP.ProbeResult(False, "x", step="audio output").step == "audio output"
    assert MP.ProbeResult(True).step == ""


def test_edge_the_first_backend_answering_stops_the_search(monkeypatch):
    calls = _fake_runs(monkeypatch, {
        "pipewire": MP.ProbeResult(True, "", 0.1, 2, 1, backend="pipewire"),
        "pulseaudio": MP.ProbeResult(False, "never asked", 0.0),
    })
    assert MP.probe().backend == "pipewire"
    assert calls == ["pipewire"]


def test_happy_the_reply_carries_backend_and_devices():
    reply = {"ok": True, "outputs": 1, "inputs": 1, "backend": "pipewire",
             "output_devices": [{"id": "a", "description": "Speakers", "default": True}],
             "input_devices": [{"id": "m", "description": "Mic", "default": False},
                               {"id": 5, "description": None}]}
    result = MP._result_from_reply(reply, 0.2)
    assert result.backend == "pipewire"
    assert result.output_devices == (MP.AudioDeviceInfo("a", "Speakers", True),)
    assert result.input_devices == (MP.AudioDeviceInfo("m", "Mic", False),)  # a broken entry is dropped


# -- the child primes PyQt's notify check before any multimedia object ----------------

def test_happy_the_child_delivers_an_event_before_the_first_multimedia_object(monkeypatch):
    from PyQt6 import QtMultimedia
    from PyQt6.QtCore import QCoreApplication
    from PyQt6.QtWidgets import QApplication

    QApplication.instance() or QApplication([])

    order = []
    real_send = QCoreApplication.sendEvent

    def send(obj, event):
        order.append("event")
        return real_send(obj, event)

    class Fake:
        def __init__(self, *a, **k):
            order.append(type(self).__name__)

        def setAudioOutput(self, *_a):
            pass

    class QAudioDecoder(Fake): pass
    class QMediaPlayer(Fake): pass
    class QAudioOutput(Fake): pass

    class QMediaDevices:
        @staticmethod
        def audioOutputs():
            order.append("devices")
            return []

        audioInputs = audioOutputs
        defaultAudioOutput = defaultAudioInput = staticmethod(lambda: None)

    monkeypatch.setattr(QCoreApplication, "sendEvent", staticmethod(send))
    for cls in (QAudioDecoder, QMediaPlayer, QAudioOutput, QMediaDevices):
        monkeypatch.setattr(QtMultimedia, cls.__name__, cls)
    monkeypatch.setattr(MP, "_say", lambda message: None)
    monkeypatch.setattr(MP, "_die_with_parent", lambda: None)
    monkeypatch.setattr(MP, "_allow_parent_debugger", lambda: None)
    monkeypatch.delenv(MP.DEADLINE_ENV, raising=False)
    monkeypatch.setattr(MP, "_DEVICE_SETTLE_SECONDS", 0.0)
    assert MP._child_main() == 0
    assert order[0] == "event", order
    assert order.index("event") < order.index("QAudioDecoder")


# -- the start applies the saved backend -------------------------------------------

def test_happy_main_applies_the_saved_backend_before_any_worker_starts():
    source = (ROOT / "main.py").read_text(encoding="utf-8")
    body = source[source.index("def main() -> int:"):]
    assert body.index("apply_no_gpu_probe(") < body.index("apply_saved_backend(") \
        < body.index('"--agent-worker"')


def _script_env(tmp_path, backend: str | None, users: str | None) -> dict:
    home = tmp_path / "home"
    (home / ".config" / "axross").mkdir(parents=True)
    if backend:
        (home / ".config" / "axross" / "audio.json").write_text(json.dumps({"backend": backend}))
    env = {k: v for k, v in os.environ.items() if not k.startswith(("AXROSS_", "QT_AUDIO"))}
    env.update(HOME=str(home), XDG_CONFIG_HOME=str(home / ".config"),
               XDG_STATE_HOME=str(home / "state"), QT_QPA_PLATFORM="offscreen",
               PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring")
    if users:
        env[VAR] = users
    return env


@pytest.mark.parametrize(("saved", "users", "seen"), [
    ("pulseaudio", None, "pulseaudio"),      # happy: the saved choice reaches Qt
    ("pipewire", "pulseaudio", "pulseaudio"),  # sad: the user's own variable wins
    (None, None, "<unset>"),                 # edge: auto - Qt's own choice
])
def test_e2e_a_started_axross_has_the_backend_in_its_environment(tmp_path, saved, users, seen):
    import subprocess
    out = tmp_path / "seen.txt"
    script = tmp_path / "s.py"
    script.write_text("import os\nopen(%r, 'w').write(os.environ.get('QT_AUDIO_BACKEND', '<unset>'))\n"
                      % str(out))
    r = subprocess.run([sys.executable, str(ROOT / "main.py"), "--script", str(script)],
                       env=_script_env(tmp_path, saved, users), capture_output=True, text=True,
                       timeout=120, cwd=str(ROOT))
    assert out.exists(), r.stderr[-1500:]
    assert out.read_text() == seen


def test_edge_a_later_check_with_another_backend_does_not_change_this_process(monkeypatch):
    """Qt reads QT_AUDIO_BACKEND once: after the first answer the process
    stays on that backend until a restart, and so do the workers it starts."""
    _fake_runs(monkeypatch, {"pulseaudio": MP.ProbeResult(True, "", 0.1, 1, 1, backend="pulseaudio")})
    assert MP.probe().backend == "pulseaudio"
    assert os.environ[VAR] == "pulseaudio"
    MP.reset()
    _fake_runs(monkeypatch, {"pipewire": MP.ProbeResult(True, "", 0.1, 1, 1, backend="pipewire")})
    assert MP.probe().backend == "pipewire"   # the check itself reports what answered
    assert os.environ[VAR] == "pulseaudio"    # this process keeps what Qt took
    assert MP.active_backend() == "pulseaudio"
