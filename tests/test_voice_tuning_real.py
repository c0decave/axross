"""How a voice speaks, for real: the voice worker (core.voice_worker) with a
real Piper voice, driven by the requests the Agent dock and Listen build
(ui.voice.speak_request). A faster speed gives shorter speech, a higher
pitch a higher fundamental frequency at the same length, a lower volume a
lower peak, a longer pause longer speech.

Skips unless piper-tts and a voice are there. The packages: importable
here (pip install axross[voice]) - the worker as axross starts it; or
AXROSS_VOICE_WORKER_IMAGE names a podman image whose Python
(AXROSS_VOICE_WORKER_PYTHON, default python3) has piper-tts - the same
worker from this tree, in a disposable container (--network=none,
read-only, no capabilities). Nothing is installed on the host. The voice:
core.voice_models.installed() under $XDG_DATA_HOME, or under
AXROSS_VOICE_DATA (a data home that holds axross/voice/<id>/, for example
one core.voice_models.download filled).
"""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

np = pytest.importorskip("numpy")

from core import voice_models as VM  # noqa: E402
from core import voice_settings as VS  # noqa: E402
from core import voice_text as VT  # noqa: E402
from core import voice_worker as VW  # noqa: E402

IMAGE = os.environ.get("AXROSS_VOICE_WORKER_IMAGE", "")
PYTHON = os.environ.get("AXROSS_VOICE_WORKER_PYTHON", "python3")
TEXT = {"en": "The file is there and everything is fine.",
        "de": "Die Datei ist da und alles ist in Ordnung."}
#: Noise off: Piper's synthesis is then the same every time, and two
#: lengths compare exactly.
STEADY = {"expressiveness": 0.0, "rhythm": 0.0}


def _podman_env() -> dict:
    """Rootless podman keeps its images under the real home; the tests run
    with a scratch HOME and XDG folders."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("XDG_")}
    env["HOME"] = pwd.getpwuid(os.getuid()).pw_dir
    env["XDG_RUNTIME_DIR"] = f"/run/user/{os.getuid()}"
    return env


def _container_command(data: Path) -> list[str]:
    env = _podman_env()
    unset = [arg for k in os.environ if k.startswith("XDG_") for arg in ("-u", k)]
    return ["env", *unset, f"HOME={env['HOME']}", f"XDG_RUNTIME_DIR={env['XDG_RUNTIME_DIR']}",
            "podman", "run", "--rm", "-i", "--network=none", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--read-only", "--tmpfs", "/tmp",
            "--pids-limit", "256", "--memory", "3g",
            "-v", f"{ROOT}:{ROOT}:ro", "-v", f"{data}:{data}:ro", "-w", str(ROOT),
            "-e", f"PYTHONPATH={ROOT}", "--entrypoint", PYTHON, IMAGE, "-m", "core.voice_worker"]


@pytest.fixture(scope="module")
def real():
    """(worker, installed voice model) - or skip, saying what is missing."""
    data = os.environ.get("AXROSS_VOICE_DATA")
    saved = os.environ.get("XDG_DATA_HOME")
    if data:
        os.environ["XDG_DATA_HOME"] = data
    try:
        model = next((VM.model(v) for lang in ("en", "de") for v in VS.VOICES[lang]
                      if VM.installed(VM.model(v))), None)
        if model is None:
            pytest.skip("no Piper voice is downloaded (core.voice_models.installed)")
        if VW.piper_available():
            worker = VW.VoiceWorker()
        elif IMAGE and shutil.which("podman"):
            probe = subprocess.run(["podman", "image", "exists", IMAGE], env=_podman_env(),
                                   capture_output=True, timeout=60)
            if probe.returncode != 0:
                pytest.skip(f"no podman image {IMAGE}")
            worker = VW.VoiceWorker(command=_container_command(VM.data_dir().parent.parent))
        else:
            pytest.skip("piper-tts is not installed and AXROSS_VOICE_WORKER_IMAGE names no image")
        hello = worker.call({"op": "hello"}, timeout=120)
        if not hello.get("piper"):
            worker.close()
            pytest.skip("the voice worker has no piper-tts")
        yield worker, model
        worker.close()
    finally:
        if data:
            if saved is None:
                os.environ.pop("XDG_DATA_HOME", None)
            else:
                os.environ["XDG_DATA_HOME"] = saved


def speak(real, text: str | None = None, **tuning) -> tuple[bytes, int]:
    """The PCM (int16 mono) and rate the real worker speaks *text* with."""
    from ui.voice import speak_request, speech_sentences

    worker, model = real
    lang = model.language
    request = speak_request(model, lang, speech_sentences(text or TEXT[lang], lang,
                                                          VT.load_lexicon()),
                            {**VS.default_tuning(), **tuning})
    chunks, rates = [], set()

    def on_event(event):
        import base64

        chunks.append(base64.b64decode(event["pcm"]))
        rates.add(int(event["rate"]))

    reply = worker.call(request, timeout=180, on_event=on_event)
    assert reply.get("ok") is True, reply
    assert len(rates) == 1, rates
    return b"".join(chunks), rates.pop()


def f0(pcm: bytes, rate: int) -> float:
    """The median fundamental frequency of the voiced frames (autocorrelation,
    60-500 Hz)."""
    audio = np.frombuffer(pcm, dtype="<i2").astype(np.float64)
    frame, hop = int(0.04 * rate), int(0.01 * rate)
    lo, hi = int(rate / 500), int(rate / 60)
    loud = 0.3 * np.sqrt(np.mean(audio ** 2))
    found = []
    for start in range(0, len(audio) - frame, hop):
        x = audio[start:start + frame]
        if np.sqrt(np.mean(x ** 2)) < loud:
            continue
        x = x - x.mean()
        ac = np.correlate(x, x, "full")[frame - 1:]
        if ac[0] <= 0:
            continue
        lag = lo + int(np.argmax(ac[lo:hi]))
        if ac[lag] / ac[0] > 0.5:  # clearly periodic: voiced
            found.append(rate / lag)
    assert len(found) >= 10, "too few voiced frames to measure"
    return float(np.median(found))


def peak(pcm: bytes) -> int:
    return int(np.max(np.abs(np.frombuffer(pcm, dtype="<i2").astype(np.int64))))


def test_happy_a_faster_speed_gives_shorter_speech_and_a_slower_longer(real):
    base, rate = speak(real, **STEADY)
    fast, _ = speak(real, speed=1.6, **STEADY)
    slow, _ = speak(real, speed=0.7, **STEADY)
    print(f"\nspeed 1.0: {len(base) / 2 / rate:.2f} s, 1.6: {len(fast) / 2 / rate:.2f} s, "
          f"0.7: {len(slow) / 2 / rate:.2f} s")
    assert 0.5 < len(fast) / len(base) < 0.75  # about 1 / 1.6
    assert 1.25 < len(slow) / len(base) < 1.6  # about 1 / 0.7


def test_happy_a_higher_pitch_gives_a_higher_voice_of_the_same_length(real):
    base, rate = speak(real, **STEADY)
    high, _ = speak(real, pitch=6.0, **STEADY)
    low, _ = speak(real, pitch=-6.0, **STEADY)
    f_base, f_high, f_low = f0(base, rate), f0(high, rate), f0(low, rate)
    print(f"\nF0 pitch 0: {f_base:.0f} Hz, +6: {f_high:.0f} Hz, -6: {f_low:.0f} Hz; length "
          f"{len(base) / 2 / rate:.2f} / {len(high) / 2 / rate:.2f} / {len(low) / 2 / rate:.2f} s")
    assert f_high / f_base > 1.25  # 2 ** (6 / 12) = 1.41
    assert f_low / f_base < 0.8  # 0.71
    for shifted in (high, low):  # Piper made it slower or faster first: the length stays
        assert 0.85 < len(shifted) / len(base) < 1.15


def test_happy_volume_and_pause(real):
    loud, rate = speak(real, **STEADY)
    quiet, _ = speak(real, volume=0.5, **STEADY)
    assert peak(quiet) == pytest.approx(peak(loud) / 2, rel=0.02)
    two = VT.sample_phrase(real[1].language)
    short, _ = speak(real, two, pause=0.0, **STEADY)
    long, _ = speak(real, two, pause=1.5, **STEADY)
    assert (len(long) - len(short)) // 2 == pytest.approx(1.5 * rate, abs=2)


def test_sad_the_real_worker_refuses_a_value_outside_its_range(real):
    worker, model = real
    voice, config = VM.voice_paths(model)
    reply = worker.call({"op": "speak", "voice": str(voice), "config": str(config),
                         "lang": model.language, "sentences": [[["en", "Hello."]]],
                         "pitch": 40}, timeout=60)
    assert reply["ok"] is False and "pitch" in reply["error"]


def test_edge_the_extremes_of_every_range_are_spoken(real):
    for side in ("low", "high"):
        pcm, _rate = speak(real, "Hello.", **{n: getattr(t, side) for n, t in VS.TUNING.items()})
        assert pcm, side
