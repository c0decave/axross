"""The voice pipeline for real, in a disposable podman container: Piper
speaks a German sentence with English terms (mapped English phonemes on
the German voice), faster-whisper hears it, and the English terms come
back recognisable; the English voice says one fixed line and is heard.

Nothing is installed on the host: the container installs the pinned
wheels from a local directory with --network=none, into its own tmpfs,
and runs core.voice_worker from this tree mounted read-only.

Skips cleanly unless podman, the image (python:3.14-slim) and the two
directories are there:

  AXROSS_VOICE_WHEELS  wheels for cp314: piper-tts 1.8.0, onnxruntime 1.31.0,
                       faster-whisper 1.2.1, ctranslate2 4.8.4 and their deps
  AXROSS_VOICE_MODELS  voices/de_DE-thorsten-high.onnx(.json),
                       voices/en_US-ryan-medium.onnx(.json), whisper-small/
"""

from __future__ import annotations

import json
import os
import pwd
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
IMAGE = "docker.io/library/python:3.14-slim"
WHEELS = os.environ.get("AXROSS_VOICE_WHEELS", "")
MODELS = os.environ.get("AXROSS_VOICE_MODELS", "")
#: Runs over the 11 terms (synthesis is stochastic: more runs, tighter rates).
RUNS = int(os.environ.get("AXROSS_VOICE_E2E_RUNS", "3"))
PINS = ("piper-tts==1.8.0", "onnxruntime==1.31.0", "faster-whisper==1.2.1", "ctranslate2==4.8.4")


def _engine_env() -> dict:
    """Rootless podman keeps its images under the real home; the tests run
    with a scratch HOME."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("XDG_") or k == "XDG_RUNTIME_DIR"}
    env["HOME"] = pwd.getpwuid(os.getuid()).pw_dir
    return env


def _ready() -> str:
    if not shutil.which("podman"):
        return "podman is not installed"
    if not (WHEELS and os.path.isdir(WHEELS)):
        return "AXROSS_VOICE_WHEELS names no wheel directory"
    if not (MODELS and os.path.isfile(os.path.join(MODELS, "voices",
                                                   "de_DE-thorsten-high.onnx"))):
        return "AXROSS_VOICE_MODELS names no model directory"
    probe = subprocess.run(["podman", "image", "exists", IMAGE], env=_engine_env(),
                           capture_output=True, timeout=60)
    return "" if probe.returncode == 0 else f"no {IMAGE} image"


@pytest.fixture(scope="module")
def roundtrip():
    why = _ready()
    if why:
        pytest.skip(why)
    script = (f"pip install -q --no-index --no-cache-dir --find-links /wheels --target /tmp/site "
              f"{' '.join(PINS)} && PYTHONPATH=/tmp/site:/src "
              f"python /src/tests/voice_e2e_driver.py /models {RUNS}")
    argv = ["podman", "run", "--rm", "--network=none", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--read-only",
            "--tmpfs", "/tmp:rw,exec,size=3g", "--pids-limit", "512", "--memory", "6g",
            "-e", "HOME=/tmp", "-e", "PIP_DISABLE_PIP_VERSION_CHECK=1",
            "-v", f"{WHEELS}:/wheels:ro", "-v", f"{MODELS}:/models:ro",
            "-v", f"{ROOT}:/src:ro", "-w", "/src", IMAGE, "sh", "-c", script]
    proc = subprocess.run(argv, env=_engine_env(), capture_output=True, text=True, timeout=1500)
    assert proc.returncode == 0, proc.stderr[-4000:] + proc.stdout[-2000:]
    results = [json.loads(line) for line in proc.stdout.splitlines() if line.startswith("{")]
    print("\n".join(json.dumps(r, ensure_ascii=False) for r in results))
    return results


def _hits(result) -> list[bool]:
    heard = result["heard"].lower().replace("-", " ")
    return [any(spelling in heard for spelling in term.split("|")) for term in result["terms"]]


def test_happy_the_container_has_piper_and_whisper(roundtrip):
    hello = next(r for r in roundtrip if r["check"] == "hello")
    assert hello["piper"] is True and hello["whisper"] is True


def test_happy_english_terms_in_german_speech_come_back_recognisable(roundtrip):
    """Synthesis is stochastic (Piper's noise): the bound is on the rate
    over every sentence and run. Measured with the mixed rule (German
    espeak's loanwords kept, the rest mapped): 101/132 = 0.765 over 12 runs
    (mapped only 86/132, all German 61/132). With the default 3 runs (33
    terms) two standard deviations below that is 0.62."""
    german = [r for r in roundtrip if r["check"] == "german"]
    hits = [hit for r in german for hit in _hits(r)]
    assert german and sum(hits) / len(hits) >= 0.62, (sum(hits), len(hits))
    assert all(["en", "Server"] in r["segments"][0] for r in german if "Server" in r["said"])


def test_happy_a_loanword_of_german_espeak_is_said_its_way(roundtrip):
    """Server is in German espeak's dictionary as English: kept, it was
    recognised 12 of 12 times (mapped: 4 of 12)."""
    server = [r for r in roundtrip if r["check"] == "german" and "Server" in r["said"]]
    heard = sum("server" in r["heard"].lower() for r in server)
    assert heard >= len(server) - 1, [r["heard"] for r in server]


def test_happy_cache_is_spoken_in_english_not_read_as_german(roundtrip):
    """Read as German, "Cache" is heard as "Kache"; spoken in English it is
    "cash" - in every run."""
    for r in roundtrip:
        if r["check"] == "german" and "Cache" in r["said"]:
            heard = r["heard"].lower()
            assert ("cash" in heard or "cache" in heard) and "kache" not in heard, r["heard"]


def test_edge_mixed_mapped_and_all_german_are_reported(roundtrip):
    """The other rule and every part read as German, for comparison - not
    a bound of their own (stochastic; the measured rates are above)."""
    rates = {}
    for check in ("german", "mapped", "control"):
        hits = [hit for r in roundtrip if r["check"] == check for hit in _hits(r)]
        rates[check] = (sum(hits), len(hits))
    print(f"mixed {rates['german'][0]}/{rates['german'][1]}, "
          f"mapped {rates['mapped'][0]}/{rates['mapped'][1]}, "
          f"all German {rates['control'][0]}/{rates['control'][1]}")
    assert rates["german"][1] == rates["mapped"][1] == rates["control"][1] > 0


def test_happy_the_english_voice_says_the_fixed_line(roundtrip):
    heard = next(r for r in roundtrip if r["check"] == "english")["heard"].lower()
    assert "sorry" in heard and "dave" in heard and "can't do that" in heard.replace("’", "'")
