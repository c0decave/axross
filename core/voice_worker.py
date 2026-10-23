"""Speech synthesis (Piper) and local speech recognition (faster-whisper)
in a child process.

The Agent dock never loads onnxruntime or CTranslate2 itself: a child
does, so a crash in either stays out of the GUI, and Stop ends speech at
once by killing the child (the next request starts a fresh one). The
child is ``python -m core.voice_worker``; a frozen build has no ``python
-m`` and answers ``--voice-worker`` itself (main.py).

The pipe carries JSON lines, never pickle. Audio and text travel only
over it - nothing is written to disk, and nothing is logged: the child's
stderr goes nowhere and it prints nothing but replies.

Requests and replies (``id`` ties them together)::

    {"id": n, "op": "hello"}
      -> {"id": n, "ok": true, "piper": bool, "whisper": bool}
    {"id": n, "op": "speak", "voice": onnx, "config": json, "lang": "de"|"en",
     "sentences": [[[kind, text], ...], ...], "length_scale": float|null,
     "term_rule": "mixed"|"mapped"|null,
     "noise_scale": float|null, "noise_w_scale": float|null}
      -> {"id": n, "event": "audio", "rate": hz, "pcm": base64 int16 mono}  (one per sentence)
      -> {"id": n, "ok": true, "done": true}
    {"id": n, "op": "transcribe", "model": dir, "pcm": base64 int16 16 kHz mono,
     "language": "de"|"en"|null}
      -> {"id": n, "ok": true, "text": str, "language": str}
    any failure -> {"id": n, "ok": false, "error": str}

A German voice speaks the English terms of a sentence (kind "en", found by
core.voice_text.segment) with English phonemes (espeak-ng, ENGLISH_ESPEAK)
mapped onto phonemes the German voice was trained on; the whole sentence
is one synthesis with one speaker.
"""

from __future__ import annotations

import base64
import importlib.util
import json
import os
import re
import selectors
import subprocess
import sys
import threading
import time
import unicodedata
from pathlib import Path
from typing import Callable

from core.analysis_worker import WorkerProtocolError, _LineReader
from core.subprocess_env import worker_env
from core.voice_text import map_english_phonemes

#: espeak-ng voice of the English terms in German speech: American English
#: (rhotic) understood better than RP - see
#: core.voice_text.EXTRA_ENGLISH_TO_GERMAN_PHONEMES for the measurement.
ENGLISH_ESPEAK = "en-us"
GERMAN_ESPEAK = "de"
#: Synthesis of the German voice with English terms: calmer noise and a
#: little slower than the voice's defaults (measured best, same probe).
GERMAN_SYNTHESIS = {"noise_scale": 0.4, "noise_w_scale": 0.5, "length_scale": 1.05}
#: How English terms in German speech are phonemized:
#: "mapped" - always English phonemes (ENGLISH_ESPEAK) mapped onto German ones;
#: "mixed"  - a term German espeak's dictionary flags as an English loanword
#:            ("(en)...(de)": Server, Upload, Tool, Download, Browser...), or one
#:            of KEEP_GERMAN_ESPEAK, keeps German espeak's own pronunciation -
#:            phonemes the German voice was trained on; the others are mapped.
TERM_RULES = ("mixed", "mapped")
DEFAULT_TERM_RULE = "mixed"
#: Terms German espeak does not flag but says better than the mapped English
#: phonemes - from the podman A/B runs (Container: German espeak 4/4,
#: mapped 1/4 recognised by Whisper).
KEEP_GERMAN_ESPEAK = frozenset({"container"})
_FLAG = re.compile(r"\([a-z-]+\)")
#: Seconds a fresh child may take to import onnxruntime / CTranslate2 and
#: load a model before its first answer.
STARTUP_SECONDS = 60.0
SENTENCE_PAUSE = 0.3


class VoiceWorkerError(Exception):
    """The child failed, timed out or sent something that is no reply."""


class VoiceWorkerCancelled(VoiceWorkerError):
    pass


def worker_argv() -> list[str]:
    if getattr(sys, "frozen", False):
        return [sys.executable, "--voice-worker"]
    return [sys.executable, "-m", "core.voice_worker"]


def _importable(name: str) -> bool:
    try:
        return importlib.util.find_spec(name) is not None
    except (ImportError, ValueError):
        return False


def piper_available() -> bool:
    return _importable("piper")


def whisper_available() -> bool:
    return _importable("faster_whisper")


def _package_root() -> str:
    return str(Path(__file__).resolve().parent.parent)


class VoiceWorker:
    """Parent side: one child, started on demand, one request at a time.

    :meth:`call` blocks - call it from a background thread. :meth:`close`
    and a set *cancel* event end a request in flight by killing the child.
    """

    def __init__(self, command: list[str] | None = None) -> None:
        self._command = command or worker_argv()
        self._proc: subprocess.Popen | None = None
        self._reader = _LineReader()
        self._call_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._next_id = 0
        self._closed = threading.Event()

    @property
    def pid(self) -> int | None:
        proc = self._proc
        return proc.pid if proc is not None and proc.poll() is None else None

    def _start(self) -> subprocess.Popen:
        # The frozen child reuses this process's extraction folder and its
        # libraries: the loader variables stay (core.subprocess_env.worker_env).
        env = worker_env()
        root = _package_root()
        env["PYTHONPATH"] = root + (os.pathsep + env["PYTHONPATH"] if env.get("PYTHONPATH") else "")
        proc = subprocess.Popen(
            self._command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL, env=env, cwd=root, close_fds=True,
        )
        self._reader = _LineReader()
        return proc

    def kill(self) -> None:
        """End the child (a request in flight fails); the next call starts a new one."""
        with self._state_lock:
            proc, self._proc = self._proc, None
        if proc is None:
            return
        try:
            proc.kill()
        except OSError:
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass
        for stream in (proc.stdin, proc.stdout):
            try:
                stream.close()
            except (OSError, AttributeError):
                pass

    def close(self) -> None:
        self._closed.set()
        self.kill()

    def call(
        self,
        request: dict,
        *,
        timeout: float,
        on_event: Callable[[dict], None] | None = None,
        cancel: threading.Event | None = None,
        startup: float = STARTUP_SECONDS,
    ) -> dict:
        """Send *request*, return its reply. Every event moves the deadline
        to *timeout* from then (a long answer is many sentences)."""
        with self._call_lock:
            self._closed.clear()
            with self._state_lock:
                fresh = self._proc is None or self._proc.poll() is not None
                if fresh:
                    try:
                        self._proc = self._start()
                    except OSError as exc:
                        raise VoiceWorkerError(f"the voice worker could not start: {exc}") from exc
                proc = self._proc
            self._next_id += 1
            rid = self._next_id
            try:
                proc.stdin.write(json.dumps({**request, "id": rid}).encode() + b"\n")
                proc.stdin.flush()
                return self._read(proc, rid, timeout, timeout + (startup if fresh else 0),
                                  on_event, cancel)
            except VoiceWorkerError:
                self.kill()
                raise
            except (OSError, ValueError, WorkerProtocolError) as exc:
                self.kill()
                if cancel is not None and cancel.is_set():
                    raise VoiceWorkerCancelled("cancelled") from exc
                raise VoiceWorkerError(f"the voice worker failed: {exc}") from exc

    def _read(self, proc, rid, timeout, first_wait, on_event, cancel) -> dict:
        fd = proc.stdout.fileno()
        deadline = time.monotonic() + first_wait
        selector = selectors.DefaultSelector()
        selector.register(fd, selectors.EVENT_READ)
        try:
            while True:
                line = self._reader.next_line()
                if line is not None:
                    reply = json.loads(line)
                    if not isinstance(reply, dict):
                        raise WorkerProtocolError("reply is not an object")
                    if reply.get("id") != rid:
                        continue
                    if "event" in reply:
                        deadline = time.monotonic() + timeout
                        if on_event is not None:
                            on_event(reply)
                        if cancel is not None and cancel.is_set():
                            raise VoiceWorkerCancelled("cancelled")
                        continue
                    return reply
                if cancel is not None and cancel.is_set():
                    raise VoiceWorkerCancelled("cancelled")
                if self._closed.is_set():
                    raise VoiceWorkerError("the voice worker was closed")
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise VoiceWorkerError(f"the voice worker timed out after {timeout:.0f} s")
                if not selector.select(min(remaining, 0.1)):
                    continue
                chunk = os.read(fd, 1 << 16)
                if not chunk:
                    try:
                        code = proc.wait(timeout=2)
                    except subprocess.TimeoutExpired:
                        code = None
                    raise VoiceWorkerError(f"the voice worker ended (exit status {code})")
                self._reader.feed(chunk)
        finally:
            selector.close()


# -- child side --------------------------------------------------------------------------------


def _keep_german(term: str) -> bool:
    low = term.lower()
    return low in KEEP_GERMAN_ESPEAK or any(
        low.endswith(end) and low[: -len(end)] in KEEP_GERMAN_ESPEAK
        for end in ("es", "en", "s", "n"))


def is_loanword(phonemes: str) -> bool:
    """German espeak said (part of) it with its English pronunciation."""
    return "(en" in phonemes


def _unflagged(phonemes: str) -> str:
    return _FLAG.sub("", phonemes)


def sentence_phonemes(segments, phonemize: Callable[[str, str], str],
                      rule: str = DEFAULT_TERM_RULE) -> str:
    """One German-voice sentence: German parts phonemized as German,
    English terms by *rule* (TERM_RULES). *phonemize(voice, text)* returns
    espeak-ng's phonemes with its language-switch flags."""
    rule = rule if rule in TERM_RULES else DEFAULT_TERM_RULE
    parts = []
    for item in segments:
        if not isinstance(item, (list, tuple)) or len(item) != 2:
            continue
        kind, text = item
        if not isinstance(text, str) or not text.strip():
            continue
        if kind == "de":
            parts.append(_unflagged(phonemize(GERMAN_ESPEAK, text)))
        elif kind == "en":
            term = text.replace("-", " ")
            if rule == "mixed":
                german = phonemize(GERMAN_ESPEAK, term)
                if is_loanword(german) or _keep_german(term):
                    parts.append(_unflagged(german))
                    continue
            parts.append(map_english_phonemes(_unflagged(phonemize(ENGLISH_ESPEAK, term))))
    return " ".join(" ".join(p for p in parts if p).split())


def float_to_pcm16(samples, peak: float | None = 0.95) -> bytes:
    """Float samples (-1..1) as int16 bytes; *peak* scales the loudest
    sample to that level first (None: as they are, clipped)."""
    import array

    try:
        import numpy as np
    except ImportError:  # pragma: no cover - the child always has numpy
        np = None
    if np is not None:
        audio = np.asarray(samples, dtype=np.float32)
        if peak is not None and audio.size:
            top = float(np.max(np.abs(audio)))
            if top > 1e-4:
                audio = audio * (peak / top)
        return (np.clip(audio, -1.0, 1.0) * 32767).astype("<i2").tobytes()
    values = [float(s) for s in samples]
    if peak is not None and values:
        top = max(abs(v) for v in values)
        if top > 1e-4:
            values = [v * peak / top for v in values]
    return array.array("h", (int(max(-1.0, min(1.0, v)) * 32767) for v in values)).tobytes()


class _Child:
    def __init__(self) -> None:
        self._voices: dict[tuple, object] = {}
        self._whisper: dict[str, object] = {}
        self._espeak = None

    def _send(self, obj: dict) -> None:
        sys.stdout.write(json.dumps(obj) + "\n")
        sys.stdout.flush()

    def _phonemize(self, lang: str, text: str) -> str:
        """espeak-ng's phonemes of *text*, its language-switch flags kept
        (piper's own phonemizer drops them)."""
        from piper import espeakbridge

        if self._espeak is None:
            from piper.phonemize_espeak import ESPEAK_DATA_DIR

            espeakbridge.initialize(str(ESPEAK_DATA_DIR))
            self._espeak = True
        espeakbridge.set_voice(lang)
        out = []
        for phonemes, terminator, _end in espeakbridge.get_phonemes(text):
            out.append(phonemes + terminator + (" " if terminator in (",", ":", ";") else ""))
        return unicodedata.normalize("NFC", " ".join(out))

    def _voice(self, model: str, config: str):
        key = (model, config)
        if key not in self._voices:
            from piper import PiperVoice

            self._voices = {key: PiperVoice.load(model, config_path=config)}  # one voice kept
        return self._voices[key]

    def speak(self, rid, req: dict) -> None:
        if not piper_available():
            raise RuntimeError("piper-tts is not installed (pip install axross[voice])")
        from piper import SynthesisConfig

        voice = self._voice(str(req["voice"]), str(req["config"]))
        rate = int(voice.config.sample_rate)
        german = req.get("lang") == "de"
        tuning = dict(GERMAN_SYNTHESIS) if german else {}
        for key in ("length_scale", "noise_scale", "noise_w_scale"):
            value = req.get(key)
            if isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 3:
                tuning[key] = float(value)
        syn = SynthesisConfig(**tuning)
        id_map = voice.config.phoneme_id_map
        pause = b"\0\0" * int(rate * SENTENCE_PAUSE)
        for index, segments in enumerate(req.get("sentences") or []):
            if german:
                ph = sentence_phonemes(segments, self._phonemize,
                                       str(req.get("term_rule") or DEFAULT_TERM_RULE))
            else:
                text = " ".join(t for _k, t in segments if isinstance(t, str))
                ph = " ".join("".join(s) for s in voice.phonemize(text) if s)
            phonemes = [p for p in unicodedata.normalize("NFD", ph) if p in id_map]
            if not phonemes:
                continue
            audio = voice.phoneme_ids_to_audio(voice.phonemes_to_ids(phonemes), syn)
            pcm = float_to_pcm16(audio)
            self._send({"id": rid, "event": "audio", "rate": rate,
                        "pcm": base64.b64encode((pause if index else b"") + pcm).decode()})
        self._send({"id": rid, "ok": True, "done": True})

    def transcribe(self, rid, req: dict) -> None:
        if not whisper_available():
            raise RuntimeError("faster-whisper is not installed (pip install axross[voice])")
        import numpy as np
        from faster_whisper import WhisperModel

        folder = str(req["model"])
        if folder not in self._whisper:
            self._whisper = {folder: WhisperModel(folder, device="cpu", compute_type="int8")}
        model = self._whisper[folder]
        pcm = base64.b64decode(str(req.get("pcm") or ""))
        audio = np.frombuffer(pcm[: len(pcm) // 2 * 2], dtype="<i2").astype(np.float32) / 32768.0
        language = req.get("language") if req.get("language") in ("de", "en") else None
        segments, info = model.transcribe(audio, language=language, beam_size=5,
                                          condition_on_previous_text=False)
        text = " ".join(s.text.strip() for s in segments).strip()
        self._send({"id": rid, "ok": True, "text": text, "language": info.language})

    def handle(self, line: bytes) -> None:
        try:
            req = json.loads(line)
        except ValueError:
            self._send({"id": None, "ok": False, "error": "the request is no JSON"})
            return
        if not isinstance(req, dict):
            self._send({"id": None, "ok": False, "error": "the request is no object"})
            return
        rid, op = req.get("id"), req.get("op")
        try:
            if op == "hello":
                self._send({"id": rid, "ok": True, "piper": piper_available(),
                            "whisper": whisper_available()})
            elif op == "speak":
                self.speak(rid, req)
            elif op == "transcribe":
                self.transcribe(rid, req)
            else:
                self._send({"id": rid, "ok": False, "error": f"unknown op {op}"})
        except Exception as exc:  # noqa: BLE001 - every failure is a reply
            self._send({"id": rid, "ok": False, "error": f"{type(exc).__name__}: {exc}"})


def _child_main() -> int:
    import logging

    logging.disable(logging.CRITICAL)  # nothing about what is said or heard is logged
    child = _Child()
    for line in sys.stdin.buffer:
        if line.strip():
            child.handle(line)
    return 0


if __name__ == "__main__":
    sys.exit(_child_main())
