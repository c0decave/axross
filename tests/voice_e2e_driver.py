"""Runs INSIDE the disposable container of tests/test_voice_e2e_podman.py:
real Piper synthesis through core.voice_worker (the worker the dock uses,
with core.voice_text's segmentation), then real faster-whisper recognition
of what was synthesized. Prints one JSON line per result.

Usage: python voice_e2e_driver.py <models dir> [runs]
  <models>/voices/de_DE-thorsten-high.onnx(.json), en_US-ryan-medium.onnx(.json),
  <models>/whisper-small/ (CTranslate2 model)
"""

from __future__ import annotations

import base64
import json
import sys
import time

import numpy as np

from core import voice_text as VT
from core.voice_worker import VoiceWorker

MODELS = sys.argv[1]
RUNS = int(sys.argv[2]) if len(sys.argv) > 2 else 2
#: (sentence, terms - "a|b" accepts a homophone of the English term)
GERMAN = (
    ("Ich habe den Server neu gestartet und das Backup geprüft.", ("server", "backup")),
    ("Der Cache ist leer, der Timeout war zu kurz.", ("cache|cash", "timeout")),
    ("Der Pull Request ist offen, der Commit fehlt noch.", ("pull request|pulte quest", "commit")),
    ("Ich habe den Upload auf den Container abgeschlossen.", ("upload", "container")),
    ("Das Tool hat die Logs im Workspace gefunden.", ("tool", "logs", "workspace")),
)
ENGLISH = "I'm sorry, Dave. I'm afraid I can't do that."


def speak(worker, voice, lang, text, **tuning):
    lex = VT.load_lexicon()
    sentences = [VT.segment(s, lex) if lang == "de" else [("en", s)]
                 for s in VT.split_sentences(text)]
    chunks, rate = [], 0

    def on_event(event):
        nonlocal rate
        rate = event["rate"]
        chunks.append(base64.b64decode(event["pcm"]))

    reply = worker.call({"op": "speak", "voice": f"{MODELS}/voices/{voice}.onnx",
                         "config": f"{MODELS}/voices/{voice}.onnx.json", "lang": lang,
                         "sentences": sentences, **tuning}, timeout=300, on_event=on_event)
    assert reply.get("ok"), reply
    return b"".join(chunks), rate, sentences


def to_16k(pcm: bytes, rate: int) -> bytes:
    audio = np.frombuffer(pcm, dtype="<i2").astype(np.float32)
    n = int(len(audio) * 16000 / rate)
    resampled = np.interp(np.linspace(0, len(audio) - 1, n), np.arange(len(audio)), audio)
    return resampled.astype("<i2").tobytes()


def transcribe(worker, pcm16k: bytes, language: str) -> str:
    reply = worker.call({"op": "transcribe", "model": f"{MODELS}/whisper-small",
                         "pcm": base64.b64encode(pcm16k).decode(), "language": language},
                        timeout=600)
    assert reply.get("ok"), reply
    return reply["text"]


def main() -> int:
    tts, stt = VoiceWorker(), VoiceWorker()
    try:
        print(json.dumps({"check": "hello", **tts.call({"op": "hello"}, timeout=120)}), flush=True)
        for run in range(RUNS):
            for sentence, terms in GERMAN:
                # The term rule of the worker (its default), the other rule,
                # and every part read as German, for comparison.
                for check, rule in (("german", None), ("mapped", "mapped"), ("control", "")):
                    tuning = {"term_rule": rule} if rule else {}
                    started = time.monotonic()
                    if check == "control":
                        lex = VT.load_lexicon()
                        plain = [[("de", " ".join(t for _k, t in VT.segment(sentence, lex)))]]
                        chunks = []
                        tts.call({"op": "speak",
                                  "voice": f"{MODELS}/voices/de_DE-thorsten-high.onnx",
                                  "config": f"{MODELS}/voices/de_DE-thorsten-high.onnx.json",
                                  "lang": "de", "sentences": plain}, timeout=300,
                                 on_event=lambda e: chunks.append(base64.b64decode(e["pcm"])))
                        pcm, rate, segments = b"".join(chunks), 22050, plain
                    else:
                        pcm, rate, segments = speak(tts, "de_DE-thorsten-high", "de", sentence,
                                                    **tuning)
                    synth = time.monotonic() - started
                    heard = transcribe(stt, to_16k(pcm, rate), "de")
                    print(json.dumps({"check": check, "run": run, "said": sentence,
                                      "segments": segments, "terms": terms, "heard": heard,
                                      "audio_seconds": round(len(pcm) / 2 / rate, 2),
                                      "synth_seconds": round(synth, 2)}, ensure_ascii=False),
                          flush=True)
        pcm, rate, _segments = speak(tts, "en_US-ryan-medium", "en", ENGLISH, length_scale=1.15)
        print(json.dumps({"check": "english", "said": ENGLISH,
                          "heard": transcribe(stt, to_16k(pcm, rate), "en")}), flush=True)
    finally:
        tts.close()
        stt.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
