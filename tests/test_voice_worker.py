"""The voice worker: synthesis (Piper) and local recognition
(faster-whisper) in a child process that Stop can kill.

The host has neither package: these tests drive the parent side against a
fake child that speaks the same JSON-lines protocol, the real child for
what it answers without the packages, and the child's phoneme assembly
with a fake phonemizer. tests/test_voice_e2e_podman.py runs the real
packages in a disposable container.
"""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import voice_worker as VW  # noqa: E402

FAKE = textwrap.dedent(r'''
    import base64, json, os, sys, time
    mode = sys.argv[1] if len(sys.argv) > 1 else "ok"
    for line in sys.stdin:
        req = json.loads(line)
        rid = req["id"]
        def send(obj):
            sys.stdout.write(json.dumps(obj) + "\n"); sys.stdout.flush()
        if mode == "crash":
            os._exit(3)
        if mode == "garbage":
            sys.stdout.write("not json\n"); sys.stdout.flush(); continue
        if mode == "silent":
            time.sleep(30); continue
        if req["op"] == "hello":
            send({"id": rid, "ok": True, "piper": True, "whisper": True, "pid": os.getpid()})
        elif req["op"] == "speak":
            for n in range(len(req["sentences"])):
                send({"id": rid, "event": "audio", "rate": 22050,
                      "pcm": base64.b64encode(bytes([n]) * 4).decode()})
                if mode == "slow":
                    time.sleep(0.5)
            send({"id": rid, "ok": True, "done": True})
        elif req["op"] == "transcribe":
            pcm = base64.b64decode(req["pcm"])
            send({"id": rid, "ok": True, "text": f"heard {len(pcm)} bytes", "language": "de"})
        else:
            send({"id": rid, "ok": False, "error": "unknown op"})
''')


@pytest.fixture
def fake(tmp_path):
    script = tmp_path / "fake_worker.py"
    script.write_text(FAKE, encoding="utf-8")

    def make(mode: str = "ok") -> VW.VoiceWorker:
        worker = VW.VoiceWorker(command=[sys.executable, str(script), mode])
        return worker

    return make


def _close(worker):
    worker.close()


# -- parent side against a fake child ---------------------------------------------------------


def test_happy_speak_streams_audio_chunks(fake):
    worker = fake()
    try:
        chunks = []
        reply = worker.call({"op": "speak", "sentences": [[["de", "a"]], [["de", "b"]]]},
                            timeout=10, on_event=chunks.append)
        assert reply["ok"] and reply["done"]
        assert [base64.b64decode(c["pcm"]) for c in chunks] == [b"\0" * 4, b"\1" * 4]
    finally:
        _close(worker)


def test_happy_transcribe_and_the_child_is_reused(fake):
    worker = fake()
    try:
        pcm = base64.b64encode(b"\0\0" * 160).decode()
        first = worker.call({"op": "transcribe", "pcm": pcm}, timeout=10)
        assert first["text"] == "heard 320 bytes"
        pid = worker.call({"op": "hello"}, timeout=10)["pid"]
        assert worker.call({"op": "hello"}, timeout=10)["pid"] == pid
    finally:
        _close(worker)


def test_sad_a_crashing_child_is_an_error_and_the_next_call_starts_a_new_one(fake, tmp_path):
    worker = fake("crash")
    with pytest.raises(VW.VoiceWorkerError, match="exit"):
        worker.call({"op": "hello"}, timeout=10)
    worker._command = worker._command[:-1] + ["ok"]
    try:
        assert worker.call({"op": "hello"}, timeout=10)["ok"]
    finally:
        _close(worker)


def test_sad_garbage_from_the_child_is_a_protocol_error(fake):
    worker = fake("garbage")
    try:
        with pytest.raises(VW.VoiceWorkerError):
            worker.call({"op": "hello"}, timeout=10)
    finally:
        _close(worker)


def test_sad_an_error_reply_is_returned_not_raised(fake):
    worker = fake()
    try:
        reply = worker.call({"op": "dance"}, timeout=10)
        assert reply == {"id": reply["id"], "ok": False, "error": "unknown op"}
    finally:
        _close(worker)


def test_edge_a_silent_child_times_out_and_is_killed(fake):
    worker = fake("silent")
    started = time.monotonic()
    with pytest.raises(VW.VoiceWorkerError, match="timed out"):
        worker.call({"op": "hello"}, timeout=0.5, startup=0)
    assert time.monotonic() - started < 5
    assert worker.pid is None


def test_edge_cancel_kills_the_child_mid_speech(fake):
    worker = fake("slow")
    cancel = threading.Event()
    chunks = []

    def on_event(event):
        chunks.append(event)
        cancel.set()

    with pytest.raises(VW.VoiceWorkerCancelled):
        worker.call({"op": "speak", "sentences": [[["de", "x"]]] * 5}, timeout=10,
                    on_event=on_event, cancel=cancel)
    assert len(chunks) == 1
    assert worker.pid is None


def test_edge_close_from_another_thread_ends_a_call(fake):
    worker = fake("silent")
    threading.Timer(0.3, worker.close).start()
    with pytest.raises(VW.VoiceWorkerError):
        worker.call({"op": "hello"}, timeout=10)


# -- how the child is started -------------------------------------------------------------------


def test_happy_from_source_the_child_is_python_dash_m():
    with mock.patch.object(sys, "frozen", False, create=True):
        assert VW.worker_argv() == [sys.executable, "-m", "core.voice_worker"]


def test_happy_frozen_the_binary_answers_a_flag():
    with mock.patch.object(sys, "frozen", True, create=True):
        assert VW.worker_argv() == [sys.executable, "--voice-worker"]


def test_happy_the_real_child_without_the_packages_says_so():
    worker = VW.VoiceWorker()
    try:
        hello = worker.call({"op": "hello"}, timeout=60)
        assert hello["ok"] is True
        assert hello["piper"] is VW.piper_available() and hello["whisper"] is \
            VW.whisper_available()
        if not hello["piper"]:
            reply = worker.call({"op": "speak", "voice": "/nope.onnx", "config": "/nope.json",
                                 "lang": "de", "sentences": [[["de", "Hallo"]]]}, timeout=60)
            assert reply["ok"] is False and "piper" in reply["error"]
    finally:
        worker.close()


def test_happy_main_py_dispatches_the_voice_worker_flag():
    worker = VW.VoiceWorker(command=[sys.executable, str(ROOT / "main.py"), "--voice-worker"])
    try:
        assert worker.call({"op": "hello"}, timeout=60)["ok"] is True
    finally:
        worker.close()


def test_sad_the_child_refuses_a_request_that_is_no_object():
    proc = subprocess.run([sys.executable, "-m", "core.voice_worker"], input=b'[1]\n{"id": 2}\n',
                          capture_output=True, timeout=60, cwd=ROOT)
    lines = [json.loads(line) for line in proc.stdout.splitlines()]
    assert lines[0]["ok"] is False and lines[1] == {"id": 2, "ok": False,
                                                    "error": "unknown op None"}


# -- the child's phoneme assembly ----------------------------------------------------------------


#: What espeak-ng says, with its language-switch flags: German espeak's
#: dictionary marks English loanwords "(en)...(de)".
_ESPEAK = {
    ("de", "Ich habe den"): "ɪç haːbə deːn", ("de", "neu gestartet."): "nɔʏ ɡəʃtaɾtət.",
    ("de", "Server"): "(en)sˈɜːvə(de)", ("en-us", "Server"): "sˈɜːvɚ",
    ("de", "Cache"): "kˈaxə", ("en-us", "Cache"): "kˈæʃ",
    ("de", "Container"): "kˈɔntaɪnɜ", ("en-us", "Container"): "kəntˈeɪnɚ",
    ("de", "read only"): "rˈeːat ˈɔnliː", ("en-us", "read only"): "ɹˈiːd ˈoʊnli",
}


def _fake_phonemize(lang: str, text: str) -> str:
    return _ESPEAK[(lang, text)]


def test_happy_mapped_rule_gives_every_term_english_phonemes():
    ph = VW.sentence_phonemes([["de", "Ich habe den"], ["en", "Server"], ["de", "neu gestartet."]],
                              _fake_phonemize, rule="mapped")
    assert ph == "ɪç haːbə deːn sˈøːvɐ nɔʏ ɡəʃtaɾtət."


def test_happy_mixed_rule_keeps_german_espeaks_loanwords():
    """German espeak flags Server as English: its own pronunciation, which
    the German voice was trained on, wins over mapped English phonemes."""
    ph = VW.sentence_phonemes([["de", "Ich habe den"], ["en", "Server"], ["de", "neu gestartet."]],
                              _fake_phonemize, rule="mixed")
    assert ph == "ɪç haːbə deːn sˈɜːvə nɔʏ ɡəʃtaɾtət."


def test_happy_mixed_rule_maps_a_term_german_espeak_reads_as_german():
    assert VW.sentence_phonemes([["en", "Cache"]], _fake_phonemize, rule="mixed") == "kˈɛʃ"


def test_edge_the_keep_german_list_wins_without_a_flag():
    assert "container" in VW.KEEP_GERMAN_ESPEAK
    assert VW.sentence_phonemes([["en", "Container"]], _fake_phonemize,
                                rule="mixed") == "kˈɔntaɪnɜ"
    assert VW.sentence_phonemes([["en", "Container"]], _fake_phonemize,
                                rule="mapped") == "kəntˈeːnɐ"


def test_edge_the_keep_german_list_finds_german_plural_endings():
    table = dict(_ESPEAK)
    table[("de", "Containern")] = "kˈɔntaɪnɜn"
    table[("en-us", "Containern")] = "kəntˈeɪnɚn"
    ph = VW.sentence_phonemes([["en", "Containern"]], lambda lang, text: table[(lang, text)],
                              rule="mixed")
    assert ph == "kˈɔntaɪnɜn"


def test_edge_hyphens_in_terms_are_spaces_and_unknown_kinds_are_skipped():
    ph = VW.sentence_phonemes([["en", "read-only"], ["xx", "?"]], _fake_phonemize)
    assert ph == "ɾˈiːd ˈoːnli"


def test_sad_an_unknown_rule_is_the_default_rule():
    assert VW.sentence_phonemes([["en", "Server"]], _fake_phonemize, rule="bogus") == \
        VW.sentence_phonemes([["en", "Server"]], _fake_phonemize)


def test_edge_flags_never_reach_the_phonemes():
    assert "(" not in VW.sentence_phonemes([["de", "Ich habe den"], ["en", "Server"]],
                                           _fake_phonemize, rule="mapped")
    assert VW.is_loanword("ɪç (en)sˈɜːvə(de)") and not VW.is_loanword("kˈaxə")


def test_edge_pcm_conversion_clips_and_scales():
    out = VW.float_to_pcm16([0.0, 0.5, -0.5, 2.0, -2.0], peak=None)
    import array

    values = array.array("h", out).tolist()
    assert values[0] == 0 and values[3] == 32767 and values[4] == -32767
    assert 16000 < values[1] < 16500
