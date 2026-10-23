"""Speech recognition on a server: an OpenAI-compatible
``POST {endpoint}/audio/transcriptions`` (core.voice_stt), against a real
local HTTP server. The recording travels from memory - nothing is written
to disk."""

from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import llm_profiles as LP  # noqa: E402
from core import voice_stt as STT  # noqa: E402


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *_args):  # quiet
        pass

    def do_POST(self):  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length)
        self.server.seen.append({"path": self.path, "headers": dict(self.headers), "body": body})
        status, payload = self.server.answer
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload if isinstance(payload, bytes) else json.dumps(payload).encode())


@pytest.fixture
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    httpd.seen = []
    httpd.answer = (200, {"text": "Hallo Welt"})
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()
    httpd.server_close()


def _profile(httpd, **kw):
    return LP.LLMProfile(name="p", provider="openai",
                         endpoint=f"http://127.0.0.1:{httpd.server_port}/v1",
                         stt_engine="server", **kw)


PCM = b"\x01\x00" * 1600  # 0.1 s of 16 kHz mono int16


def test_happy_the_recording_goes_as_a_wav_upload(server, tmp_path, monkeypatch):
    monkeypatch.setenv("TMPDIR", str(tmp_path))
    text = STT.transcribe_server(_profile(server), "sk-test", PCM, language="de")
    assert text == "Hallo Welt"
    seen = server.seen[0]
    assert seen["path"] == "/v1/audio/transcriptions"
    assert seen["headers"]["Authorization"] == "Bearer sk-test"
    body = seen["body"]
    assert b'name="model"\r\n\r\nwhisper-1\r\n' in body
    assert b'name="language"\r\n\r\nde\r\n' in body
    assert b'filename="speech.wav"' in body and b"RIFF" in body and b"WAVE" in body
    assert PCM in body
    assert list(tmp_path.iterdir()) == []  # nothing written to disk


def test_happy_the_profile_model_and_endpoint_are_used(server):
    profile = _profile(server, stt_model="large-v3")
    profile.endpoint = "http://127.0.0.1:1/v1"  # the LLM elsewhere
    profile.stt_endpoint = f"http://127.0.0.1:{server.server_port}/stt"
    STT.transcribe_server(profile, "", PCM, language=None)
    seen = server.seen[0]
    assert seen["path"] == "/stt/audio/transcriptions"
    assert b"large-v3" in seen["body"]
    assert "Authorization" not in seen["headers"]
    assert b'name="language"' not in seen["body"]


def test_sad_an_http_error_is_a_transcription_error(server):
    server.answer = (401, {"error": {"message": "bad key"}})
    with pytest.raises(STT.TranscriptionError, match="401"):
        STT.transcribe_server(_profile(server), "x", PCM)


def test_sad_an_answer_without_text_is_an_error(server):
    server.answer = (200, b"<html>no</html>")
    with pytest.raises(STT.TranscriptionError):
        STT.transcribe_server(_profile(server), "x", PCM)
    server.answer = (200, {"nope": 1})
    with pytest.raises(STT.TranscriptionError):
        STT.transcribe_server(_profile(server), "x", PCM)


def test_sad_an_unreachable_server_is_an_error():
    profile = LP.LLMProfile(name="p", provider="openai", endpoint="http://127.0.0.1:9/v1",
                            stt_engine="server", timeout=2)
    with pytest.raises(STT.TranscriptionError):
        STT.transcribe_server(profile, "", PCM)


def test_edge_wav_header_describes_16k_mono_int16():
    wav = STT.wav_bytes(PCM)
    assert wav[:4] == b"RIFF" and wav[8:12] == b"WAVE"
    assert int.from_bytes(wav[24:28], "little") == 16000
    assert int.from_bytes(wav[22:24], "little") == 1
    assert int.from_bytes(wav[34:36], "little") == 16
    assert wav[44:] == PCM


def test_edge_an_odd_byte_count_is_trimmed():
    assert STT.wav_bytes(b"\x01\x02\x03")[44:] == b"\x01\x02"


def test_edge_a_huge_answer_is_cut_off(server):
    server.answer = (200, {"text": "x" * (STT.MAX_ANSWER_BYTES + 10)})
    with pytest.raises(STT.TranscriptionError):
        STT.transcribe_server(_profile(server), "", PCM)


def test_edge_the_api_key_is_never_part_of_the_url(server):
    STT.transcribe_server(_profile(server), "sk-secret", PCM)
    assert "sk-secret" not in server.seen[0]["path"]
    assert os.environ.get("AXROSS_STT_KEY") is None
