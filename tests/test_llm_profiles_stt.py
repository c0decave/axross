"""Speech recognition per LLM profile: local faster-whisper (default) or an
OpenAI-compatible transcription endpoint. llm.json files from before
these fields load unchanged."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import llm_profiles as LP  # noqa: E402


def test_happy_defaults_are_local_recognition():
    p = LP.LLMProfile(name="x")
    assert (p.stt_engine, p.stt_endpoint, p.stt_model) == ("local", "", "")
    assert p.problems() == []


def test_happy_an_old_llm_json_without_the_fields_loads(tmp_path):
    path = tmp_path / "llm.json"
    path.write_text(json.dumps({"profiles": [
        {"name": "lab", "provider": "openai", "endpoint": "http://127.0.0.1:18080/v1",
         "model": "qwen", "temperature": 0.3, "timeout": 60.0, "max_output_tokens": 900,
         "allow_model_load": False, "confirmed_origin": ""}], "active": "lab"}),
        encoding="utf-8")
    s = LP.LLMSettings.load(path)
    p = s.active_profile()
    assert p is not None and p.model == "qwen" and p.stt_engine == "local"
    assert not s.file_not_fully_loaded


def test_happy_the_fields_round_trip(tmp_path):
    path = tmp_path / "llm.json"
    p = LP.LLMProfile(name="srv", provider="openai", endpoint="http://127.0.0.1:1234/v1",
                      stt_engine="server", stt_endpoint="http://127.0.0.1:9000/v1",
                      stt_model="whisper-large")
    LP.LLMSettings([p], "srv").save(path)
    back = LP.LLMSettings.load(path).profile("srv")
    assert (back.stt_engine, back.stt_endpoint, back.stt_model) == (
        "server", "http://127.0.0.1:9000/v1", "whisper-large")


def test_happy_the_transcription_url_defaults_to_the_profile_endpoint():
    p = LP.LLMProfile(name="x", provider="openai", endpoint="http://127.0.0.1:1234/v1/",
                      stt_engine="server")
    assert p.transcription_url() == "http://127.0.0.1:1234/v1/audio/transcriptions"
    p.stt_endpoint = "http://10.0.0.5:9000/v1"
    assert p.transcription_url() == "http://10.0.0.5:9000/v1/audio/transcriptions"
    assert p.stt_server_model() == "whisper-1"
    p.stt_model = "large-v3"
    assert p.stt_server_model() == "large-v3"


@pytest.mark.parametrize("field,value", [
    ("stt_engine", "cloud"), ("stt_endpoint", "ftp://x"), ("stt_endpoint", "http://[::1"),
])
def test_sad_invalid_recognition_settings_are_problems(field, value):
    p = LP.LLMProfile(name="x")
    setattr(p, field, value)
    assert p.problems()


def test_sad_an_unknown_local_model_is_a_problem():
    p = LP.LLMProfile(name="x", stt_engine="local", stt_model="gigantic")
    assert p.problems()
    assert LP.LLMProfile(name="x", stt_engine="local", stt_model="small").problems() == []


def test_edge_invalid_recognition_values_in_the_file_do_not_drop_the_profile(tmp_path):
    path = tmp_path / "llm.json"
    path.write_text(json.dumps({"profiles": [
        {"name": "a", "provider": "ollama", "stt_engine": "cloud", "stt_endpoint": "ftp://x",
         "stt_model": "gigantic"}]}), encoding="utf-8")
    p = LP.LLMSettings.load(path).profile("a")
    assert p is not None
    assert (p.stt_engine, p.stt_endpoint, p.stt_model) == ("local", "", "")


def test_edge_a_remote_transcription_endpoint_needs_consent():
    p = LP.LLMProfile(name="x", provider="openai", endpoint="http://127.0.0.1:1234/v1",
                      stt_engine="server", stt_endpoint="https://stt.example.org/v1")
    assert p.stt_needs_consent()
    p.stt_endpoint = ""
    assert not p.stt_needs_consent()  # the local LLM server itself
    local = LP.LLMProfile(name="y", stt_engine="local",
                          endpoint="https://llm.example.org/v1", provider="openai")
    assert not local.stt_needs_consent()  # nothing leaves the machine


def test_edge_the_llm_consent_covers_the_same_endpoint():
    p = LP.LLMProfile(name="x", provider="openai", endpoint="https://llm.example.org/v1",
                      stt_engine="server")
    assert p.stt_needs_consent()
    p.consent()
    assert not p.stt_needs_consent()
