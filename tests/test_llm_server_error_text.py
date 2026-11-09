"""The LLM server's (and an MCP or transcription server's) own words of an
error answer reach the user: ollama's "model not found, try pulling it
first", OpenAI's context-length message, "Incorrect API key", "exceeded your
quota" - not only "answered HTTP 404". The text is read bounded, stripped of
control and bidi characters, cut short, and never carries the API key."""

from __future__ import annotations

import io
import json
import threading
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core import agent as A
from core import agent_net as N
from core import mcp_client as C
from core import voice_stt as V
from core.llm_profiles import LLMProfile


@pytest.fixture(autouse=True)
def _no_proxy(monkeypatch):
    for name in ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY",
                 "ALL_PROXY", "no_proxy", "NO_PROXY"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture
def server():
    answer = {}

    class Handler(BaseHTTPRequestHandler):
        def _any(self):
            length = int(self.headers.get("Content-Length") or 0)
            if length:
                self.rfile.read(length)
            status, kind, data = answer["value"]
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        do_GET = do_POST = _any

        def log_message(self, *args):
            pass

    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()

    def set_answer(status, body, kind="application/json"):
        data = body if isinstance(body, bytes) else json.dumps(body).encode()
        answer["value"] = (status, kind, data)

    set_answer.port = httpd.server_address[1]
    yield set_answer
    httpd.shutdown()
    httpd.server_close()


def _profile(port, provider="openai"):
    return LLMProfile(name="x", provider=provider, endpoint=f"http://127.0.0.1:{port}/v1",
                      model="m", timeout=5)


def _http_error(body: bytes, code=400):
    return urllib.error.HTTPError("http://x/", code, "Bad", {}, io.BytesIO(body))


@pytest.mark.parametrize("status, body, expected", [
    (404, {"error": 'model "llama3.1" not found, try pulling it first'},
     'answered HTTP 404: model "llama3.1" not found, try pulling it first'),
    (400, {"error": {"message": "This model's maximum context length is 8192 tokens.",
                     "type": "invalid_request_error"}},
     "answered HTTP 400: This model's maximum context length is 8192 tokens."),
    (401, {"error": {"message": "Incorrect API key provided: sk-...abcd."}},
     "answered HTTP 401: Incorrect API key provided: sk-...abcd."),
    (429, {"error": {"message": "You exceeded your current quota."}},
     "answered HTTP 429: You exceeded your current quota."),
])
def test_happy_the_chat_error_carries_the_servers_message(server, status, body, expected):
    server(status, body)
    with pytest.raises(A.AgentError) as caught:
        A.post_chat(_profile(server.port), "", {"model": "m", "messages": []})
    assert str(caught.value).endswith(expected)


def test_happy_the_model_list_error_carries_the_servers_message(server):
    server(401, {"error": {"message": "Incorrect API key provided"}})
    with pytest.raises(A.AgentError, match="answered HTTP 401: Incorrect API key provided"):
        A.list_models(_profile(server.port), "")


def test_happy_an_mcp_http_server_error_carries_its_message(server):
    server(403, {"error": {"code": -32001, "message": "token expired"}})
    config = C.McpServerConfig(name="web", transport="http",
                               url=f"http://127.0.0.1:{server.port}/mcp", timeout=5)
    with pytest.raises(C.McpClientError, match="answered HTTP 403: token expired"):
        C.McpClient(config)


def test_happy_the_transcription_error_carries_the_servers_message():
    def opener(request, timeout):
        raise _http_error(json.dumps({"detail": "model whisper-9 not found"}).encode(), 404)

    profile = LLMProfile(name="x", provider="openai", endpoint="http://127.0.0.1:9/v1",
                         model="m", timeout=5)
    with pytest.raises(V.TranscriptionError,
                       match="answered HTTP 404: model whisper-9 not found"):
        V.transcribe_server(profile, "", b"\0\0" * 160, opener=opener)


def test_sad_the_api_key_never_shows_even_when_the_server_echoes_it(server):
    server(401, {"error": {"message": "Incorrect API key provided: sk-SECRET-123456."}})
    with pytest.raises(A.AgentError) as caught:
        A.post_chat(_profile(server.port), "sk-SECRET-123456", {"model": "m", "messages": []})
    assert "sk-SECRET-123456" not in str(caught.value)
    assert "Incorrect API key provided: ***." in str(caught.value)


def test_sad_an_html_error_page_adds_nothing(server):
    server(502, b"<html><body><h1>502 Bad Gateway</h1></body></html>", "text/html")
    with pytest.raises(A.AgentError) as caught:
        A.post_chat(_profile(server.port), "", {"model": "m", "messages": []})
    assert str(caught.value).endswith("answered HTTP 502")


def test_edge_control_and_bidi_characters_go_and_the_text_is_cut():
    body = json.dumps({"error": "bad\x1b[31m model\u202e evil\n" + "x" * 2000}).encode()
    text = N.server_error_text(_http_error(body))
    assert text.startswith(": bad [31m model evil x")
    assert "\x1b" not in text and "\u202e" not in text and "\n" not in text
    assert len(text) <= 2 + N.ERROR_TEXT_CHARS and text.endswith("…")


def test_edge_a_huge_body_is_read_bounded_and_broken_bodies_say_nothing():
    class Body(io.BytesIO):
        asked = []

        def read(self, n=-1):
            self.asked.append(n)
            return super().read(n)

    body = Body(b'{"message": "' + b"y" * 10_000_000 + b'"}')
    error = urllib.error.HTTPError("http://x/", 500, "Bad", {}, body)
    assert N.server_error_text(error) == ""  # cut JSON is no message
    assert Body.asked == [N.ERROR_BODY_BYTES]
    broken = N.server_error_text(_http_error(b"\xff\xfe\x00garbage {"))
    assert broken.endswith(" garbage {") and "\x00" not in broken
    assert N.server_error_text(_http_error(b"")) == ""
    assert N.server_error_text(_http_error(json.dumps({"error": {"code": 5}}).encode())) == ""
    assert N.server_error_text(_http_error(json.dumps(
        {"detail": [{"loc": ["body"], "msg": "field required"}]}).encode())) == ": field required"
    assert N.server_error_text(_http_error(b"plain text: overloaded")) == ": plain text: overloaded"
