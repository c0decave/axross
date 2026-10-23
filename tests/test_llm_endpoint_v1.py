"""An OpenAI-compatible endpoint given without its /v1 still works.

Reported: listing the models of an LM Studio on another machine of the
LAN failed. Measured against that LM Studio: <endpoint>/v1/models answers
the model list, but a profile endpoint typed as http://203.0.113.10:1234
made axross ask /models, and LM Studio answers that with 200 {"error":
"Unexpected endpoint or method. (GET /models)"}. Only Ollama profiles had
/v1 added; chat, analysis and server speech recognition took the same
endpoint and failed the same way. Typed without http:// the message was
"cannot reach the LLM server at : unknown url type".

Now an OpenAI-compatible endpoint without a path means its /v1 (a path
that is given is kept), and an endpoint without http(s):// says so.
"""

from __future__ import annotations

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import agent as A  # noqa: E402
from core import llm_profiles as LP  # noqa: E402


class _LMStudio:
    """Answers like LM Studio: the list under /v1/models, and 200 with an
    error object for every other path."""

    def __enter__(self):
        state = self
        self.seen: list[str] = []

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *a):
                pass

            def do_GET(self):
                state.seen.append(self.path)
                if self.path == "/v1/models":
                    body = {"data": [{"id": "qwen3.6-35b-a3b-mlx@4bit"}, {"id": "olmocr"}]}
                else:
                    body = {"error": f"Unexpected endpoint or method. (GET {self.path})"}
                data = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

        self._srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._srv.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self._srv.server_address[1]}"
        return self

    def __exit__(self, *exc):
        self._srv.shutdown()
        self._srv.server_close()
        return False


def _profile(endpoint: str, provider: str = "lmstudio") -> LP.LLMProfile:
    return LP.LLMProfile(name="lm", provider=provider, endpoint=endpoint)


# --- happy -----------------------------------------------------------------


@pytest.mark.parametrize("suffix", ["", "/"])
def test_happy_lm_studio_without_v1_lists_its_models(suffix):
    with _LMStudio() as srv:
        names = A.list_models(_profile(srv.url + suffix), "")
    assert names == ["qwen3.6-35b-a3b-mlx@4bit", "olmocr"]
    assert srv.seen == ["/v1/models"]


@pytest.mark.parametrize("provider", ["lmstudio", "openai", "mlx-lm"])
def test_happy_every_openai_compatible_use_gets_the_v1(provider):
    p = _profile("http://203.0.113.10:1234", provider)
    assert p.resolved_endpoint() == "http://203.0.113.10:1234/v1"
    assert A.chat_url(p) == "http://203.0.113.10:1234/v1/chat/completions"
    assert A.models_url(p) == "http://203.0.113.10:1234/v1/models"
    assert p.transcription_url() == "http://203.0.113.10:1234/v1/audio/transcriptions"


# --- sad -------------------------------------------------------------------


@pytest.mark.parametrize("endpoint", ["203.0.113.10:1234", "localhost:1234/v1", "ftp://h/v1"])
def test_sad_an_endpoint_without_http_says_what_to_type(endpoint):
    with pytest.raises(A.AgentError) as info:
        A.list_models(_profile(endpoint), "")
    text = str(info.value)
    assert "http://" in text and "unknown url type" not in text
    with pytest.raises(A.AgentError, match="http://"):
        A.post_chat(_profile(endpoint), "", {"messages": []})


# --- edge ------------------------------------------------------------------


@pytest.mark.parametrize("endpoint", [
    "http://h:1234/v1", "http://h:1234/v1/", "https://example.org/openai/v2", "http://h/api",
])
def test_edge_a_given_path_is_kept(endpoint):
    assert _profile(endpoint).resolved_endpoint() == endpoint


def test_edge_ollama_and_the_defaults_are_unchanged():
    assert _profile("http://h:11434", "ollama").resolved_endpoint() == "http://h:11434"
    assert _profile("", "lmstudio").resolved_endpoint() == "http://localhost:1234/v1"
    assert _profile("", "ollama").resolved_endpoint() == "http://localhost:11434"


def test_edge_query_and_fragment_free_endpoint_with_port_only():
    # "http://h:1234?x" is no endpoint anyone types, but it must not become
    # "http://h:1234?x/v1".
    assert _profile("http://h:1234/").resolved_endpoint() == "http://h:1234/v1"
