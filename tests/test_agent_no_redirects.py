"""The LLM request and an MCP server's http requests never follow a
redirect: urllib would send the Authorization header (the API key, the
server's token) on to whatever host the redirect names, past the allowed
hosts."""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from core import agent as A
from core import mcp_client as C
from core.llm_profiles import LLMProfile


class _Server:
    def __init__(self, host, answer):
        self.seen = []
        seen = self.seen

        class Handler(BaseHTTPRequestHandler):
            def _any(self):
                length = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(length) if length else b""
                seen.append((self.command, self.path, self.headers.get("Authorization")))
                status, headers, data = answer(self, body)
                self.send_response(status)
                for key, value in headers.items():
                    self.send_header(key, value)
                self.end_headers()
                self.wfile.write(data)

            do_GET = do_POST = _any

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer((host, 0), Handler)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def pair(monkeypatch):
    for name in (
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
        monkeypatch.delenv(name, raising=False)
    other = _Server("127.0.0.2", lambda h, b: (200, {"Content-Type": "application/json"}, b"{}"))
    first = _Server(
        "127.0.0.1", lambda h, b: (307, {"Location": f"http://127.0.0.2:{other.port}/steal"}, b"")
    )
    yield first, other
    first.close()
    other.close()


def test_sad_the_llm_request_does_not_follow_a_redirect(pair):
    first, other = pair
    profile = LLMProfile(
        name="x", provider="lmstudio", endpoint=f"http://127.0.0.1:{first.port}/v1", model="m"
    )
    with pytest.raises(A.AgentError, match="redirect"):
        A.post_chat(profile, "sk-SECRET", {"model": "m", "messages": []})
    assert other.seen == []


def test_sad_an_mcp_http_server_cannot_redirect_its_token_away(pair):
    first, other = pair
    config = C.McpServerConfig(name="web", transport="http", url=f"http://127.0.0.1:{first.port}/mcp",
                               bearer=True, timeout=5)
    with pytest.raises(C.McpClientError, match="redirect"):
        C.McpClient(config, token="TOKEN")
    assert other.seen == []


def test_happy_a_plain_answer_still_works(monkeypatch):
    for name in (
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
    ):
        monkeypatch.delenv(name, raising=False)
    answer = {"choices": [{"message": {"role": "assistant", "content": "hi"}}]}
    server = _Server("127.0.0.1", lambda h, b: (200, {"Content-Type": "application/json"},
                                                json.dumps(answer).encode()))
    try:
        profile = LLMProfile(
            name="x", provider="lmstudio", endpoint=f"http://127.0.0.1:{server.port}/v1", model="m"
        )
        assert A.post_chat(profile, "", {"model": "m", "messages": []}) == answer
    finally:
        server.close()
