"""The Agent dock honours the profile's "May load a model that is not in
memory (evicts the loaded one)".

Found while testing the dock against LM Studio: Fetch models lists every
model LM Studio has on disk (80 on the test Mac, two loaded), the profile
has the switch, and the Analysis dock passes it to sift
(core/analysis_worker.py), which refuses a cold model while another one is
loaded. core.agent never read it: a tab with a cold model made LM Studio or
Ollama load it and evict the loaded one. Now the agent asks the server
which models are loaded before it sends anything, and refuses the same way
sift does: a cold model only when nothing is loaded, or when the profile
allows the load; a server that cannot be asked is a refusal, not a
permission.
"""

from __future__ import annotations

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import agent as A  # noqa: E402
from core import llm_profiles as LP  # noqa: E402
from tests.test_agent_loop import _no_proxy  # noqa: E402,F401


class _Server:
    """LM Studio's /api/v0/models or Ollama's /api/ps, and a chat endpoint
    that counts what it was sent."""

    def __init__(self, *, lmstudio=None, ps=None, status=200):
        self.chats = 0
        self.asked: list[str] = []
        fake = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802 - http.server API
                fake.asked.append(self.path)
                body = {"/api/v0/models": lmstudio, "/api/ps": ps}.get(self.path)
                if body is None or status != 200:
                    self.send_response(status if status != 200 else 404)
                    self.end_headers()
                    return
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())

            def do_POST(self):  # noqa: N802 - http.server API
                self.rfile.read(int(self.headers["Content-Length"]))
                fake.chats += 1
                data = {"choices": [{"message": {"role": "assistant", "content": "hi"},
                                     "finish_reason": "stop"}]}
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps(data).encode())

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.05},
                         daemon=True).start()
        self.root = f"http://127.0.0.1:{self.server.server_address[1]}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def server():
    made = []

    def make(**kw):
        s = _Server(**kw)
        made.append(s)
        return s

    yield make
    for s in made:
        s.close()


def _lms(*entries):
    return {"data": [{"id": i, "state": s} for i, s in entries]}


def _ps(*names):
    return {"models": [{"name": n, "model": n} for n in names]}


def _run(srv, tmp_path, *, provider="lmstudio", model="cold", allow=False, endpoint=None):
    profile = LP.LLMProfile(name="p", provider=provider, model=model, allow_model_load=allow,
                            endpoint=endpoint or (srv.root if provider == "ollama"
                                                  else srv.root + "/v1"))
    return A.Agent(A.AgentConfig(profile=profile, root=str(tmp_path))).run("hi")


# -- happy ---------------------------------------------------------------------------------


def test_happy_lmstudio_a_loaded_model_is_used(server, tmp_path):
    srv = server(lmstudio=_lms(("warm", "loaded"), ("cold", "not-loaded")))
    assert _run(srv, tmp_path, model="warm").answer == "hi"
    assert srv.chats == 1 and srv.asked == ["/api/v0/models"]


def test_happy_ollama_a_loaded_model_is_used(server, tmp_path):
    srv = server(ps=_ps("qwen2.5:1.5b"))
    assert _run(srv, tmp_path, provider="ollama", model="qwen2.5:1.5b").answer == "hi"
    assert srv.chats == 1 and srv.asked == ["/api/ps"]


def test_happy_the_profile_may_load_asks_nothing(server, tmp_path):
    srv = server(lmstudio=_lms(("warm", "loaded"), ("cold", "not-loaded")))
    assert _run(srv, tmp_path, model="cold", allow=True).answer == "hi"
    assert srv.asked == [] and srv.chats == 1


# -- sad -----------------------------------------------------------------------------------


def test_sad_lmstudio_a_cold_model_beside_a_loaded_one_is_refused(server, tmp_path):
    srv = server(lmstudio=_lms(("warm", "loaded"), ("cold", "not-loaded")))
    with pytest.raises(A.AgentError) as caught:
        _run(srv, tmp_path, model="cold")
    text = str(caught.value)
    assert "cold" in text and "warm" in text and "May load a model" in text
    assert srv.chats == 0, "nothing was sent: the server loaded nothing"


def test_sad_ollama_a_cold_model_beside_a_loaded_one_is_refused(server, tmp_path):
    srv = server(ps=_ps("llama3:8b"))
    with pytest.raises(A.AgentError, match="not loaded"):
        _run(srv, tmp_path, provider="ollama", model="qwen2.5:1.5b")
    assert srv.chats == 0


def test_sad_a_server_that_cannot_be_asked_is_a_refusal(server, tmp_path):
    srv = server(lmstudio=_lms(("warm", "loaded")), status=500)
    with pytest.raises(A.AgentError, match="cannot check whether"):
        _run(srv, tmp_path, model="warm")
    assert srv.chats == 0


# -- edge ----------------------------------------------------------------------------------


def test_edge_an_idle_server_may_load_the_model(server, tmp_path):
    srv = server(lmstudio=_lms(("warm", "not-loaded"), ("cold", "not-loaded")))
    assert _run(srv, tmp_path, model="cold").answer == "hi"
    srv2 = server(ps=_ps())
    assert _run(srv2, tmp_path, provider="ollama", model="qwen2.5:1.5b").answer == "hi"


def test_edge_names_match_as_the_servers_resolve_them(server, tmp_path):
    srv = server(lmstudio=_lms(("Qwen3-Warm", "loaded")))
    assert _run(srv, tmp_path, model="qwen3-warm").answer == "hi"
    srv2 = server(ps=_ps("mine:latest"))
    assert _run(srv2, tmp_path, provider="ollama", model="mine").answer == "hi"


def test_edge_other_providers_are_not_asked(server, tmp_path):
    srv = server(lmstudio=_lms(("warm", "loaded")))
    assert _run(srv, tmp_path, provider="openai", model="cold").answer == "hi"
    assert srv.asked == []


def test_edge_a_model_lmstudio_does_not_list_is_left_to_the_server(server, tmp_path):
    """Not in the list: the server answers for itself (an error, or a model
    it resolves) - no refusal axross cannot justify."""
    srv = server(lmstudio=_lms(("warm", "loaded")))
    assert _run(srv, tmp_path, model="elsewhere").answer == "hi"


def test_edge_a_server_without_the_list_endpoint_is_asked_as_before(server, tmp_path):
    """404: a plain OpenAI-compatible server (or a proxy that passes /v1
    only) lists no loaded models - nothing it reports can be evicted."""
    srv = server(lmstudio=None)
    assert _run(srv, tmp_path, model="cold").answer == "hi"
    assert srv.asked == ["/api/v0/models"] and srv.chats == 1


def test_edge_an_unreachable_server_is_left_to_the_request(tmp_path):
    """Nothing listens: no residency question - the request says it
    cannot reach the server, as before."""
    import socket

    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    profile = LP.LLMProfile(name="p", provider="lmstudio", model="cold",
                            endpoint=f"http://127.0.0.1:{port}/v1")
    assert A.model_load_refusal(profile, "") == ""
    with pytest.raises(A.AgentError, match="cannot reach the LLM server"):
        A.Agent(A.AgentConfig(profile=profile, root=str(tmp_path))).run("hi")


def test_edge_lmstudio_without_load_states_is_a_refusal(server, tmp_path):
    """An LM Studio build whose list has no state cannot tell what is loaded."""
    srv = server(lmstudio={"data": [{"id": "warm"}, {"id": "cold"}]})
    with pytest.raises(A.AgentError, match="cannot check whether"):
        _run(srv, tmp_path, model="cold")
    assert srv.chats == 0


def test_sad_a_sandboxed_tab_is_refused_by_axross(server, tmp_path):
    """A sandboxed agent's requests are sent by axross: axross checks."""
    from core import agent_sandbox as SB

    srv = server(lmstudio=_lms(("warm", "loaded"), ("cold", "not-loaded")))
    profile = LP.LLMProfile(name="p", provider="lmstudio", endpoint=srv.root + "/v1",
                            model="cold")
    agent = SB.SandboxedAgent(A.AgentConfig(profile=profile, root=str(tmp_path)), None,
                              command=SB.worker_argv())
    try:
        with pytest.raises(A.AgentError, match="not loaded"):
            agent.run("hi")
    finally:
        agent.close()
    assert srv.chats == 0


# -- the dock ------------------------------------------------------------------------------


def test_happy_e2e_the_tab_says_why_it_sent_nothing(server, tmp_path):
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QApplication

    from core.agent_session import SessionStore
    from ui.agent_dock import AgentDock

    app = QApplication.instance() or QApplication([])
    srv = server(lmstudio=_lms(("warm", "loaded"), ("cold", "not-loaded")))
    profile = LP.LLMProfile(name="mac", provider="lmstudio", endpoint=srv.root, model="cold")
    settings = LP.LLMSettings([profile], "mac")
    dock = AgentDock(settings_loader=lambda: settings, settings_saver=lambda s: None,
                     key_lookup=lambda n: "", confirm_remote=lambda p, h: True,
                     confirm_call=lambda n, a: False, root_provider=lambda: str(tmp_path),
                     session_store=SessionStore(tmp_path / "sessions"))
    try:
        tab = dock.current_tab()
        tab.input.setPlainText("hello")
        QTest.keyClick(tab.input, Qt.Key.Key_Return, Qt.KeyboardModifier.ControlModifier)
        import time

        end = time.monotonic() + 10
        while (tab.busy() or not tab.send_button.isEnabled()) and time.monotonic() < end:
            app.processEvents()
            time.sleep(0.01)
        app.processEvents()
        text = tab.transcript.toPlainText()
        assert "cold" in text and "not loaded" in text
        assert srv.chats == 0
    finally:
        dock.shutdown()
        dock.deleteLater()
        app.processEvents()
