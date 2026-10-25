"""An opener makes its TLS context at its first https request, not before.

Measured 2026-10-25 (perf/llm-agent, scratch prof_loop.py): every model
request (core.agent.post_chat), every "is the model loaded" check, every
model listing and every request of an http MCP server built a urllib opener,
and urllib's HTTPSHandler makes an SSL context when it is constructed
(ssl.create_default_context -> set_default_verify_paths): 3.3 ms per opener,
holding the GIL, a third of the agent loop's own time per step - also for an
http:// endpoint (LM Studio, Ollama, llama.cpp on this machine), which never
uses it. The context is now made when an https request needs it, exactly as
urllib makes it.
"""

from __future__ import annotations

import http.client
import ssl
import sys
import threading
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import agent as A  # noqa: E402
from core import agent_net as N  # noqa: E402
from core.llm_profiles import LLMProfile  # noqa: E402
from tests.test_agent_loop import _no_proxy, fake  # noqa: E402,F401


@pytest.fixture
def contexts(monkeypatch):
    """Every TLS context urllib's way of making one made."""
    made: list = []
    original = http.client._create_https_context

    def counted(version):
        context = original(version)
        made.append(context)
        return context

    monkeypatch.setattr(http.client, "_create_https_context", counted)
    return made


def _https_handlers(opener) -> list:
    return [h for h in opener.handlers if isinstance(h, urllib.request.HTTPSHandler)]


# -- happy ------------------------------------------------------------------------------------


def test_happy_a_model_request_to_an_http_endpoint_makes_no_tls_context(fake, contexts):
    server = fake({"content": "hello"})
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")
    answer = A.post_chat(profile, "", {"model": "tiny", "messages": []},
                         cancel=threading.Event())
    assert answer["choices"][0]["message"]["content"] == "hello"
    assert A.post_chat(profile, "", {"model": "tiny", "messages": []})["choices"]
    assert contexts == []


def test_happy_a_plain_opener_and_a_cuttable_one_make_none_until_https(contexts):
    N.opener_without_redirects()
    N.opener_without_redirects(*N.AbortableConnections().handlers())
    assert contexts == []


def test_happy_an_https_request_gets_the_context_urllib_makes(contexts, monkeypatch):
    seen: list = []

    def do_open(self, http_class, req, **kwargs):
        seen.append(kwargs.get("context"))
        raise urllib.error.URLError("stopped before the network")

    monkeypatch.setattr(urllib.request.AbstractHTTPHandler, "do_open", do_open)
    for opener in (N.opener_without_redirects(),
                   N.opener_without_redirects(*N.AbortableConnections().handlers())):
        for _ in range(2):
            with pytest.raises(urllib.error.URLError):
                opener.open("https://llm.example/v1/models", timeout=1)
    assert len(contexts) == 2, "one per opener, made at its first https request"
    assert seen == [contexts[0], contexts[0], contexts[1], contexts[1]]
    for context in contexts:
        assert isinstance(context, ssl.SSLContext)
        assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname


# -- sad --------------------------------------------------------------------------------------


def test_sad_an_https_server_that_is_not_there_fails_as_before(contexts):
    opener = N.opener_without_redirects()
    with pytest.raises(urllib.error.URLError):
        opener.open("https://127.0.0.1:9/v1/models", timeout=2)
    assert len(contexts) == 1


def test_sad_a_redirect_is_still_refused(fake):
    server = fake()
    profile = LLMProfile(name="local", provider="lmstudio", endpoint=server.url, model="tiny")
    server.replies.append(302)
    with pytest.raises(A.AgentError, match="redirect"):
        A.post_chat(profile, "", {"model": "tiny", "messages": []})


# -- edge -------------------------------------------------------------------------------------


def test_edge_a_given_context_and_check_hostname_are_kept(contexts):
    given = ssl.create_default_context()
    handler = N._LazyHTTPSHandler(context=given, check_hostname=False)
    assert handler._context is given and given.check_hostname is False
    lazy = N._LazyHTTPSHandler(check_hostname=False)
    assert contexts == []
    assert lazy._context.check_hostname is False
    assert lazy._context is lazy._context, "made once"
    assert len(contexts) == 1


def test_edge_only_one_https_handler_serves_an_opener(contexts):
    plain = _https_handlers(N.opener_without_redirects())
    cuttable = _https_handlers(N.opener_without_redirects(*N.AbortableConnections().handlers()))
    assert [type(h).__name__ for h in plain] == ["_LazyHTTPSHandler"]
    assert [type(h).__name__ for h in cuttable] == ["_TrackingHTTPSHandler"]


def test_edge_without_urllibs_helper_the_connection_makes_its_own(monkeypatch):
    # Python 3.10/3.11 have no http.client._create_https_context: urllib
    # left the context to HTTPSConnection then, and so does the handler.
    monkeypatch.delattr(http.client, "_create_https_context")
    assert N._LazyHTTPSHandler()._context is None


def test_edge_an_http_mcp_server_request_makes_no_tls_context(fake, contexts):
    # core.mcp_client posts through opener_without_redirects as well.
    server = fake()
    request = urllib.request.Request(server.url + "/models", headers={"Accept": "application/json"})
    with pytest.raises(urllib.error.HTTPError):
        N.opener_without_redirects().open(request, timeout=5)
    assert contexts == []
