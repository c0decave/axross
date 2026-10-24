"""An unreachable LLM server says what kind of unreachable it is.

Reported: the Agent dock worked against LM Studio on another machine, then
showed "cannot reach the LLM server at 203.0.113.10: timed out" and
"...: [Errno 110] Connection timed out". Measured from a second machine at
the same time: ping, SSH and the LM Studio port all timed out - the whole
machine had dropped off the network (not LM Studio alone, not axross).
The message did not say so; a person read it as "LM Studio is dead".

Now: refused (nothing listens - start the server), no answer at all
(the machine is asleep, off or elsewhere), no route, an unknown name, and
a server that accepted but did not answer within the profile's timeout
(the model may still be working) each get their own sentence.
"""

from __future__ import annotations

import errno
import socket
import sys
import threading
import urllib.error
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import agent as A  # noqa: E402
from core import llm_profiles as LP  # noqa: E402


def _profile(url: str, timeout: float = 30.0) -> LP.LLMProfile:
    return LP.LLMProfile(name="p", provider="lmstudio", model="m", endpoint=url, timeout=timeout)


P = _profile("http://203.0.113.10:1234/v1")


# -- happy: each kind gets its own reason ------------------------------------------

def test_happy_refused_means_nothing_listens():
    text = A.unreachable_text(P, urllib.error.URLError(ConnectionRefusedError(
        errno.ECONNREFUSED, "Connection refused")))
    assert text.startswith("cannot reach the LLM server at 203.0.113.10")
    assert "nothing listens on port 1234" in text and "is the LLM server running" in text


@pytest.mark.parametrize("exc", [
    urllib.error.URLError(OSError(errno.ETIMEDOUT, "Connection timed out")),
    urllib.error.URLError(TimeoutError("timed out")),   # the connect hit the profile's timeout
])
def test_happy_no_answer_at_all_points_at_the_machine(exc):
    text = A.unreachable_text(P, exc)
    assert text.startswith("cannot reach the LLM server at 203.0.113.10")
    assert "the machine does not answer at all" in text
    assert "asleep" in text


def test_happy_a_slow_answer_is_not_called_unreachable():
    text = A.unreachable_text(_profile("http://203.0.113.10:1234/v1", 120), TimeoutError("timed out"))
    assert "cannot reach" not in text
    assert "did not answer within 120 s" in text and "timeout" in text


# -- sad -----------------------------------------------------------------------------

@pytest.mark.parametrize("code", [errno.EHOSTUNREACH, errno.ENETUNREACH])
def test_sad_no_route_names_the_network(code):
    text = A.unreachable_text(P, urllib.error.URLError(OSError(code, "No route to host")))
    assert "no route to 203.0.113.10" in text


def test_sad_an_unknown_name_says_so():
    profile = _profile("http://llm.invalid:1234/v1")
    text = A.unreachable_text(profile, urllib.error.URLError(socket.gaierror(-2, "Name or service not known")))
    assert "the name llm.invalid is not known" in text


# -- edge ----------------------------------------------------------------------------

def test_edge_another_error_keeps_its_own_text():
    text = A.unreachable_text(P, urllib.error.URLError("unknown url type: x"))
    assert text == "cannot reach the LLM server at 203.0.113.10: unknown url type: x"


def test_edge_the_default_port_is_named_for_a_url_without_one():
    text = A.unreachable_text(_profile("http://llm.example/v1"),
                              urllib.error.URLError(ConnectionRefusedError(errno.ECONNREFUSED, "x")))
    assert "port 80" in text


# -- e2e: real sockets through the agent's own request path --------------------------

def _closed_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_e2e_a_closed_port_is_refused(tmp_path):
    profile = _profile(f"http://127.0.0.1:{_closed_port()}/v1", 5)
    with pytest.raises(A.AgentError) as info:
        A.Agent(A.AgentConfig(profile=profile, root=str(tmp_path))).run("hi")
    assert "nothing listens on port" in str(info.value)


def test_e2e_a_server_that_accepts_and_stays_silent_is_slow_not_unreachable(tmp_path):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    held = []
    stop = threading.Event()

    def accept():
        server.settimeout(0.2)
        while not stop.is_set():
            try:
                held.append(server.accept()[0])  # read nothing, answer nothing
            except OSError:
                pass

    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    profile = _profile(f"http://127.0.0.1:{server.getsockname()[1]}/v1", 1.5)
    try:
        with pytest.raises(A.AgentError) as info:
            A.Agent(A.AgentConfig(profile=profile, root=str(tmp_path))).run("hi")
    finally:
        stop.set()
        thread.join(2)
        for conn in held:
            conn.close()
        server.close()
    text = str(info.value)
    assert "did not answer within 1.5 s" in text and "cannot reach" not in text
