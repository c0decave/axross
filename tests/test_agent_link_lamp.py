"""A lamp in the Agent dock's title bar says whether the LLM is reachable.

Requested: green when the Agent dock is connected to the LLM,
red when not, orange while it tries - in the dock's frame, best its top
row.

"Connected" is evidence, never a guess: the last request to the tab's
profile - a model listing (the check) or a chat request of a task -
succeeded. Red after a failure, without a profile, and before anything
was asked; orange while a check or a request is on its way. The check
runs off the GUI thread, bounded by core.agent.MODELS_TIMEOUT, only while
the dock is shown, and never to a remote endpoint without consent (it
would carry the key there).
"""

from __future__ import annotations

import os
import socket
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtGui import QColor  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication, QToolButton  # noqa: E402

from core import agent as A  # noqa: E402
from core import agent_link as L  # noqa: E402
from core import llm_profiles as LP  # noqa: E402
from tests.test_agent_loop import _no_proxy, fake  # noqa: E402,F401
from tests.test_agent_tabs import env, say, wait_idle  # noqa: E402,F401

APP = QApplication.instance() or QApplication([])


def _profile(endpoint="http://127.0.0.1:9/v1", model="tiny", **kw):
    return LP.LLMProfile(name="local", provider="lmstudio", endpoint=endpoint, model=model, **kw)


def _closed_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _wait(cond, seconds=8.0):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    APP.processEvents()
    return bool(cond())


# -- core.agent_link.probe ---------------------------------------------------------------------


def test_happy_probe_lists_the_models(fake):
    server = fake()
    server.models = ["tiny", "big"]
    assert L.probe(_profile(server.url), "") == (True, "")
    assert server.gets == ["/v1/models"]


def test_sad_probe_of_a_closed_port_says_why():
    ok, detail = L.probe(_profile(f"http://127.0.0.1:{_closed_port()}/v1"), "")
    assert not ok and "cannot reach the LLM server at 127.0.0.1" in detail


def test_sad_probe_of_a_server_without_a_model_list(fake):
    server = fake()  # answers GET with 501
    ok, detail = L.probe(_profile(server.url), "")
    assert not ok and "HTTP 501" in detail


def test_sad_probe_never_reaches_a_remote_endpoint_without_consent(monkeypatch):
    monkeypatch.setattr(A, "list_models", lambda *a: pytest.fail("the key went out"))
    ok, detail = L.probe(_profile("http://203.0.113.5:1234/v1"), "secret")
    assert not ok and "consent" in detail and "203.0.113.5" in detail


def test_sad_probe_of_an_endpoint_without_http(monkeypatch):
    monkeypatch.setattr(A, "list_models", lambda *a: pytest.fail("asked a broken endpoint"))
    ok, detail = L.probe(_profile("localhost:1234"), "")
    assert not ok and detail


def test_edge_probe_says_when_the_model_is_not_listed(fake):
    server = fake()
    server.models = ["other"]
    ok, detail = L.probe(_profile(server.url, model="tiny"), "")
    assert ok and "tiny" in detail and "not list" in detail


def test_edge_probe_reads_model_names_as_the_server_does(monkeypatch):
    monkeypatch.setattr(A, "list_models", lambda p, k: ["qwen2.5:latest", "Tiny-Model"])
    ollama = LP.LLMProfile(name="o", provider="ollama", endpoint="http://127.0.0.1:9",
                           model="qwen2.5")
    assert L.probe(ollama, "") == (True, "")
    assert L.probe(_profile(model="tiny-model"), "") == (True, "")
    ollama.model = "qwen2.5:7b"
    assert L.probe(ollama, "")[1] == "the server does not list the model qwen2.5:7b"


def test_edge_probe_with_a_consented_remote_endpoint_asks(monkeypatch):
    asked = []
    monkeypatch.setattr(A, "list_models", lambda p, k: asked.append(k) or ["tiny"])
    profile = _profile("http://203.0.113.5:1234/v1")
    profile.consent()
    assert L.probe(profile, "key") == (True, "")
    assert asked == ["key"]


# -- the agent's connection events ------------------------------------------------------------


def test_happy_a_request_says_trying_then_connected(fake, tmp_path):
    server = fake({"content": "hi"})
    events: list[dict] = []
    A.Agent(A.AgentConfig(profile=_profile(server.url), root=str(tmp_path)),
            on_event=events.append).run("hello")
    assert [e["state"] for e in events if e["type"] == "connection"] == ["trying", "connected"]


def test_sad_a_failed_request_says_why(fake, tmp_path):
    server = fake(500)
    events: list[dict] = []
    with pytest.raises(A.AgentError):
        A.Agent(A.AgentConfig(profile=_profile(server.url), root=str(tmp_path)),
                on_event=events.append).run("hello")
    states = [(e["state"], e.get("detail", "")) for e in events if e["type"] == "connection"]
    assert states[0] == ("trying", "") and states[1][0] == "failed"
    assert "HTTP 500" in states[1][1]


def test_sad_a_sandboxed_agents_failed_request_is_said_by_axross(fake, tmp_path):
    from core import agent_sandbox as SB

    server = fake(500)
    events: list[dict] = []
    agent = SB.SandboxedAgent(A.AgentConfig(profile=_profile(server.url), root=str(tmp_path)),
                              None, on_event=events.append, command=SB.worker_argv())
    try:
        with pytest.raises(A.AgentError):
            agent.run("hello")
    finally:
        agent.close()
    states = [e["state"] for e in events if e["type"] == "connection"]
    assert states == ["trying", "failed"]


def test_edge_an_answer_without_a_message_is_a_failed_request(tmp_path, monkeypatch):
    monkeypatch.setattr(A, "post_chat", lambda *a, **k: {"choices": []})
    events: list[dict] = []
    with pytest.raises(A.AgentError):
        A.Agent(A.AgentConfig(profile=_profile(), root=str(tmp_path)),
                on_event=events.append).run("hello")
    assert [e["state"] for e in events if e["type"] == "connection"] == ["trying", "failed"]


def test_edge_a_transport_agent_leaves_the_connection_to_its_owner(tmp_path):
    events: list[dict] = []
    agent = A.Agent(A.AgentConfig(profile=_profile(), root=str(tmp_path)), on_event=events.append,
                    transport=lambda body: {"choices": [{"message": {"content": "ok"}}]})
    agent.run("hello")
    assert not [e for e in events if e["type"] == "connection"]


# -- core.agent_link.LinkTracker ---------------------------------------------------------------


def test_happy_tracker_goes_orange_then_green():
    t = L.LinkTracker()
    t.reset(_profile())
    assert t.state == L.OFFLINE and t.needs_check()
    token = t.begin_check()
    assert t.state == L.TRYING and not t.needs_check()
    t.end_check(token, True, "")
    assert t.state == L.ONLINE and not t.needs_check()
    assert "http://127.0.0.1:9/v1" in t.tooltip() and "tiny" in t.tooltip()
    assert "Connected" in t.tooltip()


def test_happy_tracker_follows_the_requests_of_a_task():
    t = L.LinkTracker()
    t.reset(_profile())
    t.on_event({"type": "connection", "state": "trying"})
    assert t.state == L.TRYING
    t.on_event({"type": "connection", "state": "connected"})
    assert t.state == L.ONLINE


def test_sad_a_failed_request_turns_it_red_with_the_reason():
    t = L.LinkTracker()
    t.reset(_profile())
    t.on_event({"type": "connection", "state": "trying"})
    t.on_event({"type": "connection", "state": "failed", "detail": "answered HTTP 500"})
    assert t.state == L.OFFLINE and "answered HTTP 500" in t.tooltip()
    assert t.needs_check()


def test_sad_no_profile_is_red():
    t = L.LinkTracker()
    t.no_profile()
    assert t.state == L.OFFLINE and "No LLM profile" in t.tooltip() and not t.needs_check()


def test_sad_odd_events_change_nothing():
    t = L.LinkTracker()
    t.reset(_profile())
    token = t.begin_check()
    t.end_check(token, True, "")
    for event in ({"type": "connection", "state": "boom"}, {"type": "assistant"},
                  {"type": "connection"}, {"type": "connection", "state": None}):
        t.on_event(event)
        assert t.state == L.ONLINE


def test_edge_a_check_result_older_than_a_request_is_dropped():
    t = L.LinkTracker()
    t.reset(_profile())
    token = t.begin_check()
    t.on_event({"type": "connection", "state": "trying"})
    t.on_event({"type": "connection", "state": "connected"})
    t.end_check(token, False, "late failure")
    assert t.state == L.ONLINE


def test_edge_a_stop_while_a_check_was_on_its_way_never_stays_orange():
    t = L.LinkTracker()
    t.reset(_profile())
    token = t.begin_check()
    t.on_event({"type": "connection", "state": "trying"})
    t.on_event({"type": "connection", "state": "cancelled"})
    assert t.state == L.OFFLINE and t.needs_check()
    assert not t.end_check(token, True, "")  # the old check no longer counts
    assert not t.on_event({"type": "connection", "state": "cancelled"})


def test_edge_a_request_of_a_tab_without_a_known_profile_still_tells_the_truth():
    t = L.LinkTracker()
    t.no_profile()
    t.on_event({"type": "connection", "state": "trying"})
    t.on_event({"type": "connection", "state": "connected"})
    assert t.state == L.ONLINE and t.tooltip().startswith("Connected to the LLM")


def test_edge_a_stopped_request_brings_back_the_state_before_it():
    t = L.LinkTracker()
    t.reset(_profile())
    t.end_check(t.begin_check(), True, "")
    t.on_event({"type": "connection", "state": "trying"})
    t.on_event({"type": "connection", "state": "cancelled"})
    assert t.state == L.ONLINE
    t.on_event({"type": "connection", "state": "failed", "detail": "x"})
    t.on_event({"type": "connection", "state": "trying"})
    t.on_event({"type": "connection", "state": "cancelled"})
    assert t.state == L.OFFLINE and "x" in t.tooltip()


def test_edge_a_new_profile_forgets_the_old_state():
    t = L.LinkTracker()
    t.reset(_profile())
    t.end_check(t.begin_check(), True, "")
    assert not t.reset(_profile())  # the same profile: kept
    assert t.state == L.ONLINE
    assert t.reset(_profile(model="other"))
    assert t.state == L.OFFLINE and t.needs_check()


def test_edge_a_model_the_server_does_not_list_is_named_in_the_tooltip():
    t = L.LinkTracker()
    t.reset(_profile())
    t.end_check(t.begin_check(), True, "the server does not list the model tiny")
    assert t.state == L.ONLINE and "does not list the model tiny" in t.tooltip()


# -- the lamp widget ---------------------------------------------------------------------------


def _luminance(colour: QColor) -> float:
    def channel(v: float) -> float:
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4

    return (0.2126 * channel(colour.redF()) + 0.7152 * channel(colour.greenF())
            + 0.0722 * channel(colour.blueF()))


def _contrast(a: QColor, b: QColor) -> float:
    la, lb = sorted((_luminance(a), _luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def test_happy_the_lamp_has_three_colours_readable_on_light_and_dark():
    from ui.agent_link_lamp import LinkLamp

    lamp = LinkLamp()
    colours = {}
    for state in (L.OFFLINE, L.TRYING, L.ONLINE):
        lamp.set_state(state, "tip")
        colours[state] = lamp.colour().name()
        for background in ("#ffffff", "#1e1e1e"):
            assert _contrast(lamp.colour(), QColor(background)) >= 2.0, (state, background)
    assert len(set(colours.values())) == 3
    lamp.deleteLater()


def test_sad_the_lamp_says_its_state_in_words_not_only_in_colour():
    from ui.agent_link_lamp import LinkLamp

    lamp = LinkLamp()
    lamp.set_state(L.OFFLINE, "Not connected to the LLM: x")
    assert lamp.toolTip() == "Not connected to the LLM: x"
    assert "not connected" in lamp.accessibleName().lower()
    lamp.set_state("nonsense", "?")
    assert lamp.state == L.OFFLINE
    lamp.deleteLater()


def test_edge_a_dock_without_a_title_bar_never_shows_the_lamp_over_its_tabs(env):
    env.fake()
    dock = env.dock()
    dock.show()
    APP.processEvents()
    assert dock.lamp.parent() is dock and not dock.lamp.isVisible()


def test_edge_the_title_bar_takes_an_indicator_before_its_buttons():
    from PyQt6.QtWidgets import QDockWidget

    from ui.agent_link_lamp import LinkLamp
    from ui.dock_titlebar import DockTitleBar

    dock = QDockWidget("Agent")
    bar = DockTitleBar("Agent", "bot", dock)
    dock.setTitleBarWidget(bar)
    lamp = LinkLamp()
    bar.add_indicator(lamp)
    layout = bar.layout()
    assert layout.indexOf(lamp) == layout.indexOf(bar._float_btn) - 1
    assert lamp.parent() is bar
    dock.deleteLater()


# -- the dock, offscreen -----------------------------------------------------------------------


def _dock_with_bar(env):
    from ui.dock_titlebar import DockTitleBar

    dock = env.dock()
    bar = DockTitleBar("Agent", "bot", dock)
    dock.setTitleBarWidget(bar)
    dock.show_lamp_in(bar)
    dock.resize(700, 500)
    return dock, bar


def test_happy_e2e_showing_the_dock_checks_and_the_lamp_turns_green(env):
    server = env.fake()
    server.models = ["tiny"]
    server.models_delay = 0.6
    dock, bar = _dock_with_bar(env)
    assert server.gets == [], "nothing is asked while the dock is hidden"
    dock.show()
    assert _wait(lambda: dock.lamp.state == L.TRYING, 2), dock.lamp.toolTip()
    assert _wait(lambda: dock.lamp.state == L.ONLINE), dock.lamp.toolTip()
    assert dock.lamp.parent() is bar and dock.lamp.isVisible()
    assert server.url in dock.lamp.toolTip() and "tiny" in dock.lamp.toolTip()
    assert server.gets == ["/v1/models"]


def test_happy_e2e_the_lamp_is_orange_while_a_task_waits_for_the_model(env):
    server = env.fake({"content": "slow answer", "_delay": 1.0})
    server.models = ["tiny"]
    dock, _bar = _dock_with_bar(env)
    dock.show()
    assert _wait(lambda: dock.lamp.state == L.ONLINE)
    tab = dock.current_tab()
    tab.input.setPlainText("hello")
    QTest.mouseClick(tab.send_button, Qt.MouseButton.LeftButton)
    assert _wait(lambda: dock.lamp.state == L.TRYING, 2)
    wait_idle(tab)
    assert dock.lamp.state == L.ONLINE
    assert "slow answer" in tab.transcript.toPlainText()


def test_sad_e2e_a_server_that_is_not_there_is_red(env):
    env.fake()
    env.llm.profiles[0].endpoint = f"http://127.0.0.1:{_closed_port()}/v1"
    dock, _bar = _dock_with_bar(env)
    dock.show()
    assert _wait(lambda: dock.lamp.state == L.OFFLINE and "cannot reach" in dock.lamp.toolTip())


def test_sad_e2e_a_failed_request_turns_the_lamp_red(env):
    server = env.fake(500)
    server.models = ["tiny"]
    dock, _bar = _dock_with_bar(env)
    dock.show()
    assert _wait(lambda: dock.lamp.state == L.ONLINE)
    say(dock.current_tab(), "hello")
    assert dock.lamp.state == L.OFFLINE
    assert "HTTP 500" in dock.lamp.toolTip()


def test_sad_e2e_no_profile_is_red_without_any_request(env):
    env.fake()
    env.llm = LP.LLMSettings([], "")
    dock, _bar = _dock_with_bar(env)
    dock.show()
    APP.processEvents()
    assert dock.lamp.state == L.OFFLINE and "No LLM profile" in dock.lamp.toolTip()


def test_edge_e2e_a_click_on_the_red_lamp_checks_again(env):
    server = env.fake()  # no model list yet: the server is still starting
    dock, _bar = _dock_with_bar(env)
    dock.show()
    assert _wait(lambda: dock.lamp.state == L.OFFLINE and "HTTP 501" in dock.lamp.toolTip())
    server.models = ["tiny"]
    QTest.mouseClick(dock.lamp, Qt.MouseButton.LeftButton)
    assert _wait(lambda: dock.lamp.state == L.ONLINE)
    assert len(server.gets) == 2


def test_edge_e2e_each_tab_shows_its_own_profile(env):
    good = env.fake()
    good.models = ["tiny"]
    bad_url = f"http://127.0.0.1:{_closed_port()}/v1"
    env.llm.profiles.append(LP.LLMProfile(name="down", provider="lmstudio",
                                          endpoint=bad_url, model="m"))
    dock, _bar = _dock_with_bar(env)
    dock.show()
    first = dock.current_tab()
    assert _wait(lambda: dock.lamp.state == L.ONLINE)
    second = dock.new_tab()
    second.model_combo.setCurrentIndex(second.model_combo.findData("down"))
    assert _wait(lambda: dock.lamp.state == L.OFFLINE and bad_url in dock.lamp.toolTip())
    dock.tabs.setCurrentWidget(first)
    APP.processEvents()
    assert dock.lamp.state == L.ONLINE and good.url in dock.lamp.toolTip()


def test_edge_e2e_a_stopped_task_does_not_leave_the_lamp_orange(env):
    server = env.fake({"content": "never", "_delay": 8})
    server.models = ["tiny"]
    dock, _bar = _dock_with_bar(env)
    dock.show()
    assert _wait(lambda: dock.lamp.state == L.ONLINE)
    tab = dock.current_tab()
    tab.input.setPlainText("long")
    tab.send()
    assert _wait(lambda: dock.lamp.state == L.TRYING, 3)
    tab.stop()
    wait_idle(tab, 5)
    assert dock.lamp.state == L.ONLINE


def test_edge_e2e_the_main_window_puts_the_lamp_in_the_agent_title_bar(tmp_path, monkeypatch):
    from core import agent_session as AS
    from core import agent_settings as AGS

    monkeypatch.setattr(AGS, "settings_file", lambda: tmp_path / "agent" / "settings.json")
    monkeypatch.setattr(AS, "sessions_dir", lambda: tmp_path / "agent" / "sessions")
    from unittest import mock

    from core import bookmarks as BM

    with mock.patch("pathlib.Path.home", return_value=tmp_path), \
            mock.patch.object(BM, "BOOKMARKS_FILE", tmp_path / "bookmarks.json"):
        from ui.main_window import MainWindow

        w = MainWindow()
        try:
            dock = w._agent_dock
            bar = dock.titleBarWidget()
            lamps = [b for b in bar.findChildren(QToolButton) if b is dock.lamp]
            assert lamps, "the lamp is not in the Agent dock's title bar"
            w.show()
            w._focus_agent()
            APP.processEvents()
            assert dock.lamp.isVisible()
            # No profile in a fresh home: red, and said why.
            assert dock.lamp.state == L.OFFLINE and "No LLM profile" in dock.lamp.toolTip()
        finally:
            dock.shutdown()
            w.close()
            w.deleteLater()
            APP.processEvents()


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
