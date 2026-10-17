"""The Agent dock: a local LLM works with axross, the user decides each change.

The model is the scripted fake of test_agent_loop; the dialogs are
injected, so every path - yes, no, stop, remote consent - runs without a
human.
"""

from __future__ import annotations

import os
import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import llm_profiles as LP  # noqa: E402
from core.agent_session import SessionStore  # noqa: E402
from tests.test_agent_loop import _call, _Fake  # noqa: E402

_PROXIES = ("http_proxy", "https_proxy", "all_proxy", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        import tempfile

        self._saved_env = {k: os.environ.pop(k) for k in _PROXIES if k in os.environ}
        self.tmp = tempfile.TemporaryDirectory(prefix="axross-agent-dock-")
        self.root = Path(self.tmp.name) / "work"
        self.root.mkdir()
        self.sessions = Path(self.tmp.name) / "sessions"
        self.servers: list[_Fake] = []
        self.asked: list[tuple[str, dict]] = []
        self.answer = True
        self.remote_ok = True

    def tearDown(self) -> None:
        for server in self.servers:
            server.close()
        dock = getattr(self, "dock", None)
        if dock is not None:
            dock.shutdown()
            dock.deleteLater()
            self.app.processEvents()
        self.tmp.cleanup()
        os.environ.update(self._saved_env)

    def make(self, *replies, endpoint=None, profile_name="local"):
        from ui.agent_dock import AgentDock

        server = _Fake(replies)
        self.servers.append(server)
        profile = LP.LLMProfile(name=profile_name, provider="lmstudio",
                                endpoint=endpoint or server.url, model="tiny")
        settings = LP.LLMSettings([profile], profile_name)
        self.dock = AgentDock(
            settings_loader=lambda: settings,
            settings_saver=lambda s: None,
            key_lookup=lambda name: "",
            confirm_remote=lambda p, h: self.remote_ok,
            confirm_call=lambda n, a: self.asked.append((n, a)) or self.answer,
            root_provider=lambda: str(self.root),
            session_store=SessionStore(self.sessions),
        )
        return server

    def wait_idle(self, seconds=10.0) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.app.processEvents()
            if not self.dock.busy() and self.dock.send_button.isEnabled():
                self.app.processEvents()
                return
            time.sleep(0.01)
        self.fail("the agent did not finish")

    def say(self, text: str) -> None:
        self.dock.input.setPlainText(text)
        self.dock.send()
        self.wait_idle()


class HappyTest(_Base):
    def test_happy_a_question_is_answered_in_the_transcript(self) -> None:
        (self.root / "notes.txt").write_text("Friday 10:00\n")
        server = self.make(
            {
                "tool_calls": [
                    _call("read_file", {"path": str(self.root / "notes.txt"), "encoding": "text"})
                ]
            },
            {"content": "The meeting is on Friday at 10."},
        )
        self.say("When is the meeting?")
        text = self.dock.transcript.toPlainText()
        self.assertIn("When is the meeting?", text)
        self.assertIn("read_file", text)
        self.assertIn("The meeting is on Friday at 10.", text)
        self.assertIn("Friday 10:00", server.requests[1]["messages"][-1]["content"])
        self.assertEqual(self.asked, [])

    def test_happy_a_change_runs_after_yes(self) -> None:
        self.make(
            {
                "tool_calls": [
                    _call("write_file", {"path": str(self.root / "a.txt"), "content": "hi"})
                ]
            },
            {"content": "Done."},
        )
        self.dock.allow_write.setChecked(True)
        self.say("Write hi to a.txt")
        self.assertEqual((self.root / "a.txt").read_text(), "hi")
        self.assertEqual([n for n, _ in self.asked], ["write_file"])

    def test_happy_the_conversation_continues(self) -> None:
        server = self.make({"content": "One."}, {"content": "Two."})
        self.say("first")
        self.say("second")
        roles = [m["role"] for m in server.requests[1]["messages"]]
        self.assertEqual(roles, ["system", "user", "assistant", "user"])


class SadTest(_Base):
    def test_sad_no_means_nothing_changes(self) -> None:
        self.make(
            {
                "tool_calls": [
                    _call("write_file", {"path": str(self.root / "a.txt"), "content": "hi"})
                ]
            },
            {"content": "Not written."},
        )
        self.dock.allow_write.setChecked(True)
        self.answer = False
        self.say("Write hi")
        self.assertFalse((self.root / "a.txt").exists())
        self.assertIn("declined", self.dock.transcript.toPlainText())

    def test_sad_changes_are_not_offered_unless_ticked(self) -> None:
        server = self.make({"content": "ok"})
        self.say("anything")
        names = {t["function"]["name"] for t in server.requests[0]["tools"]}
        self.assertNotIn("write_file", names)
        self.assertNotIn("remote_exec", names)

    def test_sad_a_remote_profile_without_consent_sends_nothing(self) -> None:
        server = self.make({"content": "never"}, endpoint="https://llm.example.com/v1")
        self.remote_ok = False
        self.dock.input.setPlainText("hi")
        self.dock.send()
        self.app.processEvents()
        self.assertFalse(self.dock.busy())
        self.assertEqual(server.requests, [])

    def test_sad_an_unreachable_server_is_reported(self) -> None:
        self.make(endpoint="http://127.0.0.1:9/v1")
        self.say("hi")
        self.assertIn("cannot reach", self.dock.transcript.toPlainText())


class EdgeTest(_Base):
    def test_edge_the_secret_arguments_are_masked_in_the_question(self) -> None:
        self.make(
            {
                "tool_calls": [
                    _call("encrypt", {"path": str(self.root / "a.txt"), "passphrase": "s3cret"})
                ]
            },
            {"content": "ok"},
        )
        (self.root / "a.txt").write_text("x")
        self.dock.allow_write.setChecked(True)
        item = next(self.dock.groups.item(i) for i in range(self.dock.groups.count())
                    if self.dock.groups.item(i).text() == "crypto")
        from PyQt6.QtCore import Qt

        item.setCheckState(Qt.CheckState.Checked)
        self.answer = False
        self.say("encrypt it")
        self.assertEqual(self.asked[0][1]["passphrase"], "•••")
        self.assertNotIn("s3cret", self.dock.transcript.toPlainText())

    def test_edge_stop_answers_no_and_ends_the_run(self) -> None:
        loop = {"tool_calls": [_call("stat", {"path": str(self.root)})]}
        self.make(*[loop] * 50)
        self.dock.input.setPlainText("loop")
        self.dock.send()
        for _ in range(20):
            self.app.processEvents()
            time.sleep(0.01)
        self.dock.stop()
        self.wait_idle()
        self.assertIn("Stopped", self.dock.transcript.toPlainText())

    def test_edge_new_settings_keep_the_conversation(self) -> None:
        # A tab is one conversation: ticking "Allow changes" after a plan
        # must not make the model forget the plan.
        server = self.make({"content": "a"}, {"content": "b"})
        self.say("one")
        self.dock.allow_write.setChecked(True)
        self.say("two")
        roles = [m["role"] for m in server.requests[1]["messages"]]
        self.assertEqual(roles, ["system", "user", "assistant", "user"])
        names = {t["function"]["name"] for t in server.requests[1]["tools"]}
        self.assertIn("write_file", names)
        self.assertIn("continues with them", self.dock.transcript.toPlainText())

    def test_edge_html_in_the_answer_is_shown_as_text(self) -> None:
        self.make({"content": "<img src=http://evil/x> <b>bold</b>"})
        self.say("hi")
        self.assertIn("<img src=http://evil/x>", self.dock.transcript.toPlainText())
        self.assertNotIn("<img", self.dock.transcript.toHtml().replace("&lt;img", ""))


if __name__ == "__main__":
    unittest.main()
