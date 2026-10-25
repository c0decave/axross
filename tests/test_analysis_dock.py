"""The Analysis dock: follows the selection, shows sift's explanation, safely."""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import core.bookmarks as BM  # noqa: E402
from core.file_analysis import AnalysisResult, Target  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402


class _Qt(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def wait_for(self, cond, seconds=5.0) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.app.processEvents()
            if cond():
                return
            time.sleep(0.01)
        self.fail("condition not reached")


_SUMMARY = {
    "filename": "people.csv",
    "kind": "csv",
    "classification": "Comma-separated data table",
    "summary": "A CSV table with 2 rows. <img src=http://evil/x> & more",
    "key_points": ["name: string", "<b>age</b>: integer"],
    "tags": ["people", "<script>"],
    "findings": [{"kind": "secret", "text": "password=<hidden>"}],
    "warnings": ["truncated"],
    "notes": [],
    "llm_used": False,
    "size_human": "24 B",
}


class RenderTest(_Qt):
    def test_happy_the_explanation_and_its_parts_are_shown(self) -> None:
        from ui.analysis_dock import render_result_html

        html = render_result_html(AnalysisResult(True, summary=_SUMMARY))
        for part in (
            "Comma-separated data table",
            "A CSV table with 2 rows.",
            "name: string",
            "people",
            "truncated",
            "without an LLM",
        ):
            self.assertIn(part, html)

    def test_sad_file_derived_text_is_escaped(self) -> None:
        from ui.analysis_dock import render_result_html

        html = render_result_html(AnalysisResult(True, summary=_SUMMARY))
        for raw in ("<img", "<script>", "<b>age</b>", "<hidden>"):
            self.assertNotIn(raw, html)
        self.assertIn("&lt;img src=http://evil/x&gt; &amp; more", html)

    def test_sad_an_error_is_shown_escaped(self) -> None:
        from ui.analysis_dock import render_result_html

        html = render_result_html(AnalysisResult(False, error="cannot read <x>: denied"))
        self.assertIn("cannot read &lt;x&gt;: denied", html)

    def test_edge_missing_and_odd_fields_do_not_break_rendering(self) -> None:
        from ui.analysis_dock import render_result_html

        for summary in ({}, {"key_points": None, "tags": "notalist", "findings": [1, None, "x"]}):
            with self.subTest(summary=summary):
                self.assertIsInstance(
                    render_result_html(AnalysisResult(True, summary=summary)), str
                )


class _SlowAnalyzer:
    def __init__(self) -> None:
        self.started: list[str] = []
        self.gate = threading.Event()
        self.cancels = 0

    def analyse(self, target, force=False, llm=None, on_event=None, cancel=None, options=None):
        self.started.append(target.name)
        if target.name == "slow.txt":
            self.gate.wait(5)
        return AnalysisResult(
            True, summary={"filename": target.name, "summary": f"about {target.name}"}
        )

    def cached(self, target, llm=None, options=None):
        return None

    def cancel(self):
        self.cancels += 1
        self.gate.set()

    def close(self):
        self.gate.set()


def _t(name):
    return Target(backend=LocalFS(), path="/x/" + name, name=name, size=1, mtime=0.0)


class DockTest(_Qt):
    def _dock(self, analyzer):
        from ui.analysis_dock import AnalysisDock

        dock = AnalysisDock(analyzer_factory=lambda: analyzer, available=lambda: True)
        self.addCleanup(dock.shutdown)
        self.addCleanup(dock.deleteLater)
        return dock

    def test_happy_a_result_is_shown_for_the_requested_file(self) -> None:
        dock = self._dock(_SlowAnalyzer())
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: "about a.txt" in dock.body.toPlainText())
        self.assertIn("a.txt", dock.title.text())

    def test_happy_the_latest_selection_wins(self) -> None:
        analyzer = _SlowAnalyzer()
        dock = self._dock(analyzer)
        dock.analyse(_t("slow.txt"))
        self.wait_for(lambda: analyzer.started == ["slow.txt"])
        dock.analyse(_t("b.txt"))
        dock.analyse(_t("c.txt"))
        analyzer.gate.set()
        self.wait_for(lambda: "about c.txt" in dock.body.toPlainText())
        self.assertNotIn("b.txt", analyzer.started)  # superseded before it started
        time.sleep(0.2)
        self.app.processEvents()
        self.assertIn("about c.txt", dock.body.toPlainText())  # the slow one did not overwrite it

    def test_sad_without_sift_the_dock_says_how_to_get_it(self) -> None:
        from ui.analysis_dock import AnalysisDock

        dock = AnalysisDock(
            analyzer_factory=lambda: self.fail("no analyzer without sift"), available=lambda: False
        )
        self.addCleanup(dock.deleteLater)
        dock.analyse(_t("a.txt"))
        self.assertIn("sift", dock.body.toPlainText())

    def test_edge_messages_replace_a_shown_result(self) -> None:
        dock = self._dock(_SlowAnalyzer())
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: "about a.txt" in dock.body.toPlainText())
        dock.show_message("Select a single file to see its analysis.")
        self.assertIn("Select a single file", dock.body.toPlainText())


class _LLMAnalyzer:
    """Answers like sift with an LLM: progress events, then a result with calls."""

    def __init__(self) -> None:
        self.requests: list[dict | None] = []
        self._results = {}

    def analyse(self, target, force=False, llm=None, on_event=None, cancel=None, options=None):
        self.requests.append(llm)
        if llm and on_event:
            on_event({"event": "progress", "answer": 120, "reasoning": 800})
        if not llm:
            res = AnalysisResult(
                True, summary={"filename": target.name, "summary": "heuristic", "llm_used": False}
            )
        else:
            res = AnalysisResult(
                True,
                summary={
                    "filename": target.name,
                    "summary": "model <says>",
                    "llm_used": True,
                    "model": "demo:latest",
                },
                calls=[
                    {
                        "prompt_tokens": 26,
                        "completion_tokens": 12,
                        "tokens_per_second": 25.0,
                        "ttft_seconds": 0.13,
                    }
                ],
            )
        self._results[(target.path, bool(llm))] = res
        return res

    def cached(self, target, llm=None, options=None):
        return self._results.get((target.path, bool(llm)))

    def cancel(self):
        pass

    def close(self):
        pass


class _DockLLMBase(_Qt):
    def setUp(self) -> None:
        from core import llm_profiles as LP

        self.LP = LP
        self.settings = LP.LLMSettings(
            [LP.LLMProfile(name="local", model="demo:latest")], active="local"
        )
        self.saved = []
        self.confirm_answer = (True, False)
        self.asked = []
        self.key_lookups = []

    def _dock(self, analyzer):
        from ui.analysis_dock import AnalysisDock

        dock = AnalysisDock(
            analyzer_factory=lambda: analyzer,
            available=lambda: True,
            settings_loader=lambda: self.settings,
            settings_saver=lambda s: self.saved.append(s),
            key_lookup=lambda name: self.key_lookups.append(name) or "sk-from-keyring",
            confirm_remote=lambda profile, host: self.asked.append(host) or self.confirm_answer,
        )
        self.addCleanup(dock.shutdown)
        self.addCleanup(dock.deleteLater)
        return dock


class DockLLMTest(_DockLLMBase):
    def test_happy_llm_analysis_shows_progress_answer_and_stats(self) -> None:
        analyzer = _LLMAnalyzer()
        dock = self._dock(analyzer)
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: "heuristic" in dock.body.toPlainText())
        self.assertTrue(dock.llm_button.isEnabled())
        self.assertIn("without", dock.mode_icon.toolTip())
        dock.llm_button.click()
        self.wait_for(
            lambda: (
                "model &lt;says&gt;" in dock.body.toHtml()
                or "model <says>" in dock.body.toPlainText()
            )
        )
        text = dock.body.toPlainText()
        self.assertIn("with an LLM", text)
        self.assertIn("26", text)
        self.assertIn("25.0 tok/s", text)
        self.assertIn("with an LLM", dock.mode_icon.toolTip())
        self.assertEqual(analyzer.requests[-1]["api_key"], "sk-from-keyring")
        self.assertEqual(analyzer.requests[-1]["model"], "demo:latest")
        self.assertEqual(self.asked, [])  # local endpoint: no question

    def test_sad_without_an_active_profile_the_llm_button_is_off(self) -> None:
        self.settings = self.LP.LLMSettings([self.LP.LLMProfile(name="local")], active="")
        dock = self._dock(_LLMAnalyzer())
        dock.analyse(_t("a.txt"))
        self.assertFalse(dock.llm_button.isEnabled())

    def test_sad_a_remote_endpoint_is_asked_for_and_a_no_sends_nothing(self) -> None:
        self.settings.profiles[0].endpoint = "https://llm.example.org/v1"
        analyzer = _LLMAnalyzer()
        dock = self._dock(analyzer)
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: "heuristic" in dock.body.toPlainText())
        self.confirm_answer = (False, False)
        dock.llm_button.click()
        self.app.processEvents()
        time.sleep(0.2)
        self.app.processEvents()
        self.assertEqual(self.asked, ["llm.example.org"])
        self.assertTrue(all(r is None for r in analyzer.requests))

    def test_edge_yes_and_remember_saves_the_consent_once(self) -> None:
        self.settings.profiles[0].endpoint = "https://llm.example.org/v1"
        analyzer = _LLMAnalyzer()
        dock = self._dock(analyzer)
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: "heuristic" in dock.body.toPlainText())
        self.confirm_answer = (True, True)
        dock.llm_button.click()
        self.wait_for(lambda: "with an LLM" in dock.body.toPlainText())
        self.assertEqual(
            self.saved[-1].profiles[0].confirmed_origin, "https://llm.example.org:443"
        )
        dock.analyse(_t("b.txt"))
        self.wait_for(
            lambda: dock.title.text() == "b.txt" and "heuristic" in dock.body.toPlainText()
        )
        dock.llm_button.click()
        self.wait_for(lambda: "with an LLM" in dock.body.toPlainText())
        self.assertEqual(self.asked, ["llm.example.org"])  # asked once

    def test_sad_a_consent_that_cannot_be_saved_still_analyses(self) -> None:
        """LLMSettings.save refuses to replace an llm.json it could not
        read; the refusal must not escape the button's slot."""
        self.settings.profiles[0].endpoint = "https://llm.example.org/v1"
        analyzer = _LLMAnalyzer()
        dock = self._dock(analyzer)

        def refuse(_settings):
            raise OSError("Not saving: the unreadable llm.json could not be kept")

        dock._save_settings = refuse
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: "heuristic" in dock.body.toPlainText())
        self.confirm_answer = (True, True)
        dock.llm_button.click()
        self.wait_for(lambda: "with an LLM" in dock.body.toPlainText())

    def test_edge_a_known_llm_answer_is_shown_again_on_selection(self) -> None:
        analyzer = _LLMAnalyzer()
        dock = self._dock(analyzer)
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: "heuristic" in dock.body.toPlainText())
        dock.llm_button.click()
        self.wait_for(lambda: "with an LLM" in dock.body.toPlainText())
        dock.analyse(_t("b.txt"))
        self.wait_for(
            lambda: dock.title.text() == "b.txt" and "heuristic" in dock.body.toPlainText()
        )
        n = len(analyzer.requests)
        dock.analyse(_t("a.txt"))
        self.wait_for(
            lambda: dock.title.text() == "a.txt" and "with an LLM" in dock.body.toPlainText()
        )
        self.assertEqual(len(analyzer.requests), n)  # from the cache, no new run

    def test_happy_progress_events_show_live_counts_for_the_latest_request(self) -> None:
        dock = self._dock(_LLMAnalyzer())
        dock._latest = 7
        dock._on_event(7, {"event": "progress", "answer": 1234, "reasoning": 56})
        self.assertIn("1,234", dock.progress_label.text())
        self.assertIn("56", dock.progress_label.text())
        dock._on_event(6, {"event": "progress", "answer": 99999, "reasoning": 0})
        self.assertNotIn("99,999", dock.progress_label.text())

    def test_sad_render_escapes_the_stats_too(self) -> None:
        from ui.analysis_dock import render_result_html

        html = render_result_html(
            AnalysisResult(
                True,
                summary={"llm_used": True, "model": "<m>"},
                calls=[{"prompt_tokens": "<1>", "completion_tokens": 2}],
            )
        )
        self.assertNotIn("<m>", html)
        self.assertNotIn("<1>", html)

    def test_sad_consent_for_one_host_does_not_cover_another(self) -> None:
        self.settings.profiles[0].endpoint = "https://llm.example.org/v1"
        self.settings.profiles[0].confirmed_origin = "https://llm.example.org:443"
        dock = self._dock(_LLMAnalyzer())
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: "heuristic" in dock.body.toPlainText())
        self.settings.profiles[0].endpoint = "https://api.other.example/v1"
        dock.refresh_profiles()
        self.confirm_answer = (False, False)
        dock.llm_button.click()
        self.assertEqual(self.asked, ["api.other.example"])

    def test_happy_selections_never_touch_the_keyring(self) -> None:
        dock = self._dock(_LLMAnalyzer())
        for name in ("a.txt", "b.txt", "c.txt", "d.txt", "e.txt"):
            dock.analyse(_t(name))
        self.wait_for(
            lambda: dock.title.text() == "e.txt" and "heuristic" in dock.body.toPlainText()
        )
        self.assertEqual(self.key_lookups, [])
        dock.llm_button.click()
        self.assertEqual(self.key_lookups, ["local"])

    def test_edge_the_two_lanes_do_not_wait_for_each_other(self) -> None:
        from ui.analysis_dock import AnalysisDock

        gate = threading.Event()

        class Slow(_LLMAnalyzer):
            def analyse(self, target, force=False, llm=None, on_event=None, cancel=None, options=None):
                if llm:
                    gate.wait(10)
                return super().analyse(target, force=force, llm=llm, on_event=on_event)

        made = []
        dock = AnalysisDock(
            analyzer_factory=lambda: made.append(Slow()) or made[-1],
            available=lambda: True,
            settings_loader=lambda: self.settings,
            key_lookup=lambda n: "",
            confirm_remote=lambda p, h: (True, False),
        )
        self.addCleanup(dock.shutdown)
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: "heuristic" in dock.body.toPlainText())
        dock.llm_button.click()  # the model hangs
        dock.analyse(_t("b.txt"))
        self.wait_for(
            lambda: dock.title.text() == "b.txt" and "heuristic" in dock.body.toPlainText()
        )
        self.assertEqual(len(made), 2)  # one analyzer, one worker process, per lane
        gate.set()


class _GatedAnalyzer(_LLMAnalyzer):
    """The auto lane waits for ``auto_gate``, the LLM lane for ``llm_gate``."""

    def __init__(self, llm_error: str = "") -> None:
        super().__init__()
        self.auto_gate = threading.Event()
        self.llm_gate = threading.Event()
        self.llm_error = llm_error

    def analyse(self, target, force=False, llm=None, on_event=None, cancel=None, options=None):
        (self.llm_gate if llm else self.auto_gate).wait(5)
        if llm and self.llm_error:
            self.requests.append(llm)
            return AnalysisResult(False, error=self.llm_error)
        return super().analyse(target, force=force, llm=llm, on_event=on_event)

    def close(self):
        self.auto_gate.set()
        self.llm_gate.set()


class DockLanesTest(_DockLLMBase):
    def test_happy_a_running_llm_answer_survives_a_reselection_of_its_file(self) -> None:
        analyzer = _GatedAnalyzer()
        analyzer.auto_gate.set()
        dock = self._dock(analyzer)
        target = _t("f.txt")
        dock.analyse(target)
        self.wait_for(lambda: "heuristic" in dock.body.toPlainText())
        dock.llm_button.click()
        dock.analyse(target)  # a click into the pane selects the same file again
        analyzer.llm_gate.set()
        self.wait_for(lambda: "with an LLM" in dock.body.toPlainText())
        self.assertIn("model", dock.body.toPlainText())

    def test_edge_forced_analysis_of_the_same_file_runs_again(self) -> None:
        analyzer = _GatedAnalyzer()
        analyzer.auto_gate.set()
        dock = self._dock(analyzer)
        target = _t("f.txt")
        dock.analyse(target)
        self.wait_for(lambda: len(analyzer.requests) == 1)
        dock.analyse(target)
        time.sleep(0.1)
        self.app.processEvents()
        self.assertEqual(len(analyzer.requests), 1)  # unchanged: nothing to do
        dock.analyse(target, force=True)
        self.wait_for(lambda: len(analyzer.requests) == 2)

    def test_happy_the_auto_result_is_shown_while_the_llm_works(self) -> None:
        analyzer = _GatedAnalyzer()
        dock = self._dock(analyzer)
        dock.analyse(_t("f.txt"))
        dock.llm_button.click()  # before the automatic result is there
        analyzer.auto_gate.set()
        self.wait_for(lambda: "heuristic" in dock.body.toPlainText())
        self.assertTrue(dock.progress_label.isVisibleTo(dock))  # the model still works
        analyzer.llm_gate.set()
        self.wait_for(lambda: "with an LLM" in dock.body.toPlainText())
        self.assertFalse(dock.progress_label.isVisibleTo(dock))

    def test_sad_a_failed_llm_keeps_the_auto_result_and_says_why(self) -> None:
        analyzer = _GatedAnalyzer(llm_error="model not reachable")
        dock = self._dock(analyzer)
        dock.analyse(_t("f.txt"))
        dock.llm_button.click()
        analyzer.auto_gate.set()
        self.wait_for(lambda: "heuristic" in dock.body.toPlainText())
        analyzer.llm_gate.set()
        self.wait_for(lambda: "model not reachable" in dock.body.toPlainText())
        self.assertIn("heuristic", dock.body.toPlainText())
        self.assertIn("without", dock.mode_icon.toolTip())

    def test_sad_a_late_auto_result_does_not_replace_the_models_answer(self) -> None:
        # The auto lane can be the slower one (a previous file still in it,
        # a remote copy); its answer came last and replaced the model's.
        analyzer = _GatedAnalyzer()
        dock = self._dock(analyzer)
        dock.analyse(_t("f.txt"))
        dock.llm_button.click()
        analyzer.llm_gate.set()
        self.wait_for(lambda: "with an LLM" in dock.body.toPlainText())
        analyzer.auto_gate.set()
        self.wait_for(lambda: len(analyzer.requests) == 2)
        time.sleep(0.1)
        self.app.processEvents()
        self.assertIn("model", dock.body.toPlainText())
        self.assertIn("with an LLM", dock.body.toPlainText())
        self.assertIn("with an LLM", dock.mode_icon.toolTip())

    def test_edge_a_late_auto_result_keeps_the_models_error_above_it(self) -> None:
        analyzer = _GatedAnalyzer(llm_error="model not reachable")
        dock = self._dock(analyzer)
        dock.analyse(_t("f.txt"))
        dock.llm_button.click()
        analyzer.llm_gate.set()
        self.wait_for(lambda: "model not reachable" in dock.body.toPlainText())
        analyzer.auto_gate.set()
        self.wait_for(lambda: "heuristic" in dock.body.toPlainText())
        self.assertIn("model not reachable", dock.body.toPlainText())

    def test_happy_after_another_file_the_auto_result_is_shown_again(self) -> None:
        analyzer = _GatedAnalyzer()
        analyzer.llm_gate.set()
        dock = self._dock(analyzer)
        dock.analyse(_t("f.txt"))
        dock.llm_button.click()
        self.wait_for(lambda: "with an LLM" in dock.body.toPlainText())
        dock.analyse(_t("g.txt"))  # the model's answer belonged to f.txt
        analyzer.auto_gate.set()
        self.wait_for(
            lambda: dock.title.text() == "g.txt" and "heuristic" in dock.body.toPlainText()
        )

    def test_edge_an_llm_answer_for_a_file_left_behind_is_not_shown(self) -> None:
        analyzer = _GatedAnalyzer()
        analyzer.auto_gate.set()
        dock = self._dock(analyzer)
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: "heuristic" in dock.body.toPlainText())
        dock.llm_button.click()
        dock.analyse(_t("b.txt"))
        self.wait_for(
            lambda: dock.title.text() == "b.txt" and "heuristic" in dock.body.toPlainText()
        )
        analyzer.llm_gate.set()
        self.wait_for(lambda: len(analyzer.requests) == 3)
        time.sleep(0.1)
        self.app.processEvents()
        self.assertEqual(dock.title.text(), "b.txt")
        self.assertNotIn("with an LLM", dock.body.toPlainText())


class _GatedListingBackend:
    name = "Fake"

    def __init__(self, items=None, error: Exception | None = None):
        self.items = items or []
        self.error = error
        self.gate = threading.Event()

    def list_dir(self, path):
        self.gate.wait(5)
        if self.error is not None:
            raise self.error
        return self.items

    def join(self, *parts):
        return "/".join(p.rstrip("/") for p in parts)


class DockListingTest(_DockLLMBase):
    def _rows(self, dock):
        return [dock.queue_list.item(i).text() for i in range(dock.queue_list.count())]

    def test_sad_a_late_listing_does_not_replace_the_file_shown_since(self) -> None:
        for error in (PermissionError("Permission denied"), None):
            with self.subTest(error=repr(error)):
                backend = _GatedListingBackend([FileItem(name="x.txt", size=1)], error)
                analyzer = _LLMAnalyzer()
                dock = self._dock(analyzer)
                dock.offer_folder(backend, "/d", "d")
                dock.batch_button.click()
                dock.analyse(_t("new.txt"))  # the user moves on while it lists
                self.wait_for(lambda: "heuristic" in dock.body.toPlainText())
                backend.gate.set()
                time.sleep(0.2)
                self.app.processEvents()
                self.assertEqual(dock.title.text(), "new.txt")
                self.assertIn("heuristic", dock.body.toPlainText())
                self.assertEqual(self._rows(dock), [])
                self.assertFalse(dock.batch_button.isVisibleTo(dock))

    def test_happy_a_listing_for_the_offer_on_screen_is_queued(self) -> None:
        backend = _GatedListingBackend([FileItem(name="x.txt", size=1)])
        dock = self._dock(_LLMAnalyzer())
        dock.offer_folder(backend, "/d", "d")
        dock.batch_button.click()
        backend.gate.set()
        self.wait_for(lambda: len(self._rows(dock)) == 1)

    def test_edge_an_older_listing_of_the_same_folder_is_dropped(self) -> None:
        first = _GatedListingBackend([FileItem(name="old.txt", size=1)])
        second = _GatedListingBackend([FileItem(name="new.txt", size=1)])
        dock = self._dock(_LLMAnalyzer())
        dock.offer_folder(first, "/d", "d")
        dock.batch_button.click()
        dock.offer_folder(second, "/d", "d")
        dock.batch_button.click()
        first.gate.set()
        time.sleep(0.2)
        self.app.processEvents()
        self.assertEqual(self._rows(dock), [])
        second.gate.set()
        self.wait_for(lambda: len(self._rows(dock)) == 1)
        self.assertIn("new.txt", self._rows(dock)[0])

    def test_sad_the_same_folder_offered_again_keeps_its_listing(self) -> None:
        # A reload of the pane (F5, the watcher) offers the selected folder
        # again; that dropped the listing the user had started.
        backend = _GatedListingBackend([FileItem(name="x.txt", size=1)])
        dock = self._dock(_LLMAnalyzer())
        dock.offer_folder(backend, "/d", "d")
        dock.batch_button.click()
        dock.offer_folder(backend, "/d", "d")
        backend.gate.set()
        self.wait_for(lambda: len(self._rows(dock)) == 1)
        self.assertFalse(dock.batch_button.isVisibleTo(dock))

    def test_happy_the_same_batch_offered_again_stays_queued(self) -> None:
        dock = self._dock(_LLMAnalyzer())
        targets = [_t("a.txt"), _t("b.txt")]
        dock.offer_batch(targets, "2 files selected")
        dock.batch_button.click()
        self.wait_for(lambda: all(r.startswith("✓") for r in self._rows(dock)))
        dock.offer_batch(list(targets), "2 files selected")
        self.assertFalse(dock.batch_button.isVisibleTo(dock))  # nothing to queue twice
        self.assertEqual(len(self._rows(dock)), 2)

    def test_edge_another_offer_still_replaces_the_one_on_screen(self) -> None:
        backend = _GatedListingBackend([FileItem(name="x.txt", size=1)])
        dock = self._dock(_LLMAnalyzer())
        dock.offer_folder(backend, "/d", "d")
        dock.batch_button.click()
        dock.offer_folder(backend, "/e", "e")  # another folder of the same backend
        self.assertTrue(dock.batch_button.isEnabled())
        backend.gate.set()
        time.sleep(0.2)
        self.app.processEvents()
        self.assertEqual(self._rows(dock), [])
        changed = Target(backend=LocalFS(), path="/x/a.txt", name="a.txt", size=2, mtime=0.0)
        dock.offer_batch([_t("a.txt")], "1 file")
        dock.batch_button.click()
        self.wait_for(lambda: len(self._rows(dock)) == 1)
        dock.offer_batch([changed], "1 file")  # the file changed: a new offer
        self.assertTrue(dock.batch_button.isVisibleTo(dock))

    def test_sad_a_listing_after_shutdown_asks_nothing_and_queues_nothing(self) -> None:
        self.settings.profiles[0].endpoint = "https://api.example.com/v1"
        backend = _GatedListingBackend([FileItem(name="x.txt", size=1)])
        dock = self._dock(_LLMAnalyzer())
        dock.offer_folder(backend, "/d", "d")
        dock.batch_button.click()
        dock.shutdown()
        backend.gate.set()
        time.sleep(0.2)
        self.app.processEvents()
        self.assertEqual(self.asked, [])
        self.assertEqual(self._rows(dock), [])


class _QueueAnalyzer(_LLMAnalyzer):
    """Records the order; a file named hold*.txt waits for the gate."""

    def __init__(self) -> None:
        super().__init__()
        self.order: list[str] = []
        self.gate = threading.Event()

    def analyse(self, target, force=False, llm=None, on_event=None, cancel=None, options=None):
        if llm:
            self.order.append(target.name)
            if target.name.startswith("hold"):
                self.gate.wait(5)
        return super().analyse(target, force=force, llm=llm, on_event=on_event)


class _ListingBackend:
    name = "Fake"

    def __init__(self, items):
        self.items = items
        self.listed = []

    def list_dir(self, path):
        self.listed.append(path)
        return self.items

    def join(self, *parts):
        return "/".join(p.rstrip("/") for p in parts)


class DockQueueTest(_DockLLMBase):
    def _rows(self, dock):
        return [dock.queue_list.item(i).text() for i in range(dock.queue_list.count())]

    def test_happy_a_batch_runs_in_order_and_each_row_shows_its_result(self) -> None:
        analyzer = _QueueAnalyzer()
        dock = self._dock(analyzer)
        dock.offer_batch([_t("a.txt"), _t("b.txt"), _t("c.txt")], "3 files selected")
        self.assertTrue(dock.batch_button.isVisible() or dock.batch_button.isVisibleTo(dock))
        dock.batch_button.click()
        self.wait_for(
            lambda: all(r.startswith("✓") for r in self._rows(dock)) and len(self._rows(dock)) == 3
        )
        self.assertEqual(analyzer.order, ["a.txt", "b.txt", "c.txt"])
        dock.queue_list.setCurrentRow(1)
        dock.queue_list.itemClicked.emit(dock.queue_list.item(1))
        self.assertEqual(dock.title.text(), "b.txt")
        self.assertIn("with an LLM", dock.body.toPlainText())

    def test_sad_stop_drops_what_waits_and_lets_the_running_one_finish(self) -> None:
        analyzer = _QueueAnalyzer()
        dock = self._dock(analyzer)
        dock.offer_batch([_t("hold.txt"), _t("b.txt"), _t("c.txt")], "3 files")
        dock.batch_button.click()
        self.wait_for(lambda: analyzer.order == ["hold.txt"])
        dock.stop_button.click()
        analyzer.gate.set()
        self.wait_for(lambda: self._rows(dock)[0].startswith("✓"))
        time.sleep(0.2)
        self.app.processEvents()
        self.assertEqual(analyzer.order, ["hold.txt"])
        self.assertTrue(all("stopped" in r for r in self._rows(dock)[1:]))

    def test_edge_a_single_click_goes_before_the_waiting_queue(self) -> None:
        analyzer = _QueueAnalyzer()
        dock = self._dock(analyzer)
        dock.offer_batch([_t("hold.txt"), _t("b.txt")], "2 files")
        dock.batch_button.click()
        self.wait_for(lambda: analyzer.order == ["hold.txt"])
        dock.analyse(_t("single.txt"))
        self.wait_for(
            lambda: dock.title.text() == "single.txt" and "heuristic" in dock.body.toPlainText()
        )
        dock.llm_button.click()
        analyzer.gate.set()
        self.wait_for(lambda: len(analyzer.order) == 3)
        self.assertEqual(analyzer.order, ["hold.txt", "single.txt", "b.txt"])

    def test_happy_a_folder_is_listed_in_the_background_files_only(self) -> None:
        from models.file_item import FileItem

        backend = _ListingBackend(
            [
                FileItem(name="x.txt", size=3),
                FileItem(name="sub", is_dir=True),
                FileItem(name="l.txt", is_link=True),
                FileItem(name="y.csv", size=9),
            ]
        )
        analyzer = _QueueAnalyzer()
        dock = self._dock(analyzer)
        dock.offer_folder(backend, "/data", "data")
        dock.batch_button.click()
        self.wait_for(lambda: len(analyzer.order) == 2)
        self.assertEqual(backend.listed, ["/data"])
        self.assertEqual(analyzer.order, ["x.txt", "y.csv"])
        self.assertEqual(sorted(r[2:].split(" ")[0] for r in self._rows(dock)), ["x.txt", "y.csv"])

    def test_sad_no_profile_no_batch_and_a_remote_is_asked_once(self) -> None:
        self.settings = self.LP.LLMSettings([self.LP.LLMProfile(name="p")], active="")
        dock = self._dock(_QueueAnalyzer())
        dock.offer_batch([_t("a.txt")], "1 file")
        self.assertFalse(dock.batch_button.isEnabled())
        self.settings = self.LP.LLMSettings(
            [self.LP.LLMProfile(name="r", endpoint="https://llm.example.org")], active="r"
        )
        dock = self._dock(_QueueAnalyzer())
        dock.offer_batch([_t("a.txt"), _t("b.txt")], "2 files")
        dock.batch_button.click()
        self.wait_for(lambda: len(self._rows(dock)) == 2)
        self.assertEqual(self.asked, ["llm.example.org"])

    def test_sad_a_declined_batch_can_be_started_again(self) -> None:
        from models.file_item import FileItem

        self.settings.profiles[0].endpoint = "https://llm.example.org/v1"
        self.confirm_answer = (False, False)
        dock = self._dock(_QueueAnalyzer())
        dock.offer_folder(_ListingBackend([FileItem(name="x.txt", size=1)]), "/d", "d")
        dock.batch_button.click()
        self.wait_for(lambda: bool(self.asked))
        self.wait_for(lambda: dock.batch_button.isEnabled())
        self.assertNotIn("Listing", dock.body.toPlainText())
        self.assertEqual(self._rows(dock), [])

    def test_edge_a_row_click_hides_a_stale_progress_line(self) -> None:
        analyzer = _QueueAnalyzer()
        dock = self._dock(analyzer)
        dock.offer_batch([_t("hold.txt"), _t("b.txt")], "2 files")
        dock.batch_button.click()
        self.wait_for(lambda: analyzer.order == ["hold.txt"])
        dock.stop_button.click()
        dock.analyse(_t("single.txt"))
        self.wait_for(lambda: dock.title.text() == "single.txt")
        dock.llm_button.click()
        self.assertTrue(dock.progress_label.isVisibleTo(dock))
        dock.queue_list.itemClicked.emit(dock.queue_list.item(1))
        self.assertEqual(dock.title.text(), "b.txt")
        self.assertFalse(dock.progress_label.isVisibleTo(dock))
        analyzer.gate.set()

    def test_happy_a_running_row_counts_its_own_time(self) -> None:
        analyzer = _QueueAnalyzer()
        dock = self._dock(analyzer)
        dock.offer_batch([_t("hold.txt")], "1 file")
        dock.batch_button.click()
        self.wait_for(lambda: analyzer.order == ["hold.txt"])
        token = next(iter(dock._rows))
        self.wait_for(lambda: token in dock._started_at)  # the signal crosses threads
        dock._started_at[token] -= 30  # it started 30 s ago
        dock.queue_list.itemClicked.emit(dock.queue_list.item(0))
        dock._on_event(token, {"event": "progress", "answer": 5, "reasoning": 0})
        self.assertIn("30 s", dock.progress_label.text())
        analyzer.gate.set()

    def test_edge_too_many_files_are_refused(self) -> None:
        from ui import analysis_dock as AD

        dock = self._dock(_QueueAnalyzer())
        dock.offer_batch([_t(f"f{i}.txt") for i in range(AD.MAX_BATCH + 1)], "many")
        dock.batch_button.click()
        self.assertEqual(self._rows(dock), [])
        self.assertIn(str(AD.MAX_BATCH), dock.body.toPlainText())


class ConsentPromptTest(_Qt):
    """The remote-consent prompt says where the file goes; a profile name is
    the user's text, never markup that could hide the host."""

    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        from PyQt6.QtWidgets import QWidget

        cls.parent = QWidget()  # the dock in the app

    def _prompt(self, name: str):
        """Run the real prompt (exec answers No); return the answer and what
        the box showed while it was open."""
        from PyQt6.QtCore import Qt
        from PyQt6.QtWidgets import QLabel, QMessageBox

        from core import llm_profiles as LP
        from ui import analysis_dock as AD

        seen = {}

        def fake_exec(box):
            label = next(w for w in box.findChildren(QLabel) if name in w.text())
            seen["text"] = label.text()
            seen["rich"] = label.textFormat() != Qt.TextFormat.PlainText and Qt.mightBeRichText(
                label.text()
            )
            seen["default_no"] = box.defaultButton() is box.button(QMessageBox.StandardButton.No)
            return QMessageBox.StandardButton.No

        profile = LP.LLMProfile(name=name, endpoint="https://llm.example.org")
        with mock.patch.object(QMessageBox, "exec", fake_exec):
            answer = AD._ask_remote(self.parent, profile, profile.host())
        return answer, seen

    def _flush_deletes(self) -> None:
        from PyQt6.QtCore import QCoreApplication, QEvent

        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
        self.app.processEvents()

    def test_happy_the_prompt_names_the_profile_and_the_host(self) -> None:
        answer, seen = self._prompt("work")
        self.assertEqual(answer, (False, False))
        self.assertIn("work", seen["text"])
        self.assertIn("llm.example.org", seen["text"])
        self.assertFalse(seen["rich"])
        self.assertTrue(seen["default_no"])

    def test_sad_markup_in_the_name_cannot_hide_the_host(self) -> None:
        # Shown as HTML, this read "The profile local " - the host and the
        # warning swallowed by the open comment.
        _answer, seen = self._prompt("<b>local</b> <!--")
        self.assertFalse(seen["rich"])
        self.assertIn("llm.example.org", seen["text"])

    def test_edge_an_entity_in_the_name_is_shown_as_typed(self) -> None:
        _answer, seen = self._prompt("a &lt;b&gt; c")
        self.assertFalse(seen["rich"])

    def test_sad_a_theme_switch_after_a_prompt_does_not_crash(self) -> None:
        # In a child process: on 0.7.21 this was a segfault. The box kept a
        # check box that Python had freed when _ask_remote returned, and the
        # next style change laid the box out again.
        import subprocess

        script = (
            "import os\n"
            "from unittest import mock\n"
            "from PyQt6.QtWidgets import QApplication, QMessageBox, QWidget\n"
            "from core import llm_profiles as LP\n"
            "from ui import analysis_dock as AD\n"
            "app = QApplication([])\n"
            "dock = QWidget()\n"
            "p = LP.LLMProfile(name='work', endpoint='https://llm.example.org')\n"
            "with mock.patch.object(QMessageBox, 'exec',"
            " lambda b: QMessageBox.StandardButton.Yes):\n"
            "    print(AD._ask_remote(dock, p, p.host()))\n"
            "app.setStyle('Fusion')\n"
            "app.setStyle('Windows')\n"
            "app.processEvents()\n"
            "print('alive')\n"
        )
        env = dict(os.environ, QT_QPA_PLATFORM="offscreen")
        proc = subprocess.run(
            [sys.executable, "-c", script],
            cwd=str(Path(__file__).resolve().parent.parent),
            env=env,
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        self.assertIn("(True, False)", proc.stdout)
        self.assertIn("alive", proc.stdout)

    def test_edge_an_answered_prompt_is_deleted(self) -> None:
        from PyQt6.QtWidgets import QMessageBox

        for _ in range(3):
            self._prompt("work")
        self._flush_deletes()
        self.assertEqual(self.parent.findChildren(QMessageBox), [])


class MainWindowAnalysisTest(_Qt):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._home = tempfile.mkdtemp()
        cls._patch = mock.patch("pathlib.Path.home", return_value=Path(cls._home))
        cls._patch.start()
        cls._orig = BM.BOOKMARKS_FILE
        BM.BOOKMARKS_FILE = Path(cls._home) / "bookmarks.json"
        from ui.main_window import MainWindow

        cls.win = MainWindow()
        cls.win.show()
        cls.app.processEvents()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.win.close()
        cls.win.deleteLater()
        BM.BOOKMARKS_FILE = cls._orig
        cls._patch.stop()
        shutil.rmtree(cls._home, ignore_errors=True)

    def _select(self, pane, items, paths):
        pane.selected_file_items = lambda: items
        pane.selected_items = lambda: paths

    def test_happy_the_dock_starts_hidden_and_toggles_with_ctrl_shift_i(self) -> None:
        from PyQt6.QtGui import QAction, QKeySequence

        dock = self.win._analysis_dock
        self.assertFalse(dock.isVisible())
        toggles = [
            a
            for a in self.win.findChildren(QAction)
            if QKeySequence("Ctrl+Shift+I") in a.shortcuts()
        ]
        self.assertEqual(len(toggles), 1)
        toggles[0].trigger()
        self.app.processEvents()
        self.assertTrue(dock.isVisible())
        toggles[0].trigger()
        self.app.processEvents()
        self.assertFalse(dock.isVisible())

    def test_happy_a_selected_file_is_analysed_while_the_dock_is_open(self) -> None:
        pane = self.win._active_pane
        dock = self.win._analysis_dock
        item = FileItem(name="notes.txt", size=12, modified=datetime.fromtimestamp(5000))
        self._select(pane, [item], ["/data/notes.txt"])
        with mock.patch.object(dock, "analyse") as analyse:
            dock.show()
            self.app.processEvents()
            pane.selection_changed.emit()
            self.wait_for(lambda: analyse.called)
            dock.hide()
        target = analyse.call_args.args[0]
        self.assertEqual(
            (target.path, target.name, target.size, target.mtime),
            ("/data/notes.txt", "notes.txt", 12, 5000.0),
        )
        self.assertIs(target.backend, pane.backend)

    def test_sad_nothing_is_analysed_while_the_dock_is_hidden(self) -> None:
        pane = self.win._active_pane
        dock = self.win._analysis_dock
        self._select(pane, [FileItem(name="a.txt", size=1)], ["/a.txt"])
        with mock.patch.object(dock, "analyse") as analyse:
            dock.hide()
            pane.selection_changed.emit()
            time.sleep(0.4)
            self.app.processEvents()
        analyse.assert_not_called()

    def test_happy_tools_menu_and_dock_button_open_the_profiles(self) -> None:
        from PyQt6.QtGui import QAction

        from ui.settings_dialog import SettingsDialog

        opened = []

        def fake_exec(dialog) -> int:
            opened.append(dialog.current_page_id())
            return 0
        with (
            mock.patch.object(SettingsDialog, "exec", fake_exec),
            mock.patch.object(self.win._analysis_dock, "refresh_profiles") as refresh,
        ):
            menu = [a for a in self.win.findChildren(QAction) if a.text() == "&LLM Profiles…"]
            self.assertEqual(len(menu), 1)
            menu[0].trigger()
            self.win._analysis_dock.settings_button.click()
        self.assertEqual(opened, ["llm", "llm"])  # Edit > Settings… on LLM Profiles
        self.assertEqual(refresh.call_count, 2)

    def test_happy_a_folder_or_several_files_are_offered_as_a_batch(self) -> None:
        pane = self.win._active_pane
        dock = self.win._analysis_dock
        with (
            mock.patch.object(dock, "offer_folder") as folder,
            mock.patch.object(dock, "offer_batch") as batch,
        ):
            dock.show()
            self._select(pane, [FileItem(name="dir", is_dir=True)], ["/dir"])
            self.win._analyse_selection()
            self._select(
                pane,
                [
                    FileItem(name="a", size=1),
                    FileItem(name="d", is_dir=True),
                    FileItem(name="b", size=2),
                ],
                ["/a", "/d", "/b"],
            )
            self.win._analyse_selection()
            dock.hide()
        self.assertEqual(folder.call_args.args, (pane.backend, "/dir", "dir"))
        targets = batch.call_args.args[0]
        self.assertEqual([t.path for t in targets], ["/a", "/b"])

    def test_sad_after_navigating_the_old_folders_file_is_not_kept(self) -> None:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "A").mkdir()
        (tmp / "B").mkdir()
        (tmp / "A" / "secret_a.txt").write_text("hello from a\n")
        pane = self.win._active_pane
        for name in ("selected_file_items", "selected_items"):  # the real selection here
            pane.__dict__.pop(name, None)
        dock = self.win._analysis_dock
        dock.show()
        self.addCleanup(dock.hide)
        pane.navigate(str(tmp / "A"))
        self.wait_for(lambda: pane._proxy.rowCount() >= 1)
        with mock.patch.object(dock, "analyse") as analyse:
            for row in range(pane._proxy.rowCount()):
                if pane._proxy.index(row, 0).data() == "secret_a.txt":
                    pane._table.selectRow(row)
            self.wait_for(lambda: analyse.called)
            dock._target = analyse.call_args.args[0]  # what the dock now shows
            pane.navigate(str(tmp / "B"))
            self.wait_for(lambda: dock._target is None)
        self.assertIn("Select a file", dock.body.toPlainText())
        self.assertFalse(dock.llm_button.isEnabled())

    def test_sad_a_reload_of_the_pane_keeps_a_queued_folder(self) -> None:
        from core import llm_profiles as LP

        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, tmp, True)
        (tmp / "sub").mkdir()
        (tmp / "sub" / "x.txt").write_text("x\n")
        pane = self.win._active_pane
        for name in ("selected_file_items", "selected_items"):  # the real selection here
            pane.__dict__.pop(name, None)
        dock = self.win._analysis_dock
        dock.show()
        self.addCleanup(dock.hide)
        queued = []
        with (
            mock.patch.object(dock, "_profile", LP.LLMProfile(name="local", model="m")),
            mock.patch.object(dock._llm, "request", lambda *a, **k: queued.append(a)),
        ):
            pane.navigate(str(tmp))
            self.wait_for(lambda: pane._proxy.rowCount() >= 1)
            for row in range(pane._proxy.rowCount()):
                if pane._proxy.index(row, 0).data() == "sub":
                    pane._table.selectRow(row)
            self.wait_for(lambda: dock.batch_button.isVisibleTo(dock))
            dock.batch_button.click()
            self.wait_for(lambda: len(queued) == 1)
            (tmp / "new.txt").write_text("y\n")  # the folder shown changes: a reload
            pane.refresh_async(quiet=True)
            self.wait_for(lambda: pane._proxy.rowCount() >= 2 and not pane.is_loading)
            time.sleep(0.4)  # the window's 200 ms debounce
            self.app.processEvents()
            self.assertEqual([i.name for i in pane.selected_file_items()], ["sub"])
            self.assertFalse(dock.batch_button.isVisibleTo(dock))
            self.assertIn("queued", dock.body.toPlainText())
        self.assertEqual(len(queued), 1)

    def test_edge_a_click_into_the_active_pane_does_not_reanalyse(self) -> None:
        pane = self.win._active_pane
        dock = self.win._analysis_dock
        dock.show()
        self.addCleanup(dock.hide)
        self.app.processEvents()
        self.win._analysis_timer.stop()
        self.win._set_active_pane(pane)  # already active: nothing changed
        self.assertFalse(self.win._analysis_timer.isActive())

    def test_edge_an_empty_or_unreadable_selection_gets_a_message(self) -> None:
        pane = self.win._active_pane
        dock = self.win._analysis_dock
        cases = [
            ([], [], "Select a file to see what it is."),
            # a row whose path the pane cannot give (unsafe name): no guess
            ([FileItem(name="a"), FileItem(name="b")], ["/a"], "Select a single file"),
            # several rows, none a plain file
            (
                [FileItem(name="d", is_dir=True), FileItem(name="l", is_link=True)],
                ["/d", "/l"],
                "Select a single file",
            ),
        ]
        with (
            mock.patch.object(dock, "analyse") as analyse,
            mock.patch.object(dock, "offer_batch") as batch,
        ):
            dock.show()
            for items, paths, message in cases:
                with self.subTest(message=message, n=len(items)):
                    self._select(pane, items, paths)
                    self.win._analyse_selection()
                    self.assertIn(message, dock.body.toPlainText())
            dock.hide()
        analyse.assert_not_called()
        batch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
