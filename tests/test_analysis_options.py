"""The Analysis settings on their way to sift: the dock hands them to the
analyzer, the analyzer to the worker, the worker child into sift's Config -
and a change reaches a running dock without a restart."""

from __future__ import annotations

import io
import os
import stat
import sys
import threading
import time
import unittest
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import analysis_settings as AS  # noqa: E402
from core import analysis_worker as AW  # noqa: E402
from core import file_analysis as FA  # noqa: E402
from core.analysis_worker import WorkerResult  # noqa: E402
from core.file_analysis import AnalysisResult, Target  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

pytest.importorskip("sift")


def _notes(tmp_path: Path, lines: int = 3000) -> Path:
    path = tmp_path / "notes.txt"
    path.write_text("".join(f"Line {i} of the plain notes file.\n" for i in range(lines)))
    return path


# -- the worker child: options into sift's Config ------------------------------------------------


class WorkerConfigTest(unittest.TestCase):
    def test_happy_every_option_reaches_sifts_config(self) -> None:
        request = {
            "time_budget": 12.0,
            "llm": {"provider": "openai", "endpoint": "http://127.0.0.1:1/v1", "model": "m"},
            "sift": {"max_bytes": 1000, "vision": False, "context_tokens": 4096, "tags": 4,
                     "categories": ["Invoices", "Contracts"], "cache": False},
        }
        config = AW._config_for(request)
        self.assertEqual(
            (config.max_bytes, config.vision, config.context_tokens, config.tags,
             config.categories, config.time_budget),
            (1000, False, 4096, 4, ["Invoices", "Contracts"], 12.0),
        )

    def test_happy_without_an_llm_the_read_limit_applies_too(self) -> None:
        config = AW._config_for({"sift": {"max_bytes": 2048}, "time_budget": 5})
        self.assertTrue(config.no_llm)
        self.assertEqual((config.max_bytes, config.time_budget), (2048, 5.0))

    def test_sad_a_value_sift_refuses_is_refused_in_the_child(self) -> None:
        from sift.config import ConfigError

        with self.assertRaises(ConfigError):
            AW._config_for({"sift": {"context_tokens": 100}})
        with self.assertRaises(ConfigError):
            AW._config_for({"sift": {"tags": 99}})
        with self.assertRaises(ConfigError):
            AW._config_for({"sift": {"categories": ["a", "A"]}})

    def test_edge_no_options_is_sifts_defaults(self) -> None:
        from sift.config import Config

        config = AW._config_for({})
        self.assertEqual((config.max_bytes, config.tags, config.categories),
                         (Config().max_bytes, 0, []))
        # An unknown key from a newer parent is not passed to sift.
        config = AW._config_for({"sift": {"spool_dir": "/elsewhere", "endpoint": "http://x"}})
        self.assertEqual((config.spool_dir, config.endpoint), ("", ""))


class WorkerLiveTest(unittest.TestCase):
    """The real child process with sift."""

    def setUp(self) -> None:
        import tempfile

        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: __import__("shutil").rmtree(self.tmp, ignore_errors=True))

    def test_happy_max_bytes_truncates_in_the_child(self) -> None:
        notes = _notes(self.tmp)
        worker = AW.AnalysisWorker(cache_dir=None)
        self.addCleanup(worker.close)
        short = worker.analyse(str(notes), "notes.txt", sift={"max_bytes": 20000})
        full = worker.analyse(str(notes), "notes.txt")
        self.assertTrue(short.ok, short.error)
        self.assertTrue(short.summary["truncated"])
        self.assertTrue(any("read first 20000" in n for n in short.summary["notes"]))
        self.assertFalse(full.summary["truncated"])

    def test_sad_an_invalid_option_is_an_error_reply_not_a_dead_child(self) -> None:
        notes = _notes(self.tmp, 10)
        worker = AW.AnalysisWorker(cache_dir=None)
        self.addCleanup(worker.close)
        bad = worker.analyse(str(notes), "notes.txt", sift={"context_tokens": 100})
        self.assertFalse(bad.ok)
        self.assertIn("context_tokens", bad.error)
        pid = worker.pid
        good = worker.analyse(str(notes), "notes.txt")
        self.assertTrue(good.ok)
        self.assertEqual(worker.pid, pid)  # the same child answered

    def test_edge_the_cache_switch_is_per_request_and_the_folder_private(self) -> None:
        cache = self.tmp / "cache"
        notes = _notes(self.tmp, 20)
        worker = AW.AnalysisWorker(cache_dir=cache)
        self.addCleanup(worker.close)
        off = worker.analyse(str(notes), "notes.txt", sift={"cache": False})
        self.assertTrue(off.ok)
        self.assertEqual(stat.S_IMODE(cache.stat().st_mode), 0o700)
        self.assertEqual(list(cache.rglob("*.json")), [])
        first = worker.analyse(str(notes), "notes.txt", sift={"cache": True})
        second = worker.analyse(str(notes), "notes.txt", sift={"cache": True})
        self.assertFalse(first.from_cache)
        self.assertTrue(second.from_cache)
        self.assertEqual(len(list(cache.rglob("*.json"))), 1)
        self.assertEqual(AS.clear_cache(cache), 1)
        self.assertEqual(list(cache.rglob("*.json")), [])


# -- the analyzer: options to the worker, the remote copy capped -------------------------------


class _FakeWorker:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def analyse(self, path, display_name, **kw):
        self.calls.append(kw)
        return WorkerResult(True, summary={"filename": display_name, "llm_used": False})

    def cancel(self):
        pass

    def close(self):
        pass


class _Remote:
    def __init__(self, files):
        self.files = files
        self.opened = []

    def open_read(self, path):
        self.opened.append(path)
        return io.BytesIO(self.files[path])


class AnalyzerOptionsTest(unittest.TestCase):
    def test_happy_the_options_reach_the_worker(self) -> None:
        import tempfile

        worker = _FakeWorker()
        fa = FA.FileAnalyzer(worker=worker)
        with tempfile.NamedTemporaryFile(suffix=".txt") as fh:
            target = Target(LocalFS(), fh.name, "a.txt", 0, 0.0)
            options = AS.AnalysisSettings(time_budget=300.0, tags=3, max_bytes=5000).run_options()
            fa.analyse(target, options=options)
        kw = worker.calls[-1]
        self.assertEqual(kw["time_budget"], 300.0)
        self.assertEqual(kw["cpu_seconds"], AW.cpu_seconds_for(300.0))
        self.assertEqual(kw["sift"], {k: v for k, v in options.items() if k != "time_budget"})

    def test_sad_a_remote_file_over_max_bytes_is_not_copied(self) -> None:
        backend = _Remote({"/r/big.bin": b"x" * 2000})
        fa = FA.FileAnalyzer(worker=_FakeWorker())
        target = Target(backend, "/r/big.bin", "big.bin", 2000, 1.0)
        result = fa.analyse(target, options=AS.AnalysisSettings(max_bytes=1000).run_options())
        self.assertFalse(result.ok)
        self.assertIn("limit", result.error)
        self.assertEqual(backend.opened, [])
        result = fa.analyse(target, options=AS.AnalysisSettings(max_bytes=5000).run_options())
        self.assertTrue(result.ok)
        self.assertEqual(backend.opened, ["/r/big.bin"])

    def test_edge_other_options_are_another_answer_but_the_cache_switch_is_not(self) -> None:
        import tempfile

        worker = _FakeWorker()
        fa = FA.FileAnalyzer(worker=worker)
        with tempfile.NamedTemporaryFile(suffix=".txt") as fh:
            target = Target(LocalFS(), fh.name, "a.txt", 0, 0.0)
            base = AS.AnalysisSettings()
            fa.analyse(target, options=base.run_options())
            self.assertTrue(fa.analyse(target, options=base.run_options()).from_session_cache)
            no_cache = AS.AnalysisSettings(cache=False).run_options()
            self.assertTrue(fa.analyse(target, options=no_cache).from_session_cache)
            tagged = AS.AnalysisSettings(tags=2).run_options()
            self.assertFalse(fa.analyse(target, options=tagged).from_session_cache)
            self.assertIsNotNone(fa.cached(target, None, tagged))
        self.assertEqual(len(worker.calls), 2)


# -- the dock: auto analysis on/off, the settings picked up live -------------------------------


class _Qt(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def wait_for(self, cond, seconds=5.0) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.app.processEvents()
            if cond():
                return
            time.sleep(0.01)
        self.fail("condition not reached")


class _RecordingAnalyzer:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict | None, dict | None]] = []
        self.lock = threading.Lock()

    def analyse(self, target, force=False, llm=None, on_event=None, cancel=None, options=None):
        with self.lock:
            self.calls.append((target.name, llm, options))
        return AnalysisResult(True, summary={"filename": target.name,
                                             "summary": f"about {target.name}"})

    def cached(self, target, llm=None, options=None):
        return None

    def cancel(self):
        pass

    def close(self):
        pass


def _t(name):
    return Target(backend=LocalFS(), path="/x/" + name, name=name, size=1, mtime=0.0)


class DockSettingsTest(_Qt):
    def setUp(self) -> None:
        from core import llm_profiles as LP

        self.analysis = AS.AnalysisSettings()
        self.llm = LP.LLMSettings([LP.LLMProfile(name="agent-model", model="big"),
                                   LP.LLMProfile(name="sift-model", model="small")],
                                  active="agent-model")

    def _dock(self, analyzer):
        from ui.analysis_dock import AnalysisDock

        dock = AnalysisDock(analyzer_factory=lambda: analyzer, available=lambda: True,
                            settings_loader=lambda: self.llm,
                            analysis_settings_loader=lambda: self.analysis,
                            key_lookup=lambda name: "")
        self.addCleanup(dock.shutdown)
        self.addCleanup(dock.deleteLater)
        return dock

    def test_happy_the_dock_hands_its_settings_to_the_analyzer(self) -> None:
        self.analysis = AS.AnalysisSettings(tags=3, max_bytes=4000)
        analyzer = _RecordingAnalyzer()
        dock = self._dock(analyzer)
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: analyzer.calls)
        self.assertEqual(analyzer.calls[0][2], self.analysis.run_options())

    def test_happy_a_saved_change_reaches_the_running_dock(self) -> None:
        analyzer = _RecordingAnalyzer()
        dock = self._dock(analyzer)
        dock.show()
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: len(analyzer.calls) == 1)
        self.analysis = AS.AnalysisSettings(tags=5)
        dock.reload_settings()
        # The file on screen is explained again with the new settings.
        self.wait_for(lambda: len(analyzer.calls) == 2)
        self.assertEqual(analyzer.calls[1][2]["tags"], 5)
        dock.analyse(_t("b.txt"))
        self.wait_for(lambda: len(analyzer.calls) == 3)
        self.assertEqual(analyzer.calls[2][2]["tags"], 5)

    def test_happy_analysis_has_its_own_llm_profile(self) -> None:
        self.analysis = AS.AnalysisSettings(llm_profile="sift-model")
        analyzer = _RecordingAnalyzer()
        dock = self._dock(analyzer)
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: analyzer.calls)
        dock.analyse_with_llm()
        self.wait_for(lambda: len(analyzer.calls) == 2)
        self.assertEqual(analyzer.calls[1][1]["model"], "small")
        self.assertIn("sift-model", dock.llm_button.toolTip())

    def test_sad_auto_analysis_off_runs_nothing_on_selection(self) -> None:
        self.analysis = AS.AnalysisSettings(auto_analyse=False)
        analyzer = _RecordingAnalyzer()
        dock = self._dock(analyzer)
        dock.analyse(_t("a.txt"))
        dock.analyse(_t("b.txt"))
        time.sleep(0.3)
        self.app.processEvents()
        self.assertEqual(analyzer.calls, [])
        self.assertIn("b.txt", dock.title.text())
        self.assertIn("Automatic analysis is off", dock.body.toPlainText())
        self.assertEqual(dock.again.text(), "Analyse")
        self.assertTrue(dock.again.isEnabled())
        dock.again.click()
        self.wait_for(lambda: analyzer.calls)
        self.assertEqual(analyzer.calls[0][0], "b.txt")
        self.wait_for(lambda: "about b.txt" in dock.body.toPlainText())
        self.assertEqual(dock.again.text(), "Analyse again")

    def test_sad_an_explicit_request_runs_with_auto_analysis_off(self) -> None:
        self.analysis = AS.AnalysisSettings(auto_analyse=False)
        analyzer = _RecordingAnalyzer()
        dock = self._dock(analyzer)
        dock.analyse(_t("a.txt"))  # held back: a selection
        dock.analyse(_t("a.txt"), explicit=True)  # Analyse with sift on the same file
        self.wait_for(lambda: analyzer.calls)
        self.assertEqual([c[0] for c in analyzer.calls], ["a.txt"])

    def test_edge_a_missing_analysis_profile_falls_back_to_the_active_one(self) -> None:
        self.analysis = AS.AnalysisSettings(llm_profile="gone")
        dock = self._dock(_RecordingAnalyzer())
        self.assertEqual(dock._profile.name, "agent-model")

    def test_edge_a_broken_settings_loader_keeps_the_defaults(self) -> None:
        from ui.analysis_dock import AnalysisDock

        def broken():
            raise OSError("disk gone")

        analyzer = _RecordingAnalyzer()
        dock = AnalysisDock(analyzer_factory=lambda: analyzer, available=lambda: True,
                            settings_loader=lambda: self.llm, analysis_settings_loader=broken)
        self.addCleanup(dock.shutdown)
        self.addCleanup(dock.deleteLater)
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: analyzer.calls)
        self.assertEqual(analyzer.calls[0][2], AS.AnalysisSettings().run_options())

    def test_edge_a_hidden_dock_runs_nothing_on_a_change(self) -> None:
        analyzer = _RecordingAnalyzer()
        dock = self._dock(analyzer)
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: len(analyzer.calls) == 1)
        self.assertFalse(dock.isVisible())
        self.analysis = AS.AnalysisSettings(tags=5)
        dock.reload_settings()
        time.sleep(0.2)
        self.app.processEvents()
        self.assertEqual(len(analyzer.calls), 1)
        # Shown again, the selection of the same file is explained anew.
        dock.analyse(_t("a.txt"))
        self.wait_for(lambda: len(analyzer.calls) == 2)
        self.assertEqual(analyzer.calls[1][2]["tags"], 5)

    def test_edge_switching_auto_analysis_on_again_explains_the_held_file(self) -> None:
        self.analysis = AS.AnalysisSettings(auto_analyse=False)
        analyzer = _RecordingAnalyzer()
        dock = self._dock(analyzer)
        dock.show()
        dock.analyse(_t("held.txt"))
        self.analysis = AS.AnalysisSettings(auto_analyse=True)
        dock.reload_settings()
        self.wait_for(lambda: analyzer.calls)
        self.assertEqual(analyzer.calls[0][0], "held.txt")
