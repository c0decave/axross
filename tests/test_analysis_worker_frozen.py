"""The sift analysis runs in the frozen axross-full binary too: the child is
started as ``axross --analysis-worker`` there (a frozen build has no
``python -m``), and the full bundle ships sift."""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from core import analysis_worker as AW  # noqa: E402


class WorkerArgvTest(unittest.TestCase):
    def test_happy_from_source_the_child_is_python_dash_m(self) -> None:
        with mock.patch.object(sys, "frozen", False, create=True):
            self.assertEqual(AW.worker_argv(), [sys.executable, "-m", "core.analysis_worker"])

    def test_happy_frozen_the_child_is_the_binary_with_a_flag(self) -> None:
        with mock.patch.object(sys, "frozen", True, create=True):
            self.assertEqual(AW.worker_argv(), [sys.executable, "--analysis-worker"])

    def test_happy_frozen_with_sift_bundled_the_analysis_is_available(self) -> None:
        spec = mock.Mock()
        with mock.patch.object(sys, "frozen", True, create=True), mock.patch(
            "importlib.util.find_spec", return_value=spec
        ):
            self.assertTrue(AW.sift_available())

    def test_sad_frozen_without_sift_the_analysis_is_off(self) -> None:
        with mock.patch.object(sys, "frozen", True, create=True), mock.patch(
            "importlib.util.find_spec", return_value=None
        ):
            self.assertFalse(AW.sift_available())

    def test_edge_the_worker_default_command_follows_worker_argv(self) -> None:
        with mock.patch.object(sys, "frozen", True, create=True):
            worker = AW.AnalysisWorker(cache_dir=None)
        self.addCleanup(worker.close)
        self.assertEqual(worker._command, [sys.executable, "--analysis-worker"])


@unittest.skipUnless(AW.sift_available(), "sift is not installed")
class MainDispatchTest(unittest.TestCase):
    """main.py answers --analysis-worker the way the frozen binary will."""

    def test_happy_main_analysis_worker_explains_a_csv(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "people.csv")
            Path(path).write_bytes(b"name,age\nann,31\nbob,45\n")
            worker = AW.AnalysisWorker(
                cache_dir=None,
                command=[sys.executable, str(ROOT / "main.py"), "--analysis-worker"],
            )
            self.addCleanup(worker.close)
            res = worker.analyse(path, "people.csv")
        self.assertTrue(res.ok, res.error)
        self.assertEqual(res.summary["kind"], "csv")


class FullBundleShipsSiftTest(unittest.TestCase):
    def test_happy_the_builder_installs_sift(self) -> None:
        text = (ROOT / "Dockerfile.build").read_text()
        self.assertRegex(text, r'"sift-summarizer>=[0-9.]+"')

    def test_happy_the_full_preflight_requires_sift(self) -> None:
        text = (ROOT / "scripts" / "build_bundle.sh").read_text()
        full = re.search(r"FULL_MODS=\((.*?)\n\)", text, re.S).group(1)
        self.assertIn('"sift:', full)

    def test_edge_slim_excludes_sift_and_full_collects_it(self) -> None:
        text = (ROOT / "build" / "axross.spec").read_text()
        slim = re.search(r'if FLAVOR == "slim":\n    excludes \+= \[(.*?)\n    \]', text, re.S)
        self.assertIsNotNone(slim)
        self.assertIn('"sift"', slim.group(1))
        self.assertRegex(text, r'collect_submodules\("sift"\)')

    def test_edge_the_builder_pypdf_floor_meets_sifts(self) -> None:
        # sift reads PDFs only with pypdf >= 6.18.1 (sift's pyproject, extra "pdf").
        text = (ROOT / "Dockerfile.build").read_text()
        floor = re.search(r'"pypdf>=([0-9.]+)"', text).group(1)
        self.assertGreaterEqual(tuple(int(x) for x in floor.split(".")), (6, 18, 1))


if __name__ == "__main__":
    unittest.main()
