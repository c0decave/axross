"""A consent the analysis dock remembers survives a later save of the
LLM profile dialog that was opened before it.

The dialog loads llm.json once, when it opens. While it is open the dock
can still ask for and remember a consent (a folder listing that finishes
in the background enqueues an analysis). Saving the dialog afterwards
wrote its stale copy back and dropped that consent.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import llm_profiles as LP  # noqa: E402

_ENDPOINT = "https://llm.example:8443/v1"


class ConsentLostUpdateTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / "llm.json"
        # No proxy from the host environment may change the consent key.
        env = mock.patch.dict(
            os.environ,
            {k: "" for k in ("http_proxy", "https_proxy", "HTTP_PROXY", "HTTPS_PROXY")},
        )
        env.start()
        self.addCleanup(env.stop)
        for name, fn in (
            ("store_api_key", lambda n, k: True),
            ("get_api_key", lambda n: ""),
            ("delete_api_key", lambda n: True),
        ):
            patcher = mock.patch.object(LP, name, side_effect=fn)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.warnings: list = []
        patcher = mock.patch(
            "ui.llm_settings_dialog.QMessageBox.warning",
            side_effect=lambda *a, **k: self.warnings.append(a[2]),
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        LP.LLMSettings(
            [LP.LLMProfile(name="lab", provider="openai", endpoint=_ENDPOINT, model="m1")],
            active="lab",
        ).save(self.path)

    def _dialog(self):
        from ui.llm_settings_dialog import LLMSettingsDialog

        d = LLMSettingsDialog(settings_path=self.path)
        self.addCleanup(d.deleteLater)
        return d

    def _dock_remembers_consent(self) -> None:
        """The dock's own path: ask, the user ticks "remember", it saves."""
        from ui.analysis_dock import AnalysisDock

        dock = AnalysisDock(
            available=lambda: True,
            settings_loader=lambda: LP.LLMSettings.load(self.path),
            settings_saver=lambda s: s.save(self.path),
            key_lookup=lambda name: "",
            confirm_remote=lambda profile, host: (True, True),
        )
        self.addCleanup(dock.deleteLater)
        self.addCleanup(dock.shutdown)
        dock.refresh_profiles()
        self.assertIsNotNone(dock._llm_request(ask=True))

    def _stored(self, name: str) -> LP.LLMProfile:
        profile = LP.LLMSettings.load(self.path).profile(name)
        assert profile is not None
        return profile

    def test_happy_dialog_save_keeps_a_consent_given_while_it_was_open(self) -> None:
        d = self._dialog()
        self._dock_remembers_consent()
        self.assertFalse(self._stored("lab").needs_consent())
        d.profile_list.setCurrentRow(0)
        d.model_combo.setEditText("m2")  # an unrelated edit
        self.assertTrue(d.save(), self.warnings)
        stored = self._stored("lab")
        self.assertEqual(stored.model, "m2")
        self.assertFalse(stored.needs_consent())

    def test_happy_consent_follows_a_profile_renamed_in_the_dialog(self) -> None:
        d = self._dialog()
        self._dock_remembers_consent()
        d.profile_list.setCurrentRow(0)
        d.name_edit.setText("lab2")
        self.assertTrue(d.save(), self.warnings)
        self.assertFalse(self._stored("lab2").needs_consent())

    def test_sad_consent_is_not_carried_to_a_different_host(self) -> None:
        d = self._dialog()
        self._dock_remembers_consent()
        d.profile_list.setCurrentRow(0)
        d.endpoint_edit.setText("https://other.example/v1")
        self.assertTrue(d.save(), self.warnings)
        self.assertTrue(self._stored("lab").needs_consent())

    def test_edge_file_vanished_meanwhile_dialog_still_saves(self) -> None:
        d = self._dialog()
        self.path.unlink()
        d.profile_list.setCurrentRow(0)
        d.model_combo.setEditText("m3")
        self.assertTrue(d.save(), self.warnings)
        stored = self._stored("lab")
        self.assertEqual(stored.model, "m3")
        self.assertTrue(stored.needs_consent())


if __name__ == "__main__":
    unittest.main()
