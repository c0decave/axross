"""LLM profile dialog: edit, validate, keep keys in the keyring, list models."""

from __future__ import annotations

import os
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import agent as A  # noqa: E402
from core import llm_profiles as LP  # noqa: E402


class _Qt(unittest.TestCase):
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
        self.keys: dict[str, str] = {}
        for name, fn in (
            ("store_api_key", lambda n, k: self.keys.update({n: k}) or True),
            ("get_api_key", lambda n: self.keys.get(n, "")),
            ("delete_api_key", lambda n: self.keys.pop(n, None) is not None),
        ):
            patcher = mock.patch.object(LP, name, side_effect=fn)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.warnings = []
        patcher = mock.patch(
            "ui.llm_settings_dialog.QMessageBox.warning",
            side_effect=lambda *a, **k: self.warnings.append(a[2]),
        )
        patcher.start()
        self.addCleanup(patcher.stop)

    def dlg(self):
        from ui.llm_settings_dialog import LLMSettingsDialog

        d = LLMSettingsDialog(settings_path=self.path)
        self.addCleanup(d.deleteLater)
        return d

    def wait_for(self, cond, seconds=10.0) -> None:
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            self.app.processEvents()
            if cond():
                return
            time.sleep(0.02)
        self.fail("condition not reached")


class DialogTest(_Qt):
    def _fill(self, d, name="local", provider="ollama", endpoint="", model="demo:latest", key=""):
        d.add_profile()
        d.name_edit.setText(name)
        d.provider_combo.setCurrentText(provider)
        d.endpoint_edit.setText(endpoint)
        d.model_combo.setEditText(model)
        d.key_edit.setText(key)

    def test_happy_a_new_profile_is_saved_and_the_key_goes_to_the_keyring(self) -> None:
        d = self.dlg()
        self._fill(
            d,
            name="lab",
            provider="openai",
            endpoint="https://llm.example.org/v1",
            model="m1",
            key="sk-abc",
        )
        d.make_active()
        self.assertTrue(d.save())
        s = LP.LLMSettings.load(self.path)
        self.assertEqual(
            [(p.name, p.provider, p.endpoint, p.model) for p in s.profiles],
            [("lab", "openai", "https://llm.example.org/v1", "m1")],
        )
        self.assertEqual(s.active, "lab")
        self.assertNotIn("sk-abc", self.path.read_text())
        self.assertEqual(self.keys, {"lab": "sk-abc"})

    def test_sad_saving_over_an_unreadable_file_keeps_its_profiles(self) -> None:
        """The dialog opens empty over a truncated llm.json; adding one
        profile and saving must leave the old profiles recoverable."""
        old = b'{"profiles": [{"name": "work", "provider": "ollama", "model": "big"}], "act'
        self.path.write_bytes(old)
        d = self.dlg()
        self._fill(d, name="lab")
        self.assertTrue(d.save())
        copies = sorted(self.path.parent.glob("llm.json.unreadable-*"))
        self.assertEqual([c.read_bytes() for c in copies], [old])
        self.assertEqual([p.name for p in LP.LLMSettings.load(self.path).profiles], ["lab"])

    def test_sad_a_save_that_cannot_keep_the_unreadable_file_is_refused(self) -> None:
        old = b'{"profiles": [{"name": "work"'
        self.path.write_bytes(old)
        d = self.dlg()
        self._fill(d, name="lab", key="sk-new")
        with mock.patch.object(LP, "keep_unreadable_copy", return_value=False):
            self.assertFalse(d.save())
        self.assertEqual(self.path.read_bytes(), old)
        self.assertEqual(self.keys, {}, "no key is stored for a profile that was not saved")
        self.assertTrue(self.warnings)

    def test_sad_an_invalid_profile_is_not_saved(self) -> None:
        d = self.dlg()
        self._fill(d, name="bad", provider="openai", endpoint="ftp://x")
        self.assertFalse(d.save())
        self.assertFalse(self.path.exists())
        self.assertTrue(any("http(s)" in w for w in self.warnings))

    def test_sad_two_profiles_with_one_name_are_refused(self) -> None:
        d = self.dlg()
        self._fill(d, name="same")
        self._fill(d, name="same")
        self.assertFalse(d.save())
        self.assertTrue(any("same" in w for w in self.warnings))

    def test_happy_remote_endpoints_show_a_warning(self) -> None:
        d = self.dlg()
        self._fill(d, endpoint="https://api.example.com/v1")
        self.assertTrue(d.remote_label.isVisibleTo(d))
        self.assertIn("api.example.com", d.remote_label.text())
        d.endpoint_edit.setText("http://127.0.0.1:11434")
        self.assertFalse(d.remote_label.isVisibleTo(d))

    def test_edge_deleting_a_profile_deletes_its_key(self) -> None:
        LP.LLMSettings([LP.LLMProfile(name="old")], active="old").save(self.path)
        self.keys["old"] = "sk-old"
        d = self.dlg()
        d.profile_list.setCurrentRow(0)
        d.delete_profile()
        self.assertTrue(d.save())
        self.assertEqual(LP.LLMSettings.load(self.path).profiles, [])
        self.assertEqual(self.keys, {})

    def test_edge_an_existing_key_is_not_shown_and_kept_when_left_empty(self) -> None:
        LP.LLMSettings([LP.LLMProfile(name="k")], active="k").save(self.path)
        self.keys["k"] = "sk-keep"
        d = self.dlg()
        d.profile_list.setCurrentRow(0)
        self.assertEqual(d.key_edit.text(), "")
        self.assertIn("stored", d.key_edit.placeholderText())
        self.assertTrue(d.save())
        self.assertEqual(self.keys, {"k": "sk-keep"})

    def test_happy_models_are_listed_from_the_server_off_the_gui_thread(self) -> None:
        from tests.fake_llm_server import FakeOllama

        d = self.dlg()
        with FakeOllama() as srv:
            self._fill(d, endpoint=srv.url, model="")
            d.fetch_models()
            self.wait_for(lambda: d.model_combo.count() >= 2)
        names = [d.model_combo.itemText(i) for i in range(d.model_combo.count())]
        self.assertEqual(sorted(names), ["demo:latest", "other:7b"])

    def test_sad_an_unreachable_server_says_so(self) -> None:
        d = self.dlg()
        self._fill(d, endpoint="http://127.0.0.1:9")
        d.fetch_models()
        self.wait_for(
            lambda: "No answer" in d.status_label.text() or "failed" in d.status_label.text()
        )


class DialogReviewFixesTest(_Qt):
    def test_happy_renaming_keeps_the_key_and_the_active_choice(self) -> None:
        LP.LLMSettings(
            [LP.LLMProfile(name="lab", provider="openai", endpoint="https://lab.example.org/v1")],
            active="lab",
        ).save(self.path)
        self.keys["lab"] = "sk-lab"
        d = self.dlg()
        d.profile_list.setCurrentRow(0)
        d.name_edit.setText("lab2")
        self.assertTrue(d.save())
        s = LP.LLMSettings.load(self.path)
        self.assertEqual(([p.name for p in s.profiles], s.active), (["lab2"], "lab2"))
        self.assertEqual(self.keys, {"lab2": "sk-lab"})

    def test_sad_a_new_profile_with_a_deleted_name_gets_no_old_key(self) -> None:
        LP.LLMSettings(
            [LP.LLMProfile(name="x", provider="openai", endpoint="https://a.example/v1")],
            active="x",
        ).save(self.path)
        self.keys["x"] = "sk-for-a"
        d = self.dlg()
        d.profile_list.setCurrentRow(0)
        d.delete_profile()
        d.add_profile()
        d.name_edit.setText("x")
        d.endpoint_edit.setText("https://b.example/v1")
        self.assertIn("none", d.key_edit.placeholderText())
        self.assertTrue(d.save())
        self.assertEqual(self.keys, {})

    def test_edge_two_profiles_swapping_names_keep_their_own_keys(self) -> None:
        LP.LLMSettings([LP.LLMProfile(name="a"), LP.LLMProfile(name="b")], active="a").save(
            self.path
        )
        self.keys.update({"a": "key-a", "b": "key-b"})
        d = self.dlg()
        d.profile_list.setCurrentRow(0)
        d.name_edit.setText("tmp")
        d.profile_list.setCurrentRow(1)
        d.name_edit.setText("a")
        d.profile_list.setCurrentRow(0)
        d.name_edit.setText("b")
        self.assertTrue(d.save())
        s = LP.LLMSettings.load(self.path)
        self.assertEqual(s.active, "b")  # the profile that was active, under its new name
        self.assertEqual(self.keys, {"b": "key-a", "a": "key-b"})

    def test_sad_models_of_one_profile_never_land_in_another(self) -> None:
        LP.LLMSettings(
            [
                LP.LLMProfile(name="a", provider="openai", endpoint="https://a.example/v1"),
                LP.LLMProfile(
                    name="b", provider="openai", endpoint="https://b.example/v1", model="b1"
                ),
            ],
            active="a",
        ).save(self.path)
        d = self.dlg()
        d.profile_list.setCurrentRow(0)
        d._fetch_token += 1  # a fetch for profile a is under way
        pending = d._fetch_token
        d.profile_list.setCurrentRow(1)  # the user moves on to profile b
        # profile a's answer arrives (core.agent.model_inventory's entries)
        d._on_models(pending, [A.ModelEntry("a-only-model:7b")], "")
        self.assertEqual(d.model_combo.count(), 0)
        self.assertEqual(d.model_combo.currentText(), "b1")
        self.assertTrue(d.save())
        s = LP.LLMSettings.load(self.path)
        self.assertEqual([p.model for p in s.profiles], ["", "b1"])

    def test_happy_models_for_the_shown_profile_are_still_listed(self) -> None:
        LP.LLMSettings([LP.LLMProfile(name="a")], active="a").save(self.path)
        d = self.dlg()
        d.profile_list.setCurrentRow(0)
        d._fetch_token += 1
        d._on_models(d._fetch_token, [A.ModelEntry("m1"), A.ModelEntry("m2")], "")
        self.assertEqual([d.model_combo.itemText(i) for i in range(2)], ["m1", "m2"])

    def test_sad_server_text_is_shown_as_plain_text(self) -> None:
        from PyQt6.QtCore import Qt

        d = self.dlg()
        self.assertEqual(d.status_label.textFormat(), Qt.TextFormat.PlainText)
        self.assertEqual(d.remote_label.textFormat(), Qt.TextFormat.PlainText)


class DialogRemoteWarningTest(_Qt):
    def _endpoint(self, d, url: str) -> None:
        d.add_profile()
        d.name_edit.setText("p")
        d.provider_combo.setCurrentText("openai")
        d.endpoint_edit.setText(url)

    def test_happy_a_proxy_on_the_way_makes_a_local_endpoint_remote(self) -> None:
        # The dock asks before sending through a proxy (review C, C1); the
        # dialog said nothing.
        d = self.dlg()
        env = {"http_proxy": "http://127.0.0.1:3128", "no_proxy": ""}
        with mock.patch.dict(os.environ, env):
            self._endpoint(d, "http://localhost:11434/v1")
            self.assertTrue(d.remote_label.isVisibleTo(d))
            self.assertIn("127.0.0.1:3128", d.remote_label.text())

    def test_sad_a_half_typed_ipv6_endpoint_raises_nothing(self) -> None:
        d = self.dlg()
        hook = mock.Mock()
        with mock.patch("sys.excepthook", hook):
            for url in ("http://[", "http://[::1", "http://[::1]:11434/v1"):
                self._endpoint(d, url)
                self.app.processEvents()
        hook.assert_not_called()

    def test_edge_without_a_proxy_localhost_stays_local(self) -> None:
        d = self.dlg()
        with mock.patch.dict(os.environ, {"http_proxy": "", "HTTP_PROXY": "", "no_proxy": ""}):
            self._endpoint(d, "http://localhost:11434/v1")
            self.assertFalse(d.remote_label.isVisibleTo(d))


if __name__ == "__main__":
    unittest.main()


class FirstProfileIsActiveTest(_Qt):
    """Found while recording the feature video: a first profile saved
    without "Use for analysis" left the Agent dock with "No LLM profile is
    active" - the new user's first try failed."""

    _fill = DialogTest._fill

    def test_happy_the_first_profile_becomes_the_active_one(self) -> None:
        d = self.dlg()
        self._fill(d, name="Local Qwen", provider="openai",
                   endpoint="http://127.0.0.1:18080/v1", model="m1", key="")
        self.assertTrue(d.save())
        s = LP.LLMSettings.load(self.path)
        self.assertEqual(s.active, "Local Qwen")
        self.assertEqual(s.active_profile().name, "Local Qwen")

    def test_sad_a_chosen_active_profile_is_kept(self) -> None:
        d = self.dlg()
        self._fill(d, name="one", provider="openai", endpoint="http://127.0.0.1:1/v1", model="m")
        self._fill(d, name="two", provider="openai", endpoint="http://127.0.0.1:2/v1", model="m")
        d.make_active()  # "two" is the shown one
        self.assertTrue(d.save())
        self.assertEqual(LP.LLMSettings.load(self.path).active, "two")

    def test_edge_deleting_the_active_one_makes_the_next_active(self) -> None:
        d = self.dlg()
        self._fill(d, name="one", provider="openai", endpoint="http://127.0.0.1:1/v1", model="m")
        d.make_active()
        self._fill(d, name="two", provider="openai", endpoint="http://127.0.0.1:2/v1", model="m")
        d.profile_list.setCurrentRow(0)
        d.delete_profile()
        self.assertTrue(d.save())
        self.assertEqual(LP.LLMSettings.load(self.path).active, "two")

    def test_edge_no_profiles_no_active(self) -> None:
        d = self.dlg()
        self.assertTrue(d.save())
        self.assertEqual(LP.LLMSettings.load(self.path).active, "")



class NoGuessInCoreTest(unittest.TestCase):
    """The Analysis dock offers no LLM while no profile is named active
    (tests/test_analysis_dock.py); the dialog names the first one, the core
    does not guess."""

    def test_sad_a_single_unnamed_profile_is_not_active(self) -> None:
        s = LP.LLMSettings([LP.LLMProfile(name="only")], "")
        self.assertIsNone(s.active_profile())
