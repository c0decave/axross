"""Settings that did not work, found while building Edit > Settings…

Each test names the bug it holds down:

* a hand-edited ``monochrome_icons: "no"`` in session.json switched the
  icons monochrome (``bool("no")`` is True) - on start and on a layout
  restore;
* a layout restore read ``compact: "yes"`` as on, while the start read it
  as off: two parsers of one key had drifted apart;
* Paranoid Security Mode was forgotten on the next start: the switch only
  changed the running process;
* saving the Network & Proxy settings with the password field left empty
  ("(unchanged)") threw away the password typed earlier for this session;
* Tools > Metadata Settings… left one hidden dialog behind per opening.
"""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tests.test_main_window_state_files import _WindowStateTest  # noqa: E402


def _layout_session(**window) -> dict:
    """A session with one local pane, so restore_layout_on_start rebuilds it."""
    return {
        "splitter": {
            "type": "splitter",
            "orientation": "horizontal",
            "sizes": [100],
            "children": [{"type": "pane", "path": "/", "local": True}],
        },
        "window": window,
    }


class MonochromeAndCompactParsingTest(_WindowStateTest):
    def setUp(self) -> None:
        super().setUp()
        from ui import icon_provider

        icon_provider.set_monochrome(False)
        self.addCleanup(icon_provider.set_monochrome, False)

    def test_sad_a_hand_edited_monochrome_value_does_not_switch_icons_monochrome(self) -> None:
        from ui import icon_provider

        self.session.write_text(
            json.dumps({"window": {"monochrome_icons": "no", "restore_layout_on_start": False}})
        )
        self.make_window()
        self.assertFalse(icon_provider.is_monochrome())

    def test_sad_a_layout_restore_reads_compact_and_monochrome_like_the_start(self) -> None:
        from ui import icon_provider

        self.session.write_text(json.dumps(_layout_session(compact="yes", monochrome_icons="no")))
        win = self.make_window()
        self.assertTrue(win.restore_layout_on_start())
        self.assertFalse(win._compact_mode)
        self.assertFalse(icon_provider.is_monochrome())

    def test_edge_a_real_true_still_switches_both_on(self) -> None:
        from ui import icon_provider

        self.session.write_text(json.dumps(_layout_session(compact=True, monochrome_icons=True)))
        win = self.make_window()
        self.assertTrue(win.restore_layout_on_start())
        self.assertTrue(win._compact_mode)
        self.assertTrue(icon_provider.is_monochrome())


class ParanoidSurvivesRestartTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core import open_limits as OL
        from core import security_mode as SM

        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        for target, name, value in ((OL, "SETTINGS_PATH", self.tmp / "settings.json"),):
            patcher = mock.patch.object(target, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        previous = SM.current_policy().name
        self.addCleanup(SM.set_policy, previous)
        SM.set_policy("normal")
        env = mock.patch.dict(os.environ, {}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        os.environ.pop("AXROSS_SECURITY_MODE", None)

    def test_happy_paranoid_chosen_in_the_window_is_back_after_a_restart(self) -> None:
        from core import security_mode as SM
        from ui.main_window import MainWindow

        with mock.patch.object(MainWindow, "_load_persistent_visual_settings"):
            win = MainWindow()
        self.addCleanup(win.deleteLater)
        self.addCleanup(win.close)
        win._reconnect_timer.stop()
        win.set_paranoid_mode(True)
        # A new process: the policy is read afresh, the environment says nothing.
        SM._CURRENT = None
        SM.apply_stored_mode()
        self.assertTrue(SM.is_paranoid())
        win.set_paranoid_mode(False)
        SM._CURRENT = None
        SM.apply_stored_mode()
        self.assertFalse(SM.is_paranoid())


class ProxySessionPasswordTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        from PyQt6.QtWidgets import QApplication

        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core import proxy_settings as PS

        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = self.tmp / "proxy.json"
        for name, value in (
            ("SETTINGS_PATH", self.path),
            ("get_password", lambda: ""),
            ("set_password", lambda _value: True),
        ):
            patcher = mock.patch.object(PS, name, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.addCleanup(PS.set_session_password, "")

    def test_sad_saving_with_an_empty_password_field_keeps_the_typed_password(self) -> None:
        from core import proxy_settings as PS
        from ui.network_proxy_dialog import NetworkProxyDialog

        self.path.write_text(json.dumps({
            "proxy_type": "socks5", "host": "socks.corp", "port": 1080,
            "username": "alice", "store_password": False,
        }))
        PS.set_session_password("typed-earlier")
        dialog = NetworkProxyDialog(None, path=self.path)
        self.addCleanup(dialog.deleteLater)
        dialog._bypass.setPlainText("localhost\n*.lan")  # an unrelated change
        dialog._save()
        cfg = PS.resolve("default", None, "files.example", 22).config
        self.assertEqual(cfg.password, "typed-earlier")
        self.assertEqual(json.loads(self.path.read_text())["bypass"], ["localhost", "*.lan"])

    def test_edge_a_newly_typed_password_still_replaces_it(self) -> None:
        from core import proxy_settings as PS
        from ui.network_proxy_dialog import NetworkProxyDialog

        self.path.write_text(json.dumps({
            "proxy_type": "socks5", "host": "socks.corp", "port": 1080,
            "username": "alice", "store_password": False,
        }))
        PS.set_session_password("typed-earlier")
        dialog = NetworkProxyDialog(None, path=self.path)
        self.addCleanup(dialog.deleteLater)
        dialog._password.setText("new-one")
        dialog._save()
        self.assertEqual(PS.resolve("default", None, "files.example", 22).config.password,
                         "new-one")


class SettingsEntriesAreFreedTest(_WindowStateTest):
    def test_sad_metadata_settings_leave_no_dialog_behind(self) -> None:
        from PyQt6.QtCore import QCoreApplication, QEvent
        from PyQt6.QtWidgets import QDialog

        win = self.make_window()

        def flush():
            for _ in range(3):
                self.app.processEvents()
                QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)

        def reject_at_once(dialog):
            dialog.reject()
            return 0

        flush()
        before = len(win.findChildren(QDialog))
        with mock.patch.object(QDialog, "exec", reject_at_once):
            for _ in range(3):
                win._show_metadata_settings()
                flush()
        self.assertEqual(len(win.findChildren(QDialog)), before)


if __name__ == "__main__":
    unittest.main()
