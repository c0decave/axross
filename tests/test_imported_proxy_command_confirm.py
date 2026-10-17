"""An imported profile's ProxyCommand runs only after the user confirmed it.

File > Import Profiles (JSON) took a shared
profiles.json as is. An entry carrying ``proxy_command`` ran that shell
command on the next Connect - a profile handed around by a colleague, a
wiki or a ticket was enough to execute anything on the user's machine,
without the command ever being shown.
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

from core.connection_manager import ConnectionManager  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402


def _profile(marker: str, **kw) -> ConnectionProfile:
    return ConnectionProfile(
        name="build-server",
        protocol="sftp",
        host="build.example.invalid",
        username="ci",
        proxy_command=f"touch {marker}",
        **kw,
    )


class CoreGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.marker = os.path.join(self.tmp, "ran")

    def test_sad_an_unconfirmed_proxy_command_never_runs(self) -> None:
        profile = _profile(self.marker, proxy_command_confirmed=False)
        with self.assertRaises(PermissionError) as ctx:
            ConnectionManager()._create_session(profile, "pw", "", None)
        self.assertIn("touch", str(ctx.exception))
        self.assertFalse(os.path.exists(self.marker))

    def test_happy_a_confirmed_proxy_command_is_used(self) -> None:
        profile = _profile(self.marker)  # own profiles are confirmed
        self.assertTrue(profile.proxy_command_confirmed)
        try:
            ConnectionManager()._create_session(profile, "pw", "", None)
        except Exception:  # noqa: BLE001 - "touch" is no SSH server
            pass
        self.assertTrue(os.path.exists(self.marker))

    def test_edge_the_flag_survives_saving_and_defaults_to_confirmed(self) -> None:
        unconfirmed = _profile(self.marker, proxy_command_confirmed=False)
        data = unconfirmed.to_dict()
        self.assertIs(data["proxy_command_confirmed"], False)
        self.assertFalse(ConnectionProfile.from_dict(data).proxy_command_confirmed)
        self.assertNotIn("proxy_command_confirmed", _profile(self.marker).to_dict())
        data.pop("proxy_command_confirmed")
        self.assertTrue(ConnectionProfile.from_dict(data).proxy_command_confirmed)


class WindowTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from ui import main_window as MW

        self.MW = MW
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        with mock.patch("pathlib.Path.home", return_value=Path(self.tmp)):
            self.win = MW.MainWindow()
        self.addCleanup(self.win.deleteLater)
        self.addCleanup(self.win.close)
        self.saved: list = []
        self.win._profile_manager = mock.Mock()
        self.win._profile_manager.get.return_value = None
        self.win._profile_manager.add.side_effect = self.saved.append
        self.marker = os.path.join(self.tmp, "ran")

    def import_file(self, entries: dict) -> None:
        path = os.path.join(self.tmp, "shared.json")
        Path(path).write_text(json.dumps(entries))
        with (
            mock.patch("PyQt6.QtWidgets.QFileDialog.getOpenFileName", return_value=(path, "")),
            mock.patch.object(self.MW.QMessageBox, "information"),
            mock.patch.object(self.MW.QMessageBox, "warning"),
        ):
            self.win._import_profiles_json()

    def test_happy_import_marks_a_proxy_command_unconfirmed(self) -> None:
        entry = _profile(self.marker).to_dict()
        entry["proxy_command_confirmed"] = True  # the file cannot vouch for itself
        plain = {"name": "plain", "protocol": "sftp", "host": "h", "username": "u"}
        self.import_file({"build-server": entry, "plain": plain})
        by_name = {p.name: p for p in self.saved}
        self.assertFalse(by_name["build-server"].proxy_command_confirmed)
        self.assertTrue(by_name["plain"].proxy_command_confirmed)

    def connect(self, profile, answer):
        asked: list = []

        def question(*args, **_kw):
            asked.append(args[2])
            return answer

        with (
            mock.patch.object(self.MW.QMessageBox, "question", side_effect=question),
            mock.patch("core.connect_worker.run_connect") as run,
        ):
            self.win._run_connect_async(profile, "", "", lambda s: None, lambda e: None)
        return asked, run

    def test_sad_declining_shows_the_command_and_does_not_connect(self) -> None:
        profile = _profile(self.marker, proxy_command_confirmed=False)
        asked, run = self.connect(profile, self.MW.QMessageBox.StandardButton.No)
        self.assertEqual(len(asked), 1)
        self.assertIn(f"touch {self.marker}", asked[0])
        run.assert_not_called()
        self.assertFalse(profile.proxy_command_confirmed)

    def test_edge_confirming_once_connects_and_is_remembered(self) -> None:
        profile = _profile(self.marker, proxy_command_confirmed=False)
        asked, run = self.connect(profile, self.MW.QMessageBox.StandardButton.Yes)
        self.assertEqual(len(asked), 1)
        run.assert_called_once()
        self.assertTrue(profile.proxy_command_confirmed)
        self.assertEqual(self.saved, [profile])
        asked, run = self.connect(profile, self.MW.QMessageBox.StandardButton.No)
        self.assertEqual(asked, [])  # not asked again
        run.assert_called_once()


if __name__ == "__main__":
    unittest.main()
