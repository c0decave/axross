"""Tools > Network & Proxy, the connection dialog's proxy modes and the
per-pane proxy indicator. Qt runs offscreen; keyring and the settings
file are redirected so the developer's real proxy is never read."""

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

from core import proxy_settings as PS  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402
from tests.proxy_testkit import EchoServer, FakeSocks5Server, allow_loopback_proxy  # noqa: E402


class _QtCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.path = self.tmp / "proxy.json"
        patcher = mock.patch.object(PS, "SETTINGS_PATH", self.path)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.passwords: dict[str, str] = {}
        for name, impl in (
            ("get_password", lambda: self.passwords.get("pw", "")),
            ("set_password", self._set_password),
        ):
            p = mock.patch.object(PS, name, impl)
            p.start()
            self.addCleanup(p.stop)

    def _set_password(self, value: str) -> bool:
        if value:
            self.passwords["pw"] = value
        else:
            self.passwords.pop("pw", None)
        return True

    def write_settings(self, **fields) -> None:
        self.path.write_text(json.dumps(fields), encoding="utf-8")


class KindHelpersTest(unittest.TestCase):
    def test_roundtrip_for_every_http_kind(self) -> None:
        from ui.network_proxy_dialog import auth_index, kind_from_indexes, transport_index

        for kind in ("socks5", "socks4", "http", "https", "http+ntlm", "https+negotiate"):
            self.assertEqual(kind_from_indexes(transport_index(kind), auth_index(kind)), kind, kind)

    def test_auth_choice_is_ignored_for_socks(self) -> None:
        from ui.network_proxy_dialog import AUTH_CHOICES, kind_from_indexes, transport_index

        ntlm = [v for _l, v in AUTH_CHOICES].index("ntlm")
        self.assertEqual(kind_from_indexes(transport_index("socks5"), ntlm), "socks5")

    def test_unknown_kind_falls_back_to_first_entry(self) -> None:
        from ui.network_proxy_dialog import auth_index, transport_index

        self.assertEqual(transport_index("bogus"), 0)
        self.assertEqual(auth_index("bogus"), 0)
        self.assertEqual(auth_index("socks5"), 0)


class NetworkProxyDialogTest(_QtCase):
    def _dialog(self, manager=None):
        from ui.network_proxy_dialog import NetworkProxyDialog

        dialog = NetworkProxyDialog(manager, path=self.path)
        self.addCleanup(dialog.deleteLater)
        return dialog

    def test_fresh_dialog_means_direct(self) -> None:
        d = self._dialog().collect()
        self.assertEqual(d.proxy_type, "none")
        self.assertEqual(d.bypass, list(PS.DEFAULT_BYPASS))

    def test_loads_stored_settings(self) -> None:
        self.write_settings(
            proxy_type="https+ntlm",
            host="proxy.corp",
            port=3128,
            username="alice",
            store_password=True,
            bypass=["*.lan", "10.0.0.0/8"],
            ca_file="",
            pac_url="",
        )
        dialog = self._dialog()
        got = dialog.collect()
        self.assertEqual(got.proxy_type, "https+ntlm")
        self.assertEqual((got.host, got.port, got.username), ("proxy.corp", 3128, "alice"))
        self.assertTrue(got.store_password)
        self.assertEqual(got.bypass, ["*.lan", "10.0.0.0/8"])

    def test_save_writes_file_and_password_to_keyring(self) -> None:
        dialog = self._dialog()
        dialog._type.setCurrentIndex(1)  # SOCKS5
        dialog._host.setText("socks.corp")
        dialog._port.setValue(1081)
        dialog._username.setText("bob")
        dialog._password.setText("s3cret")
        dialog._store_pw.setChecked(True)
        dialog._save()
        stored = json.loads(self.path.read_text())
        self.assertEqual(stored["proxy_type"], "socks5")
        self.assertEqual(stored["host"], "socks.corp")
        self.assertNotIn("s3cret", self.path.read_text())
        self.assertEqual(self.passwords["pw"], "s3cret")
        self.assertEqual(dialog.result(), dialog.DialogCode.Accepted)

    def test_unchecked_store_removes_a_stored_password(self) -> None:
        self.passwords["pw"] = "old"
        dialog = self._dialog()
        dialog._type.setCurrentIndex(1)
        dialog._host.setText("socks.corp")
        dialog._store_pw.setChecked(False)
        dialog._save()
        self.assertNotIn("pw", self.passwords)

    def test_missing_host_is_refused_and_nothing_is_written(self) -> None:
        dialog = self._dialog()
        dialog._type.setCurrentIndex(1)
        with mock.patch("ui.network_proxy_dialog.QMessageBox.warning") as warn:
            dialog._save()
        warn.assert_called_once()
        self.assertFalse(self.path.exists())
        self.assertNotEqual(dialog.result(), dialog.DialogCode.Accepted)

    def test_auth_combo_follows_the_transport(self) -> None:
        dialog = self._dialog()
        dialog._type.setCurrentIndex(1)  # SOCKS5
        self.assertFalse(dialog._auth.isEnabled())
        dialog._type.setCurrentIndex(4)  # HTTPS proxy
        self.assertTrue(dialog._auth.isEnabled())
        self.assertTrue(dialog._ca_file.isEnabled())

    def test_pac_disables_the_fixed_endpoint(self) -> None:
        dialog = self._dialog()
        dialog._type.setCurrentIndex(3)
        dialog._pac.setText("http://pac.corp/wpad.dat")
        self.assertFalse(dialog._host.isEnabled())
        self.assertFalse(dialog._port.isEnabled())

    def test_pac_without_host_can_be_saved(self) -> None:
        dialog = self._dialog()
        dialog._type.setCurrentIndex(3)
        dialog._pac.setText("http://pac.corp/wpad.dat")
        dialog._save()
        self.assertEqual(json.loads(self.path.read_text())["pac_url"], "http://pac.corp/wpad.dat")

    def test_blank_bypass_lines_are_dropped(self) -> None:
        dialog = self._dialog()
        dialog._bypass.setPlainText("a.lan\n\n  \n b.lan  \n")
        self.assertEqual(dialog.collect().bypass, ["a.lan", "b.lan"])

    def _wait_for_probe(self, dialog) -> None:
        self.assertIsNotNone(dialog._probe)
        dialog._probe.wait(10000)
        self.app.processEvents()

    def test_test_button_reports_success_through_the_proxy(self) -> None:
        echo = EchoServer(banner=b"")
        self.addCleanup(echo.close)
        socks = FakeSocks5Server(routes={("db.internal", 5432): ("127.0.0.1", echo.port)})
        self.addCleanup(socks.close)
        guard = allow_loopback_proxy()
        guard.__enter__()
        self.addCleanup(guard.__exit__, None, None, None)
        dialog = self._dialog()
        dialog._type.setCurrentIndex(1)
        dialog._host.setText("127.0.0.1")
        dialog._port.setValue(socks.port)
        dialog._test_host.setText("db.internal")
        dialog._test_port.setValue(5432)
        dialog._run_test()
        self._wait_for_probe(dialog)
        self.assertIn("✔", dialog._test_result.text())
        self.assertIn(("db.internal", 5432), socks.connects)

    def test_test_button_names_the_failing_stage(self) -> None:
        dialog = self._dialog()
        dialog._type.setCurrentIndex(1)
        dialog._host.setText("127.0.0.1")
        dialog._port.setValue(1)  # nothing listens there
        dialog._test_host.setText("db.internal")
        with allow_loopback_proxy():
            dialog._run_test()
            self._wait_for_probe(dialog)
        text = dialog._test_result.text()
        self.assertIn("✘", text)
        self.assertIn("stage", text)

    def test_test_button_reports_bypassed_target_as_direct(self) -> None:
        dialog = self._dialog()
        dialog._type.setCurrentIndex(1)
        dialog._host.setText("127.0.0.1")
        dialog._port.setValue(1)
        dialog._bypass.setPlainText("*.lan")
        dialog._test_host.setText("files.lan")
        dialog._run_test()
        self._wait_for_probe(dialog)
        self.assertIn("Direct", dialog._test_result.text())
        self.assertIn("✔", dialog._test_result.text())

    def test_test_without_target_asks_for_one(self) -> None:
        dialog = self._dialog()
        dialog._run_test()
        self.assertIsNone(dialog._probe)
        self.assertIn("target host", dialog._test_result.text())

    def test_adopt_switches_profiles_and_persists_once(self) -> None:
        profiles = [
            ConnectionProfile(name="a", protocol="sftp", host="h"),
            ConnectionProfile(name="r", protocol="rsh", host="h"),
        ]
        manager = mock.MagicMock()
        manager.all_profiles.return_value = profiles
        dialog = self._dialog(manager)
        from PyQt6.QtWidgets import QMessageBox as yes

        with (
            mock.patch(
                "ui.network_proxy_dialog.QMessageBox.question", return_value=yes.StandardButton.Yes
            ),
            mock.patch("ui.network_proxy_dialog.QMessageBox.information") as info,
        ):
            dialog._adopt_for_all()
        self.assertEqual([p.proxy_mode for p in profiles], ["default", "custom"])
        manager.save.assert_called_once()
        self.assertIn("1 profile", info.call_args[0][2])

    def test_adopt_declined_changes_nothing(self) -> None:
        profiles = [ConnectionProfile(name="a", protocol="sftp", host="h")]
        manager = mock.MagicMock()
        manager.all_profiles.return_value = profiles
        dialog = self._dialog(manager)
        from PyQt6.QtWidgets import QMessageBox

        with mock.patch(
            "ui.network_proxy_dialog.QMessageBox.question",
            return_value=QMessageBox.StandardButton.No,
        ):
            dialog._adopt_for_all()
        self.assertEqual(profiles[0].proxy_mode, "custom")
        manager.save.assert_not_called()

    def test_adopt_button_is_disabled_without_a_profile_store(self) -> None:
        self.assertFalse(self._dialog()._adopt_btn.isEnabled())


class ConnectionDialogProxyModeTest(_QtCase):
    def _dialog(self, profile=None):
        from ui.connection_dialog import ConnectionDialog

        manager = mock.MagicMock()
        manager.list_names.return_value = []
        dialog = ConnectionDialog(manager, profile=profile)
        self.addCleanup(dialog.deleteLater)
        dialog._host.setText("files.example")
        dialog._username.setText("alice")
        return dialog

    def _select(self, dialog, proto: str) -> None:
        dialog._protocol_combo.setCurrentIndex(dialog._protocol_ids.index(proto))

    def test_new_profile_is_direct_without_a_default_proxy(self) -> None:
        dialog = self._dialog()
        self._select(dialog, "sftp")
        self.assertFalse(dialog._proxy_group.isChecked())
        self.assertEqual(dialog._build_profile().proxy_mode, "none")

    def test_new_profile_uses_the_default_when_one_is_configured(self) -> None:
        self.write_settings(proxy_type="socks5", host="p", port=1080, bypass=[])
        dialog = self._dialog()
        self._select(dialog, "sftp")
        self.assertTrue(dialog._proxy_group.isChecked())
        built = dialog._build_profile()
        self.assertEqual(built.proxy_mode, "default")
        self.assertEqual((built.proxy_type, built.proxy_host), ("none", ""))
        self.assertIn("SOCKS5 p:1080", dialog._proxy_default_hint.text())

    def test_custom_https_ntlm_roundtrips_through_a_profile(self) -> None:
        dialog = self._dialog()
        self._select(dialog, "sftp")
        dialog._proxy_group.setChecked(True)
        dialog._proxy_mode.setCurrentIndex(1)
        dialog._proxy_type.setCurrentIndex(3)  # HTTPS proxy
        dialog._proxy_auth.setCurrentIndex(2)  # NTLM
        dialog._proxy_host.setText("gw.corp")
        dialog._proxy_port.setValue(8443)
        dialog._proxy_username.setText("CORP\\alice")
        built = dialog._build_profile()
        self.assertEqual(built.proxy_mode, "custom")
        self.assertEqual(built.proxy_type, "https+ntlm")
        self.assertEqual(built.proxy_host, "gw.corp")
        reloaded = self._dialog(profile=built)
        again = reloaded._build_profile()
        self.assertEqual(
            (again.proxy_type, again.proxy_host, again.proxy_port, again.proxy_username),
            ("https+ntlm", "gw.corp", 8443, "CORP\\alice"),
        )

    def test_default_mode_profile_loads_as_default(self) -> None:
        prof = ConnectionProfile(
            name="p", protocol="sftp", host="h", username="u", proxy_mode="default"
        )
        dialog = self._dialog(profile=prof)
        self.assertTrue(dialog._proxy_group.isChecked())
        self.assertEqual(dialog._proxy_mode.currentIndex(), 0)
        self.assertFalse(dialog._proxy_host.isEnabled())

    def test_explicit_direct_profile_loads_unchecked(self) -> None:
        prof = ConnectionProfile(
            name="p", protocol="sftp", host="h", username="u", proxy_mode="none"
        )
        dialog = self._dialog(profile=prof)
        self.assertFalse(dialog._proxy_group.isChecked())

    def test_legacy_profile_with_socks_proxy_stays_custom(self) -> None:
        prof = ConnectionProfile(
            name="p",
            protocol="sftp",
            host="h",
            username="u",
            proxy_type="socks4",
            proxy_host="old",
            proxy_port=9050,
        )
        dialog = self._dialog(profile=prof)
        built = dialog._build_profile()
        self.assertEqual(
            (built.proxy_mode, built.proxy_type, built.proxy_host), ("custom", "socks4", "old")
        )

    def test_auth_combo_only_for_http_transports(self) -> None:
        dialog = self._dialog()
        dialog._proxy_group.setChecked(True)
        dialog._proxy_mode.setCurrentIndex(1)
        dialog._proxy_type.setCurrentIndex(0)
        self.assertFalse(dialog._proxy_auth.isEnabled())
        dialog._proxy_type.setCurrentIndex(2)
        self.assertTrue(dialog._proxy_auth.isEnabled())

    def test_custom_without_host_fails_validation(self) -> None:
        dialog = self._dialog()
        self._select(dialog, "sftp")
        dialog._proxy_group.setChecked(True)
        dialog._proxy_mode.setCurrentIndex(1)
        dialog._auth_password.setChecked(True)
        with mock.patch("ui.connection_dialog.QMessageBox.warning") as warn:
            self.assertFalse(dialog._validate())
        self.assertIn("Proxy host", warn.call_args[0][2])

    def test_default_mode_needs_no_host(self) -> None:
        dialog = self._dialog()
        self._select(dialog, "sftp")
        dialog._proxy_group.setChecked(True)
        dialog._proxy_mode.setCurrentIndex(0)
        dialog._auth_password.setChecked(True)
        with mock.patch("ui.connection_dialog.QMessageBox.warning") as warn:
            self.assertTrue(dialog._validate(), warn.call_args)

    def test_unsupported_protocol_forces_direct(self) -> None:
        self.write_settings(proxy_type="socks5", host="p", port=1080, bypass=[])
        dialog = self._dialog()
        self._select(dialog, "rsh")
        self.assertFalse(dialog._proxy_group.isEnabled())
        self.assertEqual(dialog._build_profile().proxy_mode, "none")


class PaneProxyIndicatorTest(_QtCase):
    def _pane(self):
        from core.local_fs import LocalFS
        from ui.file_pane import FilePaneWidget

        pane = FilePaneWidget(LocalFS())
        self.addCleanup(pane.deleteLater)
        return pane

    def test_hidden_by_default(self) -> None:
        pane = self._pane()
        self.assertTrue(pane._proxy_label.isHidden())

    def test_shows_text_and_tooltip(self) -> None:
        pane = self._pane()
        pane.set_proxy_info("via SOCKS5 p:1080", "SOCKS5 p:1080 (default proxy)")
        self.assertFalse(pane._proxy_label.isHidden())
        self.assertEqual(pane._proxy_label.text(), "via SOCKS5 p:1080")
        self.assertIn("default proxy", pane._proxy_label.toolTip())

    def test_empty_text_hides_again_but_keeps_the_tooltip(self) -> None:
        pane = self._pane()
        pane.set_proxy_info("via X", "t")
        pane.set_proxy_info("", "Direct (target matches the bypass list)")
        self.assertTrue(pane._proxy_label.isHidden())
        self.assertIn("Direct", pane._proxy_label.toolTip())


class MainWindowIndicatorTest(_QtCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._home = tempfile.mkdtemp()
        cls._patch = mock.patch("pathlib.Path.home", return_value=Path(cls._home))
        cls._patch.start()
        from ui.main_window import MainWindow

        cls.win = MainWindow()

    @classmethod
    def tearDownClass(cls) -> None:
        cls.win.deleteLater()
        cls._patch.stop()
        shutil.rmtree(cls._home, ignore_errors=True)

    def _pane_with(self, profile):
        pane = mock.MagicMock()
        self.win._pane_profiles[pane] = profile
        self.addCleanup(self.win._pane_profiles.pop, pane, None)
        return pane

    def test_menu_entry_exists(self) -> None:
        from PyQt6.QtGui import QAction

        texts = [a.text().replace("&", "") for a in self.win.findChildren(QAction)]
        self.assertTrue(any("Network" in t and "Proxy" in t for t in texts), texts)

    def test_pane_with_default_proxy_shows_the_route(self) -> None:
        self.write_settings(proxy_type="http", host="gw", port=3128, bypass=[])
        pane = self._pane_with(
            ConnectionProfile(name="x", protocol="sftp", host="h", proxy_mode="default")
        )
        self.win._refresh_proxy_indicator(pane)
        text, tip = pane.set_proxy_info.call_args[0]
        self.assertEqual(text, "via HTTP gw:3128")
        self.assertIn("default proxy", tip)

    def test_direct_profile_clears_the_label(self) -> None:
        pane = self._pane_with(ConnectionProfile(name="x", protocol="sftp", host="h"))
        self.win._refresh_proxy_indicator(pane)
        self.assertEqual(pane.set_proxy_info.call_args[0][0], "")

    def test_pane_without_profile_is_cleared(self) -> None:
        pane = mock.MagicMock()
        self.win._refresh_proxy_indicator(pane)
        pane.set_proxy_info.assert_called_once_with("", "")

    def test_unresolvable_pac_is_flagged_not_raised(self) -> None:
        self.write_settings(proxy_type="none", pac_url="http://pac.invalid/x.pac", bypass=[])
        pane = self._pane_with(
            ConnectionProfile(name="x", protocol="sftp", host="h", proxy_mode="default")
        )
        with mock.patch.object(
            PS, "pac_script", side_effect=PS.ProxyResolutionError("PAC unreachable")
        ):
            self.win._refresh_proxy_indicator(pane)
        text, tip = pane.set_proxy_info.call_args[0]
        self.assertEqual(text, "Proxy: ?")
        self.assertIn("PAC unreachable", tip)

    def test_description_never_contains_the_password(self) -> None:
        self.write_settings(
            proxy_type="http+basic",
            host="gw",
            port=3128,
            username="u",
            store_password=True,
            bypass=[],
        )
        self.passwords["pw"] = "TOPSECRET"
        pane = self._pane_with(
            ConnectionProfile(name="x", protocol="sftp", host="h", proxy_mode="default")
        )
        self.win._refresh_proxy_indicator(pane)
        for part in pane.set_proxy_info.call_args[0]:
            self.assertNotIn("TOPSECRET", part)


if __name__ == "__main__":
    unittest.main()
