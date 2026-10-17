"""Quick Connect asks for the passphrase of an encrypted SSH key.

``_quick_connect_profile`` had
``pass`` where a key-auth profile should ask for its key's passphrase, so
the connect ran with "" - and ``_load_private_key`` swallowed paramiko's
PasswordRequiredException into a generic "Cannot load key". Quick
Connect, a bookmark open and Reconnect on a restored placeholder (all
through ``_quick_connect_profile``) could never use an encrypted key.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import paramiko  # noqa: E402

from core.scp_client import SCPSession  # noqa: E402
from core.ssh_client import SSHSession  # noqa: E402


class _Keys(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.tmp = tempfile.mkdtemp()
        key = paramiko.RSAKey.generate(1024)
        cls.encrypted = os.path.join(cls.tmp, "id_enc")
        key.write_private_key_file(cls.encrypted, password="s3cret")
        cls.plain = os.path.join(cls.tmp, "id_plain")
        key.write_private_key_file(cls.plain)
        cls.garbage = os.path.join(cls.tmp, "id_garbage")
        Path(cls.garbage).write_text("not a key\n")

    @classmethod
    def tearDownClass(cls) -> None:
        shutil.rmtree(cls.tmp, ignore_errors=True)


class LoadPrivateKeyTest(_Keys):
    LOADERS = (
        ("ssh", lambda path, pw: SSHSession._load_private_key(None, path, pw)),
        ("scp", SCPSession._load_private_key),
    )

    def test_happy_the_right_passphrase_loads_the_key(self) -> None:
        for name, load in self.LOADERS:
            with self.subTest(name):
                self.assertIsInstance(load(self.encrypted, "s3cret"), paramiko.RSAKey)
                self.assertIsInstance(load(self.plain, ""), paramiko.RSAKey)

    def test_sad_no_or_a_wrong_passphrase_says_a_passphrase_is_needed(self) -> None:
        for name, load in self.LOADERS:
            for passphrase in ("", "wrong"):
                with self.subTest(name, passphrase=passphrase):
                    with self.assertRaises(paramiko.PasswordRequiredException) as ctx:
                        load(self.encrypted, passphrase)
                    self.assertIn(self.encrypted, str(ctx.exception))

    def test_edge_an_unreadable_key_is_not_a_passphrase_question(self) -> None:
        for name, load in self.LOADERS:
            with self.subTest(name):
                with self.assertRaises(paramiko.SSHException) as ctx:
                    load(self.garbage, "")
                self.assertNotIsInstance(ctx.exception, paramiko.PasswordRequiredException)


class QuickConnectPassphraseTest(_Keys):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        from core.profiles import ConnectionProfile
        from ui import main_window as MW

        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        with mock.patch("pathlib.Path.home", return_value=Path(home)):
            self.win = MW.MainWindow()
        self.addCleanup(self.win.deleteLater)
        self.addCleanup(self.win.close)
        self.addCleanup(self.win._pane_profiles.clear)
        self.profile = ConnectionProfile(
            name="enc",
            protocol="sftp",
            host="h.example",
            username="u",
            auth_type="key",
            key_file=self.encrypted,
        )
        self.attempts: list[str] = []
        self.session = mock.Mock(transport=None)
        self.session.name = "u@h.example"
        self.prompts: list = []
        self.answers: list = []
        self.errors: list = []
        patches = [
            mock.patch.object(self.win, "_run_connect_async", side_effect=self._run),
            mock.patch.object(self.win, "_add_pane_to_splitter", side_effect=self._add_pane),
            mock.patch.object(self.win, "_set_active_pane"),
            mock.patch.object(self.win, "_add_to_recent"),
            mock.patch("PyQt6.QtWidgets.QInputDialog.getText", side_effect=self._ask),
            mock.patch.object(
                MW.QMessageBox, "critical", side_effect=lambda *a, **k: self.errors.append(a[2])
            ),
        ]
        for patch in patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.added: list = []

    def _ask(self, *args, **_kw):
        self.prompts.append(args[2])
        return self.answers.pop(0) if self.answers else ("", False)

    def _add_pane(self, _splitter, session, **kw):
        self.added.append(kw)
        return mock.Mock()

    def _run(self, profile, password, key_passphrase, on_success, on_failure):
        self.attempts.append(key_passphrase)
        try:
            SSHSession._load_private_key(None, profile.key_file, key_passphrase)
        except Exception as exc:  # noqa: BLE001 - what the worker forwards
            on_failure(exc)
            return
        on_success(self.session)

    def test_happy_the_passphrase_is_asked_and_the_connect_retried(self) -> None:
        self.answers = [("s3cret", True)]
        self.win._quick_connect_profile(self.profile)
        self.assertEqual(self.attempts, ["", "s3cret"])
        self.assertEqual(len(self.prompts), 1)
        self.assertIn(self.encrypted, self.prompts[0])
        self.assertEqual(self.errors, [])
        # The pane keeps the passphrase for its auto-reconnect.
        self.assertEqual(self.added[0]["key_passphrase"], "s3cret")

    def test_sad_cancelling_the_prompt_stops_without_an_error_box(self) -> None:
        self.answers = [("", False)]
        self.win._quick_connect_profile(self.profile)
        self.assertEqual(self.attempts, [""])
        self.assertEqual(self.added, [])
        self.assertEqual(self.errors, [])

    def test_edge_a_wrong_passphrase_is_asked_again_then_given_up(self) -> None:
        self.answers = [("bad1", True), ("bad2", True), ("bad3", True), ("s3cret", True)]
        self.win._quick_connect_profile(self.profile)
        self.assertEqual(self.attempts, ["", "bad1", "bad2", "bad3"])
        self.assertIn("wrong", self.prompts[1].lower())
        self.assertEqual(len(self.errors), 1)
        self.assertEqual(self.added, [])

    def test_edge_a_plain_key_connects_without_a_prompt(self) -> None:
        self.profile.key_file = self.plain
        self.win._quick_connect_profile(self.profile)
        self.assertEqual(self.attempts, [""])
        self.assertEqual(self.prompts, [])
        self.assertEqual(len(self.added), 1)


if __name__ == "__main__":
    unittest.main()
