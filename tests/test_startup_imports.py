"""The GUI start imports neither optional SDKs nor paramiko.

Measured (CPU time, old vs new in alternation): start to a shown window
1.16-1.56 s before, 0.24-0.44 s after. paramiko alone was ~0.13 s, pulled
in by connection_manager and main_window although a fresh window shows a
local pane; SSH sessions are now imported on first use.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))


def _run(code: str) -> str:
    env = dict(os.environ, PYTHONPATH=str(ROOT), QT_QPA_PLATFORM="offscreen")
    out = subprocess.run(
        [sys.executable, "-c", textwrap.dedent(code)],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(ROOT),
        timeout=120,
    )
    assert out.returncode == 0, out.stderr
    return out.stdout.strip().splitlines()[-1]


class StartupImportTest(unittest.TestCase):
    def test_a_shown_main_window_has_not_imported_paramiko(self) -> None:
        try:
            import PyQt6  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        got = _run(
            """
            import sys, tempfile, os
            os.environ["HOME"] = tempfile.mkdtemp()
            from core.backend_registry import init_registry
            init_registry()
            from PyQt6.QtWidgets import QApplication
            from ui.main_window import MainWindow
            app = QApplication([])
            w = MainWindow(); w.show(); app.processEvents()
            print("paramiko" in sys.modules, "boto3" in sys.modules)
            """
        )
        self.assertEqual(got, "False False")

    def test_connection_manager_import_does_not_load_ssh(self) -> None:
        got = _run(
            """
            import sys
            import core.connection_manager
            print("core.ssh_client" in sys.modules)
            """
        )
        self.assertEqual(got, "False")


class LazySessionNamesTest(unittest.TestCase):
    def test_happy_the_session_classes_are_still_module_attributes(self) -> None:
        from core import connection_manager as cm
        from core.scp_client import SCPSession
        from core.ssh_client import SSHSession, UnknownHostKeyError

        self.assertIs(cm.SSHSession, SSHSession)
        self.assertIs(cm.SCPSession, SCPSession)
        self.assertIs(cm.UnknownHostKeyError, UnknownHostKeyError)

    def test_sad_unknown_names_still_raise_attribute_error(self) -> None:
        from core import connection_manager as cm

        with self.assertRaises(AttributeError):
            cm.NoSuchThing  # noqa: B018

    def test_edge_a_patched_class_is_the_one_used(self) -> None:
        import importlib

        from core.profiles import ConnectionProfile

        # The module mock.patch resolves (sys.modules): another test
        # re-imports connection_manager under patched sys.modules, which can
        # leave the ``core`` package attribute pointing at a different copy.
        cm = importlib.import_module("core.connection_manager")

        fake = mock.MagicMock()
        with mock.patch("core.connection_manager.SSHSession", return_value=fake) as cls:
            got = cm.ConnectionManager()._create_session(
                ConnectionProfile(name="x", protocol="sftp", host="h", username="u"), "", "", None
            )
        cls.assert_called_once()
        self.assertIs(got, fake)


class IsSshSessionTest(unittest.TestCase):
    def setUp(self) -> None:
        try:
            import PyQt6  # noqa: F401
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")

    def test_happy_an_ssh_session_is_recognised(self) -> None:
        from core.ssh_client import SSHSession
        from ui.main_window import _is_ssh_session

        self.assertTrue(_is_ssh_session(object.__new__(SSHSession)))

    def test_sad_other_backends_are_not(self) -> None:
        from core.local_fs import LocalFS
        from ui.main_window import _is_ssh_session

        self.assertFalse(_is_ssh_session(LocalFS()))
        self.assertFalse(_is_ssh_session(None))

    def test_edge_without_the_ssh_module_loaded_nothing_is_an_ssh_session(self) -> None:
        got = _run(
            """
            from ui.main_window import _is_ssh_session
            from core.local_fs import LocalFS
            print(_is_ssh_session(LocalFS()))
            """
        )
        self.assertEqual(got, "False")


if __name__ == "__main__":
    unittest.main()
