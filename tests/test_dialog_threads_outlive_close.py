"""A test-connection or proxy-probe thread outlives its dialog safely.

Found in review (round 2): "Test Connection" (ConnectionDialog) and "Test
proxy" (NetworkProxyDialog) ran a QThread parented to the dialog, and the
main window keeps both dialogs as children until it is destroyed. Closing
the dialog did not stop or detach the thread:

* its late result still reached the closed dialog, which popped
  "Connection Failed" / "Success" message boxes after the user cancelled;
* quitting the app while the attempt still ran (an unreachable host takes
  the full connect timeout) destroyed the window, the dialog and the
  RUNNING QThread with it - Qt aborts the process ("QThread: Destroyed
  while thread is still running").
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

# The app's own shutdown, in a child: main() returns, its MainWindow goes
# with the frame while the dialog's attempt is still running.
_CHILD = textwrap.dedent(
    """
    import sys, threading
    sys.path.insert(0, {root!r})
    from PyQt6.QtWidgets import QApplication
    app = QApplication([])
    from core import connection_manager as CM
    from core import proxy_settings as PS

    def slow(*_a, **_k):
        threading.Event().wait(1.5)
        raise OSError("unreachable")

    CM.ConnectionManager.connect = slow
    PS.probe = slow
    from ui import main_window as MW

    def main():
        win = MW.MainWindow()
        if {which!r} == "connection":
            from ui.connection_dialog import ConnectionDialog
            dlg = ConnectionDialog(win._profile_manager, parent=win)
            dlg._profile_name.setText("p")
            dlg._host.setText("unreachable.invalid")
            dlg._username.setText("u")
            dlg._test_connection()
        else:
            from core.proxy_settings import ProxyDefaults
            from ui.network_proxy_dialog import NetworkProxyDialog
            dlg = NetworkProxyDialog(win._profile_manager, parent=win)
            dlg._test_host.setText("example.com")
            dlg.collect = lambda: ProxyDefaults(proxy_type="http", host="127.0.0.1", port=9)
            dlg._run_test()
        assert {attr!r} and getattr(dlg, {attr!r}).isRunning()
        dlg.reject()
        win.close()
        return 0

    main()
    print("clean exit")
    """
)


def _run_child(which: str, attr: str) -> subprocess.CompletedProcess:
    code = _CHILD.format(root=str(ROOT), which=which, attr=attr)
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
    )


class AppExitWhileTestingTest(unittest.TestCase):
    def test_sad_quitting_during_a_test_connection_exits_cleanly(self) -> None:
        proc = _run_child("connection", "_connect_thread")
        self.assertNotIn("Destroyed while thread is still running", proc.stderr)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        self.assertIn("clean exit", proc.stdout)

    def test_sad_quitting_during_a_proxy_probe_exits_cleanly(self) -> None:
        proc = _run_child("proxy", "_probe")
        self.assertNotIn("Destroyed while thread is still running", proc.stderr)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        self.assertIn("clean exit", proc.stdout)


class LateResultTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def settle(self, predicate, timeout: float = 5.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if predicate():
                return True
            time.sleep(0.01)
        return False

    def make_dialog(self):
        from core.profiles import ProfileManager
        from ui.connection_dialog import ConnectionDialog

        dlg = ConnectionDialog(ProfileManager(), parent=None)
        self.addCleanup(dlg.deleteLater)
        dlg._profile_name.setText("p")
        dlg._host.setText("unreachable.invalid")
        dlg._username.setText("u")
        return dlg

    def run_test_connection(self, *, close_first: bool, result=OSError("unreachable")):
        from core import connection_manager as CM

        gate = threading.Event()
        finished = threading.Event()

        class _Session:
            def home(self):
                return "/home/u"

        def connect(*_a, **_k):
            gate.wait(5)
            finished.set()
            if isinstance(result, Exception):
                raise result
            return _Session()

        dlg = self.make_dialog()
        with mock.patch.object(CM.ConnectionManager, "connect", connect), mock.patch(
            "ui.connection_dialog.QMessageBox.critical"
        ) as critical, mock.patch("ui.connection_dialog.QMessageBox.information") as info:
            dlg._test_connection()
            thread = dlg._connect_thread
            if close_first:
                dlg.reject()
            gate.set()
            self.assertTrue(finished.wait(5))
            self.assertTrue(thread.wait(5000))
            self.settle(lambda: False, timeout=0.3)
        return dlg, critical, info

    def test_happy_an_open_dialog_reports_the_result(self) -> None:
        dlg, critical, _info = self.run_test_connection(close_first=False)
        critical.assert_called_once()
        self.assertTrue(dlg._btn_test.isEnabled())

    def test_sad_a_cancelled_dialog_pops_no_late_failure(self) -> None:
        _dlg, critical, info = self.run_test_connection(close_first=True)
        critical.assert_not_called()
        info.assert_not_called()

    def test_edge_a_cancelled_dialog_pops_no_late_success_either(self) -> None:
        _dlg, critical, info = self.run_test_connection(close_first=True, result=None)
        critical.assert_not_called()
        info.assert_not_called()


if __name__ == "__main__":
    unittest.main()
