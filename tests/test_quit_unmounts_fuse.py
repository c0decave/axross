"""Closing the window unmounts the panes' FUSE mounts first.

MainWindow.closeEvent never shut the file
panes down. A pane's FUSE mount stayed in the kernel after the app quit
(its serving thread gone, so every access to the mount point hung or
failed with "Transport endpoint is not connected"), and disconnect_all()
closed the backend the mount still served.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class _Handle:
    mount_point = "/mnt/x"

    def __init__(self, calls, fail=False):
        self.calls = calls
        self.fail = fail

    def unmount(self, timeout=5.0):
        self.calls.append("unmount")
        if self.fail:
            raise OSError("fusermount: busy")


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def window(self):
        from ui import main_window as MW

        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        with mock.patch("pathlib.Path.home", return_value=Path(home)):
            win = MW.MainWindow()
        self.addCleanup(win.deleteLater)
        return win


class QuitOrderTest(_Base):
    def test_happy_every_mount_is_unmounted_before_the_sessions_close(self) -> None:
        win = self.window()
        win._add_local_pane()
        calls: list = []
        for pane in win._panes:
            pane._fuse_handle = _Handle(calls)
        cm = win._connection_manager
        original = cm.disconnect_all
        with mock.patch.object(
            cm, "disconnect_all", side_effect=lambda: (calls.append("disconnect_all"), original())
        ):
            win.close()
        self.assertEqual(calls, ["unmount", "unmount", "disconnect_all"])
        self.assertTrue(all(p._fuse_handle is None for p in win._panes))

    def test_sad_a_failing_unmount_does_not_stop_the_rest_of_the_close(self) -> None:
        win = self.window()
        win._add_local_pane()
        calls: list = []
        win._panes[0]._fuse_handle = _Handle(calls, fail=True)
        win._panes[1]._fuse_handle = _Handle(calls)
        cm = win._connection_manager
        original = cm.disconnect_all
        with mock.patch.object(
            cm, "disconnect_all", side_effect=lambda: (calls.append("disconnect_all"), original())
        ):
            win.close()
        self.assertEqual(calls, ["unmount", "unmount", "disconnect_all"])

    def test_edge_panes_without_a_mount_close_quietly(self) -> None:
        win = self.window()
        win.close()
        self.assertTrue(all(getattr(p, "_shutting_down", False) for p in win._panes))


def _fuse_usable() -> bool:
    from core import fuse_mount as FM

    return (
        FM.FUSE_AVAILABLE
        and os.path.exists("/dev/fuse")
        and (shutil.which("fusermount3") or shutil.which("fusermount")) is not None
    )


class RealMountTest(_Base):
    def test_happy_a_real_mount_is_gone_after_quit(self) -> None:
        if not _fuse_usable():
            self.skipTest("needs FUSE (fusepy, /dev/fuse, fusermount)")
        from core import fuse_mount as FM
        from core.local_fs import LocalFS

        src = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, src, ignore_errors=True)
        (src / "a.txt").write_text("x")
        mnt = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, mnt, ignore_errors=True)
        handle = FM.mount(LocalFS(), str(mnt), root=str(src))
        self.addCleanup(handle.unmount)  # only matters when the test fails
        for _ in range(50):
            if os.path.ismount(mnt):
                break
            time.sleep(0.1)
        if not os.path.ismount(mnt):
            self.skipTest("FUSE mount did not come up")
        win = self.window()
        win._panes[0]._fuse_handle = handle
        win.close()
        self.assertFalse(os.path.ismount(mnt))


if __name__ == "__main__":
    unittest.main()
