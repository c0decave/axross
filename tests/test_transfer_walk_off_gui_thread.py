"""F5 / F6 on a remote folder no longer walk the tree on the GUI thread.

After the background conflict scan,
``_start_transfer_between`` called ``TransferManager.transfer_files`` on
the GUI thread. That walks the whole source tree again (is_dir,
exists/mkdir, list_dir and a destination probe per folder): 300 remote
folders at 30 ms per call froze the window for ~10 s. The walk now runs
on a worker thread; the jobs are registered on the GUI thread in the
same order as before, and a move still removes its emptied folders.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


class _Item:
    def __init__(self, name, is_dir, size=3):
        self.name, self.is_dir, self.is_link, self.size = name, is_dir, False, size
        self.modified = datetime.now()


class _GatedRemote:
    """/data holds folders d0..dN with three files each; every listing
    waits for *gate* so the walk can be held while the GUI is checked."""

    name = "remote"

    def __init__(self, folders=3, gate=None):
        self.folders = folders
        self.gate = gate or threading.Event()
        self.walk_threads: set = set()

    def separator(self):
        return "/"

    def join(self, *p):
        return "/".join(x.rstrip("/") for x in p)

    def parent(self, p):
        return p.rsplit("/", 1)[0] or "/"

    def normalize(self, p):
        return p

    def is_dir(self, p):
        return p.count("/") <= 2

    def exists(self, p):
        return True

    def stat(self, p):
        return _Item(p.rsplit("/", 1)[-1], self.is_dir(p))

    def list_dir(self, p):
        self.walk_threads.add(threading.get_ident())
        self.gate.wait(10)
        if p == "/data":
            return [_Item(f"d{i}", True) for i in range(self.folders)]
        if p == "/data/broken":
            raise OSError("permission denied")
        return [_Item(f"f{i}", False) for i in range(3)]


class _Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        try:
            from PyQt6.QtWidgets import QApplication
        except ImportError:
            raise unittest.SkipTest("PyQt6 not installed")
        cls.app = QApplication.instance() or QApplication([])

    def pump_until(self, cond, timeout=10.0) -> bool:
        end = time.time() + timeout
        while time.time() < end:
            self.app.processEvents()
            if cond():
                return True
            time.sleep(0.005)
        return cond()

    def manager(self):
        from core.transfer_manager import TransferManager

        tm = TransferManager()
        self.addCleanup(tm.shutdown)
        tm._worker.enqueue = lambda job: None  # the walk is under test, not the copy
        return tm


class ManagerWalkTest(_Base):
    def test_happy_background_walk_returns_at_once_and_keeps_the_job_order(self) -> None:
        from core.local_fs import LocalFS

        dest = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dest, ignore_errors=True)
        gate = threading.Event()
        remote = _GatedRemote(gate=gate)
        tm = self.manager()
        done: list = []
        added: list = []
        tm.job_added.connect(lambda job: added.append(job.source_path))
        start = time.monotonic()
        tm.transfer_files_in_background(remote, LocalFS(), ["/data"], dest, on_done=done.append)
        self.assertLess(time.monotonic() - start, 0.5)
        self.assertEqual(added, [])
        self.assertTrue(tm.busy(remote))  # a closing pane keeps the connection
        gate.set()
        self.assertTrue(self.pump_until(lambda: done))
        self.assertNotIn(threading.get_ident(), remote.walk_threads)
        # The same jobs, in the same order, as the synchronous walk.
        sync_dest = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, sync_dest, ignore_errors=True)
        expected = [
            j.source_path for j in tm.transfer_files(remote, LocalFS(), ["/data"], sync_dest)
        ]
        self.assertEqual([j.source_path for j in done[0]], expected[: len(done[0])])
        self.assertEqual(added[: len(done[0])], [j.source_path for j in done[0]])
        self.assertEqual(len(done[0]), 9)

    def test_sad_an_unreadable_folder_still_becomes_a_failed_row(self) -> None:
        from core.local_fs import LocalFS

        dest = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dest, ignore_errors=True)
        remote = _GatedRemote()
        remote.gate.set()
        tm = self.manager()
        errors: list = []
        done: list = []
        tm.job_error.connect(lambda jid, msg: errors.append(msg))
        tm.transfer_files_in_background(
            remote, LocalFS(), ["/data/broken"], dest, on_done=done.append
        )
        self.assertTrue(self.pump_until(lambda: done))
        self.assertEqual(len(done[0]), 1)
        self.assertTrue(any("cannot read the folder" in m for m in errors))
        self.assertFalse(tm.busy(remote))

    def test_edge_shutdown_during_the_walk_registers_nothing(self) -> None:
        from core.local_fs import LocalFS
        from core.transfer_manager import TransferManager

        dest = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, dest, ignore_errors=True)
        remote = _GatedRemote()
        tm = TransferManager()
        self.addCleanup(tm.shutdown)  # a second shutdown is harmless
        done: list = []
        tm.transfer_files_in_background(remote, LocalFS(), ["/data"], dest, on_done=done.append)
        tm.shutdown()
        remote.gate.set()
        self.pump_until(lambda: False, timeout=0.5)
        self.assertEqual(done, [])
        self.assertEqual(tm.all_jobs(), [])

    def test_edge_a_move_of_empty_folders_still_removes_them(self) -> None:
        from core.local_fs import LocalFS

        src = Path(tempfile.mkdtemp())
        dest = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, src, ignore_errors=True)
        self.addCleanup(shutil.rmtree, dest, ignore_errors=True)
        (src / "outer" / "inner").mkdir(parents=True)
        tm = self.manager()
        done: list = []
        tm.transfer_files_in_background(
            LocalFS(), LocalFS(), [str(src / "outer")], dest, move=True, on_done=done.append
        )
        self.assertTrue(self.pump_until(lambda: done))
        self.assertEqual(done[0], [])
        self.assertFalse((src / "outer").exists())
        self.assertTrue((Path(dest) / "outer" / "inner").is_dir())


class WindowTest(_Base):
    def test_happy_f5_returns_while_the_remote_tree_is_walked(self) -> None:
        from core.local_fs import LocalFS
        from ui import main_window as MW

        home = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, home, ignore_errors=True)
        with mock.patch("pathlib.Path.home", return_value=Path(home)):
            win = MW.MainWindow()
        self.addCleanup(win.deleteLater)
        self.addCleanup(win.close)
        win._transfer_manager._worker.enqueue = lambda job: None
        gate = threading.Event()
        self.addCleanup(gate.set)
        remote = _GatedRemote(gate=gate)
        source = mock.Mock(backend=remote, current_path="/")
        target = mock.Mock(backend=LocalFS(), current_path=home)
        start = time.monotonic()
        win._start_transfer_between(source, target, ["/data"])
        self.assertLess(time.monotonic() - start, 0.5)
        gate.set()
        # (Queued, not run: the jobs keep the remote busy, the walk is over.)
        self.assertTrue(self.pump_until(lambda: len(win._transfer_manager.all_jobs()) == 9))
        self.assertEqual(win._transfer_manager._walks, [])


if __name__ == "__main__":
    unittest.main()
