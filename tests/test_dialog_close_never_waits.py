"""Closing a window during a slow background run never blocks the GUI
thread, and a quit with a transfer worker stuck in a backend call exits
cleanly (review round 2).

* Find on Network Hosts: ``closeEvent`` joined the sweep thread for 5 s on
  the GUI thread, then ``reject()`` joined it for another 5 s - a host
  that did not answer froze the window for 10 s.
* Properties (folder size), Compare and Disk Usage waited ``wait(5000)``
  for their walk before handing the thread over.
* ``TransferManager.shutdown`` gave the pool's QThreads 5 s and then left
  them to be destroyed with the manager while still running in a backend
  call (a dead FTP link, a hung NFS server): "QThread: Destroyed while
  thread is still running", abort, exit status 134.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QCoreApplication  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _settle(release: threading.Event, until, seconds: float = 5.0) -> None:
    release.set()
    end = time.monotonic() + seconds
    while not until() and time.monotonic() < end:
        QCoreApplication.processEvents()
        time.sleep(0.01)


def test_sad_closing_find_on_network_hosts_mid_sweep_returns_at_once():
    from ui.network_search_dialog import NetworkSearchDialog

    entered, release = threading.Event(), threading.Event()
    ended = threading.Event()

    def sweep(config, on_hit, on_status, cancel):
        entered.set()
        release.wait(10)  # a connect / list_dir that does not answer
        ended.set()
        return None

    dlg = NetworkSearchDialog(sweep_fn=sweep)
    dlg.show()
    dlg.targets_edit.setPlainText("10.0.0.1")
    dlg.password_edit.setText("secret")
    dlg.start()
    assert entered.wait(5)
    started = time.monotonic()
    dlg.close()
    dlg.reject()  # Esc
    assert time.monotonic() - started < 1.0
    assert dlg.password_edit.text() == ""
    assert dlg._cancel is not None and dlg._cancel.is_set()
    _settle(release, lambda: dlg._thread is None)
    assert ended.is_set() and dlg._thread is None  # the finished callback cleaned up
    dlg.deleteLater()


class _Item:
    name = "d"
    is_dir = True
    is_link = False
    size = 0


def _stuck_backend(entered: threading.Event, release: threading.Event):
    from core.local_fs import LocalFS

    class Stuck(LocalFS):
        has_cheap_recursive_walk = False

        def list_dir(self, path):
            entered.set()
            release.wait(10)
            return []

    return Stuck()


@pytest.mark.parametrize("which", ["properties", "compare", "disk"])
def test_sad_closing_a_dialog_mid_walk_returns_at_once(which):
    import types

    from core.backend import FileItem
    from ui import thread_lifetime as TL

    entered, release = threading.Event(), threading.Event()
    backend = _stuck_backend(entered, release)

    def stuck(*_a, **_k):
        entered.set()
        release.wait(10)
        return []

    if which == "properties":
        from ui.properties_dialog import PropertiesDialog

        dlg = PropertiesDialog(backend, "/x", FileItem(name="x", is_dir=True))
        dlg._start_size_walk()
    elif which == "compare":
        from ui.compare_dialog import CompareDialog

        pane = types.SimpleNamespace(current_path="/", backend=backend)
        dlg = CompareDialog(pane, pane, compare_fn=stuck)
    else:
        from ui.disk_usage_dialog import DiskUsageDialog

        dlg = DiskUsageDialog([], snapshot_fn=stuck)
    assert entered.wait(5)
    thread = dlg._thread
    started = time.monotonic()
    dlg.reject()
    assert time.monotonic() - started < 1.0
    assert dlg._thread is None
    assert thread in TL._DETACHED  # handed over, not destroyed while it runs
    _settle(release, lambda: not TL._DETACHED)
    dlg.deleteLater()


_STUCK_TRANSFER = textwrap.dedent(
    """
    import os, sys, threading, time
    sys.path.insert(0, {root!r})
    from PyQt6.QtWidgets import QApplication, QMainWindow
    from core.local_fs import LocalFS
    from core.transfer_manager import TransferManager
    from core.qt_exit import delete_python_owned_qobjects, install_orderly_qt_exit

    install_orderly_qt_exit()
    folder = {folder!r}
    open(os.path.join(folder, "a.bin"), "wb").write(b"x" * 1000)
    started = threading.Event()

    class Hung:
        def read(self, n):
            started.set(); time.sleep(30); return b""
        def close(self): pass
        def __enter__(self): return self
        def __exit__(self, *a): pass

    class HungFS(LocalFS):
        def open_read(self, path):
            return Hung()

    def main():
        app = QApplication(sys.argv)
        win = QMainWindow()
        tm = TransferManager(win, max_parallel=1)
        tm.transfer_file(HungFS(), LocalFS(), os.path.join(folder, "a.bin"),
                         os.path.join(folder, "b.bin"))
        while not started.wait(0.05):
            app.processEvents()
        tm.shutdown()
        win.close()
        delete_python_owned_qobjects()
        return 0

    rc = main()
    print("main returned", rc, flush=True)
    raise SystemExit(rc)
    """
)


def test_sad_a_quit_with_a_transfer_stuck_in_a_backend_call_exits_cleanly(tmp_path):
    code = _STUCK_TRANSFER.format(root=str(ROOT), folder=str(tmp_path))
    proc = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                          timeout=60, env={**os.environ, "QT_QPA_PLATFORM": "offscreen"})
    assert "Destroyed while thread" not in proc.stderr
    assert proc.returncode == 0, proc.stderr[-2000:]
    assert "main returned 0" in proc.stdout
