"""A size walk / comparison / capacity probe still running when its dialog
closes does not take the app down with its owner.

Found in review (round 2): Properties (size walk), Compare and Disk Usage
run a QThread parented to the dialog. Closing the dialog waits 5 s; a
remote walk still inside a blocking call after that was "left to finish"
- but still as a child of the dialog, which is a child of the pane or the
main window. Closing that pane, or quitting the app, destroyed the RUNNING
QThread and Qt aborted the process ("QThread: Destroyed while thread is
still running").
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

_CHILD = textwrap.dedent(
    """
    import sys, threading, types
    sys.path.insert(0, {root!r})
    from PyQt6.QtCore import QCoreApplication, QEvent, QThread
    from PyQt6.QtWidgets import QApplication, QWidget
    app = QApplication([])

    # The dialogs' 5 s grace before they give up waiting, shortened.
    _wait = QThread.wait
    QThread.wait = lambda self, *a: _wait(self, 50)

    from core.local_fs import LocalFS
    from core.backend import FileItem

    entered = threading.Event()

    def stuck(*_a, **_k):
        entered.set()
        threading.Event().wait({stuck_for})
        return []

    class Stuck(LocalFS):
        has_cheap_recursive_walk = False
        list_dir = stuck

    owner = QWidget()  # the pane / the main window
    which = {which!r}
    if which == "properties":
        from ui.properties_dialog import PropertiesDialog
        dlg = PropertiesDialog(Stuck(), "/x", FileItem(name="x", is_dir=True), parent=owner)
        dlg._start_size_walk()
    elif which == "compare":
        from ui.compare_dialog import CompareDialog
        pane = types.SimpleNamespace(current_path="/", backend=Stuck())
        dlg = CompareDialog(pane, pane, parent=owner, compare_fn=stuck)
    else:
        from ui.disk_usage_dialog import DiskUsageDialog
        dlg = DiskUsageDialog([], parent=owner, snapshot_fn=stuck)
    # The worker is inside the blocking call (a remote list_dir / probe).
    assert entered.wait(5)
    dlg.reject()
    owner.deleteLater()
    QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
    {after}
    print("clean exit")
    """
)


def _run(which: str, after: str = "", stuck_for: float = 2.0) -> subprocess.CompletedProcess:
    code = _CHILD.format(root=str(ROOT), which=which, after=after, stuck_for=stuck_for)
    return subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        timeout=60,
        env={**os.environ, "QT_QPA_PLATFORM": "offscreen"},
    )


class WalkOutlivesOwnerTest(unittest.TestCase):
    def check(self, proc) -> None:
        self.assertNotIn("Destroyed while thread", proc.stderr)
        self.assertEqual(proc.returncode, 0, proc.stderr[-2000:])
        self.assertIn("clean exit", proc.stdout)

    def test_sad_closing_the_pane_after_a_stuck_size_walk(self) -> None:
        self.check(_run("properties"))

    def test_sad_quitting_after_a_stuck_comparison(self) -> None:
        self.check(_run("compare"))

    def test_sad_quitting_after_a_stuck_capacity_probe(self) -> None:
        self.check(_run("disk"))

    def test_happy_the_handed_over_walk_finishes_and_is_freed(self) -> None:
        # The app keeps running until the walk is done: the thread ends and
        # nothing of it is left behind.
        after = textwrap.dedent(
            """
            import time
            from ui import thread_lifetime as TL
            end = time.time() + 5
            while TL._DETACHED and time.time() < end:
                app.processEvents()
                time.sleep(0.01)
            QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
            assert not TL._DETACHED, TL._DETACHED
            """
        ).replace("\\n", "\\n    ")
        self.check(_run("properties", after=after, stuck_for=0.5))

    def test_edge_a_walk_that_ends_in_time_is_not_handed_over(self) -> None:
        after = textwrap.dedent(
            """
            from ui import thread_lifetime as TL
            assert not TL._DETACHED
            """
        ).replace("\\n", "\\n    ")
        self.check(_run("properties", after=after, stuck_for=0.0))


if __name__ == "__main__":
    unittest.main()
