"""A held arrow key turns pictures at most three times a second.

The hard rule for every visual of axross: at most three flashes a second.
Holding Right in the image or the media viewer stepped through a folder at
the keyboard's repeat rate (25-33 a second) - a dark picture followed by a
light one is a flash each time. Key repeats are paced now (a step at most
every HELD_STEP_SECONDS); single presses stay immediate.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QEvent, Qt  # noqa: E402
from PyQt6.QtGui import QKeyEvent  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.local_fs import LocalFS  # noqa: E402
from core.media_collect import IMAGE, MediaItem  # noqa: E402
from tests.media_testkit import write_image  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _pump(seconds: float) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.005)


def _hold(widget, key, seconds: float = 1.2, every: float = 0.03) -> None:
    """Auto-repeated presses of *key* sent to *widget* for *seconds*."""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        QApplication.sendEvent(widget, QKeyEvent(QEvent.Type.KeyPress, key,
                                                 Qt.KeyboardModifier.NoModifier, "", True))
        _pump(every)


def _pictures(tmp_path, n: int = 40) -> list[str]:
    return [str(write_image(tmp_path / f"p{i:02}.png", size=(8, 8),
                            color=(0, 0, 0) if i % 2 else (255, 255, 255)))
            for i in range(n)]


def test_sad_holding_right_in_the_media_viewer_turns_at_most_three_a_second(tmp_path):
    from ui import media_viewer as MV
    from ui import viewer_window as VW

    paths = _pictures(tmp_path)
    items = [MediaItem(path=p, name=Path(p).name, kind=IMAGE, size=1, mtime=0.0, folder="")
             for p in paths]
    viewer = MV.MediaViewer(LocalFS())
    viewer.resize(400, 300)
    viewer.show()
    viewer.set_items(items, 0)
    try:
        changes = []
        viewer.index_changed.connect(lambda i: changes.append(time.monotonic()))
        _hold(viewer, Qt.Key.Key_Right, 1.2)
        _pump(0.5)
        assert changes, "a held key still turns pictures"
        for i, at in enumerate(changes):
            within = [t for t in changes[i:] if t - at < 1.0]
            assert len(within) <= 3, f"{len(within)} pictures in a second"
        assert VW.HELD_STEP_SECONDS >= 1 / 3
        # a single press is immediate
        before = viewer.current_index
        QApplication.sendEvent(viewer, QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Left,
                                                 Qt.KeyboardModifier.NoModifier))
        assert viewer.current_index == before - 1
    finally:
        viewer.shutdown()


def test_sad_holding_right_in_the_image_viewer_turns_at_most_three_a_second(tmp_path):
    from ui.image_viewer import ImageViewerDialog

    paths = _pictures(tmp_path)
    dlg = ImageViewerDialog(LocalFS(), paths[0], siblings=paths)
    dlg.show()
    try:
        shown = []
        real = dlg._load_current

        def load():
            shown.append(time.monotonic())
            real()

        dlg._load_current = load
        focus = dlg.focusWidget() or dlg._scroll
        _hold(focus, Qt.Key.Key_Right, 1.2)
        _pump(0.5)
        assert shown
        for i, at in enumerate(shown):
            within = [t for t in shown[i:] if t - at < 1.0]
            assert len(within) <= 3, f"{len(within)} pictures in a second"
    finally:
        dlg.close()
