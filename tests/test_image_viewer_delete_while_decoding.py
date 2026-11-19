"""Del in the image viewer hits the picture on screen, not the next one
still being decoded.

Review: Next set the viewer's index at once and decoded the picture off the
GUI thread meanwhile; Del pressed in that time asked about and deleted the
next file - one the user had not seen yet - while the old picture was still
on screen. A drag out of the viewer took the same wrong file.
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import QTimer  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import previews as P  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from tests.media_testkit import write_image  # noqa: E402

APP = QApplication.instance() or QApplication([])


def test_sad_del_during_the_next_decode_deletes_the_shown_picture(tmp_path, monkeypatch):
    from ui import viewer_file_actions as VFA
    from ui.image_viewer import ImageViewerDialog

    first = str(write_image(tmp_path / "a.png"))
    second = str(write_image(tmp_path / "b.png"))
    third = str(write_image(tmp_path / "c.png"))
    gate = threading.Event()
    real = P.decode_image

    def slow_decode(backend, path, *args, **kwargs):
        if path == second:
            gate.wait(10)
        return real(backend, path, *args, **kwargs)

    monkeypatch.setattr(P, "decode_image", slow_decode)
    deleted = []

    def delete_file(_parent, _backend, path, _pane, permanent=False):
        deleted.append(path)
        return True

    monkeypatch.setattr(VFA, "delete_file", delete_file)
    dlg = ImageViewerDialog(LocalFS(), first, siblings=[first, second, third])
    try:
        assert dlg.loaded and dlg.current_path() == first
        dragged = []

        def during_decode():
            dragged.append(dlg.current_path())
            dlg.delete_current()
            gate.set()

        QTimer.singleShot(200, during_decode)
        dlg._next()  # waits for the decode of b.png, the window live
        assert dragged == [first]
        assert deleted == [first]
        assert dlg._siblings == [second, third]
        assert dlg.current_path() == second and dlg._original is not None
    finally:
        gate.set()
        dlg.close()
