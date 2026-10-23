"""Real drags into and inside the Media Player's playlist, run by
tests/test_media_player_controls.py::test_e2e_real_drags_under_xvfb under
``xvfb-run`` with the xcb platform (the offscreen platform runs no drag).

Prints ``REORDER OK`` and ``PANE DROP OK``; exits non-zero on a failure.
Usage: media_player_drag_check.py <scratch folder>
"""

from __future__ import annotations

import importlib.util
import sys
import time
import wave
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from PyQt6.QtCore import QPoint, Qt, QTimer  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

APP = QApplication.instance() or QApplication([])


def load():
    spec = importlib.util.spec_from_file_location(
        "media_player_drag_check_module", ROOT / "resources" / "extensions" / "media_player.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


MP = load()


def pump(seconds: float) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.005)


def silent_wav(path: Path) -> Path:
    with wave.open(str(path), "wb") as w:
        w.setnchannels(2)
        w.setsampwidth(2)
        w.setframerate(44100)
        w.writeframes(bytes(4 * 4410))
    return path


def drag(source_window, start: QPoint, target_window, end: QPoint, begin) -> None:
    """Press at *start* in *source_window*, let *begin()* start the drag
    (it blocks in QDrag.exec), and move to and release at *end* in
    *target_window* from a timer inside that loop."""

    def finish() -> None:
        QTest.mouseMove(target_window, end - QPoint(0, 6))
        pump(0.1)
        QTest.mouseMove(target_window, end)
        pump(0.1)
        QTest.mouseRelease(target_window, Qt.MouseButton.LeftButton,
                           Qt.KeyboardModifier.NoModifier, end)

    QTimer.singleShot(300, finish)
    begin()
    pump(0.3)


class StalledSink(MP.MemorySink):
    """Takes nothing: the playing track stays the playing one (these
    short files would otherwise end and move on during the drag)."""

    def bytes_free(self) -> int:
        return 0


def check_reorder(folder: Path) -> None:
    panel = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: StalledSink()))
    panel.setGeometry(50, 50, 500, 700)
    panel.show()
    QTest.qWaitForWindowExposed(panel)
    paths = [silent_wav(folder / f"t{i}.wav") for i in range(4)]
    panel.add_files([str(p) for p in paths])
    panel.playlist.setCurrentRow(0)
    panel.play_selected()
    pump(0.3)  # mapped and placed by the X server before the first press
    lst = panel.playlist
    vp = lst.viewport()
    win = panel.windowHandle()
    first = vp.mapTo(panel, lst.visualItemRect(lst.item(0)).center())
    last = vp.mapTo(panel, lst.visualItemRect(lst.item(3)).bottomLeft() + QPoint(8, -2))

    def begin() -> None:
        QTest.mousePress(win, Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier, first)
        QTest.mouseMove(win, first + QPoint(0, 20))
        QTest.mouseMove(win, first + QPoint(0, 40))

    drag(win, first, win, last, begin)
    order = [lst.item(i).text() for i in range(lst.count())]
    assert order == ["t1.wav", "t2.wav", "t3.wav", "t0.wav"], order
    assert panel.current_row() == 3, panel.current_row()
    assert lst.item(3).font().bold()
    print("REORDER OK", flush=True)
    panel.engine.stop()
    panel.close()


def check_pane_drop(folder: Path) -> None:
    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    music = folder / "music"
    music.mkdir()
    silent_wav(music / "dragged.wav")
    (music / "readme.txt").write_text("not audio", encoding="utf-8")
    pane = FilePaneWidget(LocalFS())
    pane.setGeometry(0, 0, 600, 500)
    pane.show()
    QTest.qWaitForWindowExposed(pane)
    pane.navigate(str(music))
    pump(0.5)
    pane._table.selectAll()
    panel = MP.PlayerPanel(engine=MP.EqEngine(sink_factory=lambda fmt: MP.MemorySink()))
    panel.setGeometry(700, 0, 450, 700)
    panel.show()
    QTest.qWaitForWindowExposed(panel)
    pump(0.3)
    target = panel.playlist.viewport().mapTo(panel, panel.playlist.viewport().rect().center())
    table_vp = pane._table.viewport()
    start = table_vp.mapTo(pane, QPoint(20, 10))

    def begin() -> None:
        pane._start_drag()  # what dragging the selection starts; blocks in exec

    drag(pane.windowHandle(), start, panel.windowHandle(), target, begin)
    end = time.time() + 5
    while panel.playlist.count() < 1 and time.time() < end:
        pump(0.05)
    names = [panel.playlist.item(i).text() for i in range(panel.playlist.count())]
    assert names == ["dragged.wav"], names
    assert "not audio" in panel.note.text(), panel.note.text()
    print("PANE DROP OK", flush=True)
    panel.close()
    pane.close()


def main() -> int:
    folder = Path(sys.argv[1])
    folder.mkdir(parents=True, exist_ok=True)
    check_reorder(folder)
    check_pane_drop(folder)
    return 0


if __name__ == "__main__":
    sys.exit(main())
