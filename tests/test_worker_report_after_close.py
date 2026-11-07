"""Settings pages whose background work reports after the page is gone.

Edit > Settings… is deleted as soon as it closes (MainWindow.open_settings:
``dialog.deleteLater()`` after ``exec()``). A Clear Cache, a voice download
or an MCP server test still running then reports to a deleted page. They
emitted a signal of the page from the worker thread - a use-after-free when
the deletion and the emit meet (core/thread_relay.py). Now they report through
a GuiCall: the report is dropped, nothing crashes, and what does not belong
to the page (the dock's session results) is still done.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6 import sip  # noqa: E402
from PyQt6.QtCore import QObject  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402

from core import analysis_settings as AS  # noqa: E402
from core import mcp_client as C  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(seconds: float = 0.3) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        APP.processEvents()
        time.sleep(0.01)


class FakeWindow(QObject):
    def __init__(self) -> None:
        super().__init__()
        self.cleared = 0

    def clear_analysis_session(self) -> None:
        self.cleared += 1


def test_sad_clear_cache_finishing_after_the_page_is_gone_still_forgets_the_session(
    tmp_path, monkeypatch
):
    from ui.analysis_settings_page import AnalysisPage

    gate, finished = threading.Event(), threading.Event()

    def slow_clear(folder):
        gate.wait(5)
        finished.set()
        return 3

    monkeypatch.setattr(AS, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(AS, "clear_cache", slow_clear)
    window = FakeWindow()
    page = AnalysisPage(window=window, path=tmp_path / "analysis.json")
    page.clear_cache()
    sip.delete(page)
    gate.set()
    assert finished.wait(5)
    pump()
    assert window.cleared == 1  # the dock's results are forgotten all the same


def test_happy_clear_cache_reports_on_the_page(tmp_path, monkeypatch):
    from ui.analysis_settings_page import AnalysisPage

    monkeypatch.setattr(AS, "cache_dir", lambda: tmp_path)
    monkeypatch.setattr(AS, "clear_cache", lambda folder: 2)
    window = FakeWindow()
    page = AnalysisPage(window=window, path=tmp_path / "analysis.json")
    page.clear_cache()
    end = time.monotonic() + 5
    while "Removed" not in page.cache_label.text() and time.monotonic() < end:
        pump(0.05)
    assert "Removed 2" in page.cache_label.text()
    assert window.cleared == 1


def test_sad_a_voice_download_ending_after_the_page_is_gone_is_dropped():
    from tests.test_voice_settings_page import _tuned_page

    gate, ended = threading.Event(), threading.Event()

    def downloader(model, progress, cancel):
        gate.wait(5)
        progress(1, 2)
        ended.set()
        return None

    page = _tuned_page(downloader=downloader)
    page._toggle_download("de")
    sip.delete(page)
    gate.set()
    assert ended.wait(5)
    pump()  # the progress and finished calls arrive for a deleted page: dropped


def test_sad_an_mcp_server_test_ending_after_settings_closed_is_dropped(tmp_path, monkeypatch):
    from tests.test_agent_settings_dialog import _dialog

    gate, ended = threading.Event(), threading.Event()

    class SlowClient:
        def __init__(self, *a, **kw):
            gate.wait(5)

        def tools(self):
            return []

        def close(self):
            ended.set()

    monkeypatch.setattr(C, "McpClient", SlowClient)
    dlg = _dialog(tmp_path / "settings.json")
    dlg.add_server()
    dlg.server_name_edit.setText("slow")
    dlg.server_command_edit.setText(f"{sys.executable} -c pass")
    dlg.test_server()
    sip.delete(dlg)
    gate.set()
    assert ended.wait(5)
    pump()


def test_sad_a_watch_report_for_a_deleted_pane_is_dropped(tmp_path):
    """The pane's watcher thread reported through a signal of the pane. A pane
    deleted with its window, without shutdown(), could be deleted while the
    thread emitted. The report now goes through a GuiCall: for a deleted pane
    it is dropped."""
    from core.local_fs import LocalFS
    from core.thread_relay import GuiCall
    from ui.file_pane import FilePaneWidget

    pane = FilePaneWidget(LocalFS())
    pane.navigate(str(tmp_path))
    assert isinstance(pane._watch_call, GuiCall)
    seen = []
    pane._on_watch_event_signal = lambda: seen.append(1)
    report = pane._watch_call
    worker = threading.Thread(target=report)
    worker.start()
    worker.join()
    pump(0.2)
    assert seen == [1]  # delivered while the pane lives
    sip.delete(pane)
    worker = threading.Thread(target=report)
    worker.start()
    worker.join()
    pump(0.2)
    assert seen == [1]  # dropped once it is gone


def test_sad_a_log_record_from_a_worker_after_the_log_bridge_is_gone_is_dropped():
    """Every thread that logs woke the Log dock with an emit on its bridge.
    At quit the bridge goes with the window while workers still log: the
    wake-up now goes through a GuiCall and is dropped once it is gone."""
    from ui.log_dock import _LogSignalBridge

    bridge = _LogSignalBridge()
    woke = []
    bridge.wake.connect(lambda: woke.append(1))
    worker = threading.Thread(target=bridge.push, args=("first", 20, ""))
    worker.start()
    worker.join()
    pump(0.2)
    assert woke == [1]
    assert bridge.take() == ([("first", 20, "")], 0)
    sip.delete(bridge)
    worker = threading.Thread(target=bridge.push, args=("late", 20, ""))
    worker.start()
    worker.join()
    pump(0.2)
    assert woke == [1]
