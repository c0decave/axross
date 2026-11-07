"""System Information: the window and the extension (ui/system_info_window.py,
resources/extensions/system_info.py).

Request: a system information extension that gathers everything about the
hardware it runs on and shows it in a window of its own, perfectly and
intuitively visualised.

The window opens from Extensions or Tools, gathers on a worker thread (the
GUI never waits for /sys), shows an overview dashboard and a page per area,
filters every page with one search field, copies and saves reports with the
identifiers hidden until *Show identifiers* is ticked, and samples live
values only while it is on screen.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtGui import QPalette  # noqa: E402
from PyQt6.QtWidgets import QApplication, QLabel, QMessageBox, QTreeWidget  # noqa: E402

from core import extensions as EX  # noqa: E402
from core import system_info as SI  # noqa: E402
from tests.markup_probe import shown  # noqa: E402
from tests.system_info_fixture import IDENTIFIERS, build_laptop, build_minimal, fake_usage  # noqa: E402
from ui import system_info_window as W  # noqa: E402

APP = QApplication.instance() or QApplication([])


def pump(until, timeout: float = 15.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        APP.processEvents()
        if until():
            return True
        time.sleep(0.01)
    APP.processEvents()
    return until()


class FakeSampler:
    """Live values without /proc: CPU use climbs by one each sample."""

    def __init__(self) -> None:
        self.calls = 0
        self.threads: set[str] = set()

    def sample(self) -> dict:
        self.calls += 1
        self.threads.add(threading.current_thread().name)
        return {"time": self.calls, "cpu": float(self.calls % 100),
                "per_cpu": [10.0] * 12,
                "memory": {"total": 32 * 1024**3, "used": 8 * 1024**3,
                           "available": 24 * 1024**3, "free": 4 * 1024**3},
                "swap": {"total": 0, "used": 0},
                "temperatures": [{"chip": "coretemp", "label": "Package id 0", "celsius": 71.0,
                                  "high": 100.0, "crit": 100.0}],
                "net": {"wlp0s20f3": {"rx": 2048.0, "tx": 1024.0}}}


@pytest.fixture
def laptop(tmp_path):
    return build_laptop(tmp_path / "root")


def info_of(root, **kwargs):
    def make():
        return SI.SystemInfo(root, usage=fake_usage, hostname="x1-carbon", system="Linux",
                             env={"XDG_CURRENT_DESKTOP": "GNOME"},
                             addresses=lambda: {"wlp0s20f3": [
                                 {"address": "192.168.178.42", "family": "ipv4"}]}, **kwargs)
    return make


@pytest.fixture
def make_window(laptop):
    made = []

    def make(root=None, *, show=True, sampler=None, **kwargs):
        sampler = sampler or FakeSampler()
        kwargs.setdefault("info_factory", info_of(root or laptop))
        win = W.SystemInfoWindow(None, sampler_factory=lambda: sampler, interval=0.02,
                                 **kwargs)
        win.sampler = sampler
        made.append(win)
        if show:
            win.resize(1100, 760)
            win.show()
        return win

    yield make
    for win in made:
        try:
            win.close()
            win.deleteLater()
        except RuntimeError:
            pass
    APP.processEvents()


def ready(win) -> bool:
    return pump(lambda: win.report is not None and win.refresh_button.isEnabled())


def visible_text(widget) -> str:
    """Every label and table cell in *widget* that is not hidden."""
    parts = []
    for label in widget.findChildren(QLabel):
        if label.isVisibleTo(widget):
            parts.append(label.text())
    for tree in widget.findChildren(QTreeWidget):
        for item in getattr(tree, "items", []):
            if not item.isHidden():
                parts.extend(item.text(c) for c in range(tree.columnCount()))
    return "\n".join(parts)


# --- happy ----------------------------------------------------------------


def test_happy_every_page_is_there_and_the_overview_has_its_tiles(make_window):
    win = make_window()
    assert ready(win)
    assert list(win.pages) == [p[0] for p in W.PAGES]
    assert win.nav.count() == len(W.PAGES)
    overview = win.pages["overview"]
    titles = [t.findChildren(QLabel)[1].text() for t in overview.grid.tiles]
    assert titles == ["CPU", "Memory", "Swap", "Storage", "Battery", "Temperatures",
                      "Graphics & Displays", "Network"]
    header = visible_text(overview.header)
    # The computer name is an identifier, shown with the others.
    assert "x1-carbon" not in header and "This computer" in header
    assert "Lenovo ThinkPad X1 Carbon Gen 11" in header
    win.show_ids.setChecked(True)
    assert "x1-carbon" in visible_text(win.pages["overview"].header)
    assert "Gathered at" in win.status.text()


def test_happy_gathering_runs_off_the_gui_thread(make_window, laptop):
    seen = {}
    release = threading.Event()

    class SlowInfo(SI.SystemInfo):
        def gather(self, progress=None, cancel=None, only=None):
            seen["thread"] = threading.current_thread()
            release.wait(10)
            return super().gather(progress, cancel, only)

    started = time.monotonic()
    win = make_window(info_factory=lambda: SlowInfo(laptop, usage=fake_usage, system="Linux"))
    built = time.monotonic() - started
    assert pump(lambda: "thread" in seen, 5)
    assert seen["thread"] is not threading.main_thread()
    assert seen["thread"].name == "axross-sysinfo-gather"
    # The window is up and answering while the gathering waits.
    assert win.report is None and "Gathering" in win.status.text()
    assert not win.refresh_button.isEnabled()
    release.set()
    assert ready(win)
    assert built < 5.0  # generous: the host is shared; the point is it did not wait


def test_happy_tiles_open_their_page(make_window):
    win = make_window()
    assert ready(win)
    storage = next(t for t in win.pages["overview"].grid.tiles if t.page == "storage")
    storage.clicked.emit()
    assert win.current_page_key() == "storage"
    assert win.stack.currentWidget() is win.pages["storage"]


def test_happy_search_filters_every_page_and_counts_hits(make_window):
    win = make_window()
    assert ready(win)
    win.search.setText("nvme")
    win.apply_filter()
    shown = {W.PAGES[r][0] for r in range(win.nav.count()) if not win.nav.item(r).isHidden()}
    assert shown == {"storage", "pci", "sensors"}
    assert win.current_page_key() == "storage"
    assert win.nav.item(3).text() == "Storage  (3)"
    text = visible_text(win.pages["storage"])
    assert "nvme0n1" in text and "SanDisk" not in text
    win.search.setText("")
    win.apply_filter()
    assert all(not win.nav.item(r).isHidden() for r in range(win.nav.count()))
    assert "SanDisk" in visible_text(win.pages["storage"])


def test_happy_a_word_in_a_section_title_shows_that_whole_section(make_window):
    win = make_window()
    assert ready(win)
    win.search.setText("battery")
    win.apply_filter()
    text = visible_text(win.pages["battery"])
    assert "AC" in text and "182" in text  # rows that do not say "battery" themselves


def test_happy_identifiers_are_hidden_until_shown(make_window):
    win = make_window()
    assert ready(win)
    everything = "\n".join(visible_text(p) for p in win.pages.values())
    for ident in IDENTIFIERS:
        assert ident not in everything, ident
    assert SI.HIDDEN in everything
    win.show_ids.setChecked(True)
    network = visible_text(win.pages["network"])
    assert "a4:c3:f0:12:34:56" in network and "192.168.178.42" in network
    assert "PF3XAMPL" in visible_text(win.pages["system"])


def test_happy_copy_section_copy_all_and_save(make_window, tmp_path, monkeypatch):
    win = make_window()
    assert ready(win)
    win.show_page("cpu")
    win.copy_section()
    section = QApplication.clipboard().text()
    assert "13th Gen Intel(R) Core(TM) i7-1365U" in section and "Samsung" not in section
    win.copy_all()
    everything = QApplication.clipboard().text()
    assert "Samsung SSD 990 PRO 1TB" in everything and "DELL U2720Q" in everything
    assert not any(ident in everything for ident in IDENTIFIERS)
    target = tmp_path / "report"
    monkeypatch.setattr(W.QFileDialog, "getSaveFileName",
                        lambda *a, **k: (str(target), "JSON (*.json)"))
    assert win.save_report()
    data = json.loads((tmp_path / "report.json").read_text())
    assert data["identifiers"] == "hidden"
    assert "PF3XAMPL" not in (tmp_path / "report.json").read_text()
    win.show_ids.setChecked(True)
    assert win.save_report(str(tmp_path / "full.txt"))
    assert "PF3XAMPL" in (tmp_path / "full.txt").read_text()
    assert "Saved the report" in win.status.text()


def test_happy_the_json_export_button_saves_and_copies_json(make_window, tmp_path, monkeypatch):
    """Feedback: JSON was a file type hidden in the save dialog - now a
    button of its own: a file, everything or the page shown to the clipboard."""
    win = make_window()
    assert ready(win)
    actions = [a.text() for a in win.json_button.menu().actions()]
    assert actions == ["Save as JSON File…", "Copy All as JSON", "Copy Section as JSON"]
    asked = {}

    def ask(_parent, _title, default, filters):
        asked.update(default=default, filters=filters)
        return str(tmp_path / "sysinfo"), "Text report (*.txt)"   # even with the text filter

    monkeypatch.setattr(W.QFileDialog, "getSaveFileName", ask)
    win.json_button.menu().actions()[0].trigger()
    assert asked["default"].endswith(".json") and asked["filters"].startswith("JSON")
    data = json.loads((tmp_path / "sysinfo.json").read_text())
    assert data["identifiers"] == "hidden" and len(data["sections"]) > 5
    assert "PF3XAMPL" not in (tmp_path / "sysinfo.json").read_text()
    win.json_button.menu().actions()[1].trigger()
    everything = json.loads(QApplication.clipboard().text())
    assert {s["key"] for s in everything["sections"]} == {s["key"] for s in data["sections"]}
    win.show_page("cpu")
    win.json_button.menu().actions()[2].trigger()
    page = json.loads(QApplication.clipboard().text())
    assert [s["key"] for s in page["sections"]] == win.page_section_keys("cpu")
    assert "as JSON" in win.status.text()
    win.show_ids.setChecked(True)
    win.copy_all_json()
    assert "PF3XAMPL" in QApplication.clipboard().text()
    assert json.loads(QApplication.clipboard().text())["identifiers"] == "shown"


def test_happy_live_values_flow_while_visible_and_stop_when_hidden(make_window):
    win = make_window()
    assert ready(win)
    assert win.live_running
    assert pump(lambda: len(win.history["cpu"]) >= 3)
    assert win.sampler.threads == {"axross-sysinfo-live"}  # never the GUI thread
    ring = win.pages["overview"].grid.tiles[0].findChild(W.RingGauge)
    assert pump(lambda: ring.value is not None and ring.value > 0)
    win.hide()
    assert not win.live_running
    APP.processEvents()
    calls = win.sampler.calls
    time.sleep(0.2)
    APP.processEvents()
    assert win.sampler.calls <= calls + 1  # at most the sample that was in flight


def test_happy_every_page_paints_in_light_and_dark(make_window):
    win = make_window()
    assert ready(win)
    for window_colour in ("#f4f5f8", "#15161b"):
        palette = QPalette(win.palette())
        palette.setColor(QPalette.ColorRole.Window, W.QColor(window_colour))
        palette.setColor(QPalette.ColorRole.Base, W.QColor(window_colour))
        palette.setColor(QPalette.ColorRole.Text, W.QColor(
            "#111111" if window_colour == "#f4f5f8" else "#eeeeee"))
        win.setPalette(palette)
        win.render()
        for key, *_rest in W.PAGES:
            win.show_page(key)
            image = win.grab().toImage()
            assert not image.isNull()
    assert W.is_dark(win.palette())


def test_happy_the_extension_adds_its_entry_and_closes_its_window(monkeypatch, laptop):
    path = EX.bundled_dir() / "system_info.py"
    spec = importlib.util.spec_from_file_location("example_system_info", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    made = []

    def fake_open(parent=None):
        win = W.SystemInfoWindow(parent, info_factory=info_of(laptop), live=False)
        win.show()
        made.append(win)
        return win

    monkeypatch.setattr(W, "open_window", fake_open)

    class Api:
        window = None
        actions: list = []

        def add_menu_action(self, label, callback, **_kw):
            self.actions.append((label, callback))

    api = Api()
    module.activate(api)
    [(label, callback)] = api.actions
    assert label == "System Information…"
    first = callback()
    assert callback() is first  # one window, brought to the front
    assert len(made) == 1 and first.isVisible()
    module.deactivate(api)
    assert not first.isVisible()
    assert module._WINDOW is None
    first.deleteLater()
    APP.processEvents()


# --- sad --------------------------------------------------------------------


def test_sad_a_failed_gathering_says_why(make_window):
    class Broken:
        def gather(self, **_kw):
            raise OSError("no /proc here")

    win = make_window(info_factory=Broken)
    assert pump(lambda: win.refresh_button.isEnabled())
    assert "no /proc here" in win.status.text()
    assert win.report is None
    win.copy_all()  # nothing to copy: no crash
    assert not win.save_report("/nonexistent/x.txt")


def test_sad_pages_without_a_source_are_dimmed_with_the_reason(make_window, tmp_path):
    win = make_window(build_minimal(tmp_path / "minimal"))
    assert ready(win)
    row = [p[0] for p in W.PAGES].index("pci")
    item = win.nav.item(row)
    assert shown(item.toolTip()).startswith("Not available")
    assert item.foreground().color() == W.muted(win)
    assert "Not available:" in visible_text(win.pages["pci"])
    assert "Not available" not in win.nav.item(1).toolTip()  # the CPU is there


def test_sad_a_save_that_fails_is_reported(make_window, tmp_path):
    win = make_window()
    assert ready(win)
    assert not win.save_report(str(tmp_path / "missing" / "dir" / "r.txt"))
    assert "Could not save" in win.status.text()


# --- edge -------------------------------------------------------------------


def test_edge_a_closed_window_drops_the_late_result(laptop):
    release = threading.Event()

    class Slow(SI.SystemInfo):
        def gather(self, progress=None, cancel=None, only=None):
            release.wait(10)
            return super().gather(progress, None, only)

    win = W.SystemInfoWindow(None, info_factory=lambda: Slow(laptop, system="Linux",
                                                              usage=fake_usage), live=False)
    thread = win.gather_thread
    win.close()
    win.deleteLater()
    APP.processEvents()
    release.set()
    thread.join(10)
    for _ in range(20):
        APP.processEvents()  # the result arrives for a deleted window: dropped, no crash


def test_edge_a_refresh_ignores_the_previous_gathering(make_window):
    win = make_window(show=False)
    assert ready(win)
    report = win.report
    generation = win._generation
    win._on_gathered(generation - 1, {"sections": []}, "")
    assert win.report is report  # stale: ignored
    win.refresh()
    assert ready(win)
    assert win._generation == generation + 1 and win.report is not report


def test_edge_escape_clears_the_search_first(make_window):
    from PyQt6.QtCore import QEvent, Qt
    from PyQt6.QtGui import QKeyEvent

    win = make_window()
    assert ready(win)
    win.search.setText("cpu")
    win.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Escape,
                                Qt.KeyboardModifier.NoModifier))
    assert win.search.text() == "" and win.isVisible()


@pytest.fixture
def german(tmp_path):
    """A German catalogue with a few of the window's strings, active for
    the test, English again afterwards."""
    from core import i18n

    folder = tmp_path / "i18n"
    folder.mkdir()
    (folder / "de.json").write_text(json.dumps({
        "System Information": "Systeminformationen",
        "Refresh": "Aktualisieren",
        "Show identifiers": "Kennungen zeigen",
        "Memory": "Arbeitsspeicher",
        "Open {title}": "{title} öffnen",
        "Copied {page} to the clipboard": "{page} in die Zwischenablage kopiert",
        "Could not save the report to {path}: {reason}":
            "Der Bericht konnte nicht nach {path} gespeichert werden: {reason}",
    }), encoding="utf-8")
    previous = i18n.active()
    i18n.install("de", folder)
    yield
    i18n._ACTIVE = previous


def test_happy_the_window_speaks_the_chosen_language(german, make_window, tmp_path):
    """The window, its buttons, its page list and its tiles are passed
    through tr() like the rest of axross (they stayed English in German)."""
    win = make_window()
    assert ready(win)
    assert win.windowTitle() == "Systeminformationen"
    assert win.refresh_button.text() == "Aktualisieren"
    assert win.show_ids.text() == "Kennungen zeigen"
    row = [p[0] for p in W.PAGES].index("memory")
    assert win.nav.item(row).text() == "Arbeitsspeicher"
    tiles = win.pages["overview"].findChildren(W.Tile)
    assert any(t.toolTip() == "Arbeitsspeicher öffnen" for t in tiles)
    win.show_page("memory")
    win.copy_section()
    assert win.status.text() == "Arbeitsspeicher in die Zwischenablage kopiert"
    win.search.setText("memory")
    win.apply_filter()
    assert win.nav.item(row).text().startswith("Arbeitsspeicher  (")
    assert not win.save_report(str(tmp_path / "missing" / "r.txt"))
    assert win.status.text().startswith("Der Bericht konnte nicht nach")


def test_sad_errors_are_sentences_not_exception_reprs(make_window, tmp_path):
    """A failed gathering shows the reason without the exception class; a
    failed save names the file and the reason without "[Errno 2]"."""
    class Broken:
        def gather(self, **_kw):
            raise OSError("no /proc here")

    broken = make_window(info_factory=Broken)
    assert pump(lambda: broken.refresh_button.isEnabled())
    assert broken.status.text() == "Could not gather the system information: no /proc here"

    win = make_window()
    assert ready(win)
    target = tmp_path / "missing" / "r.txt"
    assert not win.save_report(str(target))
    text = win.status.text()
    assert text == f"Could not save the report to {target}: No such file or directory"
    assert "Errno" not in text and "OSError" not in text


def test_edge_temperature_names_and_colours():
    assert W.temp_name({"chip": "coretemp", "label": "Package id 0"}) == "CPU package"
    assert W.temp_name({"chip": "nvme", "label": "Composite"}) == "NVMe"
    assert W.temp_name({"chip": "k10temp", "label": "Tctl"}) == "CPU package"
    assert W.temp_name({"chip": "thermal zone", "label": "acpitz"}) == "ACPI zone"
    assert W.temp_colour(45).name() == W.QColor(W.GOOD).name()
    assert W.temp_colour(70).name() == W.QColor(W.WARNING).name()
    assert W.temp_colour(85).name() == W.QColor(W.SERIOUS).name()
    assert W.temp_colour(85, high=100).name() == W.QColor(W.WARNING).name()  # its own mark
    assert W.temp_colour(76, high=75).name() == W.QColor(W.SERIOUS).name()
    assert W.temp_colour(92).name() == W.QColor(W.CRITICAL).name()
    assert W.level_colour(None).name() == "#888888"


# --- end to end ---------------------------------------------------------------


def test_e2e_tools_menu_switches_the_extension_on_and_opens_the_window(monkeypatch):
    from ui.main_window import MainWindow

    info = next(e for e in EX.discover() if e.module_name == "system_info")
    EX.set_enabled(info.ext_id, False)
    monkeypatch.setattr(QMessageBox, "question",
                        lambda *a, **k: QMessageBox.StandardButton.Yes)
    win = MainWindow()
    try:
        win._reconnect_timer.stop()
        win._system_info_action.trigger()
        host = win.extension_host
        assert host.error(info.ext_id) == ""
        module = host.module(info.ext_id)
        assert module is not None
        window = module._WINDOW
        assert isinstance(window, W.SystemInfoWindow) and window.isVisible()
        assert window.parent() is win
        assert pump(lambda: window.report is not None, 30)
        cpu = next(s for s in window.report["sections"] if s["key"] == "cpu")
        assert cpu["available"]
        entries = [a.text() for a in win.extensions_menu.actions()]
        assert "System Information…" in entries
        win._system_info_action.trigger()  # again: the same window
        assert module._WINDOW is window
        window.close()
    finally:
        EX.set_enabled(info.ext_id, False)
        win.close()
        win.deleteLater()
        APP.processEvents()


# --- found by the review of 2026-11-06 -----------------------------------------


def test_happy_the_overview_sparklines_draw_the_live_values(make_window):
    """Only the CPU and Memory pages redrew their graphs: the Overview's
    stayed on "collecting…" until something else repainted them."""
    from PyQt6.QtCore import QEvent, QObject

    win = make_window()
    assert ready(win)
    win.show_page("overview")
    sparks = win.pages["overview"].findChildren(W.Sparkline)
    assert len(sparks) >= 2
    painted = {id(s): 0 for s in sparks}

    class Count(QObject):
        def eventFilter(self, obj, event):  # noqa: N802
            if event.type() == QEvent.Type.Paint:
                painted[id(obj)] += 1
            return False

    counter = Count()
    for s in sparks:
        s.installEventFilter(counter)
    APP.processEvents()
    before = dict(painted)
    assert pump(lambda: all(painted[k] > before[k] for k in painted))


def test_sad_the_default_file_name_hides_the_computer_name(make_window, monkeypatch):
    win = make_window()
    assert ready(win)
    asked = []
    monkeypatch.setattr(W.QFileDialog, "getSaveFileName",
                        lambda _p, _t, default, _f: (asked.append(default), ("", ""))[1])
    win.save_report()
    assert "x1-carbon" not in asked[-1] and "system-info-" in asked[-1]
    win.show_ids.setChecked(True)
    win.save_report(as_json=True)
    assert "system-info-x1-carbon-" in asked[-1] and asked[-1].endswith(".json")


def test_edge_two_sensors_of_the_same_name_keep_a_bar_each():
    temps = [{"chip": "nvme", "label": "Composite", "celsius": 41.0, "high": None, "crit": None},
             {"chip": "nvme", "label": "Composite", "celsius": 55.0, "high": None, "crit": None}]
    live: list = []
    box = W.sensors_extra({"data": {"temperatures": temps, "fans": []}}, live)
    bars = box.findChildren(W.UsageBar)
    assert len(bars) == 2
    assert [b.value_text for b in bars] == [SI.celsius(41.0), SI.celsius(55.0)]
    live[0]({"temperatures": [dict(temps[0], celsius=43.0), dict(temps[1], celsius=57.0)]})
    assert [b.value_text for b in bars] == [SI.celsius(43.0), SI.celsius(57.0)]


def test_edge_cpu_bars_are_named_by_their_cpu_when_some_are_offline():
    bars = W.CoreBars()
    bars.set_values([None, None], {0: "P-core", 2: "E-core"}, [0, 2])
    bars.set_values([50.0, 10.0], ids=[0, 2])
    assert bars.ids == [0, 2]
    assert bars.toolTip().splitlines() == ["CPU 0 (P-core): 50 %", "CPU 2 (E-core): 10 %"]
