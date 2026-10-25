"""sift gets an identity and start points in axross.

Operator report (2026-10-25): sift support seemed to be missing - no icon of
its own and no start entry. Measured on 0.13.133: the Analysis dock (sift)
showed the Agent's robot ("bot") in its title bar, its name said "Analysis"
only (the toolbar tooltip was the one place that named sift), and the only
way in was the dock toggle - no "Analyse with sift" on a file. The slim build
(no sift) said "not installed in this Python environment", not where sift is.

Now: a sieve icon of its own ("sift"; the toolbar id "analysis" draws it),
"Analysis (sift)" in the title bar, the Panels menu and the tooltip, "Analyse
with sift" / "Analyse Folder with sift" in the file pane's right-click menu
(so in the Actions menu too) and Tools > "Analyse with sift"; without sift
every entry shows where sift comes from.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtCore import QItemSelectionModel  # noqa: E402
from PyQt6.QtGui import QAction, QImage, QKeySequence  # noqa: E402
from PyQt6.QtWidgets import QLabel, QToolBar  # noqa: E402

from core.file_analysis import AnalysisResult  # noqa: E402
from tests.settings_testkit import app, isolate  # noqa: E402
from ui import icon_provider as IP  # noqa: E402

APP = app()
#: Fewer painted pixels than this at 22 px is no icon a user can see.
MIN_PAINTED = 40
#: Longer than the window's selection debounce (200 ms): a late automatic
#: run would have come by then.
PAST_DEBOUNCE = 0.5


def pump(seconds: float = 0.05) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        time.sleep(0.01)


def wait_for(cond, seconds: float = 10.0) -> None:
    end = time.time() + seconds
    while time.time() < end:
        APP.processEvents()
        if cond():
            return
        time.sleep(0.01)
    raise AssertionError("condition not reached")


def _image(icon, size: int = 22) -> QImage:
    return icon.pixmap(size, size).toImage().convertToFormat(QImage.Format.Format_ARGB32)


def _painted(image: QImage) -> int:
    return sum(1 for x in range(image.width()) for y in range(image.height())
               if image.pixelColor(x, y).alpha() > 0)


def _plain(text: str) -> str:
    return text.replace("&&", "\0").replace("&", "").replace("\0", "&")


class _FakeAnalyzer:
    """Answers at once, records what it was asked."""

    def __init__(self) -> None:
        self.asked: list[str] = []

    def analyse(self, target, force=False, llm=None, on_event=None, cancel=None, options=None):
        self.asked.append(target.path)
        return AnalysisResult(True, summary={"filename": target.name,
                                             "summary": f"about {target.name}"})

    def cached(self, target, llm=None, options=None):
        return None

    def close(self):
        pass


@pytest.fixture
def stores(tmp_path, monkeypatch):
    s = isolate(tmp_path, monkeypatch)
    yield s
    s.close_windows()
    s.restore()


@pytest.fixture
def folder(tmp_path):
    data = tmp_path / "data"
    data.mkdir()
    (data / "notes.txt").write_text("hello from notes\n")
    (data / "more.txt").write_text("more\n")
    (data / "sub").mkdir()
    (data / "sub" / "inner.txt").write_text("inner\n")
    return data


def _window(stores, folder):
    win = stores.make_window()
    win.show()
    win.activateWindow()
    win._active_pane.navigate(str(folder))
    pump()
    return win


@pytest.fixture
def win(stores, folder):
    return _window(stores, folder)


@pytest.fixture
def fake(win):
    analyzer = _FakeAnalyzer()
    win._analysis_dock._auto._factory = lambda: analyzer
    return analyzer


@pytest.fixture
def slim(monkeypatch):
    """sift is not there, as in axross-slim: it cannot be imported."""
    monkeypatch.setitem(sys.modules, "sift", None)
    from core.analysis_worker import sift_available

    assert sift_available() is False


def _select(pane, names) -> None:
    proxy = pane._table.model()
    sel = pane._table.selectionModel()
    sel.clearSelection()
    for row in range(proxy.rowCount()):
        if proxy.index(row, 0).data() in names:
            sel.select(proxy.index(row, 0),
                       QItemSelectionModel.SelectionFlag.Select
                       | QItemSelectionModel.SelectionFlag.Rows)
    pump()


def _commands(pane) -> dict[str, QAction]:
    menu = pane._build_context_menu()
    pane._kept_menu = menu  # the actions live as long as their menu
    return {str(a.property("axCommand")): a for a in menu.actions() if a.property("axCommand")}


def _tool_button(win, icon_name: str) -> QAction:
    return next(a for bar in win.findChildren(QToolBar) if bar.windowTitle() in ("Main", "Tools")
                for a in bar.actions() if a.property("axIcon") == icon_name)


def _title_icon(dock) -> QImage:
    label = dock.titleBarWidget().findChildren(QLabel)[0]
    return label.pixmap().toImage().convertToFormat(QImage.Format.Format_ARGB32)


def _tools_entry(win) -> QAction:
    tools = next(a.menu() for a in win.menuBar().actions() if _plain(a.text()) == "Tools")
    return next(a for a in tools.actions() if _plain(a.text()) == "Analyse with sift")


# --- the icon ----------------------------------------------------------------


def test_happy_sift_has_an_icon_of_its_own() -> None:
    svg = IP.ICONS["sift"]
    assert 'viewBox="0 0 24 24"' in svg and 'stroke="currentColor"' in svg
    assert svg != IP.ICONS["bot"] and svg != IP.ICONS["agent"]
    # The toolbar's id "analysis" stays (a saved toolbar order names it); it draws sift.
    assert IP.ICONS["analysis"] == svg
    assert IP._ICON_COLORS.get("sift") and IP._ICON_COLORS.get("analysis")
    assert _painted(_image(IP.icon("sift"))) >= MIN_PAINTED


def test_happy_the_rendered_sift_icon_differs_from_the_agents_robot() -> None:
    assert _image(IP.icon("analysis")) != _image(IP.icon("agent"))
    assert _image(IP.icon("sift")) != _image(IP.icon("bot"))


def test_edge_monochrome_still_tells_sift_from_the_robot() -> None:
    IP.set_monochrome(True)
    try:
        assert _image(IP.icon("analysis")) != _image(IP.icon("agent"))
        assert _painted(_image(IP.icon("analysis"))) >= MIN_PAINTED
    finally:
        IP.set_monochrome(False)


def test_sad_the_sift_icon_is_no_placeholder() -> None:
    assert IP.has_icon("sift") and "sift" in IP.available_icons()
    assert _image(IP.icon("sift")) != _image(IP.icon("no-such-icon-at-all"))


def test_happy_e2e_title_bar_toolbar_and_menu_show_the_sift_icon(win) -> None:
    analysis, agent = win._analysis_dock, win._agent_dock
    assert _title_icon(analysis) != _title_icon(agent)
    assert _title_icon(analysis) == _image(IP.icon("analysis", 18), 18)
    button = _tool_button(win, "analysis")
    assert button is analysis.toggleViewAction()
    assert _image(button.icon()) != _image(_tool_button(win, "agent").icon())
    # The Panels menu shows the same action, so the same icon.
    panels = win._dock_view_menu
    assert button in panels.actions() and not button.icon().isNull()


def test_edge_e2e_a_monochrome_switch_redraws_the_sift_title_icon(win) -> None:
    dock = win._analysis_dock
    colourful = _title_icon(dock)
    try:
        win.set_monochrome_icons(True, store=False)
        pump()
        assert _title_icon(dock) != colourful
        assert _title_icon(dock) == _image(IP.icon("analysis", 18), 18)
        assert dock.titleBarWidget().findChildren(QLabel)[1].text() == "Analysis (sift)"
        tools_entry = _tools_entry(win)
        assert _image(tools_entry.icon()) == _image(IP.icon("analysis"))
    finally:
        win.set_monochrome_icons(False, store=False)


# --- the name ----------------------------------------------------------------


def test_happy_e2e_the_dock_menu_and_tooltip_say_sift(win) -> None:
    dock = win._analysis_dock
    assert dock.windowTitle() == "Analysis (sift)"
    title = dock.titleBarWidget().findChildren(QLabel)[1]
    assert title.text() == "Analysis (sift)"
    toggle = dock.toggleViewAction()
    assert _plain(toggle.text()) == "Analysis (sift)"
    assert "Analysis (sift)" in toggle.toolTip() and "Ctrl+Shift+I" in toggle.toolTip()
    owners = [a for a in win.findChildren(QAction) if QKeySequence("Ctrl+Shift+I") in a.shortcuts()]
    assert owners == [toggle]


def test_edge_the_names_go_through_the_translation(stores, folder, monkeypatch) -> None:
    from core import i18n

    german = i18n.Translator(i18n.DEFAULT_LANGUAGE)
    german._entries = {
        "Analysis (sift)": "Analyse (sift)",
        "&Analysis (sift)": "&Analyse (sift)",
        "Analyse with sift": "Mit sift analysieren",
        "Analyse with &sift": "Mit &sift analysieren",
    }
    monkeypatch.setattr(i18n, "_ACTIVE", german)
    win = _window(stores, folder)
    dock = win._analysis_dock
    assert dock.windowTitle() == "Analyse (sift)"
    assert dock.titleBarWidget().findChildren(QLabel)[1].text() == "Analyse (sift)"
    assert _plain(dock.toggleViewAction().text()) == "Analyse (sift)"
    assert dock.toggleViewAction().toolTip().startswith("Analyse (sift)")
    _select(win._active_pane, ["notes.txt"])
    assert _plain(_commands(win._active_pane)["analyse-sift"].text()) == "Mit sift analysieren"


# --- right-click: a file -------------------------------------------------------


def test_happy_e2e_analyse_with_sift_opens_the_dock_and_analyses_the_file(win, fake,
                                                                          folder) -> None:
    pane, dock = win._active_pane, win._analysis_dock
    assert not dock.isVisible()
    _select(pane, ["notes.txt"])
    entry = _commands(pane)["analyse-sift"]
    assert _plain(entry.text()) == "Analyse with sift"
    assert entry.property("axIcon") == "analysis" and not entry.icon().isNull()
    entry.trigger()
    wait_for(lambda: "about notes.txt" in dock.body.toPlainText())
    assert dock.isVisible()
    assert fake.asked == [str(folder / "notes.txt")]
    assert dock.title.text() == "notes.txt"
    pump(PAST_DEBOUNCE)
    assert fake.asked == [str(folder / "notes.txt")]  # the dock's own follow-up asked nothing new


@pytest.mark.skipif(
    not __import__("core.analysis_worker", fromlist=["x"]).sift_available(),
    reason="sift is not installed")
def test_happy_e2e_real_sift_explains_the_file_from_the_right_click(win, folder) -> None:
    pane, dock = win._active_pane, win._analysis_dock
    _select(pane, ["notes.txt"])
    _commands(pane)["analyse-sift"].trigger()
    wait_for(lambda: "Explained by sift" in dock.body.toPlainText()
             or "Analysis failed" in dock.body.toPlainText(), 60)
    assert "Explained by sift without an LLM" in dock.body.toPlainText(), dock.body.toPlainText()


def test_happy_e2e_several_files_are_offered_as_one_batch(win, fake) -> None:
    pane, dock = win._active_pane, win._analysis_dock
    _select(pane, ["notes.txt", "more.txt"])
    _commands(pane)["analyse-sift"].trigger()
    pump(PAST_DEBOUNCE)
    assert dock.isVisible()
    assert dock.batch_button.isVisible()
    assert dock.batch_button.text() == "Analyse 2 file(s) with LLM"
    assert fake.asked == []  # a batch waits for the click: it goes to the model


def test_happy_e2e_the_actions_menu_offers_it_too(win) -> None:
    pane = win._active_pane
    _select(pane, ["notes.txt"])
    win.actions_menu.aboutToShow.emit()
    commands = [a.property("axCommand") for a in win.actions_menu.actions()]
    assert "analyse-sift" in commands and "analyse-folder-sift" in commands


def test_sad_a_hostile_name_gets_no_analyse_entry(win) -> None:
    pane = win._active_pane
    _select(pane, ["notes.txt"])
    pane._safe_item_path = lambda item, warn=True: None
    assert "analyse-sift" not in _commands(pane)


def test_sad_a_pane_without_a_window_offers_no_sift_entries(folder) -> None:
    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    pane = FilePaneWidget(LocalFS())
    try:
        pane.navigate(str(folder))
        pump()
        _select(pane, ["notes.txt"])
        commands = _commands(pane)
        assert "analyse-sift" not in commands and "analyse-folder-sift" not in commands
        assert "identify" in commands  # the menu itself is there
    finally:
        pane.deleteLater()


def test_edge_a_folder_alone_gets_no_file_entry(win) -> None:
    pane = win._active_pane
    _select(pane, ["sub"])
    commands = _commands(pane)
    assert "analyse-sift" not in commands
    assert "analyse-folder-sift" in commands


# --- right-click: a folder -----------------------------------------------------


def test_happy_e2e_analyse_folder_offers_the_selected_folder(win, fake) -> None:
    pane, dock = win._active_pane, win._analysis_dock
    _select(pane, ["sub"])
    entry = _commands(pane)["analyse-folder-sift"]
    assert _plain(entry.text()) == "Analyse Folder with sift"
    assert entry.property("axIcon") == "analysis"
    entry.trigger()
    pump(PAST_DEBOUNCE)
    assert dock.isVisible() and dock.batch_button.isVisible()
    assert dock.batch_button.text() == "Analyse the files in sub with LLM"


def test_edge_e2e_on_empty_space_the_folder_shown_stays_on_offer(win, fake, folder) -> None:
    pane, dock = win._active_pane, win._analysis_dock
    pane._table.clearSelection()
    pump()
    _commands(pane)["analyse-folder-sift"].trigger()
    pump(PAST_DEBOUNCE)
    # The dock's automatic follow-up (nothing selected) must not replace it.
    assert dock.batch_button.isVisible(), dock.body.toPlainText()
    assert dock.batch_button.text() == f"Analyse the files in {folder.name} with LLM"
    pane.selection_changed.emit()  # a reload of the pane: still nothing selected
    pump(PAST_DEBOUNCE)
    assert dock.batch_button.isVisible()


def test_sad_after_navigating_away_the_folder_offer_is_dropped(win, fake, folder) -> None:
    pane, dock = win._active_pane, win._analysis_dock
    pane._table.clearSelection()
    _commands(pane)["analyse-folder-sift"].trigger()
    pump(PAST_DEBOUNCE)
    pane.navigate(str(folder / "sub"))
    pump(PAST_DEBOUNCE)
    wait_for(lambda: not dock.batch_button.isVisible())
    assert "Select a file" in dock.body.toPlainText()


# --- the menu bar ----------------------------------------------------------------


def test_happy_e2e_tools_menu_analyses_the_selected_file(win, fake, folder) -> None:
    pane, dock = win._active_pane, win._analysis_dock
    _select(pane, ["notes.txt"])
    entry = _tools_entry(win)
    assert entry.property("axIcon") == "analysis" and not entry.icon().isNull()
    entry.trigger()
    wait_for(lambda: "about notes.txt" in dock.body.toPlainText())
    assert dock.isVisible() and fake.asked == [str(folder / "notes.txt")]


def test_edge_e2e_tools_menu_with_nothing_selected_offers_the_folder(win, fake, folder) -> None:
    pane, dock = win._active_pane, win._analysis_dock
    pane._table.clearSelection()
    pump()
    _tools_entry(win).trigger()
    pump(PAST_DEBOUNCE)
    assert dock.isVisible() and dock.batch_button.isVisible()
    assert dock.batch_button.text() == f"Analyse the files in {folder.name} with LLM"


def test_sad_tools_menu_without_a_pane_says_so(win) -> None:
    win._active_pane = None
    _tools_entry(win).trigger()
    pump()
    assert win._analysis_dock.isVisible()
    assert "No file pane is active" in win._analysis_dock.body.toPlainText()


# --- without sift (axross-slim) -------------------------------------------------


def _says_where_sift_is(dock) -> None:
    text = dock.body.toPlainText()
    assert "axross-full" in text and "axross[sift]" in text, text
    assert 'href="axross:features/extra:sift"' in dock.body.toHtml()


def test_sad_slim_the_dock_says_where_sift_comes_from() -> None:
    from core.file_analysis import Target
    from ui.analysis_dock import AnalysisDock

    dock = AnalysisDock(analyzer_factory=lambda: pytest.fail("no analyzer without sift"),
                        available=lambda: False)
    try:
        _says_where_sift_is(dock)  # from the start, before anything is selected
        dock.analyse(Target(backend=None, path="/x", name="x", size=1, mtime=0.0))
        _says_where_sift_is(dock)
        dock.offer_folder(None, "/d", "d")
        _says_where_sift_is(dock)
        assert not dock.batch_button.isVisible()
        dock.offer_batch([Target(backend=None, path="/x", name="x", size=1, mtime=0.0)], "1")
        _says_where_sift_is(dock)
    finally:
        dock.shutdown()
        dock.deleteLater()


@pytest.mark.parametrize("entry", ["file", "folder", "tools", "toolbar"])
def test_sad_e2e_slim_every_entry_point_says_where_sift_is(slim, stores, folder, entry) -> None:
    win = _window(stores, folder)
    pane, dock = win._active_pane, win._analysis_dock
    if entry == "file":
        _select(pane, ["notes.txt"])
        _commands(pane)["analyse-sift"].trigger()
    elif entry == "folder":
        _select(pane, ["sub"])
        _commands(pane)["analyse-folder-sift"].trigger()
    elif entry == "tools":
        _select(pane, ["notes.txt"])
        _tools_entry(win).trigger()
    else:
        pane._table.clearSelection()
        _tool_button(win, "analysis").trigger()
    pump(PAST_DEBOUNCE)
    assert dock.isVisible()
    _says_where_sift_is(dock)
    assert dock._auto.analyzer is None and dock._llm.analyzer is None
    assert not dock.batch_button.isVisible()


def test_edge_slim_the_features_link_still_opens_features(slim, stores, folder) -> None:
    from PyQt6.QtCore import QUrl

    win = _window(stores, folder)
    asked: list[str] = []
    win._show_features = lambda key=None: asked.append(key)
    dock = win._analysis_dock
    dock.features_requested.disconnect()
    dock.features_requested.connect(win._show_features)
    dock.body.anchorClicked.emit(QUrl("axross:features/extra:sift"))
    assert asked == ["extra:sift"]


def test_edge_no_thread_is_left_running_by_a_slim_entry(slim, stores, folder) -> None:
    before = {t.name for t in threading.enumerate()}
    win = _window(stores, folder)
    _select(win._active_pane, ["notes.txt"])
    _commands(win._active_pane)["analyse-sift"].trigger()
    pump(PAST_DEBOUNCE)
    started = {t.name for t in threading.enumerate()} - before
    assert "axross-analysis" not in started


# --- right-click on a remote pane --------------------------------------------------
# Asked for: a file, a folder or a remote path straight to sift from the
# right-click menu. A RamFS pane stands for a remote one: not a LocalFS, so
# the Analysis dock must take the bytes through the backend (bounded copy).


@pytest.fixture
def remote(win):
    from core.ram_fs import RamFsSession

    ram = RamFsSession(label="remote-test")
    ram.mkdir("/data/sub", parents=True, exist_ok=True)
    with ram.open_write("/data/report.csv") as fh:
        fh.write(b"name,size\nalpha,1\nbeta,2\n")
    with ram.open_write("/data/sub/inner.txt") as fh:
        fh.write(b"inner on the remote side\n")
    pane = win._active_pane
    pane.set_backend(ram, "/data")
    pump()
    wait_for(lambda: pane._table.model().rowCount() >= 2)
    return pane


def test_happy_e2e_a_remote_file_goes_to_sift_from_the_right_click(win, fake, remote) -> None:
    from core.previews import _is_local_backend

    assert not _is_local_backend(remote.backend)
    _select(remote, ["report.csv"])
    entry = _commands(remote)["analyse-sift"]
    entry.trigger()
    wait_for(lambda: "about report.csv" in win._analysis_dock.body.toPlainText())
    assert fake.asked == ["/data/report.csv"]


@pytest.mark.skipif(
    not __import__("core.analysis_worker", fromlist=["x"]).sift_available(),
    reason="sift is not installed")
def test_happy_e2e_real_sift_explains_a_remote_file(win, remote) -> None:
    dock = win._analysis_dock
    _select(remote, ["report.csv"])
    _commands(remote)["analyse-sift"].trigger()
    wait_for(lambda: "Explained by sift" in dock.body.toPlainText()
             or "Analysis failed" in dock.body.toPlainText(), 60)
    text = dock.body.toPlainText()
    assert "Explained by sift" in text, text
    assert "report.csv" in dock.title.text()


def test_happy_e2e_a_remote_folder_is_offered_from_the_right_click(win, fake, remote) -> None:
    dock = win._analysis_dock
    _select(remote, ["sub"])
    _commands(remote)["analyse-folder-sift"].trigger()
    pump(PAST_DEBOUNCE)
    assert dock.isVisible() and dock.batch_button.isVisible()
    assert dock.batch_button.text() == "Analyse the files in sub with LLM"


def test_edge_e2e_the_remote_folder_shown_is_offered_on_empty_space(win, fake, remote) -> None:
    dock = win._analysis_dock
    remote._table.clearSelection()
    pump()
    _commands(remote)["analyse-folder-sift"].trigger()
    pump(PAST_DEBOUNCE)
    assert dock.batch_button.isVisible(), dock.body.toPlainText()
    assert dock.batch_button.text() == "Analyse the files in data with LLM"


@pytest.mark.skipif(
    not __import__("core.analysis_worker", fromlist=["x"]).sift_available(),
    reason="sift is not installed")
def test_sad_e2e_a_remote_read_that_fails_is_reported_not_hung(win, remote) -> None:
    """The connection breaks while the bytes are fetched: the dock says why."""
    def broken(path, *a, **k):
        raise OSError("connection lost while reading")

    remote.backend.open_read = broken
    _select(remote, ["report.csv"])
    _commands(remote)["analyse-sift"].trigger()
    dock = win._analysis_dock
    wait_for(lambda: "connection lost" in dock.body.toPlainText(), 60)
    assert "Explained by sift" not in dock.body.toPlainText()
