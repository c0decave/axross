"""Edit > Settings… > Analysis (sift): the real Settings dialog driven with
QTest, the real MainWindow and pane, the real sift worker.

The e2e tests follow a value the whole way: the page, analysis.json, the
worker request, sift's Config in the child (a file cut at the read limit
says so in sift's own notes) - and a change reaches the open dock at once.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtCore import Qt  # noqa: E402
from PyQt6.QtTest import QTest  # noqa: E402
from PyQt6.QtWidgets import QDialogButtonBox  # noqa: E402

from core import analysis_settings as AS  # noqa: E402
from core import analysis_worker as AW  # noqa: E402
from tests.settings_testkit import app, isolate  # noqa: E402

pytest.importorskip("sift")


@pytest.fixture
def stores(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    s = isolate(tmp_path, monkeypatch)
    yield s
    s.restore()


@pytest.fixture
def requests(monkeypatch):
    """Every request the real worker gets: (path, keyword arguments)."""
    seen: list[tuple[str, dict]] = []
    real = AW.AnalysisWorker.analyse

    def spy(self, path, display_name, **kw):
        seen.append((display_name, kw))
        return real(self, path, display_name, **kw)

    monkeypatch.setattr(AW.AnalysisWorker, "analyse", spy)
    return seen


def wait_for(cond, seconds=30.0) -> None:
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app().processEvents()
        if cond():
            return
        time.sleep(0.02)
    raise AssertionError("condition not reached")


def open_page(stores, win=None):
    win = win or stores.make_window()
    dialog = stores.settings_dialog(win)
    dialog.show()
    dialog.show_page("analysis")
    return win, dialog, dialog.page("analysis")


def click(widget) -> None:
    from PyQt6.QtCore import QPoint
    from PyQt6.QtWidgets import QCheckBox

    if isinstance(widget, QCheckBox):  # on its box: a row-wide check box is not hit beside it
        QTest.mouseClick(widget, Qt.MouseButton.LeftButton, pos=QPoint(8, widget.height() // 2))
    else:
        QTest.mouseClick(widget, Qt.MouseButton.LeftButton)


def apply(dialog) -> None:
    click(dialog.buttons.button(QDialogButtonBox.StandardButton.Apply))


def type_value(spin, text: str) -> None:
    spin.setFocus()
    spin.selectAll()
    QTest.keyClicks(spin, text)
    QTest.keyClick(spin, Qt.Key.Key_Tab)


def saved(stores) -> dict:
    return json.loads((stores.config / "analysis.json").read_text(encoding="utf-8"))


def notes_file(folder: Path, size: int = 2_500_000) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    line = "Line of the plain notes file, number {:08d}.\n"
    count = size // len(line.format(0)) + 1
    path = folder / "notes.txt"
    path.write_text("".join(line.format(i) for i in range(count)))
    return path


def select_in_pane(win, path: Path) -> None:
    pane = win._active_pane
    if pane.current_path != str(path.parent):
        pane.navigate(str(path.parent))
        wait_for(lambda: not pane.is_loading and pane.current_path == str(path.parent))
    pane.reveal_path(str(path))
    wait_for(lambda: [i.name for i in pane.selected_file_items()] == [path.name])


def show_dock(win):
    win.show()
    dock = win._analysis_dock
    dock.show()
    app().processEvents()
    return dock


# -- happy -------------------------------------------------------------------------------------


def test_happy_the_dialog_has_the_page_after_llm_profiles(stores):
    from ui.analysis_dock import DOCK_TITLE
    from ui.settings_dialog import CATEGORY_ORDER

    _win, dialog, page = open_page(stores)
    assert dialog.title_label.text() == DOCK_TITLE == "Analysis (sift)"
    assert CATEGORY_ORDER.index("llm") + 1 == CATEGORY_ORDER.index("analysis")
    import sift

    assert sift.__version__ in page.status_label.text()
    assert page.features_link.isHidden()
    # The filter finds it by its settings' names.
    dialog.apply_filter("max bytes")
    assert "analysis" in dialog.visible_page_ids()
    dialog.apply_filter("clear cache")
    assert dialog.visible_page_ids() == ["analysis"]


def test_happy_e2e_max_bytes_reaches_sifts_config_in_the_worker(stores, requests, tmp_path):
    notes = notes_file(tmp_path / "files")
    win, dialog, page = open_page(stores)
    dock = show_dock(win)
    type_value(page.max_bytes_spin, "1")  # MB
    type_value(page.tags_spin, "3")
    apply(dialog)
    assert dialog.error_text() == ""
    data = saved(stores)
    assert (data["max_bytes"], data["tags"]) == (1_000_000, 3)
    # The open dock took the change in: the next selection runs with it.
    select_in_pane(win, notes)
    wait_for(lambda: dock._auto_result is not None and dock._target.name == "notes.txt", 60)
    name, kw = requests[-1]
    assert name == "notes.txt"
    assert kw["sift"]["max_bytes"] == 1_000_000 and kw["sift"]["tags"] == 3
    summary = dock._auto_result.summary
    assert dock._auto_result.ok, dock._auto_result.error
    assert summary["truncated"] is True
    assert any("read first 1000000" in note for note in summary["notes"])
    assert "read first 1000000" in dock.body.toPlainText()


def test_happy_e2e_the_cache_switch_and_clear_cache_on_the_real_folder(stores, requests, tmp_path):
    notes = notes_file(tmp_path / "files", 20_000)
    win = stores.make_window()
    dock = show_dock(win)
    select_in_pane(win, notes)
    wait_for(lambda: dock._auto_result is not None, 60)
    cache = AS.cache_dir()
    assert cache == tmp_path / "cache" / "axross" / "sift"
    assert len(list(cache.rglob("*.json"))) == 1  # sift kept the result
    _win, dialog, page = open_page(stores, win)
    assert str(cache) in page.cache_location.text()
    click(page.clear_button)
    wait_for(lambda: "1" in page.cache_label.text())
    assert list(cache.rglob("*.json")) == []


def test_happy_the_llm_profile_for_analysis_is_its_own(stores):
    from core import llm_profiles as LP

    LP.LLMSettings([LP.LLMProfile(name="agent-model", model="big"),
                    LP.LLMProfile(name="sift-model", model="small")], "agent-model").save()
    win, dialog, page = open_page(stores)
    names = [page.profile_combo.itemData(i) for i in range(page.profile_combo.count())]
    assert names == ["", "agent-model", "sift-model"]
    page.profile_combo.setFocus()
    QTest.keyClick(page.profile_combo, Qt.Key.Key_End)
    apply(dialog)
    assert saved(stores)["llm_profile"] == "sift-model"
    assert win._analysis_dock._profile.name == "sift-model"
    assert LP.LLMSettings.load().active == "agent-model"  # the Agent's stays


# -- sad ---------------------------------------------------------------------------------------


def test_sad_e2e_auto_analysis_off_runs_nothing_on_selection(stores, requests, tmp_path):
    notes = notes_file(tmp_path / "files", 5_000)
    win, dialog, page = open_page(stores)
    assert page.auto_check.isChecked()
    click(page.auto_check)
    apply(dialog)
    assert saved(stores)["auto_analyse"] is False
    dock = show_dock(win)
    select_in_pane(win, notes)
    time.sleep(0.6)  # the selection timer is 200 ms
    app().processEvents()
    assert requests == []
    assert "Automatic analysis is off" in dock.body.toPlainText()
    assert dock.title.text() == "notes.txt"
    click(dock.again)
    wait_for(lambda: dock._auto_result is not None, 60)
    assert [r[0] for r in requests] == ["notes.txt"]


def test_sad_values_sift_refuses_are_named_and_nothing_is_saved(stores):
    _win, dialog, page = open_page(stores)
    type_value(page.context_spin, "100")
    page.categories_edit.setPlainText("Invoices\ninvoices")
    apply(dialog)
    text = dialog.error_text()
    assert "context_tokens" in text and "twice" in text
    assert not (stores.config / "analysis.json").exists()


def test_sad_without_sift_the_page_says_so_and_links_the_features(stores, monkeypatch):
    with mock.patch.dict(sys.modules, {"sift": None, "sift.cache": None, "sift.config": None,
                                       "sift.categories": None}):
        win, _dialog, page = open_page(stores)
        assert "not installed" in page.status_label.text()
        assert not page.features_link.isHidden()
        assert not page.max_bytes_spin.isEnabled()
        assert not page.clear_button.isEnabled()
        assert not page.is_dirty()
        with mock.patch.object(type(win), "_show_features") as features:
            page.features_link.linkActivated.emit("features")
        features.assert_called_once_with("extra:sift")


def test_sad_a_broken_analysis_json_shows_defaults_and_is_kept_on_save(stores):
    (stores.config / "analysis.json").write_text("{broken")
    _win, dialog, page = open_page(stores)
    assert page.values() == {k: v for k, v in AS.AnalysisSettings().to_dict().items()
                             if k != "version"}
    type_value(page.tags_spin, "2")
    apply(dialog)
    assert saved(stores)["tags"] == 2
    kept = [p for p in stores.config.iterdir() if ".unreadable-" in p.name]
    assert len(kept) == 1 and kept[0].read_text() == "{broken"


# -- edge --------------------------------------------------------------------------------------


def test_edge_an_untouched_odd_value_is_kept_to_the_byte(stores):
    AS.AnalysisSettings(max_bytes=1234, time_budget=2.5).save()
    _win, dialog, page = open_page(stores)
    assert not page.is_dirty()
    type_value(page.tags_spin, "1")
    apply(dialog)
    data = saved(stores)
    assert (data["max_bytes"], data["time_budget"], data["tags"]) == (1234, 2.5, 1)


def test_edge_the_limits_of_the_spin_boxes_are_sifts(stores):
    import sift.config as SC

    _win, _dialog, page = open_page(stores)
    assert page.tags_spin.maximum() == SC.MAX_TAGS
    assert page.tags_spin.minimum() == 0
    assert page.max_bytes_spin.maximum() == AS.MAX_BYTES_CEILING // 1_000_000
    assert page.time_spin.minimum() == AS.TIME_BUDGET_RANGE[0]
    assert page.time_spin.maximum() == AS.TIME_BUDGET_RANGE[1]
    assert page.context_spin.minimum() == AS.CONTEXT_FROM_SERVER
    assert page.context_spin.specialValueText()  # 0 reads "Server's"


def test_edge_a_stored_profile_that_is_gone_stays_selectable(stores):
    AS.AnalysisSettings(llm_profile="old-one").save()
    _win, _dialog, page = open_page(stores)
    assert page.profile_combo.currentData() == "old-one"
    assert "not found" in page.profile_combo.currentText()
    assert not page.is_dirty()
    # Profiles added on the LLM page, not saved yet, can be chosen already.
    page.refresh_llm_choices(["new-one"])
    names = [page.profile_combo.itemData(i) for i in range(page.profile_combo.count())]
    assert names == ["", "new-one", "old-one"]
    assert page.profile_combo.currentData() == "old-one"


def test_edge_categories_are_one_per_line_blank_lines_dropped(stores):
    _win, dialog, page = open_page(stores)
    page.categories_edit.setPlainText("  Invoices \n\nContracts\n")
    apply(dialog)
    assert saved(stores)["categories"] == ["Invoices", "Contracts"]
