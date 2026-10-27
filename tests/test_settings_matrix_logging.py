"""Every setting really works, the Logging page: the overall level, the level
of an area, the log file's size and count, the terminal, the collapse of
repeated messages and its window.

The rows run the four steps of tests/test_settings_matrix.py (set through the
page's real widgets -> OK -> stored in ~/.config/axross/logging.json -> a
fresh load shows it -> the effect; the default again; Cancel writes nothing;
a hand-edited value falls back). The effects are the running logging: the
loggers' levels, the log file handler of a configured start, the stderr
handler, the lines written for a burst of identical messages.
"""

from __future__ import annotations

import itertools
import json
import logging

import pytest

from core import log_config as LC
from tests import test_settings_matrix as SMX
from tests.test_settings_matrix import ctx  # noqa: F401 - the fixture of the matrix

Row = SMX.Row
_TOKENS = itertools.count()


@pytest.fixture(autouse=True)
def _configured_logging(ctx):  # noqa: F811 - the matrix fixture
    """A start's logging: the file handler in the test's folder, the stored settings."""
    root = logging.getLogger()
    old_level = root.level
    ctx.extras["log_file"] = ctx.tmp_path / "logs" / "axross.log"
    LC.configure(ctx.extras["log_file"])
    yield
    LC.teardown()
    root.setLevel(old_level)


def _store(ctx):
    return ctx.stores.config / "logging.json"


def _edit(key):
    def write(ctx, value) -> None:
        data = SMX._read_json(_store(ctx)) or {}
        data[key] = value
        _store(ctx).write_text(json.dumps(data))
    return write


def _edit_area(area_id):
    def write(ctx, value) -> None:
        data = SMX._read_json(_store(ctx)) or {}
        data.setdefault("areas", {})[area_id] = value
        _store(ctx).write_text(json.dumps(data))
    return write


def _loaded(attr):
    return lambda c: getattr(LC.LogSettings.load(), attr)


def _area_combo_set(area_id):
    return lambda ctx, d, v: SMX._combo_data(d.page("logging").area_combos[area_id], v)


def _area_combo_shown(area_id):
    return lambda d: d.page("logging").area_combos[area_id].currentData()


def effect_level(ctx, win, value) -> None:
    level = LC.level_number(value)
    assert logging.getLogger().level == level
    assert logging.getLogger("ui.main_window").getEffectiveLevel() == level


def _effect_area(logger_name, inherit_level):
    def effect(ctx, win, value) -> None:
        expected = inherit_level if value == "inherit" else LC.level_number(value)
        assert logging.getLogger(logger_name).getEffectiveLevel() == expected
    return effect


def effect_file_size(ctx, win, value) -> None:
    assert LC.file_handler().maxBytes == value * LC.MIB


def effect_backups(ctx, win, value) -> None:
    assert LC.file_handler().backupCount == value


def effect_terminal(ctx, win, value) -> None:
    assert (LC.terminal_handler() is not None) is value


def effect_collapse(ctx, win, value) -> None:
    token = f"matrix burst {next(_TOKENS)}"
    log = logging.getLogger("core.transfer_worker")
    for _ in range(20):
        log.warning(token)
    LC.flush_repeats()
    LC.file_handler().flush()
    lines = [ln for ln in ctx.extras["log_file"].read_text(encoding="utf-8").splitlines()
             if ln.endswith(token)]
    assert len(lines) == (2 if value else 20), lines


def effect_window(ctx, win, value) -> None:
    filters = [f for f in LC.file_handler().filters if isinstance(f, LC.RepeatCollapseFilter)]
    assert [f.window for f in filters] == [float(value)]


ROWS = [
    Row("logging_level", "logging", "logging.json level", ("DEBUG", "ERROR"), "INFO",
        SMX._set_combo("logging", "level_combo"), SMX._combo_shown("logging", "level_combo"),
        _loaded("level"), _edit("level"), ("LOUD", 10, None), effect_level,
        widgets=("logging.level_combo",)),
    Row("logging_area_smb", "logging", "logging.json areas.protocols.smb", ("DEBUG", "off"),
        "inherit", _area_combo_set("protocols.smb"), _area_combo_shown("protocols.smb"),
        lambda c: LC.LogSettings.load().area_choice("protocols.smb"),
        _edit_area("protocols.smb"), ("LOUD", 5, None),
        _effect_area("core.smb_client", logging.INFO), widgets=("logging.area_tree",)),
    Row("logging_area_third_party", "logging", "logging.json areas.third_party",
        ("inherit", "ERROR"), "WARNING", _area_combo_set("third_party"),
        _area_combo_shown("third_party"),
        lambda c: LC.LogSettings.load().area_choice("third_party"),
        _edit_area("third_party"), ("quiet", [1]),
        _effect_area("paramiko.transport", logging.INFO), widgets=("logging.area_tree",)),
    Row("logging_file_max_mib", "logging", "logging.json file_max_mib", (1, 100), 5,
        SMX._set_spin("logging", "file_size_spin"),
        SMX._page_attr("logging", "file_size_spin", "value"), _loaded("file_max_mib"),
        _edit("file_max_mib"), (0, 101, "5", True), effect_file_size,
        widgets=("logging.file_size_spin",)),
    Row("logging_file_backups", "logging", "logging.json file_backups", (1, 20), 3,
        SMX._set_spin("logging", "backups_spin"),
        SMX._page_attr("logging", "backups_spin", "value"), _loaded("file_backups"),
        _edit("file_backups"), (0, 21, "3"), effect_backups,
        widgets=("logging.backups_spin",)),
    Row("logging_terminal", "logging", "logging.json terminal", (True,), False,
        SMX._set_check("logging", "terminal_check"),
        SMX._page_attr("logging", "terminal_check"), _loaded("terminal"),
        _edit("terminal"), ("yes", 1), effect_terminal, widgets=("logging.terminal_check",)),
    Row("logging_collapse_repeats", "logging", "logging.json collapse_repeats", (False,), True,
        SMX._set_check("logging", "collapse_check"),
        SMX._page_attr("logging", "collapse_check"), _loaded("collapse_repeats"),
        _edit("collapse_repeats"), ("no", 0), effect_collapse,
        widgets=("logging.collapse_check",)),
    Row("logging_repeat_window", "logging", "logging.json repeat_window", (1, 300), 10,
        SMX._set_spin("logging", "window_spin"),
        SMX._page_attr("logging", "window_spin", "value"), _loaded("repeat_window"),
        _edit("repeat_window"), (0, 301, "10"), effect_window,
        widgets=("logging.window_spin",)),
]

SECRETS: list = []

ROW_PARAMS = [pytest.param(row, id=row.id) for row in ROWS]


@pytest.mark.parametrize("row", ROW_PARAMS)
def test_set_store_reload_effect(ctx, row) -> None:  # noqa: F811
    SMX.check_set_store_reload_effect(ctx, row)


@pytest.mark.parametrize("row", ROW_PARAMS)
def test_hand_edited_value_falls_back(ctx, row) -> None:  # noqa: F811
    SMX.check_hand_edited_value_falls_back(ctx, row)
