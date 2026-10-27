"""The user guides know Settings > Logging and the Log dock's area filter -
and say what the code does: the page's title and its place in the table, the
store, the defaults, the flags."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

GUIDES = ("docs/USAGE.md", "docs/USAGE_de.md", "docs/USAGE_es.md")


def _text(name: str) -> str:
    return (ROOT / name).read_text(encoding="utf-8")


@pytest.mark.parametrize("name", GUIDES)
def test_happy_each_guide_has_the_logging_row_last_in_the_settings_table(name):
    from ui.settings_dialog import _BUILTIN, CATEGORY_ORDER

    text = _text(name)
    rows = re.findall(r"^\| ([^|]+?) \| ", text, re.M)
    assert "Logging" in rows
    assert rows.index("Updates") + 1 == rows.index("Logging")
    assert CATEGORY_ORDER[-1] == "logging" and _BUILTIN["logging"][0] == "Logging"
    row = re.search(r"^\| Logging \| (.+) \|$", text, re.M).group(1)
    for needle in ("DEBUG", "WARNING", "*Reset to Defaults*"):
        assert needle in row, needle


@pytest.mark.parametrize("name", GUIDES)
def test_happy_each_guide_names_the_store_the_flags_and_the_collapse(name):
    from core import log_config as LC

    text = _text(name)
    assert "~/.config/axross/" + LC.settings_file().name in text
    assert "--debug" in text and "--verbose" in text
    assert "Last message repeated" in text  # the line the log shows, verbatim
    assert "*Areas*" in text  # the Log dock's filter button


def test_sad_the_labels_the_docs_name_exist():
    page = _text("ui/logging_settings_page.py")
    dock = _text("ui/log_dock.py")
    for label in ("Reset to Defaults", "Log to terminal (stderr)"):
        assert f'tr("{label}")' in page, label
    assert 'tr("Areas: All")' in dock
    assert '"Last message repeated %d more times in %.1f s: %s"' in _text("core/log_config.py")


def test_edge_the_defaults_in_the_docs_are_the_codes():
    from core import log_config as LC

    s = LC.LogSettings()
    text = _text("docs/USAGE.md")
    assert f"{s.file_max_mib} MiB" in text and f"{s.file_backups} rotated files" in text
    assert f"{s.repeat_window} s" in text
