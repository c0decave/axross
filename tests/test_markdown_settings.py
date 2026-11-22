"""axross-markdown's settings file (core.markdown_settings) and its window state - the twenty-seventh review's
S1 and S2: one typo in the hand-editable settings.json lost every setting at the next choice, the update mode
"off" with them (the program asked GitHub again); a symlinked settings.json was replaced by a file of its own;
the window's size went into axross's own ~/.config/axross/session.json.

Each test here failed before.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import markdown_settings as S  # noqa: E402

TYPO = '{"page_theme": "sepia", "update_mode": "off", "theme": "classic",}\n'


@pytest.fixture
def settings(tmp_path, monkeypatch):
    path = tmp_path / "config" / "axross-markdown" / "settings.json"
    path.parent.mkdir(parents=True)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))
    monkeypatch.delenv(S.ENV, raising=False)
    assert S.settings_path() == path
    return path


def test_sad_a_typo_in_the_settings_loses_no_setting_at_the_next_choice(settings):
    """A trailing comma: the file read as empty, and the next choice wrote only that choice - the page theme,
    the window theme and "update_mode": "off" gone. Now what can be read is kept, with the new choice; the file
    as it was is kept aside."""
    settings.write_text(TYPO, encoding="utf-8")
    assert S.read_setting("update_mode") == "off"
    S.write_setting("terminal_theme", "retro")
    data = json.loads(settings.read_text(encoding="utf-8"))
    assert data == {"page_theme": "sepia", "update_mode": "off", "theme": "classic", "terminal_theme": "retro"}
    aside = settings.with_name("settings.json.broken")
    assert aside.read_text(encoding="utf-8") == TYPO
    assert oct(aside.stat().st_mode & 0o777) == "0o600"


def test_sad_the_update_mode_off_survives_a_file_that_is_no_json_at_all(settings):
    """Worse than a comma (no quotes round a value, a missing comma): each pair that still parses is kept, and
    the update mode "off" in any case - the update check never turned on again by a typo."""
    from core import markdown_update as MU

    settings.write_text('{"page_theme": "sepia" "update_mode": off, theme: classic\n', encoding="utf-8")
    assert MU.mode() == "off"
    S.write_setting("page_theme", "slate")
    assert MU.mode() == "off"
    assert json.loads(settings.read_text(encoding="utf-8")) == {"page_theme": "slate", "update_mode": "off"}


def test_sad_a_broken_file_kept_aside_is_never_overwritten(settings):
    """A second broken file is kept beside the first, not over it."""
    settings.write_text(TYPO, encoding="utf-8")
    S.write_setting("terminal_theme", "retro")
    second = '{"update_mode": "auto",, }'
    settings.write_text(second, encoding="utf-8")
    S.write_setting("terminal_theme", "dark")
    assert settings.with_name("settings.json.broken").read_text(encoding="utf-8") == TYPO
    assert settings.with_name("settings.json.broken-2").read_text(encoding="utf-8") == second
    assert json.loads(settings.read_text(encoding="utf-8")) == {"update_mode": "auto", "terminal_theme": "dark"}


@pytest.mark.skipif(not hasattr(os, "symlink") or sys.platform == "win32", reason="POSIX symlinks")
def test_sad_a_symlinked_settings_file_is_written_through_its_link(settings, tmp_path):
    """A dotfiles manager (stow) links settings.json to its repository: the write replaced the link with a file
    of its own, the dotfile left as it was. Now the target is written, the link stays."""
    dotfile = tmp_path / "dotfiles" / "settings.json"
    dotfile.parent.mkdir()
    dotfile.write_text('{"theme": "classic"}\n', encoding="utf-8")
    settings.symlink_to(dotfile)
    S.write_setting("page_theme", "sepia")
    assert settings.is_symlink() and os.readlink(settings) == str(dotfile)
    assert json.loads(dotfile.read_text(encoding="utf-8")) == {"theme": "classic", "page_theme": "sepia"}
    assert not list(settings.parent.glob(".settings.json.*"))


def test_sad_the_window_theme_choice_keeps_a_broken_file_s_settings(settings):
    """View > Theme (ui.standalone_app.store_theme) wrote the file anew from what it read - nothing, for a file
    with a typo."""
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from ui import standalone_app

    settings.write_text(TYPO, encoding="utf-8")
    standalone_app.store_theme("axross-markdown", "dark")
    assert json.loads(settings.read_text(encoding="utf-8")) == {
        "page_theme": "sepia", "update_mode": "off", "theme": "dark"}
    assert standalone_app.stored_theme("axross-markdown") is not None


def test_sad_the_standalone_keeps_its_window_size_in_its_own_state(settings, tmp_path, monkeypatch):
    """axross-markdown wrote its window's size into axross's ~/.config/axross/session.json (and its lock), with
    axross not installed. Its own state now: ~/.local/state/axross-markdown/window.json."""
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtWidgets import QApplication

    from core import i18n
    from tests.test_markdown_reader_bugs11 import pump
    from ui import markdown_app, viewer_window

    app = QApplication.instance() or QApplication([])
    session = tmp_path / "axross-config" / "session.json"
    monkeypatch.setattr(i18n, "SETTINGS_FILE", str(session))
    monkeypatch.setattr(viewer_window, "STATE_FILE", None)
    monkeypatch.setenv("AXROSS_MARKDOWN_NO_UPDATE_CHECK", "1")
    page = tmp_path / "page.md"
    page.write_text("# Page\n\ntext\n", encoding="utf-8")
    markdown_app.build(app, [str(page)])
    pump(0.5)
    viewers = [widget for widget in app.topLevelWidgets()
               if type(widget).__name__ == "MarkdownViewerDialog" and widget.isVisible()]
    assert viewers
    for viewer in viewers:
        viewer.resize(777, 555)
        pump(0.1)
        viewer.done(0)
    pump(0.2)
    assert not session.exists() and not session.with_name("session.json.lock").exists()
    state = tmp_path / "state" / "axross-markdown" / "window.json"
    assert json.loads(state.read_text(encoding="utf-8"))["window"]["viewers"]["markdown"]["width"] == 777
