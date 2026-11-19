"""Review B, item 10: escape sequences and fake lines from remote names
went raw into the log ("Transfer refused: /srv/dl/<ESC>]52;c;...<BEL>
<ESC>[2K<CR>INFO all good": a terminal that shows the log runs the OSC 52
and the line looks like another one).

Now axross's log handlers escape every C0 and C1 control, ESC, DEL and the
bidi / line-separator characters of a message (a traceback keeps its own
line breaks), and a remote name with CR, LF or a C1 control is refused.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import log_config as LC  # noqa: E402
from core.remote_name import RemoteNameError, validate_remote_name  # noqa: E402

EVIL = "\x1b]52;c;ZWNobyBwd25lZAo=\x07\x1b[2K\rINFO all good"


@pytest.fixture(autouse=True)
def clean_logging():
    root = logging.getLogger()
    old_level, old_handlers = root.level, list(root.handlers)
    yield
    LC.teardown()
    for handler in list(root.handlers):
        if handler not in old_handlers:
            root.removeHandler(handler)
            handler.close()
    root.setLevel(old_level)


def _record(msg, *args, exc_info=None):
    return logging.LogRecord("core.x", logging.WARNING, __file__, 1, msg, args, exc_info)


@pytest.mark.parametrize("char", ["\x1b", "\x07", "\r", "\n", "\x00", "\x7f", "\x85", "\x9b",
                                  "\u202e", "\u2066", "\u2028", "\u200f"])
def test_sad_controls_and_bidi_marks_are_escaped(char):
    text = LC.EscapingFormatter("%(message)s").format(_record("name: %s", f"a{char}b"))
    assert char not in text and text.startswith("name: a\\")


def test_happy_plain_text_and_other_scripts_stay_as_they_are():
    text = LC.EscapingFormatter("%(message)s").format(_record("Übertragung: %s", "日本語 ok"))
    assert text == "Übertragung: 日本語 ok"


def test_edge_a_traceback_keeps_its_line_breaks_but_not_the_escapes():
    try:
        raise OSError(f"cannot open {EVIL}")
    except OSError:
        record = _record("failed", exc_info=sys.exc_info())
    text = LC.EscapingFormatter("%(message)s").format(record)
    assert "\nTraceback" in text and "\x1b" not in text and "\r" not in text


def test_sad_the_log_file_gets_no_escape_bytes(tmp_path):
    log_file = tmp_path / "axross.log"
    LC.configure(log_file, settings=LC.LogSettings())
    logging.getLogger("core.transfer_manager").warning("Transfer refused: %s", "/srv/dl/" + EVIL)
    for handler in logging.getLogger().handlers:
        handler.flush()
    raw = log_file.read_bytes()
    assert b"\x1b" not in raw and b"\x07" not in raw and b"\r" not in raw
    refused = [line for line in raw.splitlines() if b"Transfer refused" in line]
    assert len(refused) == 1 and refused[0].endswith(b"INFO all good")
    assert b"\\x1b]52;c;" in raw


@pytest.mark.parametrize("name", ["a\rb", "a\nb", "a\x85b", "a\x9bb", "a\x80b"])
def test_sad_a_remote_name_with_a_line_break_or_c1_is_refused(name):
    with pytest.raises(RemoteNameError):
        validate_remote_name(name)


def test_sad_transfer_leaf_refuses_it_too():
    from core.local_fs import LocalFS
    from core.path_policy import transfer_leaf

    with pytest.raises(ValueError):
        transfer_leaf(LocalFS(), LocalFS(), "report\r\nINFO done.txt")


def test_happy_a_tab_stays_a_valid_name():
    validate_remote_name("with\ttab.txt")


def test_sad_the_log_dock_shows_names_escaped():
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PyQt6.QtWidgets import QApplication, QMainWindow

    from ui.log_dock import LogDock

    _app = QApplication.instance() or QApplication([])  # noqa: F841
    win = QMainWindow()
    dock = LogDock(win)
    try:
        line = dock._handler.format(_record("Transfer refused: %s", EVIL))
        assert "\x1b" not in line and "\r" not in line and "\\x1b]52" in line
    finally:
        dock.shutdown()
        win.deleteLater()
