"""axross.save_script and the console's history write every byte or fail.

Reproduced 2026-11-19 (independent review): save_script (Scripts dock
Save, the console's .save) wrote the source with ONE unchecked
``os.write``. A short write - a disk filling up part-way, RLIMIT_FSIZE -
replaced the saved script with its first part and reported success. The
console's history append and compaction had the same single write. Now
the writes loop until every byte is out (and fsync), and a failed write
leaves the old file as it was and no temp file behind.
"""

from __future__ import annotations

import errno
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import scripting  # noqa: E402

REAL_WRITE = os.write


@pytest.fixture
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    return tmp_path


def _short_writes(monkeypatch, at_most=1000, fail_after=None, zero=False):
    """os.write takes at most *at_most* bytes per call; after *fail_after*
    bytes it raises ENOSPC; with *zero* it writes nothing at all."""
    written = [0]

    def write(fd, data):
        data = bytes(data)
        if zero:
            return 0
        if fail_after is not None and written[0] >= fail_after:
            raise OSError(errno.ENOSPC, "No space left on device")
        n = REAL_WRITE(fd, data[:at_most])
        written[0] += n
        return n

    monkeypatch.setattr(os, "write", write)


def _leftovers(directory: Path) -> list[str]:
    return sorted(p.name for p in directory.iterdir() if p.name.endswith(".tmp"))


def test_happy_short_writes_still_save_the_whole_script(home, monkeypatch):
    source = "print('hello')\n" + "# padding\n" * 20000
    _short_writes(monkeypatch, at_most=4096)
    path = scripting.save_script("backup_job", source)
    monkeypatch.setattr(os, "write", REAL_WRITE)
    assert scripting.load_script("backup_job") == source
    assert _leftovers(Path(path).parent) == []


def test_sad_a_disk_full_part_way_keeps_the_old_script(home, monkeypatch):
    old = "print('old')\n" * 1000
    path = Path(scripting.save_script("backup_job", old))
    _short_writes(monkeypatch, at_most=4096, fail_after=8192)
    with pytest.raises(OSError):
        scripting.save_script("backup_job", old + "# more\n" * 5000)
    monkeypatch.setattr(os, "write", REAL_WRITE)
    assert path.read_text() == old
    assert _leftovers(path.parent) == []


def test_edge_a_write_that_takes_nothing_is_an_error_not_a_hang(home, monkeypatch):
    path = Path(scripting.save_script("backup_job", "old\n"))
    _short_writes(monkeypatch, zero=True)
    with pytest.raises(OSError):
        scripting.save_script("backup_job", "new\n")
    monkeypatch.setattr(os, "write", REAL_WRITE)
    assert path.read_text() == "old\n"
    assert _leftovers(path.parent) == []


def test_happy_the_console_history_is_written_whole(tmp_path, monkeypatch):
    pytest.importorskip("PyQt6.QtWidgets")
    from ui import repl_widget

    history = tmp_path / "cfg" / "repl_history"
    monkeypatch.setattr(repl_widget, "HISTORY_PATH", history)
    owner = type("Owner", (), {})()
    owner._history = []
    owner._history_appends_since_compact = 0
    owner._compact_history_file = lambda: None
    line = "x = '" + "y" * 5000 + "'"
    _short_writes(monkeypatch, at_most=100)
    repl_widget.ReplWidget._append_history(owner, line)
    monkeypatch.setattr(os, "write", REAL_WRITE)
    assert history.read_text() == line + "\n"


def test_sad_a_failed_history_compaction_keeps_the_old_file(tmp_path, monkeypatch):
    pytest.importorskip("PyQt6.QtWidgets")
    from ui import repl_widget

    history = tmp_path / "cfg" / "repl_history"
    history.parent.mkdir(parents=True)
    history.write_text("old = 1\n")
    monkeypatch.setattr(repl_widget, "HISTORY_PATH", history)
    owner = type("Owner", (), {})()
    owner._history = [f"line{i} = {'z' * 200}" for i in range(50)]
    _short_writes(monkeypatch, at_most=100, fail_after=1000)
    repl_widget.ReplWidget._compact_history_file(owner)  # logs, never raises
    monkeypatch.setattr(os, "write", REAL_WRITE)
    assert history.read_text() == "old = 1\n"
    assert _leftovers(history.parent) == []
    # And with room on the disk the compaction writes it all.
    _short_writes(monkeypatch, at_most=100)
    repl_widget.ReplWidget._compact_history_file(owner)
    monkeypatch.setattr(os, "write", REAL_WRITE)
    assert history.read_text().splitlines() == owner._history
