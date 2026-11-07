"""Two checks a pane runs over every listing it shows are cheap now and
answer as before.

Measured on 2026-11-02 (20 000 entries): the crash-recovery check ran the
orphan pattern on every name (15 ms; now only on names that start with "."
and end with ".tmp": 3 ms), and the status line's count asked the model
for each row (6 ms; now one pass over the names: 1 ms).
"""

from __future__ import annotations

import os
import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import atomic_recovery as AR  # noqa: E402

NAMES = [
    ".tmp-0123456789ab.tmp", ".axross-atomic-0123456789ab.tmp",  # orphans
    ".tmp-0123456789AB.tmp", ".tmp-0123456789a.tmp", ".tmp-0123456789abc.tmp",
    "tmp-0123456789ab.tmp", ".tmp-0123456789ab.tmpx", ".tmp-0123456789ab.TMP",
    ".tmp", ".", "..", "", ".hidden.tmp", "file.tmp", "report.txt",
]


def test_happy_any_orphan_name_answers_as_the_pattern_does():
    rng = random.Random(7)
    for _ in range(500):
        names = rng.sample(NAMES, rng.randint(0, len(NAMES)))
        assert AR.any_orphan_name(names) == any(AR.is_orphan_name(n) for n in names), names


def test_edge_no_names_and_empty_names_hold_no_orphan():
    assert not AR.any_orphan_name([])
    assert not AR.any_orphan_name(["", None, "", "x"])


def test_happy_the_status_line_counts_the_entries_without_the_nav_rows(tmp_path):
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtWidgets import QApplication

    from core.local_fs import LocalFS
    from ui.file_pane import FilePaneWidget

    QApplication.instance() or QApplication([])
    for i in range(7):
        (tmp_path / f"f{i}").write_text("x")
    (tmp_path / "sub").mkdir()
    pane = FilePaneWidget(LocalFS())
    try:
        pane.navigate(str(tmp_path / "sub"))
        pane.navigate(str(tmp_path))
        model = pane._model
        assert any(model.get_item(r).is_nav for r in range(model.rowCount()))
        expected = sum(1 for r in range(model.rowCount()) if not model.get_item(r).is_nav)
        assert pane._items_text() == f"{expected} items" == "8 items"
    finally:
        pane.shutdown()
        pane.deleteLater()


def test_sad_a_name_with_a_final_newline_is_no_orphan_and_stays(tmp_path):
    """Found in review: the orphan pattern ends in ``$``, which also matches
    before a final newline - a user's own ``.tmp-0123456789ab.tmp\\n`` was
    an orphan to the sweep, and removed once it was an hour old. Names are
    matched whole now."""
    import time as _time

    from core.local_fs import LocalFS

    users = tmp_path / ".tmp-0123456789ab.tmp\n"
    orphan = tmp_path / ".tmp-abcdefabcdef.tmp"
    for path in (users, orphan):
        path.write_text("x")
        old = _time.time() - 2 * AR.DEFAULT_MAX_AGE_SECONDS
        os.utime(path, (old, old))
    assert not AR.is_orphan_name(users.name)
    assert not AR.any_orphan_name([users.name])
    assert AR.is_orphan_name(orphan.name)
    removed = AR.sweep_orphans(LocalFS(), str(tmp_path))
    assert removed == 1
    assert users.exists() and not orphan.exists()
