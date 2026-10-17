"""Compact mode comes back on start like the theme does.

Found in review (round 3, config; reproduced): with File > Restore
Layout on Start switched off, ``_load_persistent_visual_settings``
restored the theme and the monochrome icons but not compact mode - that
was only read by ``_apply_session``, the layout restore. The window
started normal-sized and wrote ``compact: false`` back on close, so the
choice was lost for good.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tests.test_main_window_state_files import _WindowStateTest  # noqa: E402


def _session(**window) -> str:
    return json.dumps({"window": {"restore_layout_on_start": False, **window}})


class CompactModeOnStartTest(_WindowStateTest):
    def saved_window(self) -> dict:
        from PyQt6.QtGui import QCloseEvent

        self.win.closeEvent(QCloseEvent())
        return json.loads(self.session.read_text())["window"]

    def test_happy_compact_survives_without_layout_restore(self) -> None:
        self.session.write_text(_session(compact=True, ui_theme="hacker"))
        win = self.make_window()
        self.assertTrue(win._compact_mode)
        self.assertTrue(win._compact_action.isChecked())
        self.assertTrue(self.saved_window()["compact"])

    def test_sad_compact_false_stays_off(self) -> None:
        self.session.write_text(_session(compact=False))
        win = self.make_window()
        self.assertFalse(win._compact_mode)

    def test_edge_a_non_boolean_value_is_not_compact(self) -> None:
        self.session.write_text(_session(compact="yes"))
        win = self.make_window()
        self.assertFalse(win._compact_mode)

    def test_edge_no_session_file_starts_normal(self) -> None:
        win = self.make_window()
        self.assertFalse(win._compact_mode)


def test_edge_usage_calls_column_prefs_shared():
    root = Path(__file__).resolve().parents[1]
    for guide in ("docs/USAGE.md", "docs/USAGE_de.md", "docs/USAGE_es.md"):
        line = next(
            ln for ln in (root / guide).read_text(encoding="utf-8").splitlines()
            if "column_prefs.json" in ln
        )
        lowered = line.lower()
        assert "per-pane" not in lowered and "pro-pane" not in lowered, guide
        assert "por panel" not in lowered, guide
