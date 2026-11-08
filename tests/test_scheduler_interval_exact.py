"""The Scheduler shows an interval exactly (review round 3).

Before: format_interval rounded down to the largest whole unit, so a job
every 5400 s (90 minutes) showed "every 1 h", one every 90 s "every
1 min" - a job that runs half again as often looked like an hourly one.
Now every unit it has is shown.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from ui.scheduler_dialog import format_interval  # noqa: E402


def test_sad_ninety_minutes_is_not_shown_as_one_hour():
    assert format_interval(5400) == "every 1 h 30 min"


def test_sad_every_unit_is_kept():
    assert format_interval(90) == "every 1 min 30 s"
    assert format_interval(90061) == "every 1 day 1 h 1 min 1 s"


def test_edge_whole_units_and_plural_days_read_as_before():
    assert format_interval(3600) == "every 1 h"
    assert format_interval(2 * 86400 + 3600) == "every 2 days 1 h"
