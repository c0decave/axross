#!/usr/bin/env python3
"""Disk usage view — capacity across every open connection.

``core/dashboard.py`` already probed ``disk_usage()`` per backend, with
a bounded thread pool and a per-call timeout, and rendered the result as
text, markdown and JSON. There was no window for it, so the only
capacity a user ever saw was the one line in the active pane's status
bar.

The dialog is a view over that existing snapshot. What it has to get
right is the difference between "this filesystem is empty" and "this
protocol has no filesystem": ``disk_usage()`` returns ``(0, 0, 0)`` both
when a backend does not implement it and when a probe times out, and
rendering either as ``0 %`` would invent a fact.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.dashboard import DashboardSnapshot, HostRow  # noqa: E402
from ui.disk_usage_dialog import (  # noqa: E402
    DiskUsageDialog,
    capacity_cells,
    usage_percent,
)
from ui.format_utils import format_size, human_bytes  # noqa: E402

APP = QApplication.instance() or QApplication([])

DASH = "—"
GIB = 1024**3


def _row(label="srv", protocol="sftp", total=0, used=0, free=0) -> HostRow:
    return HostRow(
        profile_key=label,
        protocol=protocol,
        label=label,
        healthy=True,
        capacity_total=total,
        capacity_used=used,
        capacity_free=free,
    )


# --------------------------------------------------------------------------
# Byte formatting, shared with the properties sheet
# --------------------------------------------------------------------------


def test_happy_human_bytes_scales_through_the_units():
    assert human_bytes(0) == "0 B"
    assert human_bytes(512) == "512 B"
    assert human_bytes(1536) == "1.5 KB"
    assert human_bytes(5 * 1024**3) == "5.0 GB"


def test_edge_format_size_keeps_the_exact_count_for_small_files():
    # Under 1 KB the human form adds nothing, so it is omitted.
    assert format_size(999) == "999 bytes"
    assert "1024 bytes" in format_size(1024)


def test_edge_human_bytes_does_not_crash_on_negative_input():
    # A backend reporting nonsense must not take the dialog down.
    assert human_bytes(-1).endswith("B")


# --------------------------------------------------------------------------
# usage_percent
# --------------------------------------------------------------------------


def test_happy_usage_percent_is_used_over_total():
    assert usage_percent(_row(total=100, used=25, free=75)) == 25


def test_edge_usage_percent_is_none_when_capacity_is_unknown():
    """(0, 0, 0) means unsupported or timed out — NOT an empty disk."""
    assert usage_percent(_row(total=0, used=0, free=0)) is None


def test_edge_usage_percent_clamps_over_full_filesystems():
    """Reserved blocks make used+free < total on ext4, and some backends
    report used > total outright. Never render 143 %."""
    assert usage_percent(_row(total=100, used=143, free=0)) == 100


def test_edge_usage_percent_ignores_negative_totals():
    assert usage_percent(_row(total=-5, used=1, free=1)) is None


# --------------------------------------------------------------------------
# capacity_cells
# --------------------------------------------------------------------------


def test_happy_capacity_cells_render_all_columns():
    cells = capacity_cells(_row(label="prod", protocol="sftp", total=10 * GIB,
                                used=4 * GIB, free=6 * GIB))
    assert cells["Backend"] == "prod"
    assert cells["Protocol"] == "sftp"
    assert "10.0 GB" in cells["Total"]
    assert "4.0 GB" in cells["Used"]
    assert "6.0 GB" in cells["Free"]
    assert cells["Usage"] == "40%"


def test_edge_unsupported_backend_says_so_instead_of_zero_percent():
    cells = capacity_cells(_row(label="imap", protocol="imap"))
    assert cells["Total"] == DASH
    assert cells["Used"] == DASH
    assert cells["Free"] == DASH
    assert cells["Usage"] == "not supported"


def test_edge_protocol_missing_renders_a_dash():
    assert capacity_cells(_row(protocol=""))["Protocol"] == DASH


# --------------------------------------------------------------------------
# The dialog
# --------------------------------------------------------------------------


def _snapshot(*rows) -> DashboardSnapshot:
    return DashboardSnapshot(captured_at=0.0, rows=list(rows))


@pytest.fixture()
def dialog():
    made: list = []

    def factory(snap, backends=()):
        dlg = DiskUsageDialog(list(backends), snapshot_fn=lambda _b: snap)
        dlg.show()
        APP.processEvents()
        dlg.wait_for_refresh()
        made.append(dlg)
        return dlg

    yield factory
    for dlg in made:
        dlg.close()
        dlg.deleteLater()
    APP.processEvents()


def test_happy_dialog_lists_one_row_per_connection(dialog):
    dlg = dialog(_snapshot(
        _row(label="a", total=GIB, used=GIB // 2, free=GIB // 2),
        _row(label="b", total=2 * GIB, used=GIB, free=GIB),
    ))
    assert dlg.displayed_labels() == ["a", "b"]


def test_happy_dialog_shows_the_usage_figure(dialog):
    dlg = dialog(_snapshot(_row(label="a", total=100, used=75, free=25)))
    assert dlg.displayed_cells()[0]["Usage"] == "75%"


def test_edge_dialog_renders_an_unsupported_backend_without_inventing_zero(dialog):
    dlg = dialog(_snapshot(_row(label="imap", protocol="imap")))
    assert dlg.displayed_cells()[0]["Usage"] == "not supported"


def test_edge_dialog_with_no_connections_says_so(dialog):
    dlg = dialog(_snapshot())
    assert dlg.displayed_labels() == []
    assert "no open connections" in dlg.status_text().lower()


def test_happy_refresh_re_reads_the_snapshot(dialog):
    dlg = dialog(_snapshot(_row(label="a", total=100, used=10, free=90)))
    assert dlg.displayed_cells()[0]["Usage"] == "10%"

    dlg._snapshot_fn = lambda _b: _snapshot(_row(label="a", total=100, used=90, free=10))
    dlg.refresh()
    dlg.wait_for_refresh()
    assert dlg.displayed_cells()[0]["Usage"] == "90%"


# --------------------------------------------------------------------------
# Sad path
# --------------------------------------------------------------------------


def test_sad_snapshot_failure_is_reported_not_raised(dialog):
    def _boom(_backends):
        raise OSError("connection manager unavailable")

    dlg = DiskUsageDialog([], snapshot_fn=_boom)
    dlg.show()
    APP.processEvents()
    dlg.wait_for_refresh()
    try:
        assert dlg.displayed_labels() == []
        assert "connection manager unavailable" in dlg.status_text()
    finally:
        dlg.close()
        dlg.deleteLater()
        APP.processEvents()


# --------------------------------------------------------------------------
# Collecting the backends to measure
# --------------------------------------------------------------------------


class _Pane:
    """Stands in for FilePaneWidget, exposing the same PUBLIC surface.

    Deliberately does NOT define ``_backend``: reaching for a private
    attribute across a module boundary works right up until the owner
    renames it, and FilePaneWidget has published a ``backend`` property
    since it was written.
    """

    def __init__(self, backend):
        self.backend = backend


def test_happy_collect_backends_reads_one_per_pane():
    from ui.disk_usage_dialog import collect_backends

    a, b = object(), object()
    assert collect_backends([_Pane(a), _Pane(b)]) == [a, b]


def test_edge_collect_backends_deduplicates_shared_sessions():
    """Two panes browsing the same host share one backend instance via
    the connection manager. Probing it twice would double the wall time
    and list the same filesystem twice."""
    from ui.disk_usage_dialog import collect_backends

    shared = object()
    assert collect_backends([_Pane(shared), _Pane(shared)]) == [shared]


def test_edge_collect_backends_skips_panes_without_one():
    from ui.disk_usage_dialog import collect_backends

    class _Bare:
        pass

    a = object()
    assert collect_backends([_Bare(), _Pane(a), _Pane(None)]) == [a]
