"""The test-suite guard for the process-wide temp directory.

tempfile.tempdir is global: one test that ran main() in-process routed it
to tmpfs, and every later test's temp files went there - the suite's
home-isolation check then failed far away from the cause.
"""

from __future__ import annotations

import tempfile

from tests.tempdir_guard import restore_tempdir


def test_happy_an_unchanged_temp_directory_reports_nothing() -> None:
    assert restore_tempdir(tempfile.tempdir) is None


def test_sad_a_moved_temp_directory_is_restored_and_reported(tmp_path) -> None:
    before = tempfile.tempdir
    tempfile.tempdir = str(tmp_path)
    try:
        assert restore_tempdir(before) == str(tmp_path)
        assert tempfile.tempdir == before
    finally:
        tempfile.tempdir = before


def test_edge_none_is_a_valid_saved_value(tmp_path) -> None:
    # tempfile.tempdir is None until gettempdir() runs for the first time.
    before = tempfile.tempdir
    tempfile.tempdir = str(tmp_path)
    try:
        assert restore_tempdir(None) == str(tmp_path)
        assert tempfile.tempdir is None
    finally:
        tempfile.tempdir = before
