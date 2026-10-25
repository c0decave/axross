"""tests/settings_testkit.isolate(): what it patches is undone with the test.

Found: a test that called isolate() and closed its windows but never
called restore() left ``Path.home`` a MagicMock for every later test, and
tests/test_suite_home_isolation.py failed far away from the cause.
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest import mock

import pytest

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from tests.settings_testkit import app, isolate  # noqa: E402

app()


def test_happy_isolate_points_home_into_the_test(tmp_path):
    with pytest.MonkeyPatch.context() as mp:
        stores = isolate(tmp_path, mp)
        assert Path.home() == stores.home == tmp_path / "home"
        stores.restore()


def test_sad_a_forgotten_restore_does_not_leak_the_home_patch(tmp_path):
    real = Path.home
    with pytest.MonkeyPatch.context() as mp:
        isolate(tmp_path, mp)
        assert Path.home() == tmp_path / "home"
    # the monkeypatch ended without restore(): Path.home must be real again
    assert not isinstance(Path.home, mock.Mock)
    assert Path.home == real
    assert Path.home() != tmp_path / "home"


def test_edge_restore_and_then_the_monkeypatch_undo_both_work(tmp_path):
    real = Path.home
    with pytest.MonkeyPatch.context() as mp:
        stores = isolate(tmp_path, mp)
        stores.restore()
        stores.restore()  # twice: no error, nothing patched twice
    assert Path.home == real
