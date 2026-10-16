"""The test-suite guard for the variables that keep a run isolated.

A hardening test pointed XDG_CACHE_HOME at its own temp folder and never
put it back; every later test then cached outside the run's private home
and the home-isolation check failed far from the cause.
"""

from __future__ import annotations

import os

from tests.env_guard import ISOLATION_VARS, restore_isolation_env, snapshot_isolation_env


def test_happy_an_untouched_environment_reports_nothing() -> None:
    assert restore_isolation_env(snapshot_isolation_env()) == {}


def test_sad_a_changed_variable_is_restored_and_reported(monkeypatch) -> None:
    saved = snapshot_isolation_env()
    os.environ["XDG_CACHE_HOME"] = "/elsewhere"
    try:
        assert restore_isolation_env(saved) == {"XDG_CACHE_HOME": "/elsewhere"}
        assert os.environ.get("XDG_CACHE_HOME") == saved["XDG_CACHE_HOME"]
    finally:
        restore_isolation_env(saved)


def test_edge_a_removed_or_added_variable_counts_too() -> None:
    saved = snapshot_isolation_env()
    removed = "XDG_STATE_HOME"
    os.environ.pop(removed, None)
    try:
        changes = restore_isolation_env(saved)
        assert removed in changes and changes[removed] is None
        assert os.environ.get(removed) == saved[removed]
    finally:
        restore_isolation_env(saved)
    assert {"HOME", "PYTHON_KEYRING_BACKEND"} <= set(ISOLATION_VARS)
