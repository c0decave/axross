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


# -- what axross sets for itself at run time -----------------------------------------

def test_happy_runtime_vars_set_by_a_test_are_taken_back(monkeypatch):
    from tests.env_guard import RUNTIME_VARS, restore_runtime_env, snapshot_runtime_env

    for name in RUNTIME_VARS:
        monkeypatch.delenv(name, raising=False)
    saved = snapshot_runtime_env()
    os.environ["QT_AUDIO_BACKEND"] = "pulseaudio"   # what multimedia_probe.probe() does
    os.environ["SSL_CERT_FILE"] = "/etc/ssl/cert.pem"
    restore_runtime_env(saved)
    assert "QT_AUDIO_BACKEND" not in os.environ and "SSL_CERT_FILE" not in os.environ


def test_edge_a_runtime_var_the_run_started_with_is_put_back(monkeypatch):
    from tests.env_guard import restore_runtime_env, snapshot_runtime_env

    monkeypatch.setenv("QT_AUDIO_BACKEND", "pipewire")
    saved = snapshot_runtime_env()
    os.environ["QT_AUDIO_BACKEND"] = "pulseaudio"
    restore_runtime_env(saved)
    assert os.environ["QT_AUDIO_BACKEND"] == "pipewire"


def test_edge_the_registries_forget_what_was_taken_back(monkeypatch):
    from core import multimedia_env, tls_env
    from tests.env_guard import restore_runtime_env, snapshot_runtime_env

    monkeypatch.delenv("QT_AUDIO_BACKEND", raising=False)
    saved = snapshot_runtime_env()
    multimedia_env.apply_audio_backend("pulseaudio")
    assert "QT_AUDIO_BACKEND" in multimedia_env.set_by_axross()
    restore_runtime_env(saved)
    assert "QT_AUDIO_BACKEND" not in multimedia_env.set_by_axross()
    assert "SSL_CERT_FILE" not in tls_env.set_by_axross() or "SSL_CERT_FILE" in os.environ
