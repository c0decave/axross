"""Every test run gets a home of its own, before any test module is imported.

Modules take their paths from Path.home() at import time
(core.i18n.SETTINGS_FILE and others), and a test window saves its session on
close. Without this, a run wrote the user's real ~/.config/axross and could
reach the user's keyring. The user site (where PyQt6 may live) is kept for
child processes by pinning PYTHONUSERBASE to where it was.
"""

from __future__ import annotations

import atexit
import os
import shutil
import site
import tempfile

if not os.environ.get("AXROSS_TEST_HOME"):
    os.environ.setdefault("PYTHONUSERBASE", site.getuserbase())
    _home = tempfile.mkdtemp(prefix="axross-test-home-")
    atexit.register(shutil.rmtree, _home, ignore_errors=True)
    os.environ["AXROSS_TEST_HOME"] = _home
    os.environ["HOME"] = _home
    for _name, _sub in (
        ("XDG_CONFIG_HOME", ".config"),
        ("XDG_DATA_HOME", ".local/share"),
        ("XDG_CACHE_HOME", ".cache"),
        ("XDG_STATE_HOME", ".local/state"),
    ):
        os.environ[_name] = os.path.join(_home, _sub)
    os.environ["PYTHON_KEYRING_BACKEND"] = "keyring.backends.null.Keyring"


import pytest  # noqa: E402
import unittest  # noqa: E402
import unittest.case  # noqa: E402

#: subTest parameter values execnet can send from an xdist worker as they are.
_PLAIN = (str, int, float, bool, type(None))
_original_sub_test = unittest.TestCase.subTest


def _sub_test_with_plain_params(self, msg=unittest.case._subtest_msg_sentinel, **params):
    """unittest's subTest, with every parameter that is not a plain value
    passed as its repr: under ``pytest -n`` the subtest report travels
    through execnet, which refuses an enum or an exception ("DumpError:
    can't serialize") and fails a test that passes in one process."""
    plain = {k: v if isinstance(v, _PLAIN) else repr(v) for k, v in params.items()}
    return _original_sub_test(self, msg, **plain)


unittest.TestCase.subTest = _sub_test_with_plain_params


@pytest.fixture(autouse=True)
def _temp_directory_unchanged():
    """Fail the test that moves the process-wide temp directory, and put it
    back (see tests/tempdir_guard.py)."""
    import tempfile

    from tests.tempdir_guard import restore_tempdir

    saved = tempfile.tempdir
    yield
    moved = restore_tempdir(saved)
    if moved is not None:
        pytest.fail(
            f"this test moved tempfile.tempdir to {moved!r}; later tests would "
            "write their temp files there",
            pytrace=False,
        )


@pytest.fixture(autouse=True)
def _isolation_env_unchanged():
    """Fail the test that changes HOME, an XDG directory or the keyring
    backend without restoring it, and put it back (tests/env_guard.py)."""
    from tests.env_guard import restore_isolation_env, snapshot_isolation_env

    saved = snapshot_isolation_env()
    yield
    changed = restore_isolation_env(saved)
    if changed:
        pytest.fail(
            f"this test left {sorted(changed)} changed; later tests would leave "
            "the run's private home",
            pytrace=False,
        )


@pytest.fixture(autouse=True)
def _axross_runtime_env_restored():
    """Take back what axross set for itself during the test (the audio
    backend, the CA bundle, no GPU probing - tests/env_guard.py)."""
    from tests.env_guard import restore_runtime_env, snapshot_runtime_env

    saved = snapshot_runtime_env()
    yield
    restore_runtime_env(saved)


@pytest.fixture(autouse=True)
def _no_held_modifier_keys():
    """Release any keyboard modifier a test left held.

    QApplication keeps the last key event's modifiers process-wide; a
    leaked Shift turned every later selectRow() into a Shift-range
    selection that selected nothing (see tests/qt_modifier_guard.py).
    Under the offscreen platform every QTest event with a modifier
    leaves it held, so a held modifier is not the test's fault - only a
    release that does not take is an error.
    """
    yield
    import sys

    if "PyQt6.QtWidgets" not in sys.modules:
        return
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance()
    if app is None or app.keyboardModifiers() == Qt.KeyboardModifier.NoModifier:
        return
    from tests.qt_modifier_guard import release_held_modifiers

    held = release_held_modifiers(app)
    if app.keyboardModifiers() != Qt.KeyboardModifier.NoModifier:
        pytest.fail(
            f"this test left {held} held and releasing it did not take; "
            "later tests would see it pressed",
            pytrace=False,
        )
