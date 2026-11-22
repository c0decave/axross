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
import sys
import tempfile

#: The pytest-xdist worker this process is ("" without -n). A worker inherits
#: the controller's environment, home included: under -n every worker shared
#: one home, and two test files writing bookmarks.json or the profiles at the
#: same time saw each other's entries (tests/test_terminal_bookmarks.py and
#: tests/test_terminal_host_bookmarks.py failed together, never alone). Each
#: worker makes a home of its own; a child process of a test keeps its own.
_WORKER = os.environ.get("PYTEST_XDIST_WORKER", "")

if (not os.environ.get("AXROSS_TEST_HOME")
        or os.environ.get("AXROSS_TEST_HOME_WORKER", "") != _WORKER):
    os.environ.setdefault("PYTHONUSERBASE", site.getuserbase())
    _home = tempfile.mkdtemp(prefix=f"axross-test-home-{_WORKER or 'main'}-")
    atexit.register(shutil.rmtree, _home, ignore_errors=True)
    os.environ["AXROSS_TEST_HOME"] = _home
    os.environ["AXROSS_TEST_HOME_WORKER"] = _WORKER
    os.environ["HOME"] = _home
    for _name, _sub in (
        ("XDG_CONFIG_HOME", ".config"),
        ("XDG_DATA_HOME", ".local/share"),
        ("XDG_CACHE_HOME", ".cache"),
        ("XDG_STATE_HOME", ".local/state"),
    ):
        os.environ[_name] = os.path.join(_home, _sub)
    os.environ["PYTHON_KEYRING_BACKEND"] = "keyring.backends.null.Keyring"


# -- a network that accepts every connection --------------------------------
#
# The lab tests decide whether the podman lab is up by connecting to it
# (``socket.create_connection((LAB_HOST, port), timeout=0.5)``). Behind a
# proxy that accepts every connection (a sandbox that relays or holds each
# one until it is allowed), that connect always succeeds: the lab tests
# then ran against a lab that is not there - an SMB login hung on its
# error box and an xdist worker aborted, taking ~5000 tests with it.
# 192.0.2.1 (TEST-NET-1, RFC 5737) can never answer on a real network; if
# a connect to it succeeds, the lab subnet counts as unreachable for the
# run: connections into it are refused, as they would be without the
# proxy. AXROSS_TEST_LAB=1 says the lab is really there all the same.
import ipaddress  # noqa: E402
import socket  # noqa: E402

#: The podman lab's subnet (the addresses the lab tests probe, e.g. tests/test_remote_sweep.py).
LAB_NETWORK = ipaddress.ip_network("10.99.0.0/16")


def _network_accepts_everything() -> bool:
    known = os.environ.get("AXROSS_TEST_ACCEPT_ALL_NET")
    if known in ("0", "1"):
        return known == "1"
    try:
        with socket.create_connection(("192.0.2.1", 9), timeout=0.3):
            found = True
    except OSError:
        found = False
    os.environ["AXROSS_TEST_ACCEPT_ALL_NET"] = "1" if found else "0"  # workers inherit it
    return found


def _in_lab(address) -> bool:
    try:
        return ipaddress.ip_address(str(address[0])) in LAB_NETWORK
    except (ValueError, TypeError, IndexError):
        return False


if os.environ.get("AXROSS_TEST_LAB") != "1" and _network_accepts_everything():
    _create_connection = socket.create_connection
    _socket_connect = socket.socket.connect
    _socket_connect_ex = socket.socket.connect_ex

    def _refuse(address):
        return ConnectionRefusedError(
            111, f"{address[0]}: the lab counts as unreachable - this network accepts "
                 "every connection (set AXROSS_TEST_LAB=1 if the lab is really up)")

    def _lab_aware_create_connection(address, *args, **kwargs):
        if _in_lab(address):
            raise _refuse(address)
        return _create_connection(address, *args, **kwargs)

    def _lab_aware_connect(self, address):
        if _in_lab(address):
            raise _refuse(address)
        return _socket_connect(self, address)

    def _lab_aware_connect_ex(self, address):
        if _in_lab(address):
            return 111
        return _socket_connect_ex(self, address)

    socket.create_connection = _lab_aware_create_connection
    socket.socket.connect = _lab_aware_connect
    socket.socket.connect_ex = _lab_aware_connect_ex


import pytest  # noqa: E402
import unittest  # noqa: E402
import unittest.case  # noqa: E402


@pytest.hookimpl(wrapper=True)
def pytest_runtest_call(item):
    """A Markdown window's stress test whose heartbeat froze (tests/markdown_heartbeat.py's Frozen) is run
    once more before it fails: its budget is a few tenths of a second, which a second pytest beside it can
    take now and then - a freeze of the window's own fails both times."""
    try:
        return (yield)
    except AssertionError as error:
        heartbeat = sys.modules.get("tests.markdown_heartbeat")
        if heartbeat is None or not isinstance(error, heartbeat.Frozen):
            raise
        return heartbeat.measure_again(item.runtest, error)


def pytest_configure(config):
    """core.cloud_http pauses before it retries a 429 / 5xx answer (seconds,
    up to the server's Retry-After): every test of a fake cloud service that
    answers errors would wait. Set once for the run, without a fixture;
    tests that look at the pauses patch ``cloud_http._sleep`` themselves."""
    from core import cloud_http

    cloud_http._sleep = lambda _seconds: None
    from tests.markdown_timing import configure

    configure(config)  # (the markers timing and budgets; under -m "not timing" a budget missed is a warning)


def pytest_collection_modifyitems(config, items):
    """The Markdown reader's tests that pass or fail by elapsed time only get the marker ``timing``, those
    that assert their content and a duration (budget()) ``budgets`` (tests/markdown_timing.py): ``-m "not
    timing"`` leaves the first out where a slow runner would fail them without a bug, and makes a budget
    missed a warning. Locally the whole suite runs, at full strictness."""
    from tests.markdown_timing import mark

    mark(items)


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


# -- exceptions that escape into Qt -----------------------------------------
#
# An exception raised in a Python slot or event handler (changeEvent, a
# lambda on a signal) goes to sys.excepthook; with Python's own hook in place
# PyQt6 calls qFatal() and the process aborts. axross installs its own hook
# (main.py), the test run did not: one stray exception - often from a widget
# an earlier test left behind, met by the next app-wide restyle - aborted an
# xdist worker and every test still scheduled on it never ran. Recorded
# here instead, and the test it happened in fails with the traceback.
import traceback  # noqa: E402

_escaped: list[str] = []


def _record_escaped(exc_type, exc, tb) -> None:
    text = "".join(traceback.format_exception(exc_type, exc, tb))
    _escaped.append(text)
    sys.__stderr__.write("exception escaped into Qt:\n" + text)


if sys.excepthook is sys.__excepthook__:
    sys.excepthook = _record_escaped


@pytest.fixture(autouse=True)
def _markdown_theme_reset():
    """The Markdown reader's page theme (ui.markdown_theme_ui's ThemeHub, one a process) back to "auto"
    after a test, and what it kept in axross's settings gone: one test's View > Theme is no later test's."""
    yield
    module = sys.modules.get("ui.markdown_theme_ui")
    if module is None or not module._HUB:
        return
    import time

    hub = module._HUB[0]
    try:
        hub._timer.stop()
    except RuntimeError:  # (deleted with its application)
        module._HUB.clear()
        return
    hub._pending, hub._theme, hub._applied, hub.clock = None, "auto", float("-inf"), time.monotonic
    try:
        from core import open_limits

        if open_limits.read_setting(module.AXROSS_SETTING) is not None:
            open_limits.write_setting(module.AXROSS_SETTING, "auto")
    except Exception:  # noqa: BLE001 - an unreadable settings file: nothing kept to undo
        pass


@pytest.fixture(autouse=True)
def _no_exception_escaped_into_qt():
    del _escaped[:]
    yield
    if _escaped:
        found = list(_escaped)
        del _escaped[:]
        pytest.fail("an exception escaped into a Qt slot or event handler during this "
                    "test:\n\n" + "\n".join(found), pytrace=False)


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


def _icon_state(module) -> tuple:
    return (module._monochrome, module._tint, module._backdrop, dict(module._ICON_COLORS))


@pytest.fixture(autouse=True)
def _icon_provider_restored():
    """Put ui.icon_provider's process-wide look back after the test:
    monochrome, the theme's tint and backdrop and the icon colours. A test
    that applied a theme or a setting left them set, and a later test's
    icons were drawn in them - test_window_icons' monochrome switch then
    changed nothing and failed, depending on which tests ran before it.
    The module is not imported here (a test without Qt never loads it)."""
    module = sys.modules.get("ui.icon_provider")
    saved = _icon_state(module) if module is not None else None
    yield
    module = sys.modules.get("ui.icon_provider")
    if module is None:
        return
    if saved is None:  # loaded during the test: back to the module's defaults
        saved = (False, None, None, None)
    if _icon_state(module)[:3] == saved[:3] and (
            saved[3] is None or _icon_state(module)[3] == saved[3]):
        return
    if saved[3] is not None:
        module._ICON_COLORS.clear()
        module._ICON_COLORS.update(saved[3])
    module._monochrome, module._tint, module._backdrop = saved[:3]
    module._render_icon.cache_clear()


@pytest.fixture(autouse=True)
def _shared_audio_settings_restored():
    """Put axross's audio settings back after the test: the run's home's
    ~/.config/axross/audio.json and core.audio_route's copy of it. They
    outlive a test: the Media Player's equalizer row saves its bands there
    and every later panel takes them, so a band one test moved re-tuned a
    later test's track (tests/test_media_player_controls.py's restored
    position read a ramp 6% high - "2.655 s for 2.5 s" - after the
    equalizer-slider test, in 5 of 8 runs)."""
    path = os.path.join(os.environ["AXROSS_TEST_HOME"], ".config", "axross", "audio.json")
    try:
        with open(path, "rb") as fh:
            before = fh.read()
    except FileNotFoundError:
        before = None
    yield
    try:
        with open(path, "rb") as fh:
            after = fh.read()
    except FileNotFoundError:
        after = None
    if after != before:
        if before is None:
            os.unlink(path)
        else:
            with open(path, "wb") as fh:
                fh.write(before)
            os.chmod(path, 0o600)
    route = sys.modules.get("core.audio_route")
    if route is not None:
        route.forget()  # its copy is read from the file again


@pytest.fixture(autouse=True)
def _no_held_mouse_buttons():
    """Release any mouse button a test left held (tests/qt_modifier_guard.py):
    under the offscreen platform QTest.mouseDClick leaves it held, and the
    docks are not fitted while a button is down."""
    yield
    import sys

    if "PyQt6.QtWidgets" not in sys.modules:
        return
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QApplication

    app = QApplication.instance()
    # a QCoreApplication (a test of core code made one) has no mouse or keyboard
    if not isinstance(app, QApplication) or app.mouseButtons() == Qt.MouseButton.NoButton:
        return
    from tests.qt_modifier_guard import release_held_mouse_buttons

    held = release_held_mouse_buttons(app)
    if app.mouseButtons() != Qt.MouseButton.NoButton:
        pytest.fail(
            f"this test left {held} held and releasing it did not take; "
            "later tests would see it pressed",
            pytrace=False,
        )


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
    # a QCoreApplication (a test of core code made one) has no mouse or keyboard
    if not isinstance(app, QApplication) or app.keyboardModifiers() == Qt.KeyboardModifier.NoModifier:
        return
    from tests.qt_modifier_guard import release_held_modifiers

    held = release_held_modifiers(app)
    if app.keyboardModifiers() != Qt.KeyboardModifier.NoModifier:
        pytest.fail(
            f"this test left {held} held and releasing it did not take; "
            "later tests would see it pressed",
            pytrace=False,
        )


# --------------------------------------------------------------------------
# Reports with undecodable names reach the xdist controller
# --------------------------------------------------------------------------
# A test about a non-UTF-8 name (a surrogate such as "\udce9") logs that
# name; its captured log travels in the report, and execnet cannot encode a
# surrogate: the worker died with UnicodeEncodeError and every test still
# scheduled on it was silently dropped (about 500 in one run). The report is
# made serialisable here, with surrogates shown as \udcXX escapes.


def _plain_report_value(value):
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return value.encode("utf-8", "backslashreplace").decode("utf-8")
        return value
    if isinstance(value, dict):
        return {_plain_report_value(k): _plain_report_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return type(value)(_plain_report_value(v) for v in value)
    return value


@pytest.hookimpl(hookwrapper=True)
def pytest_report_to_serializable(report):
    outcome = yield
    data = outcome.get_result()
    if data is not None:
        outcome.force_result(_plain_report_value(data))
