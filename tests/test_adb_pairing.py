"""First pairing: the phone asks "Allow USB debugging?" - axross says so.

Review 2026-11-18 (finding 5): a new key gave the user 15 s to find,
unlock and answer the phone, with no word that the phone was asking; a
slower answer, Deny or none ended in "ADB connect to h:5555 failed:
Reading from h:5555 timed out (15.0 seconds)".

Now the connect waits a minute for the answer, tells whoever listens
(core.connect_notice: the Test Connection status line, the status bar)
to check the phone, and a phone that did not allow it is named as such.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

adb = pytest.importorskip("core.adb_client")
if not adb.ADB_SHELL_AVAILABLE:  # pragma: no cover - optional dependency
    pytest.skip("adb-shell not installed", allow_module_level=True)

from core import connect_notice  # noqa: E402
from core.user_errors import describe  # noqa: E402
from tests.fake_adbd import FakeAdbd, make_device_tree  # noqa: E402


@pytest.fixture()
def tree(tmp_path):
    root = str(tmp_path / "device")
    make_device_tree(root)
    return root


@pytest.fixture()
def key(tmp_path):
    return str(tmp_path / "android" / "adbkey")


def test_happy_the_user_is_told_to_check_the_phone_and_has_a_minute(tree, key):
    assert adb.DEFAULT_AUTH_TIMEOUT >= 60
    device = FakeAdbd(tree, auth="key", accept_delay=1.0)
    notices: list[str] = []
    try:
        with connect_notice.receiving(notices.append):
            s = adb.AdbSession("127.0.0.1", device.port, adb_key_path=key)
        assert s.list_dir("/sdcard")
        s.close()
    finally:
        device.stop()
    assert device.prompts == 1
    assert len(notices) == 1 and "Check the phone" in notices[0]
    assert "Always allow" in notices[0]


def test_sad_no_answer_in_time_names_the_phone_not_a_read_time_out(tree, key):
    device = FakeAdbd(tree, auth="key", prompt_answer="never")
    try:
        started = time.monotonic()
        with pytest.raises(adb.AdbAuthTimeout) as info:
            adb.AdbSession("127.0.0.1", device.port, adb_key_path=key, auth_timeout=1)
        assert time.monotonic() - started < 5
    finally:
        device.stop()
    text = describe(info.value)
    assert "Allow USB debugging" in text and "Always allow" in text
    assert "Reading from" not in text


def test_sad_a_phone_that_closes_the_connection_on_deny_is_named_too(tree, key):
    device = FakeAdbd(tree, auth="key", prompt_answer="deny", accept_delay=0.2)
    try:
        with pytest.raises(adb.AdbAuthTimeout):
            adb.AdbSession("127.0.0.1", device.port, adb_key_path=key, auth_timeout=5)
    finally:
        device.stop()


def test_edge_an_authorized_key_connects_without_a_notice(tree, key):
    adb.ensure_adb_key(key)
    device = FakeAdbd(tree, auth="key", authorized=[Path(key + ".pub").read_text()])
    notices: list[str] = []
    try:
        with connect_notice.receiving(notices.append):
            adb.AdbSession("127.0.0.1", device.port, adb_key_path=key).close()
    finally:
        device.stop()
    assert notices == [] and device.prompts == 0


def test_edge_notices_go_only_to_the_thread_that_listens():
    seen: list[str] = []
    connect_notice.notify("nobody listens")
    with connect_notice.receiving(seen.append):
        connect_notice.notify("one")
    connect_notice.notify("after")
    assert seen == ["one"]


def test_happy_the_main_window_connect_worker_passes_the_notice_on():
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication

    from core.connect_worker import run_connect

    app = QApplication.instance() or QApplication([])

    class _Manager:
        def connect(self, profile, **_kwargs):
            connect_notice.notify("Check the phone")
            return object()

        def release(self, profile):
            pass

    seen: list[str] = []
    done: list[object] = []
    task = run_connect(_Manager(), object(), on_notice=seen.append, on_success=done.append)
    deadline = time.monotonic() + 10
    while not done and time.monotonic() < deadline:
        app.processEvents()
        time.sleep(0.01)
    task.thread.wait(5000)
    assert done and seen == ["Check the phone"]
