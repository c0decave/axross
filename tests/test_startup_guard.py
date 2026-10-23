"""The startup watchdog: a window that does not come up is reported.

Incident: on a laptop with an NVIDIA driver the main thread hung inside the
Media Player extension's activate() (QAudioDecoder -> cuInit) before the
window was shown. The process ran, no window came and nobody said a word;
only ``kill -USR1`` revealed where it stood. core.startup_guard arms a
watchdog in the GUI start: when the window has not been shown within the
bound it writes every thread's stack to crash.log, says on stderr (and in
the log) what happened and what to do, and tells the parent of a detached
start, which prints it on the terminal.
"""

from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import startup_guard as SG  # noqa: E402


def _crash(tmp_path: Path):
    path = tmp_path / "crash.log"
    return path, open(path, "a", encoding="utf-8")


def _read_lines(fd: int, seconds: float = 5.0) -> list[dict]:
    """JSON lines from the read end of a notify pipe until EOF or timeout."""
    import select

    data = b""
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        ready, _, _ = select.select([fd], [], [], 0.05)
        if ready:
            chunk = os.read(fd, 65536)
            if not chunk:
                break
            data += chunk
    return [json.loads(line) for line in data.decode().splitlines() if line.strip()]


# --- happy -----------------------------------------------------------------


def test_happy_a_window_that_never_shows_is_reported_with_every_stack(tmp_path):
    path, handle = _crash(tmp_path)
    err = io.StringIO()
    dog = SG.StartupWatchdog(0.3, crash_file=handle, crash_path=path, stderr=err,
                             activation=lambda: None)
    dog.start()
    try:
        assert SG.wait_for(lambda: dog.fired, 5.0)
    finally:
        dog.window_shown()
        handle.close()
    text = path.read_text()
    assert "startup watchdog" in text
    # faulthandler's all-thread dump, this test's frame among them
    assert "Thread 0x" in text or "Current thread 0x" in text
    assert "test_startup_guard.py" in text
    message = err.getvalue()
    assert "has not appeared after 0.3 s" in message
    assert f"pid {os.getpid()}" in message
    assert str(path) in message
    assert "--safe-mode" in message


def test_happy_a_window_shown_in_time_cancels_everything(tmp_path):
    path, handle = _crash(tmp_path)
    err = io.StringIO()
    dog = SG.StartupWatchdog(0.5, crash_file=handle, crash_path=path, stderr=err,
                             activation=lambda: None)
    dog.start()
    dog.window_shown()
    time.sleep(0.9)
    handle.close()
    assert not dog.fired
    assert path.read_text() == ""
    assert err.getvalue() == ""


def test_happy_the_message_names_the_extension_being_activated(tmp_path):
    path, handle = _crash(tmp_path)
    err = io.StringIO()
    dog = SG.StartupWatchdog(
        0.2, crash_file=handle, crash_path=path, stderr=err,
        activation=lambda: ("user:sleeper", "Sleeper", 12.5),
    )
    dog.start()
    try:
        assert SG.wait_for(lambda: dog.fired, 5.0)
    finally:
        dog.window_shown()
        handle.close()
    message = err.getvalue()
    assert '"Sleeper" (user:sleeper)' in message
    assert "next start does not load it" in message


def test_happy_the_detached_parent_hears_shown_and_stalled(tmp_path):
    read_fd, write_fd = os.pipe()
    dog = SG.StartupWatchdog(5.0, notify_fd=write_fd, stderr=io.StringIO(),
                             activation=lambda: None)
    dog.start()
    dog.window_shown()
    assert _read_lines(read_fd) == [{"event": "shown"}]
    os.close(read_fd)

    read_fd, write_fd = os.pipe()
    dog = SG.StartupWatchdog(0.2, notify_fd=write_fd, stderr=io.StringIO(),
                             activation=lambda: None)
    dog.start()
    assert SG.wait_for(lambda: dog.fired, 5.0)
    dog.window_shown()
    events = _read_lines(read_fd)
    os.close(read_fd)
    assert [e["event"] for e in events] == ["stalled", "shown"]
    assert "has not appeared" in events[0]["message"]


def test_happy_a_late_window_is_noted_in_the_crash_log(tmp_path):
    path, handle = _crash(tmp_path)
    dog = SG.StartupWatchdog(0.2, crash_file=handle, crash_path=path, stderr=io.StringIO(),
                             activation=lambda: None)
    dog.start()
    assert SG.wait_for(lambda: dog.fired, 5.0)
    dog.window_shown()
    handle.close()
    assert "window shown after" in path.read_text()


@pytest.mark.parametrize(
    ("value", "expected"),
    [(None, SG.WATCHDOG_SECONDS), ("5", 5.0), ("2.5", 2.5), ("0", 0.0)],
)
def test_happy_the_bound_comes_from_the_environment(value, expected):
    environ = {} if value is None else {SG.WATCHDOG_ENV: value}
    assert SG.watchdog_seconds(environ) == expected


def test_happy_the_parent_returns_once_the_child_shows_its_window():
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b'{"event": "shown"}\n')
    err = io.StringIO()
    child = _FakeChild(None)
    started = time.monotonic()
    assert SG.await_detached_child(child, read_fd, 10.0, err, crash_path=None) is True
    assert time.monotonic() - started < 2.0
    assert err.getvalue() == ""
    os.close(write_fd)


def test_happy_the_parent_prints_the_childs_stall_message():
    read_fd, write_fd = os.pipe()
    os.write(write_fd, (json.dumps({"event": "stalled", "message": "axross: stuck\nline 2"})
                        + "\n").encode())
    err = io.StringIO()
    assert SG.await_detached_child(_FakeChild(None), read_fd, 10.0, err, crash_path=None) is True
    assert err.getvalue() == "axross: stuck\nline 2\n"
    os.close(write_fd)


# --- sad -------------------------------------------------------------------


@pytest.mark.parametrize("value", ["abc", "-3", "nan", "inf", ""])
def test_sad_a_bad_bound_falls_back_to_the_default(value):
    assert SG.watchdog_seconds({SG.WATCHDOG_ENV: value}) == SG.WATCHDOG_SECONDS


def test_sad_without_a_crash_log_the_message_still_comes(tmp_path):
    err = io.StringIO()
    dog = SG.StartupWatchdog(0.2, crash_file=None, crash_path=None, stderr=err,
                             activation=lambda: None)
    dog.start()
    try:
        assert SG.wait_for(lambda: dog.fired, 5.0)
    finally:
        dog.window_shown()
    assert "has not appeared" in err.getvalue()
    assert "could not be written" in err.getvalue()


def test_sad_a_parent_that_is_gone_does_not_break_the_child():
    read_fd, write_fd = os.pipe()
    os.close(read_fd)  # the parent exited: writes fail with EPIPE
    dog = SG.StartupWatchdog(0.2, notify_fd=write_fd, stderr=io.StringIO(),
                             activation=lambda: None)
    dog.start()
    assert SG.wait_for(lambda: dog.fired, 5.0)
    dog.window_shown()  # no exception


def test_sad_a_closed_stderr_does_not_break_the_watchdog(tmp_path):
    err = io.StringIO()
    err.close()
    dog = SG.StartupWatchdog(0.2, stderr=err, activation=lambda: None)
    dog.start()
    assert SG.wait_for(lambda: dog.fired, 5.0)
    dog.window_shown()


def test_sad_an_activation_lookup_that_raises_is_left_out(tmp_path):
    err = io.StringIO()

    def broken():
        raise RuntimeError("boom")

    dog = SG.StartupWatchdog(0.2, stderr=err, activation=broken)
    dog.start()
    assert SG.wait_for(lambda: dog.fired, 5.0)
    dog.window_shown()
    assert "has not appeared" in err.getvalue()
    assert "boom" not in err.getvalue()


@pytest.mark.parametrize("value", ["x", "-1", "999999", ""])
def test_sad_a_bad_notify_fd_is_ignored_and_forgotten(value):
    environ = {SG.NOTIFY_FD_ENV: value}
    assert SG.take_notify_fd(environ) is None
    assert SG.NOTIFY_FD_ENV not in environ


def test_sad_a_descriptor_that_is_no_pipe_is_never_the_parents_channel(tmp_path):
    with open(tmp_path / "plain", "w") as handle:
        environ = {SG.NOTIFY_FD_ENV: str(handle.fileno())}
        assert SG.take_notify_fd(environ) is None


def test_sad_a_child_that_dies_at_once_is_reported_and_runs_in_the_foreground():
    read_fd, write_fd = os.pipe()
    os.close(write_fd)  # EOF: the child is gone
    err = io.StringIO()
    assert SG.await_detached_child(_FakeChild(1), read_fd, 10.0, err, crash_path=None) is False
    assert "status 1" in err.getvalue()
    assert "foreground" in err.getvalue()


def test_sad_a_child_that_never_says_anything_is_reported_at_the_deadline(tmp_path):
    read_fd, write_fd = os.pipe()
    err = io.StringIO()
    crash = tmp_path / "crash.log"
    started = time.monotonic()
    assert SG.await_detached_child(_FakeChild(None, pid=4242), read_fd, 0.5, err,
                                   crash_path=crash) is True
    assert time.monotonic() - started < 3.0
    text = err.getvalue()
    assert "has not appeared after 0.5 s" in text
    assert "4242" in text
    assert str(crash) in text
    assert "--safe-mode" in text
    os.close(write_fd)


# --- edge ------------------------------------------------------------------


def test_edge_a_quiet_wait_says_nothing_at_its_deadline():
    # The watchdog switched off: the parent only checks for an immediate
    # failure, as it did before the watchdog existed.
    read_fd, write_fd = os.pipe()
    err = io.StringIO()
    assert SG.await_detached_child(_FakeChild(None), read_fd, 0.3, err, crash_path=None,
                                   report_timeout=False) is True
    assert err.getvalue() == ""
    os.close(write_fd)
    os.close(read_fd)


def test_edge_a_disabled_watchdog_never_starts_a_thread():
    before = threading.active_count()
    dog = SG.StartupWatchdog(0.0, stderr=io.StringIO(), activation=lambda: None)
    dog.start()
    assert threading.active_count() == before
    dog.window_shown()
    assert not dog.fired


def test_edge_window_shown_twice_and_start_twice_are_harmless(tmp_path):
    read_fd, write_fd = os.pipe()
    dog = SG.StartupWatchdog(5.0, notify_fd=write_fd, stderr=io.StringIO(),
                             activation=lambda: None)
    dog.start()
    dog.start()
    dog.window_shown()
    dog.window_shown()
    assert _read_lines(read_fd) == [{"event": "shown"}]
    os.close(read_fd)


def test_edge_the_stacks_are_written_once_not_again_by_the_backstop(tmp_path, monkeypatch):
    # faulthandler's own timer is the backstop for a main thread that holds
    # the GIL; once the Python watchdog has written the stacks it is cancelled.
    monkeypatch.setattr(SG, "BACKSTOP_SECONDS", 0.3)
    path, handle = _crash(tmp_path)
    dog = SG.StartupWatchdog(0.2, crash_file=handle, crash_path=path, stderr=io.StringIO(),
                             activation=lambda: None)
    dog.start()
    assert SG.wait_for(lambda: dog.fired, 5.0)
    time.sleep(0.8)
    dog.window_shown()
    handle.close()
    text = path.read_text()
    assert text.count("Timeout (") == 0
    assert text.count("startup watchdog: the main window") == 1


def test_edge_the_backstop_writes_the_stacks_when_python_cannot(tmp_path, monkeypatch):
    # The Python thread never gets to run (stand-in: its fire is a no-op):
    # faulthandler's C thread still writes every stack.
    monkeypatch.setattr(SG, "BACKSTOP_SECONDS", 0.2)
    monkeypatch.setattr(SG.StartupWatchdog, "_fire", lambda self: None)
    path, handle = _crash(tmp_path)
    dog = SG.StartupWatchdog(0.2, crash_file=handle, crash_path=path, stderr=io.StringIO(),
                             activation=lambda: None)
    dog.start()
    time.sleep(1.0)
    dog.window_shown()
    handle.close()
    assert "Timeout (" in path.read_text()


def test_edge_the_notify_fd_is_taken_once_and_not_inherited(tmp_path):
    read_fd, write_fd = os.pipe()
    os.set_inheritable(write_fd, True)
    environ = {SG.NOTIFY_FD_ENV: str(write_fd)}
    assert SG.take_notify_fd(environ) == write_fd
    assert SG.NOTIFY_FD_ENV not in environ
    assert os.get_inheritable(write_fd) is False  # a shell started later must not hold it
    assert SG.take_notify_fd(environ) is None
    os.close(read_fd)
    os.close(write_fd)


def test_edge_a_child_that_ends_cleanly_without_a_word_counts_as_started():
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    err = io.StringIO()
    assert SG.await_detached_child(_FakeChild(0), read_fd, 10.0, err, crash_path=None) is True
    assert err.getvalue() == ""


def test_edge_a_stall_message_with_a_window_after_it_is_printed_once():
    read_fd, write_fd = os.pipe()
    os.write(write_fd, (json.dumps({"event": "stalled", "message": "stuck"}) + "\n"
                        + json.dumps({"event": "shown"}) + "\n").encode())
    err = io.StringIO()
    assert SG.await_detached_child(_FakeChild(None), read_fd, 10.0, err, crash_path=None) is True
    assert err.getvalue() == "stuck\n"
    os.close(write_fd)


def test_edge_garbage_on_the_channel_is_skipped():
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"not json\n{\"event\": \"other\"}\n{\"event\": \"shown\"}\n")
    err = io.StringIO()
    assert SG.await_detached_child(_FakeChild(None), read_fd, 10.0, err, crash_path=None) is True
    assert err.getvalue() == ""
    os.close(write_fd)


class _FakeChild:
    def __init__(self, code, pid: int = 4242) -> None:
        self._code = code
        self.pid = pid

    def poll(self):
        return self._code

    def wait(self, timeout=None):
        if self._code is None:
            raise subprocess.TimeoutExpired(cmd="axross", timeout=timeout)
        return self._code
