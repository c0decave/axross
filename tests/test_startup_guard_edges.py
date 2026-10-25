"""The paths of core.startup_guard no test reached (branch coverage, 92 %).

A crash.log that is closed under the watchdog, a parent pipe that is gone
before the window shows, a child that is alive but quiet for a while, a
message split across two reads, JSON that is no object, and the read that
fails: each is a way the startup report could raise in its thread or the
detached parent could miss the child's word.
"""

from __future__ import annotations

import io
import os
import sys
import threading
import time
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import startup_guard as SG  # noqa: E402


class _Child:
    def __init__(self, code=None, pid: int = 4242) -> None:
        self.code = code
        self.pid = pid

    def poll(self):
        return self.code

    def wait(self, timeout=None):
        return self.code


def _write_later(fd: int, parts: list[bytes], gap: float) -> threading.Thread:
    def run():
        for part in parts:
            time.sleep(gap)
            os.write(fd, part)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


# --- helpers -------------------------------------------------------------------------

def test_edge_wait_for_with_no_time_left_asks_once_more():
    assert SG.wait_for(lambda: True, 0) is True
    assert SG.wait_for(lambda: False, 0) is False


def test_happy_the_extension_being_activated_comes_from_core_extensions(monkeypatch):
    fake = types.SimpleNamespace(current_activation=lambda: ("Media Player", 1.5))
    monkeypatch.setitem(sys.modules, "core.extensions", fake)
    assert SG._current_activation() == ("Media Player", 1.5)


def test_edge_core_extensions_not_loaded_names_no_extension(monkeypatch):
    monkeypatch.delitem(sys.modules, "core.extensions", raising=False)
    assert SG._current_activation() is None
    monkeypatch.setitem(sys.modules, "core.extensions", types.SimpleNamespace())
    assert SG._current_activation() is None


def test_edge_on_windows_the_advice_is_the_task_manager(monkeypatch):
    monkeypatch.setattr(os, "name", "nt")
    assert SG._how_to_end(77) == "end it in the Task Manager (pid 77)"
    monkeypatch.setattr(os, "name", "posix")
    assert SG._how_to_end(77) == 'end it with "kill 77"'


# --- the watchdog --------------------------------------------------------------------

def test_sad_a_closed_crash_log_still_gives_the_message(tmp_path):
    """No backstop can be armed on a closed file and the stacks cannot be
    written; the message comes anyway, without a crash.log path."""
    crash = open(tmp_path / "crash.log", "a", encoding="utf-8")
    crash.close()
    err = io.StringIO()
    dog = SG.StartupWatchdog(0.2, crash_file=crash, crash_path=tmp_path / "crash.log",
                             stderr=err, activation=lambda: None)
    dog.start()
    try:
        assert dog._backstop is False
        assert SG.wait_for(lambda: dog.fired, 5.0)
    finally:
        dog.window_shown()
    assert "has not appeared" in err.getvalue()
    assert "could not be written" in err.getvalue()


def test_sad_a_crash_log_closed_before_the_late_window_is_no_error(tmp_path, caplog):
    path = tmp_path / "crash.log"
    crash = open(path, "a", encoding="utf-8")
    dog = SG.StartupWatchdog(0.2, crash_file=crash, crash_path=path, stderr=io.StringIO(),
                             activation=lambda: None)
    dog.start()
    assert SG.wait_for(lambda: dog.fired, 5.0)
    crash.close()
    dog.window_shown()  # no exception
    assert any("appeared after all" in r.getMessage() for r in caplog.records)
    assert "has not appeared" in path.read_text()


def test_sad_a_parent_pipe_closed_already_is_closed_quietly():
    read_fd, write_fd = os.pipe()
    dog = SG.StartupWatchdog(30.0, notify_fd=write_fd, stderr=io.StringIO(),
                             activation=lambda: None)
    os.close(write_fd)
    os.close(read_fd)
    dog.window_shown()  # EBADF on write and on close: no exception
    assert dog._notify_fd is None


def test_edge_a_window_shown_as_the_bound_runs_out_is_not_reported():
    """The thread's wait ends at the bound while window_shown has already
    taken the lock: the report must not come."""
    err = io.StringIO()
    dog = SG.StartupWatchdog(0.01, stderr=err, activation=lambda: None)
    dog._shown = True  # window_shown won the race, the event is not set yet
    dog._run()
    assert not dog.fired and err.getvalue() == ""


# --- the detached parent -------------------------------------------------------------

def test_happy_a_child_quiet_for_a_while_is_still_heard():
    read_fd, write_fd = os.pipe()
    writer = _write_later(write_fd, [b'{"event": "shown"}\n'], 0.6)
    err = io.StringIO()
    try:
        assert SG.await_detached_child(_Child(None), read_fd, 10.0, err, crash_path=None)
    finally:
        writer.join(5)
        os.close(write_fd)
        os.close(read_fd)
    assert err.getvalue() == ""


def test_edge_a_message_split_across_two_reads_is_put_together():
    read_fd, write_fd = os.pipe()
    writer = _write_later(write_fd, [b'{"event": "stal', b'led", "message": "stuck"}\n'], 0.3)
    err = io.StringIO()
    try:
        assert SG.await_detached_child(_Child(None), read_fd, 10.0, err, crash_path=None)
    finally:
        writer.join(5)
        os.close(write_fd)
        os.close(read_fd)
    assert err.getvalue() == "stuck\n"


def test_sad_json_that_is_no_object_is_skipped():
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b'[1, 2]\n"shown"\n42\n{"event": "stalled", "message": "late"}\n')
    err = io.StringIO()
    assert SG.await_detached_child(_Child(None), read_fd, 10.0, err, crash_path=None)
    assert err.getvalue() == "late\n"
    os.close(write_fd)
    os.close(read_fd)


@pytest.mark.parametrize(("code", "started"), [(0, True), (3, False)])
def test_sad_a_failing_read_counts_as_the_child_ending(monkeypatch, code, started):
    read_fd, write_fd = os.pipe()
    os.write(write_fd, b"x")

    def broken(*_a):
        raise OSError("EIO")

    monkeypatch.setattr(os, "read", broken)
    err = io.StringIO()
    try:
        assert SG.await_detached_child(_Child(code), read_fd, 10.0, err,
                                       crash_path=None) is started
    finally:
        monkeypatch.undo()
        os.close(write_fd)
        os.close(read_fd)
    assert ("ended with status 3" in err.getvalue()) is (not started)


def test_sad_a_child_that_ends_while_another_process_holds_the_pipe_is_seen():
    """No EOF comes (the write end is still open elsewhere); poll() tells."""
    read_fd, write_fd = os.pipe()
    err = io.StringIO()
    started = time.monotonic()
    try:
        assert SG.await_detached_child(_Child(5), read_fd, 10.0, err, crash_path=None) is False
    finally:
        os.close(write_fd)
        os.close(read_fd)
    assert time.monotonic() - started < 2.0
    assert "ended with status 5" in err.getvalue()


def test_edge_eof_from_a_child_that_does_not_end_in_time_counts_as_started():
    import subprocess

    class Lingering(_Child):
        def wait(self, timeout=None):
            raise subprocess.TimeoutExpired("axross", timeout)

    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    err = io.StringIO()
    assert SG.await_detached_child(Lingering(None), read_fd, 10.0, err, crash_path=None)
    assert err.getvalue() == ""
    os.close(read_fd)
