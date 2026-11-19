"""A local terminal's forked child never runs on as a second axross.

Reproduced 2026-11-19 (independent review): with $SHELL pointing at a
program that does not exist, ``LocalTerminalSession.start`` reached
``os.execve`` in the forked child, execve raised, and nothing called
``os._exit``: the child unwound into the GUI code (the "+ Local" button,
the terminal pane's constructor) and kept running as a hidden copy of the
application. Now the shell and its environment are worked out before the
fork, a $SHELL that is missing or not executable falls back to /bin/sh,
and anything that goes wrong in the child ends it with exit status 127.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("pty")
pytest.importorskip("PyQt6.QtWidgets")

ESCAPED = 3  # the exit status of a child that came back from start()


def _start_guarded(session) -> int:
    """start() *session*; a child that comes back out of it exits ESCAPED
    at once instead of running the rest of the test run a second time."""
    parent = os.getpid()
    try:
        session.start()
    except BaseException:
        if os.getpid() != parent:
            os._exit(ESCAPED)
        raise
    if os.getpid() != parent:
        os._exit(ESCAPED)
    return session._pid


def _exit_status(session, pid: int) -> int:
    _, status = os.waitpid(pid, 0)
    session._pid = None  # reaped here; close() must not wait for it again
    session.close()
    return os.waitstatus_to_exitcode(status)


def test_happy_a_missing_shell_falls_back_to_bin_sh(monkeypatch):
    from ui.terminal_widget import LocalTerminalSession, local_shell

    monkeypatch.setenv("SHELL", "/nonexistent/shell")
    assert local_shell() == "/bin/sh"
    session = LocalTerminalSession()
    pid = _start_guarded(session)
    session.write(b"exit 7\n")
    assert _exit_status(session, pid) == 7


def test_sad_a_shell_that_is_not_executable_falls_back(monkeypatch, tmp_path):
    from ui.terminal_widget import local_shell

    script = tmp_path / "shell"
    script.write_text("#!/bin/sh\n")
    script.chmod(stat.S_IRUSR | stat.S_IWUSR)
    monkeypatch.setenv("SHELL", str(script))
    assert local_shell() == "/bin/sh"
    monkeypatch.setenv("SHELL", str(tmp_path))  # a folder
    assert local_shell() == "/bin/sh"
    monkeypatch.delenv("SHELL")
    assert local_shell() == "/bin/sh"


def test_edge_a_usable_shell_is_kept(monkeypatch):
    from ui.terminal_widget import local_shell

    monkeypatch.setenv("SHELL", "/bin/sh")
    assert local_shell() == "/bin/sh"


def test_sad_a_failing_execve_ends_the_child_with_127(monkeypatch):
    """execve itself fails (ENOEXEC, an unlinked binary, a full process
    table on the way): the child exits 127, it never returns."""
    from ui.terminal_widget import LocalTerminalSession

    def refuse(*_args):
        raise OSError(8, "Exec format error")

    monkeypatch.setenv("SHELL", "/bin/sh")
    monkeypatch.setattr(os, "execve", refuse)
    session = LocalTerminalSession()
    pid = _start_guarded(session)
    assert _exit_status(session, pid) == 127


def test_edge_an_exception_before_execve_ends_the_child_with_127(monkeypatch):
    """Not only execve: an error anywhere after the fork (here the folder
    change raising something unexpected) ends the child too."""
    from ui.terminal_widget import LocalTerminalSession

    def boom(_folder):
        raise RuntimeError("unexpected")

    monkeypatch.setenv("SHELL", "/bin/sh")
    monkeypatch.setattr(os, "chdir", boom)
    session = LocalTerminalSession(cwd="/")
    pid = _start_guarded(session)
    assert _exit_status(session, pid) == 127
