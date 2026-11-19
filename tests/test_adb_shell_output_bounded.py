"""ADB: a shell answer is read under a cap and a deadline (review round 2).

``device.shell()`` (adb_shell) joins every packet of the answer and
waits only for each NEXT packet: a device answering ``ls`` with an
endless stream - or ``exec("cat /dev/zero")`` - filled the memory and
never returned. The answer is now read as a stream: a command's answer
stops at SHELL_OUTPUT_CAP (the connection is then dropped, its rest
unread), exec keeps its stdout_cap and the status trailer and stops at
its timeout.
"""

from __future__ import annotations

import contextlib
import itertools
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import adb_client as A  # noqa: E402


class _Device:
    def __init__(self, chunks):
        self.chunks = chunks
        self.read = 0

    def streaming_shell(self, cmd, transport_timeout_s=None, read_timeout_s=None, decode=True):
        for chunk in self.chunks(str(cmd)):
            self.read += len(chunk)
            yield chunk

    def shell(self, *a, **k):  # the old whole-answer call
        return b"".join(self.streaming_shell(*a, **k))


def _session(chunks):
    s = object.__new__(A.AdbSession)
    s._transport_timeout = 5.0
    s._long_timeout = 30.0
    s._label = "phone"
    s.device = _Device(chunks)
    s.lost = []

    @contextlib.contextmanager
    def channel():
        try:
            yield s.device
        except BaseException as exc:
            s.lost.append(exc)
            raise

    s._command_channel = channel
    s._transfer_channel = channel
    return s


def test_sad_an_endless_answer_stops_at_the_cap(monkeypatch) -> None:
    monkeypatch.setattr(A, "SHELL_OUTPUT_CAP", 1_000_000)
    s = _session(lambda cmd: itertools.repeat(b"x" * 65536))
    with pytest.raises(OSError, match="more than"):
        s._shell("ls -la /sdcard")
    assert s.device.read < 2_000_000
    assert s.lost  # the connection's rest is unread: it is dropped


def test_sad_exec_of_an_endless_command_ends_at_its_timeout(monkeypatch) -> None:
    monkeypatch.setattr(A, "SHELL_OUTPUT_CAP", 1_000_000)
    s = _session(lambda cmd: itertools.repeat(b"y" * 65536))
    with pytest.raises(TimeoutError):
        s.exec("cat /dev/zero", timeout=0.5)


def test_happy_exec_keeps_its_cap_and_the_status(monkeypatch) -> None:
    monkeypatch.setattr(A, "SHELL_OUTPUT_CAP", 1_000_000)

    def answer(cmd):
        tag = cmd.rsplit("echo ", 1)[1].split()[0]
        yield from [b"z" * 65536] * 40  # 2.5 MB, more than the cap
        yield f"{tag} 3\n".encode()

    result = _session(answer).exec("big", stdout_cap=1000)
    assert result.returncode == 3
    assert result.stdout == b"z" * 1000 and result.truncated_stdout


def test_happy_a_short_answer() -> None:
    s = _session(lambda cmd: iter([b"a\n", b"b\n"]))
    assert s._shell("echo") == "a\nb\n"
