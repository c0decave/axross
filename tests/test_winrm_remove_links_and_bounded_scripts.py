"""WinRM (review round 2): deleting through links, scripts without end,
names Windows reads as other names.

* ``Remove-Item -Recurse`` in Windows PowerShell 5.1 (what pywinrm starts)
  goes INTO a directory junction or symlink and deletes what is in its
  target - files outside the folder being deleted. The folder is now
  taken apart by a walk that removes a link itself, never its target.
* Without ``-Recurse``, ``Remove-Item`` on a folder with entries asks
  "has children... continue?" - a question no one answers over WinRM,
  and pywinrm retries its receive for ever: the session hung. The script
  looks first and answers ENOTEMPTY; powershell runs -NonInteractive.
* pywinrm's get_command_output retries a timed-out receive without end:
  a command that never ended held the session (and its lock) for good.
  Each command has a deadline now; then it is stopped (TimeoutError).
* Windows drops a trailing "." or " " of a name: ``foo.`` was ``foo``, so
  a delete of the one removed the other. Such a path is refused.
"""

from __future__ import annotations

import errno
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import winrm_client as W  # noqa: E402

winrm = pytest.importorskip("winrm")


class _Ps:
    def __init__(self, *answers) -> None:
        self.answers = list(answers)
        self.scripts: list[str] = []

    def run_ps(self, script):
        self.scripts.append(script)
        status, out = self.answers.pop(0)
        return NS(status_code=status, std_out=out, std_err=b"" if status == 0 else out)


def _winrm(*answers) -> W.WinRMSession:
    s = object.__new__(W.WinRMSession)
    s._session = _Ps(*answers)
    return s


def test_sad_recursive_remove_never_uses_remove_item_recurse() -> None:
    s = _winrm((0, b""))
    s.remove("C:\\data\\old", recursive=True)
    script = s._session.scripts[0]
    assert "-Recurse" not in script.replace("Get-ChildItem -Force -LiteralPath", "")
    assert "ReparsePoint" in script


def test_sad_non_recursive_remove_of_a_full_folder_is_not_empty() -> None:
    s = _winrm((0, W._NOT_EMPTY.encode()))
    with pytest.raises(OSError) as info:
        s.remove("C:\\data\\full")
    assert info.value.errno == errno.ENOTEMPTY


@pytest.mark.parametrize("path", ["C:\\data\\foo.", "C:\\data\\foo ", "C:\\a. \\x"])
def test_sad_a_name_windows_reads_as_another_is_refused(path) -> None:
    s = _winrm()
    for call in (lambda: s.remove(path), lambda: s.open_read(path), lambda: s.stat(path)):
        with pytest.raises(OSError) as info:
            call()
        assert info.value.errno == errno.EINVAL
    assert s._session.scripts == []


class _NeverEnds:
    def __init__(self):
        self.cleaned = self.closed = False
        self.command = ""

    def open_shell(self, *a, **k):
        return "shell"

    def run_command(self, shell_id, command, args=()):
        self.command = command
        return "cmd"

    def get_command_output_raw(self, shell_id, command_id):
        from winrm.exceptions import WinRMOperationTimeoutError

        raise WinRMOperationTimeoutError()

    def cleanup_command(self, shell_id, command_id):
        self.cleaned = True

    def close_shell(self, shell_id):
        self.closed = True


def _real_session(protocol):
    session = object.__new__(winrm.Session)
    session.protocol = protocol
    s = object.__new__(W.WinRMSession)
    s._session = session
    return s


def test_sad_a_command_without_end_is_stopped_at_its_deadline() -> None:
    proto = _NeverEnds()
    s = _real_session(proto)
    with pytest.raises(TimeoutError):
        s.exec("Start-Sleep 99999", timeout=0.5)
    assert proto.cleaned and proto.closed
    assert "-NonInteractive" in proto.command


class _Answers(_NeverEnds):
    def __init__(self, chunks):
        super().__init__()
        self.chunks = list(chunks)

    def get_command_output_raw(self, shell_id, command_id):
        out = self.chunks.pop(0)
        return out, b"", 0, not self.chunks


def test_happy_a_command_answers() -> None:
    s = _real_session(_Answers([b"hel", b"lo"]))
    result = s.exec("Write-Output hello", timeout=5)
    assert result.stdout == b"hello" and result.returncode == 0
