"""WinRM: exists() and is_dir() say False only for "not found".

exists() turned every OSError of _run_ps into False - a WinRM transport
error, a refused login, a script that failed with "access denied" - and
read any answer other than "YES" as "NO". is_dir() did the same with
every stat() failure. server_side_copy(overwrite=False) takes False as its
go-ahead to write over the file it was told to keep.

Both scripts now answer "not found" themselves, from Get-Item's
ItemNotFoundException; every other failure ends the script with an error
(a non-zero exit, an OSError here). pywinrm is replaced by a session whose
run_ps answers from a script: there is no PowerShell on the test host.
"""

from __future__ import annotations

import json
from types import SimpleNamespace as NS

import pytest

pytest.importorskip("winrm")

from winrm.exceptions import WinRMTransportError  # noqa: E402

from core import winrm_client as W  # noqa: E402
from core.server_ops import server_side_copy  # noqa: E402

FILE_ROW = {"Name": "a.txt", "IsDir": False, "Size": 3, "Mtime": "2026-01-01T00:00:00Z",
            "IsLink": False}
DIR_ROW = dict(FILE_ROW, Name="sub", IsDir=True, Size=0)


class _Ps:
    """run_ps: each answer is (status, stdout) or an exception to raise."""

    def __init__(self, *answers) -> None:
        self.answers = list(answers)
        self.scripts: list[str] = []

    def run_ps(self, script):
        self.scripts.append(script)
        answer = self.answers.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        status, out = answer
        return NS(status_code=status, std_out=out, std_err=b"" if status == 0 else out)


def _winrm(*answers) -> W.WinRMSession:
    s = object.__new__(W.WinRMSession)
    s._session = _Ps(*answers)
    return s


def test_happy_exists_present_and_absent():
    assert _winrm((0, b"YES\r\n")).exists("C:\\a.txt") is True
    assert _winrm((0, b"NO\r\n")).exists("C:\\gone.txt") is False


def test_happy_is_dir_folder_file_and_absent():
    assert _winrm((0, json.dumps(DIR_ROW).encode())).is_dir("C:\\sub") is True
    assert _winrm((0, json.dumps(FILE_ROW).encode())).is_dir("C:\\a.txt") is False
    assert _winrm((0, b"AXROSS-NOT-FOUND\r\n")).is_dir("C:\\gone") is False


def test_happy_stat_not_found_is_file_not_found():
    with pytest.raises(FileNotFoundError):
        _winrm((0, b"AXROSS-NOT-FOUND\r\n")).stat("C:\\gone")


def test_happy_the_scripts_tell_not_found_apart_from_other_errors():
    s = _winrm((0, b"NO\r\n"), (0, b"AXROSS-NOT-FOUND\r\n"))
    s.exists("C:\\gone.txt")
    s.is_dir("C:\\gone")
    for script in s._session.scripts:
        assert "catch [System.Management.Automation.ItemNotFoundException]" in script
        assert "-ErrorAction Stop" in script
        # Test-Path answers $false for a path it may not read, too.
        assert "Test-Path" not in script


@pytest.mark.parametrize(
    "answer",
    [
        WinRMTransportError("http", 500, "Bad HTTP response returned from server. Code 500"),
        ConnectionResetError("connection reset by peer"),
        TimeoutError("read timed out"),
        (1, b"Get-Item : Access to the path 'C:\\secret' is denied."),
    ],
)
def test_sad_a_failed_answer_is_an_oserror(answer):
    with pytest.raises(OSError) as info:
        _winrm(answer).exists("C:\\a.txt")
    assert not isinstance(info.value, FileNotFoundError)
    with pytest.raises(OSError) as info:
        _winrm(answer).is_dir("C:\\sub")
    assert not isinstance(info.value, FileNotFoundError)


@pytest.mark.parametrize("out", [b"", b"yes", b"#< CLIXML\r\n", b"YES\r\nNO\r\n"])
def test_sad_an_unreadable_exists_answer_is_an_oserror(out):
    with pytest.raises(OSError, match="exists"):
        _winrm((0, out)).exists("C:\\a.txt")


def test_sad_no_clobber_copy_keeps_the_target_when_the_probe_fails():
    s = _winrm(WinRMTransportError("http", 500, "Bad HTTP response"), (0, b""))
    with pytest.raises(OSError):
        server_side_copy(s, "C:\\new.txt", "C:\\keep.txt", overwrite=False)
    # Only the failed probe went out - no Copy-Item.
    assert len(s._session.scripts) == 1


def test_edge_an_empty_stat_answer_is_not_absence():
    with pytest.raises(OSError) as info:
        _winrm((0, b"")).is_dir("C:\\sub")
    assert not isinstance(info.value, FileNotFoundError)


def test_edge_append_to_a_missing_file_still_starts_empty():
    # open_write(append=True) asks exists() after a failed read: "NO" is
    # a missing file, the write goes ahead from empty.
    s = _winrm((1, b"Cannot find path"), (0, b"NO\r\n"), (0, b""))
    with s.open_write("C:\\new.bin", append=True) as fh:
        fh.write(b"x")
    assert len(s._session.scripts) == 3
