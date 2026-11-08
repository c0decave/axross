"""WinRM rename() refuses an existing destination.

The caps declare ``rename_overwrites=False``, but rename() ran
``Move-Item -Force``: an existing file at the destination was replaced
(and onto a folder Move-Item moves the source INTO it). The script now
looks with Get-Item first and answers a marker instead of moving; that
is FileExistsError. A destination that is the source itself under
another case (a case-only rename) still goes on.

pywinrm is replaced by a session whose run_ps answers from a script
(pywinrm itself is not needed): there is no PowerShell on the test host.
"""

from __future__ import annotations

from types import SimpleNamespace as NS

import pytest

from core import winrm_client as W
from core.backend_registry import WINRM_CAPS


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


# -- happy -------------------------------------------------------------------


def test_happy_a_free_destination_is_moved():
    s = _winrm((0, b""))
    s.rename("C:\\a.txt", "C:\\b.txt")
    assert "Move-Item" in s._session.scripts[0]


# -- sad ---------------------------------------------------------------------


def test_sad_an_existing_destination_is_file_exists():
    s = _winrm((0, W._DESTINATION_TAKEN.encode() + b"\r\n"))
    with pytest.raises(FileExistsError):
        s.rename("C:\\a.txt", "C:\\b.txt")


def test_sad_the_script_looks_before_it_moves():
    s = _winrm((0, b""))
    s.rename("C:\\a.txt", "C:\\b.txt")
    script = s._session.scripts[0]
    assert script.index("Get-Item -Force -LiteralPath $d") < script.index("Move-Item")
    assert W._DESTINATION_TAKEN in script


# -- edge --------------------------------------------------------------------


def test_edge_the_caps_promise_no_overwrite():
    assert WINRM_CAPS.rename_overwrites is False


def test_edge_a_case_only_rename_compares_the_full_names():
    s = _winrm((0, b""))
    s.rename("C:\\a.txt", "C:\\A.txt")
    assert "$taken.FullName -ne $item.FullName" in s._session.scripts[0]
