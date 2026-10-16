"""WinRM: PowerShell output of the wrong shape is an OSError or skipped.

The backend parses the JSON its PowerShell scripts print. A host (or
anything in the remote session's profile) controls that output, and
_parse_json_array returned array elements unchecked: a number or string
element made _parse_listing_row raise AttributeError (``row.get``), a
``Size`` that is no number ValueError (``int()``), and json.loads let
RecursionError (nesting deeper than the C stack) and ValueError (an
integer above the digit limit) through - only JSONDecodeError was
caught. cim_query had the same json.loads gap. Found by
tests/test_fuzz_winrm.py.
"""

from __future__ import annotations

import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.winrm_client import WinRMSession  # noqa: E402


class FakePs:
    def __init__(self, out: bytes = b"", status: int = 0, err: bytes = b"") -> None:
        self.out, self.status, self.err = out, status, err

    def run_ps(self, script):
        return types.SimpleNamespace(status_code=self.status, std_out=self.out, std_err=self.err)


def session(out: bytes, status: int = 0) -> WinRMSession:
    s = WinRMSession.__new__(WinRMSession)
    s._session = FakePs(out, status)
    s._host, s._username = "h", "u"
    return s


ROW = (
    b'{"Name":"a.txt","IsDir":false,"Size":5,"Mtime":"2024-01-02T03:04:05.1234567Z","IsLink":false}'
)


def test_happy_listing():
    [item] = session(ROW).list_dir("C:\\")
    assert (item.name, item.size, item.is_dir) == ("a.txt", 5, False)


@pytest.mark.parametrize(
    "out",
    [b"[1, 2]", b'["x"]', b"[null]", b"[[{}]]"],
    ids=["numbers", "strings", "null", "nested"],
)
def test_sad_array_elements_that_are_not_objects_are_skipped(out):
    assert session(out).list_dir("C:\\") == []


@pytest.mark.parametrize(
    "out", [b"[" * 100000 + b"]" * 100000, b'{"Size":' + b"9" * 5000 + b"}"], ids=["deep", "bigint"]
)
def test_sad_undecodable_json_is_an_oserror(out):
    with pytest.raises(OSError):
        session(out).list_dir("C:\\")
    with pytest.raises(OSError):
        session(out).cim_query("SELECT * FROM Win32_OperatingSystem")


def test_edge_fields_of_the_wrong_type():
    out = (
        b'[{"Name":"s","Size":"abc"},{"Name":5,"Size":1},{"Name":"","Size":1},'
        b'{"Name":"m","Mtime":5},{"Name":"n","Size":-3}]'
    )
    items = {i.name: i for i in session(out).list_dir("C:\\")}
    assert set(items) == {"s", "m", "n"}
    assert [items[n].size for n in ("s", "n")] == [0, 0]


def test_edge_stat_of_a_non_object_is_an_oserror():
    with pytest.raises(OSError):
        session(b"[5]").stat("C:\\a.txt")
