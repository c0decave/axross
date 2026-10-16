"""WMI: property values of the wrong type read safely; fuzz of the row reader.

WMISession._row_to_item (core/wmi_client.py) read the WMI properties
unchecked: ``int(row["FileSize"])`` raised ValueError for a size that is
no number, ``row["Name"].rsplit`` AttributeError for a Name that is no
string, and _parse_dmtf ``value.strip()`` AttributeError for a
LastModified that is no string. impacket's DCOM transport is replaced by
a fake enumerator here (there is no in-process DCOM / WMI server); the
rows it yields are what a broken or hostile WMI provider can return.
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations  # noqa: E402

from core.wmi_client import WMISession  # noqa: E402


class _Obj:
    def __init__(self, props: dict) -> None:
        self._props = props

    def getProperties(self):  # noqa: N802 - impacket's name
        return {k: {"value": v} for k, v in self._props.items()}


class _Enum:
    def __init__(self, rows) -> None:
        self._rows = list(rows)

    def Next(self, timeout, count):  # noqa: N802 - impacket's name
        return [_Obj(self._rows.pop(0))] if self._rows else []

    def RemRelease(self):  # noqa: N802
        pass


class _Wbem:
    def __init__(self, dirs, files) -> None:
        self.dirs, self.files = dirs, files

    def ExecQuery(self, query):  # noqa: N802
        return _Enum(self.dirs if "Win32_Directory" in query else self.files)


def _session(dirs, files) -> WMISession:
    s = WMISession.__new__(WMISession)
    s._host, s._username, s._password = "h", "u", "p"
    wbem = _Wbem(dirs, files)
    s._connect = lambda: wbem
    return s


FILE = {
    "Name": "c:\\a.txt",
    "FileName": "a",
    "Extension": "txt",
    "FileSize": "5",
    "LastModified": "20240102030405.000000+000",
}


def test_happy_listing():
    s = _session([{"Name": "c:\\sub"}], [FILE])
    assert sorted((i.name, i.size, i.is_dir) for i in s.list_dir("C:\\")) == [
        ("a.txt", 5, False),
        ("sub", 0, True),
    ]


@pytest.mark.parametrize(
    "row",
    [
        {**FILE, "FileSize": "abc"},
        {**FILE, "FileName": None, "Name": 5},
        {**FILE, "LastModified": 5},
        {**FILE, "FileSize": "9" * 5000},
        {**FILE, "Extension": 7},
    ],
    ids=["size", "name", "mtime", "huge-size", "extension"],
)
def test_sad_properties_of_the_wrong_type(row):
    [item] = _session([], [row]).list_dir("C:\\")
    assert isinstance(item.name, str) and isinstance(item.size, int) and item.size >= 0


def test_edge_random_rows():
    values = [None, 0, -1, 5, "", "abc", "5", "c:\\x\\y", b"\xff", 1.5, [], {}, "2024"]
    keys = ["Name", "FileName", "Extension", "FileSize", "LastModified", "Drive", "Path"]
    rng = random.Random(0x574D49)
    for n in range(iterations(400)):
        rows = [
            {k: rng.choice(values) for k in rng.sample(keys, rng.randint(0, len(keys)))}
            for _ in range(rng.randint(0, 3))
        ]
        s = _session(rows, rows)
        result = check_contract(lambda: s.list_dir("C:\\"), (OSError,), context=f"case {n}")
        for item in result:
            assert isinstance(item.name, str) and isinstance(item.size, int)
        check_contract(lambda: s.stat("C:\\a.txt"), (OSError,), context=f"case {n} stat")
