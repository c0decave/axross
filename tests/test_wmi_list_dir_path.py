"""WMI list_dir asks for the folder it was given, in WQL's own escaping.

The review of 2026-10-17 (B1) ran list_dir("C:\\Windows") against a
recording WMI fake: it sent ``Drive = 'C:' AND Path = '\\'`` - the
listing of C:\\, the parent - because join(path, "") dropped the empty
part and the code then took the folder for a file and listed its parent.
The Path literal also carried single backslashes, while stat doubles
them as WQL string literals need ("Path = '\\\\Windows\\\\'").
"""

from __future__ import annotations

import pytest

from core.wmi_client import WMISession


class _Obj:
    def __init__(self, props):
        self._props = props

    def getProperties(self):  # noqa: N802 - impacket's name
        return {k: {"value": v} for k, v in self._props.items()}


class _Enum:
    def __init__(self, rows):
        self._rows = list(rows)

    def Next(self, timeout, count):  # noqa: N802
        return [_Obj(self._rows.pop(0))] if self._rows else []

    def RemRelease(self):  # noqa: N802
        pass


class _Wbem:
    """Answers Name = '...' lookups from *objects*; records every query."""

    def __init__(self, objects):
        self.objects = objects  # WQL Name literal -> (class, row)
        self.queries = []

    def ExecQuery(self, query):  # noqa: N802
        self.queries.append(query)
        for literal, (cls, row) in self.objects.items():
            if f"FROM {cls} WHERE Name = '{literal}'" in query:
                return _Enum([row])
        return _Enum([])


def _session(objects=None):
    s = WMISession.__new__(WMISession)
    s._host, s._username, s._password = "h", "u", "p"
    wbem = _Wbem(objects or {})
    s._connect = lambda: wbem
    return s, wbem


def _listing_paths(wbem):
    return [q.split("AND Path = ", 1)[1] for q in wbem.queries if "AND Path = " in q]


def test_happy_a_folder_lists_itself_with_doubled_backslashes():
    s, wbem = _session({"C:\\\\Windows": ("Win32_Directory", {"Name": "c:\\windows"})})
    s.list_dir("C:\\Windows")
    assert _listing_paths(wbem) == ["'\\\\Windows\\\\'", "'\\\\Windows\\\\'"]
    assert all("Drive = 'C:'" in q for q in wbem.queries if "AND Path" in q)


def test_happy_a_nested_folder_and_forward_slashes():
    s, wbem = _session({"C:\\\\Users\\\\alex": ("Win32_Directory", {"Name": "c:\\users\\alex"})})
    s.list_dir("C:/Users/alex/")
    assert _listing_paths(wbem)[0] == "'\\\\Users\\\\alex\\\\'"


def test_sad_a_file_is_not_a_folder():
    s, wbem = _session(
        {"C:\\\\Windows\\\\notepad.exe": ("CIM_DataFile", {"Name": "c:\\windows\\notepad.exe"})}
    )
    with pytest.raises(NotADirectoryError):
        s.list_dir("C:\\Windows\\notepad.exe")
    assert _listing_paths(wbem) == []


def test_sad_a_missing_folder_is_an_oserror_not_an_empty_listing():
    s, wbem = _session()
    with pytest.raises(OSError, match="not found"):
        s.list_dir("C:\\nope")
    assert _listing_paths(wbem) == []


def test_edge_the_drive_root_and_a_quote_in_a_name():
    s, wbem = _session({"C:\\\\O''Brien": ("Win32_Directory", {"Name": "c:\\o'brien"})})
    s.list_dir("C:\\")
    assert _listing_paths(wbem)[0] == "'\\\\'"
    wbem.queries.clear()
    s.list_dir("C:\\O'Brien")
    assert _listing_paths(wbem)[0] == "'\\\\O''Brien\\\\'"
