"""WMI: exists() and is_dir() say False only for "not found".

exists() and is_dir() turned every stat() failure into False - a DCOM
connect that failed, an ExecQuery refused with WBEM_E_ACCESS_DENIED - and
_exec_query ended the enumeration on ANY exception of Next(), so a
connection dropped mid-query looked like "no rows", which stat() reported
as "not found" as well. server_side_copy(overwrite=False) and the transfer
worker take False as the go-ahead to write.

impacket ends an enumeration with WBEM_S_FALSE (Next() raises
DCERPCSessionError code 0x1 when fewer objects than asked for remain);
that, or an empty batch, is the end. Every other failure is an OSError,
and stat() raises FileNotFoundError only when both WQL classes answer
with no row. There is no in-process DCOM server: a fake WBEM service
answers instead.
"""

from __future__ import annotations

import pytest

wmi = pytest.importorskip("impacket.dcerpc.v5.dcom.wmi")

from impacket.dcerpc.v5.rpcrt import DCERPCException  # noqa: E402

from core.wmi_client import WMISession  # noqa: E402

S_FALSE = wmi.DCERPCSessionError(error_code=1)
ACCESS_DENIED = wmi.DCERPCSessionError(error_code=0x80041003)
FILE = {
    "Name": "c:\\a.txt",
    "FileName": "a",
    "Extension": "txt",
    "FileSize": "5",
    "LastModified": "20240102030405.000000+000",
}
DIR = {"Name": "c:\\sub", "FileName": "sub", "Extension": ""}


class _Obj:
    def __init__(self, props, *, broken=False):
        self._props, self._broken = props, broken

    def getProperties(self):  # noqa: N802 - impacket's name
        if self._broken:
            raise ValueError("unpack requires a buffer of 4 bytes")
        return {k: {"value": v} for k, v in self._props.items()}


class _Enum:
    """Hands out the rows one by one, then ends like impacket does:
    ``end`` is raised (S_FALSE) or returned (an empty batch)."""

    def __init__(self, rows, end):
        self._rows, self._end = list(rows), end

    def Next(self, timeout, count):  # noqa: N802
        if self._rows:
            return [self._rows.pop(0)]
        if isinstance(self._end, BaseException):
            raise self._end
        return []

    def RemRelease(self):  # noqa: N802
        pass


class _Wbem:
    def __init__(self, objects, *, end=S_FALSE, query_fails=None):
        self.objects = objects  # (WQL class, Name literal) -> _Obj
        self.end, self.query_fails = end, query_fails

    def ExecQuery(self, query):  # noqa: N802
        if self.query_fails is not None:
            raise self.query_fails
        rows = [o for (cls, name), o in self.objects.items()
                if f"FROM {cls} WHERE Name = '{name}'" in query]
        return _Enum(rows, self.end)


def _wmi(wbem=None, *, connect_fails=None) -> WMISession:
    s = WMISession.__new__(WMISession)
    s._host, s._username, s._password = "h", "u", "p"
    wbem = wbem or _Wbem({})

    def connect():
        if connect_fails is not None:
            raise connect_fails
        return wbem

    s._connect = connect
    return s


def _tree(**kw) -> _Wbem:
    return _Wbem({("CIM_DataFile", "C:\\\\a.txt"): _Obj(FILE),
                  ("Win32_Directory", "C:\\\\sub"): _Obj(DIR)}, **kw)


@pytest.mark.parametrize("end", [S_FALSE, None])
def test_happy_present_and_absent(end):
    s = _wmi(_tree(end=end))
    assert s.exists("C:\\a.txt") is True
    assert s.exists("C:\\sub") is True
    assert s.exists("C:\\gone.txt") is False
    assert s.is_dir("C:\\sub") is True
    assert s.is_dir("C:\\gone") is False


def test_happy_stat_of_a_missing_path_is_file_not_found():
    with pytest.raises(FileNotFoundError):
        _wmi(_tree()).stat("C:\\gone.txt")


@pytest.mark.parametrize(
    "where, fail",
    [
        ("connect", OSError("WMI DCOM connect to h: [Errno 111] Connection refused")),
        ("query", ACCESS_DENIED),
        ("query", DCERPCException("RPC_E_DISCONNECTED")),
        ("next", DCERPCException("RPC_E_DISCONNECTED")),
        ("next", ACCESS_DENIED),
        ("next", ConnectionResetError("reset by peer")),
    ],
)
def test_sad_a_failed_answer_is_an_oserror(where, fail):
    if where == "connect":
        s = _wmi(connect_fails=fail)
    elif where == "query":
        s = _wmi(_tree(query_fails=fail))
    else:
        s = _wmi(_tree(end=fail))
    for probe in (lambda: s.exists("C:\\gone.txt"), lambda: s.is_dir("C:\\gone")):
        with pytest.raises(OSError) as info:
            probe()
        assert not isinstance(info.value, FileNotFoundError)


def test_sad_a_row_that_cannot_be_read_is_not_absence():
    s = _wmi(_Wbem({("CIM_DataFile", "C:\\\\a.txt"): _Obj(FILE, broken=True)}))
    with pytest.raises(OSError) as info:
        s.exists("C:\\a.txt")
    assert not isinstance(info.value, FileNotFoundError)


def test_edge_a_file_is_no_folder():
    assert _wmi(_tree()).is_dir("C:\\a.txt") is False


def test_edge_a_listing_still_skips_a_row_it_cannot_read():
    # list_dir keeps what it can read: one broken entry does not hide
    # the folder's other entries.
    wbem = _tree()

    class _Listing(_Wbem):
        def ExecQuery(self, query):  # noqa: N802
            if "WHERE Drive" in query and "CIM_DataFile" in query:
                return _Enum([_Obj(FILE), _Obj(FILE, broken=True)], S_FALSE)
            if "WHERE Drive" in query:
                return _Enum([], S_FALSE)
            return wbem.ExecQuery(query)

    names = [i.name for i in _wmi(_Listing({})).list_dir("C:\\")]
    assert names == ["a.txt"]
