"""WinRM: folder copies keep their content, names survive the code page.

* copy() of a folder ran Copy-Item without -Recurse: PowerShell copies the
  container alone, so an MCP copy, a script or a WebDAV COPY made an EMPTY
  folder and reported success. It now copies with -Recurse, and refuses a
  destination that is a folder (or any for a folder): Copy-Item would put
  the copy into it.
* pywinrm opens its shell with code page 437; powershell.exe wrote its
  redirected stdout in it and _run_ps read it as UTF-8 - "Präsentation.pptx"
  was listed as "Pr\\ufffdsentation.pptx" and could not be opened. The
  scripts now ask for UTF-8 output, the names travel base64-encoded too,
  and output that is no UTF-8 is read as code page 437.
* remove / open_read / list_dir of a missing path were bare OSErrors, and
  list_dir of a file listed the file as its own content.

pywinrm's session is replaced by a fake host that runs just enough of each
script against an in-memory file table, writing stdout in code page 437
unless the script switched the console to UTF-8 (and the host allows it).
"""

from __future__ import annotations

import base64
import json
import re
import sys
import types
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import winrm_client as W  # noqa: E402

_UTF8_SWITCH = "[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding"
_NOT_FOUND = "AXROSS-NOT-FOUND"
_NOT_A_DIRECTORY = "AXROSS-NOT-A-DIRECTORY"
_TAKEN = "AXROSS-DESTINATION-EXISTS"


class _Host:
    def __init__(self, files: dict, *, utf8_allowed: bool = True, name64: bool = True):
        self.fs = dict(files)  # path -> bytes | None (folder)
        self.utf8_allowed = utf8_allowed
        self.name64 = name64
        self.scripts: list[str] = []

    def _res(self, script, out="", rc=0, err=""):
        enc = "utf-8" if (self.utf8_allowed and _UTF8_SWITCH in script) else "cp437"
        return types.SimpleNamespace(
            status_code=rc, std_out=out.encode(enc, "replace"), std_err=err.encode(enc, "replace")
        )

    @staticmethod
    def _paths(script):
        return [base64.b64decode(m).decode("utf-8")
                for m in re.findall(r"FromBase64String\('([A-Za-z0-9+/=]+)'\)\)", script)]

    def _row(self, path):
        name = path.rsplit("\\", 1)[1]
        row = {"Name": name, "IsDir": self.fs[path] is None, "Size": len(self.fs[path] or b""),
                "Mtime": "2026-01-01T10:00:00.0000000Z", "IsLink": False, "IsHidden": False}
        if self.name64 and "ToBase64String" in self.scripts[-1]:
            row["Name64"] = base64.b64encode(name.encode()).decode()
        return row

    def _missing(self, script, p):
        return self._res(script, rc=1, err=f"Cannot find path '{p}' because it does not exist.")

    def run_ps(self, script):
        self.scripts.append(script)
        paths = self._paths(script)
        if "Get-ChildItem" in script:
            p = paths[0]
            if p not in self.fs:
                return self._res(script, _NOT_FOUND if _NOT_FOUND in script else "")
            if self.fs[p] is not None:
                if _NOT_A_DIRECTORY in script:
                    return self._res(script, _NOT_A_DIRECTORY)
                return self._res(script, json.dumps([self._row(p)], ensure_ascii=False))
            rows = [self._row(k) for k in self.fs if k.rsplit("\\", 1)[0] == p]
            return self._res(script, json.dumps(rows, ensure_ascii=False))
        if "Copy-Item" in script:
            s, d = paths
            if s not in self.fs:
                return self._missing(script, s)
            taken = d in self.fs
            if taken and _TAKEN in script and (self.fs[s] is None or self.fs[d] is None):
                return self._res(script, _TAKEN)
            self.fs[d] = self.fs[s]
            if self.fs[s] is None and "Copy-Item -Recurse" in script:
                for k in list(self.fs):
                    if k.startswith(s + "\\"):
                        self.fs[d + k[len(s):]] = self.fs[k]
            return self._res(script)
        if "Remove-Item" in script or "ReadAllBytes" in script:
            p = paths[0]
            if p not in self.fs:
                if "ItemNotFoundException" in script:
                    return self._res(script, _NOT_FOUND)
                return self._missing(script, p)
            if "ReadAllBytes" in script:
                return self._res(script, base64.b64encode(self.fs[p]).decode())
            del self.fs[p]
            return self._res(script)
        if "$HOME" in script:
            home = "C:\\Users\\J\u00fcrgen"
            if "ToBase64String" in script:
                return self._res(script, base64.b64encode(home.encode()).decode())
            return self._res(script, home)
        if "Get-Item" in script:
            p = paths[0]
            if p not in self.fs:
                return self._res(script, _NOT_FOUND)
            return self._res(script, json.dumps(self._row(p), ensure_ascii=False))
        return self._res(script)


def _session(host: _Host) -> W.WinRMSession:
    s = W.WinRMSession.__new__(W.WinRMSession)
    s._session = host
    s._host, s._username = "h", "u"
    return s


_TREE = {
    "C:\\data": None,
    "C:\\data\\Pr\u00e4sentation.pptx": b"PPTX",
    "C:\\data\\\u00dcbersicht.xlsx": b"XLSX",
    "C:\\data\\proj": None,
    "C:\\data\\proj\\main.c": b"int main(){}",
    "C:\\data\\proj\\src": None,
    "C:\\data\\proj\\src\\util.c": b"util",
}


# -- copy -------------------------------------------------------------------


def test_sad_copy_of_a_folder_copies_everything_inside():
    host = _Host(_TREE)
    _session(host).copy("C:\\data\\proj", "C:\\data\\proj-copy")
    assert host.fs["C:\\data\\proj-copy\\main.c"] == b"int main(){}"
    assert host.fs["C:\\data\\proj-copy\\src\\util.c"] == b"util"


def test_sad_copy_of_a_folder_onto_an_existing_folder_is_refused():
    host = _Host({**_TREE, "C:\\data\\other": None})
    with pytest.raises(FileExistsError):
        _session(host).copy("C:\\data\\proj", "C:\\data\\other")
    assert "C:\\data\\other\\main.c" not in host.fs
    assert "C:\\data\\other\\proj" not in host.fs


def test_happy_copy_of_a_file_replaces_a_file():
    host = _Host({**_TREE, "C:\\data\\old.c": b"old"})
    _session(host).copy("C:\\data\\proj\\main.c", "C:\\data\\old.c")
    assert host.fs["C:\\data\\old.c"] == b"int main(){}"


def test_sad_copy_of_a_missing_source_is_file_not_found():
    with pytest.raises(FileNotFoundError):
        _session(_Host(_TREE)).copy("C:\\data\\gone", "C:\\data\\gone-copy")


def test_edge_copy_keeps_paths_out_of_the_script_text():
    host = _Host({"C:\\x": None, "C:\\x\\a'; Remove-Item C:\\ -Recurse; '": b"1"})
    s = _session(host)
    s.copy("C:\\x\\a'; Remove-Item C:\\ -Recurse; '", "C:\\x\\b")
    assert "Remove-Item C:" not in host.scripts[-1]


# -- names beyond ASCII -----------------------------------------------------


@pytest.mark.parametrize("utf8_allowed", [True, False], ids=["utf8-output", "codepage-437"])
def test_edge_non_ascii_names_are_listed_as_they_are_and_open(utf8_allowed):
    host = _Host(_TREE, utf8_allowed=utf8_allowed)
    s = _session(host)
    names = sorted(i.name for i in s.list_dir("C:\\data"))
    assert names == sorted(["Pr\u00e4sentation.pptx", "\u00dcbersicht.xlsx", "proj"])
    assert s.stat("C:\\data\\Pr\u00e4sentation.pptx").name == "Pr\u00e4sentation.pptx"
    assert s.open_read("C:\\data\\\u00dcbersicht.xlsx").read() == b"XLSX"


def test_edge_every_file_operation_asks_for_utf8_output():
    host = _Host(_TREE)
    s = _session(host)
    s.list_dir("C:\\data")
    s.stat("C:\\data\\proj")
    s.remove("C:\\data\\proj\\main.c")
    assert host.scripts and all(sc.startswith("try { " + _UTF8_SWITCH) for sc in host.scripts)


def test_edge_code_page_437_output_without_name64_is_read_as_437():
    host = _Host(_TREE, utf8_allowed=False, name64=False)
    names = sorted(i.name for i in _session(host).list_dir("C:\\data"))
    assert names == sorted(["Pr\u00e4sentation.pptx", "\u00dcbersicht.xlsx", "proj"])


def test_edge_home_beyond_ascii():
    assert _session(_Host(_TREE, utf8_allowed=False)).home() == "C:\\Users\\J\u00fcrgen"


# -- what is not there --------------------------------------------------------


def test_sad_remove_open_read_and_list_dir_of_a_missing_path_are_file_not_found():
    s = _session(_Host(_TREE))
    with pytest.raises(FileNotFoundError):
        s.remove("C:\\data\\gone.txt")
    with pytest.raises(FileNotFoundError):
        s.open_read("C:\\data\\gone.txt")
    with pytest.raises(FileNotFoundError):
        s.list_dir("C:\\data\\gone")


def test_sad_list_dir_of_a_file_is_not_a_directory():
    with pytest.raises(NotADirectoryError):
        _session(_Host(_TREE)).list_dir("C:\\data\\proj\\main.c")
