"""The root guard sees the Windows spellings, and ".." never reaches a remove or rename.

Measured before (review round 8, repro guard/smb_backslash_root.py):

* H1 - core.backend_guard normalised paths the POSIX way only. SMB hands
  them to smbclient, which applies Windows rules: ``remove("/x\\\\..",
  recursive=True)`` and ``remove("\\\\", recursive=True)`` deleted every
  file of the share; on WinRM ``C:\\\\Users\\\\..`` and ``c:\\\\.`` were no
  root either (Remove-Item resolves ``..``). Now a backslash separates on
  every backend but one that declares it a name character (LocalFS on
  POSIX), drive roots count after normalising, and a ``..`` component
  (with either separator, or ``C:..``) is refused in remove and in both
  paths of rename. The MCP remote path check refuses ``..`` for mutating
  calls as well;
* L3 - on the database backends ``rename(x, "//")`` stored the data under
  ``//``, which no listing shows: normpath keeps two leading slashes. The
  guard refuses the root as a rename destination too, and the database
  backends collapse leading slashes.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from types import SimpleNamespace as NS

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import test_backend_conformance as C  # noqa: E402

from core.backend_guard import has_parent_component, is_root_path  # noqa: E402
from core.path_policy import BackendPathPolicy  # noqa: E402


def _cleanup(target) -> None:
    for done in target.cleanup:
        try:
            done()
        except Exception:  # noqa: BLE001 - cleanup only
            pass


@pytest.fixture
def smb(tmp_path):
    target = C.MAKERS["smb"](tmp_path)
    b = target.backend
    b.mkdir("/x")
    with b.open_write("/x/keep") as fh:
        fh.write(b"k")
    with b.open_write("/important.docx") as fh:
        fh.write(b"data")
    yield target
    _cleanup(target)


def _share_intact(t) -> None:
    assert sorted(os.listdir(t.local_dir)) == ["important.docx", "x"]
    assert (Path(t.local_dir) / "x" / "keep").read_bytes() == b"k"


class _Ps:
    """pywinrm's run_ps, answering an empty success (no PowerShell here)."""

    def __init__(self) -> None:
        self.scripts: list[str] = []

    def run_ps(self, script):
        self.scripts.append(script)
        return NS(status_code=0, std_out=b"", std_err=b"")


def _winrm():
    from core import winrm_client as W

    s = object.__new__(W.WinRMSession)
    s._session = _Ps()
    return s


# -- happy -------------------------------------------------------------------


def test_happy_smb_an_ordinary_folder_is_still_removed(smb):
    smb.backend.remove("/x", recursive=True)
    assert sorted(os.listdir(smb.local_dir)) == ["important.docx"]


def test_happy_names_with_two_dots_inside_are_no_parent(smb):
    b = smb.backend
    with b.open_write("/a..b") as fh:
        fh.write(b"1")
    with b.open_write("/..c") as fh:
        fh.write(b"2")
    b.rename("/a..b", "/d..")
    b.remove("/d..")
    b.remove("/..c")
    _share_intact(smb)


def test_happy_winrm_an_ordinary_folder_is_removed():
    s = _winrm()
    s.remove("C:\\Users\\x", recursive=True)
    assert len(s._session.scripts) == 1


def test_happy_a_read_tool_keeps_its_dots_over_mcp():
    from core.mcp_groups import check_remote_path

    assert check_remote_path("/a/../b") == "/a/../b"
    assert check_remote_path("/a/b", mutating=True) == "/a/b"
    assert check_remote_path("/a..b/..c", mutating=True) == "/a..b/..c"


# -- sad ---------------------------------------------------------------------


@pytest.mark.parametrize("spelling", ["\\", "/x\\..", "\\x\\..\\", "x\\..", "/x/\\..", "\\\\"])
def test_sad_smb_a_backslash_spelling_of_the_share_root_is_refused(smb, spelling):
    with pytest.raises(PermissionError):
        smb.backend.remove(spelling, recursive=True)
    _share_intact(smb)


@pytest.mark.parametrize("path", ["/x\\..\\important.docx", "/x/../important.docx",
                                  "/x/keep/..", "C:..\\x"])
def test_sad_smb_a_parent_component_is_never_removed(smb, path):
    with pytest.raises(PermissionError):
        smb.backend.remove(path, recursive=True)
    _share_intact(smb)


@pytest.mark.parametrize("src,dst", [
    ("/x", "/"), ("/x", "//"), ("/x", "\\"), ("/x", "/y\\.."),
    ("/x\\..\\important.docx", "/moved"), ("/important.docx", "/x/../moved"),
])
def test_sad_smb_rename_past_or_onto_the_root_is_refused(smb, src, dst):
    with pytest.raises(PermissionError):
        smb.backend.rename(src, dst)
    _share_intact(smb)


@pytest.mark.parametrize("path", ["C:\\Users\\..", "c:\\.", "C:", "C:\\", "c:/.", "\\",
                                  "C:..", "C:\\Users\\..\\Public", "/"])
def test_sad_winrm_a_drive_root_or_parent_never_reaches_powershell(path):
    s = _winrm()
    with pytest.raises(PermissionError):
        s.remove(path, recursive=True)
    with pytest.raises(PermissionError):
        s.rename(path, "C:\\elsewhere")
    with pytest.raises(PermissionError):
        s.rename("C:\\a.txt", path)
    assert s._session.scripts == []


@pytest.fixture(params=sorted(C.MAKERS))
def every(request, tmp_path):
    target = C.MAKERS[request.param](tmp_path)
    try:
        b = target.backend
        b.mkdir(target.J("d"))
        with b.open_write(target.J("d", "f")) as fh:
            fh.write(b"hello")
        with b.open_write(target.J("g")) as fh:
            fh.write(b"other")
        yield target
    finally:
        _cleanup(target)


def _recording(b, reached):
    class Recording(type(b)):
        def remove(self, path, recursive=False):
            reached.append(("remove", path))

        def rename(self, src, dst):
            reached.append(("rename", src, dst))

    return Recording


@pytest.mark.parametrize("sep", ["/", "\\"])
def test_sad_a_parent_component_never_reaches_any_backend(every, sep):
    """remove / rename with ``..`` - checked through a subclass whose
    methods only record, so a gap here could not act on this machine."""
    b = every.backend
    if sep == "\\" and BackendPathPolicy.for_backend(b).literal_backslash:
        pytest.skip(f"{every.name}: a backslash is a name character there")
    up = every.J("d") + sep + ".." + sep + "g"
    reached: list = []
    original = b.__class__
    b.__class__ = _recording(b, reached)
    try:
        with pytest.raises(PermissionError):
            b.remove(up, recursive=True)
        with pytest.raises(PermissionError):
            b.rename(up, every.J("moved"))
        with pytest.raises(PermissionError):
            b.rename(every.J("g"), every.J("d") + sep + ".." + sep + "h")
        for root in ("/", "//"):
            with pytest.raises(PermissionError):
                b.rename(every.J("g"), root)
    finally:
        b.__class__ = original
    assert reached == []
    with b.open_read(every.J("g")) as fh:
        assert fh.read() == b"other"


def test_sad_mcp_refuses_a_parent_component_on_a_mutating_remote_call():
    from core.mcp_groups import check_remote_path

    for path in ("/a/..", "/x\\..", "C:..", "c:\\a\\..\\b", "..", "/a/../b"):
        with pytest.raises(ValueError):
            check_remote_path(path, mutating=True)


def test_sad_mcp_server_passes_mutating_for_remote_writes():
    """The two remote branches of the MCP server's write / entry checks ask
    for the mutating check (source guard: a refactor dropping it fails)."""
    source = (Path(__file__).resolve().parents[1] / "core" / "mcp_server.py").read_text()
    assert source.count("check_remote_path(path, mutating=True)") == 2


def test_sad_sqlite_rename_onto_double_slash_keeps_the_data_visible(tmp_path):
    target = C.MAKERS["sqlite"](tmp_path)
    try:
        b = target.backend
        with b.open_write("/x") as fh:
            fh.write(b"data")
        with pytest.raises(OSError):
            b.rename("/x", "//")
        assert [i.name for i in b.list_dir("/")] == ["x"]
    finally:
        _cleanup(target)


# -- edge --------------------------------------------------------------------


class _Smbish:
    def separator(self):
        return "/"


class _Win:
    def separator(self):
        return "\\"


@pytest.mark.parametrize("path,root", [
    ("\\", True), ("/x\\..", True), ("\\\\", True), ("x\\..", True), ("C:", True),
    ("C:\\", True), ("c:/.", True), ("C:\\Users\\..", True), ("/C:/", True), ("c:.", True),
    ("/", True), ("//", True), ("/a/..", True), ("", True),
    ("C:\\Users", False), ("/x\\y", False), ("C:..", False), ("/a", False),
])
def test_edge_what_counts_as_the_root_where_a_backslash_separates(path, root):
    assert is_root_path(_Smbish(), path) is root
    assert is_root_path(_Win(), path) is root


def test_edge_a_backslash_is_a_name_character_on_local_posix():
    from core.local_fs import LocalFS

    local = LocalFS()
    if not BackendPathPolicy.for_backend(local).literal_backslash:
        pytest.skip("LocalFS splits on backslashes here")
    assert not is_root_path(local, "\\")
    assert not is_root_path(local, "/a\\..")
    assert not has_parent_component(local, "/a\\..")
    assert has_parent_component(local, "/a/../b")


@pytest.mark.parametrize("path,parent", [
    ("/a/../b", True), ("a\\..\\b", True), ("C:..", True), ("c:..\\x", True), ("..", True),
    ("/a..b", False), ("/..a/b..", False), ("/a/...", False), ("/a/b", False), ("", False),
])
def test_edge_what_counts_as_a_parent_component(path, parent):
    assert has_parent_component(_Smbish(), path) is parent


def test_edge_database_paths_collapse_leading_slashes(tmp_path):
    target = C.MAKERS["sqlite"](tmp_path)
    try:
        b = target.backend
        assert b.normalize("//") == "/"
        assert b.normalize("///a//b/") == "/a/b"
        with b.open_write("/x") as fh:
            fh.write(b"data")
        b.rename("/x", "//y")
        assert [i.name for i in b.list_dir("/")] == ["y"]
        with b.open_read("/y") as fh:
            assert fh.read() == b"data"
    finally:
        _cleanup(target)
