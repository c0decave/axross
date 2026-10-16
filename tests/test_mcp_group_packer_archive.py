"""MCP capability groups ``packer`` and ``archive``.

packer: pack_formats (read-only), pack (mutating). archive: archive_list
(read-only), archive_extract (mutating). Output always lands under the MCP
root under a fresh name.
"""

from __future__ import annotations

import io
import os
import tarfile
import threading
import zipfile

import pytest

from core import mcp_server as M
from tests import mcp_group_testkit as T

SECRET = "pw-must-never-be-logged"


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "root"
    (root / "docs").mkdir(parents=True)
    (root / "docs" / "a.txt").write_text("alpha\n")
    (root / "docs" / "b.txt").write_text("beta\n")
    (root / "single.txt").write_text("one file\n")
    (tmp_path / "outside.txt").write_text("secret outside\n")
    return root


def _pk(root, write=True, groups=("packer",)):
    return T.build(root, set(groups), allow_write=write)


# -- pack_formats / gating ----------------------------------------------------------


def test_happy_pack_formats_without_write(tree):
    tools = _pk(tree, write=False)
    assert "pack" not in tools
    formats = {f["format"]: f for f in T.call(tools, "pack_formats", {})["formats"]}
    assert formats["zip"]["available"] is True and formats["zip"]["suffix"] == ".zip"
    assert formats["7z"]["encrypts"] is True and formats["zip"]["encrypts"] is False
    assert formats["gz"]["single"] is True


# -- pack -------------------------------------------------------------------------


def test_happy_pack_zip_and_never_overwrite(tree, caplog):
    T.capture_audit(caplog)
    tools = _pk(tree)
    args = {"folder": str(tree), "names": ["docs", "single.txt"], "archive_name": "bundle"}
    first = T.call(tools, "pack", args)
    second = T.call(tools, "pack", args)
    assert first["path"] == str(tree / "bundle.zip")
    assert second["path"] == str(tree / "bundle (2).zip")
    assert first["files"] == 3 and first["folders"] == 1
    with zipfile.ZipFile(first["path"]) as zf:
        assert set(zf.namelist()) == {"docs/", "docs/a.txt", "docs/b.txt", "single.txt"}
        assert zf.read("docs/a.txt") == b"alpha\n"
    lines = T.audit_lines(caplog)
    assert any("tool=pack outcome=attempt" in ln for ln in lines)
    assert any("tool=pack outcome=ok" in ln and "bundle.zip" in ln for ln in lines)


def test_happy_pack_tar_gz(tree):
    out = T.call(
        _pk(tree),
        "pack",
        {"folder": str(tree / "docs"), "names": ["a.txt"], "archive_name": "t", "format": "tar.gz"},
    )
    with tarfile.open(out["path"]) as tf:
        assert tf.getnames() == ["a.txt"]


def test_happy_pack_7z_with_password_encrypts_names(tree, caplog):
    py7zr = pytest.importorskip("py7zr")
    T.capture_audit(caplog)
    out = T.call(
        _pk(tree),
        "pack",
        {
            "folder": str(tree),
            "names": ["docs"],
            "archive_name": "locked",
            "format": "7z",
            "password": SECRET,
        },
    )
    assert out["path"].endswith("locked.7z") and out["encrypted"] is True
    # The file list itself is encrypted: without the password not even
    # the names can be read.
    with pytest.raises(py7zr.exceptions.PasswordRequired):
        py7zr.SevenZipFile(out["path"])
    with py7zr.SevenZipFile(out["path"], password=SECRET) as sz:
        assert set(sz.getnames()) == {"docs", "docs/a.txt", "docs/b.txt"}
    assert not any(SECRET in ln for ln in T.audit_lines(caplog))


def test_sad_password_needs_7z(tree, caplog):
    T.capture_audit(caplog)
    with pytest.raises(T.RpcError) as err:
        T.call(
            _pk(tree),
            "pack",
            {"folder": str(tree), "names": ["docs"], "archive_name": "x", "password": SECRET},
        )
    assert "7z" in err.value.message and SECRET not in err.value.message
    assert not any(SECRET in ln for ln in T.audit_lines(caplog))
    assert any("outcome=refused" in ln for ln in T.audit_lines(caplog))


def test_sad_pack_outside_root_and_bad_names(tree):
    tools = _pk(tree)
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "pack", {"folder": str(tree.parent), "names": ["outside.txt"], "archive_name": "x"})
    assert "escapes" in err.value.message
    for names, archive in ((["../outside.txt"], "x"), (["nope"], "x"), (["docs"], "a/b")):
        with pytest.raises(T.RpcError):
            T.call(tools, "pack", {"folder": str(tree), "names": names, "archive_name": archive})
    for bad in ({"folder": str(tree), "names": [], "archive_name": "x"},
                {"folder": str(tree), "names": ["docs"], "archive_name": "x", "format": "rar"},
                {"folder": str(tree), "names": ["docs"], "archive_name": "x", "level": "max"}):
        with pytest.raises(T.RpcError) as err:
            T.call(tools, "pack", bad)
        assert err.value.code == M.ERR_INVALID_PARAMS
    assert not list(tree.glob("x*"))


def test_edge_symlink_to_outside_is_skipped_not_packed(tree):
    os.symlink(tree.parent / "outside.txt", tree / "docs" / "leak.txt")
    out = T.call(_pk(tree), "pack", {"folder": str(tree), "names": ["docs"], "archive_name": "s"})
    assert out["skipped"] == ["docs/leak.txt"]
    with zipfile.ZipFile(out["path"]) as zf:
        assert "docs/leak.txt" not in zf.namelist()


def test_edge_single_file_format_refuses_a_folder(tree):
    with pytest.raises(T.RpcError):
        T.call(_pk(tree), "pack", {"folder": str(tree), "names": ["docs"], "archive_name": "g", "format": "gz"})
    out = T.call(_pk(tree), "pack", {"folder": str(tree), "names": ["single.txt"], "archive_name": "g", "format": "gz"})
    assert out["path"] == str(tree / "g.gz")


def test_edge_pack_honours_cancel_and_leaves_nothing(tree):
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(M.CancelledError):
        T.run_handler(_pk(tree), "pack", {"folder": str(tree), "names": ["docs"], "archive_name": "c"}, cancel=cancel)
    assert not list(tree.glob("c*")) and not list(tree.glob(".axross-pack-*"))


# -- archive_list -------------------------------------------------------------------


def _zip(path, members: dict):
    with zipfile.ZipFile(path, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)


def _ar(root, write=True):
    return T.build(root, {"archive"}, allow_write=write)


def test_happy_archive_list(tree):
    _zip(tree / "x.zip", {"one.txt": "1", "dir/two.txt": "22"})
    tools = _ar(tree, write=False)
    assert "archive_extract" not in tools
    out = T.call(tools, "archive_list", {"path": str(tree / "x.zip")})
    assert {e["name"] for e in out["entries"]} == {"one.txt", "dir/two.txt"}
    assert out["total"] == 2 and out["truncated"] is False


def test_edge_archive_list_cap(tree):
    _zip(tree / "many.zip", {f"f{n}": "x" for n in range(5)})
    out = T.call(_ar(tree), "archive_list", {"path": str(tree / "many.zip"), "max_entries": 2})
    assert len(out["entries"]) == 2 and out["total"] == 5 and out["truncated"] is True


def test_sad_archive_list_outside_root_or_not_an_archive(tree):
    tools = _ar(tree)
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "archive_list", {"path": str(tree.parent / "outside.txt")})
    assert "escapes" in err.value.message
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "archive_list", {"path": str(tree / "single.txt")})
    assert "unsupported" in err.value.message


# -- archive_extract ------------------------------------------------------------------


def test_happy_extract_into_a_fresh_folder_each_time(tree, caplog):
    T.capture_audit(caplog)
    _zip(tree / "x.zip", {"one.txt": "1", "dir/two.txt": "22"})
    tools = _ar(tree)
    first = T.call(tools, "archive_extract", {"path": str(tree / "x.zip")})
    second = T.call(tools, "archive_extract", {"path": str(tree / "x.zip")})
    assert first == {"path": str(tree / "x"), "files": 2}
    assert second["path"] == str(tree / "x-1")
    assert (tree / "x" / "dir" / "two.txt").read_text() == "22"
    assert any("tool=archive_extract outcome=ok" in ln for ln in T.audit_lines(caplog))


def test_happy_extract_into_dest_dir(tree):
    _zip(tree / "x.zip", {"one.txt": "1"})
    out = T.call(_ar(tree), "archive_extract", {"path": str(tree / "x.zip"), "dest_dir": str(tree / "docs")})
    assert out["path"] == str(tree / "docs" / "x")


def test_sad_zip_slip_is_refused_and_leaves_nothing(tree, caplog):
    T.capture_audit(caplog)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../evil.txt", "pwned")
    (tree / "slip.zip").write_bytes(buf.getvalue())
    with pytest.raises(T.RpcError):
        T.call(_ar(tree), "archive_extract", {"path": str(tree / "slip.zip")})
    assert not (tree / "slip").exists()
    assert not (tree.parent.parent / "evil.txt").exists()
    assert any("tool=archive_extract outcome=refused" in ln for ln in T.audit_lines(caplog))


def test_sad_extract_dest_outside_root(tree):
    _zip(tree / "x.zip", {"one.txt": "1"})
    with pytest.raises(T.RpcError) as err:
        T.call(_ar(tree), "archive_extract", {"path": str(tree / "x.zip"), "dest_dir": str(tree.parent)})
    assert "escapes" in err.value.message
    assert not (tree.parent / "x").exists()


def test_edge_extract_cancel_removes_the_partial_folder(tree):
    _zip(tree / "x.zip", {"one.txt": "1", "two.txt": "2"})
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(M.CancelledError):
        T.run_handler(_ar(tree), "archive_extract", {"path": str(tree / "x.zip")}, cancel=cancel)
    assert not (tree / "x").exists()


def test_sad_duplicate_names_are_refused_not_packed_twice(tree):
    # Found by the group fuzz: core.packer packs a name given twice twice
    # (zipfile warns "Duplicate name"); the GUI's selection never repeats.
    args = {"folder": str(tree), "names": ["single.txt", "single.txt"], "archive_name": "d"}
    with pytest.raises(T.RpcError) as err:
        T.call(_pk(tree), "pack", args)
    assert err.value.code == M.ERR_INVALID_PARAMS
    with pytest.raises(ValueError):  # the handler itself refuses too (no jsonschema)
        T.run_handler(_pk(tree), "pack", args)
    assert not list(tree.glob("d*.zip"))
