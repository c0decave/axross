"""MCP capability groups ``metadata`` and ``filetype``.

metadata: metadata_read, metadata_export (read-only), metadata_export_file and
metadata_remove (mutating: need --mcp-write). filetype: file_type,
file_type_scan (read-only).
"""

from __future__ import annotations

import csv
import io
import os
import threading

import pytest

from core import mcp_server as M
from tests import mcp_group_testkit as T
from tests import metadata_testkit as K

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    K.write(root / "photo.jpg", K.jpeg_bytes())
    (root / "sub").mkdir()
    K.write(root / "sub" / "deep.jpg", K.jpeg_bytes())
    (root / "notes.txt").write_text("plain text\n")
    outside = tmp_path / "outside.jpg"
    K.write(outside, K.jpeg_bytes())
    return root, outside


def _meta(root, write=False):
    return T.build(root, {"metadata"}, allow_write=write)


# -- gating ---------------------------------------------------------------------


def test_happy_read_only_metadata_tools_without_write(tree):
    root, _ = tree
    names = set(_meta(root))
    assert {"metadata_read", "metadata_export"} <= names
    assert not {"metadata_remove", "metadata_export_file"} & names


def test_happy_mutating_metadata_tools_with_write(tree):
    root, _ = tree
    assert {"metadata_remove", "metadata_export_file"} <= set(_meta(root, write=True))


def test_edge_groups_are_independent(tree):
    root, _ = tree
    names = set(T.build(root, {"filetype"}, allow_write=True))
    assert "file_type" in names and "metadata_read" not in names


def test_happy_group_tools_carry_their_group(tree):
    root, _ = tree
    tools = T.build(root, {"metadata", "filetype"}, allow_write=True)
    assert tools["metadata_read"].group == "metadata"
    assert tools["file_type"].group == "filetype"
    assert tools["metadata_remove"].write is True
    assert tools["metadata_read"].write is False
    assert tools["list_dir"].group == "core"
    assert tools["write_file"].group == "write"


# -- metadata_read ----------------------------------------------------------------


def test_happy_metadata_read_one_file(tree):
    root, _ = tree
    out = T.call(_meta(root), "metadata_read", {"path": str(root / "photo.jpg")})
    assert out["is_dir"] is False and len(out["files"]) == 1
    report = out["files"][0]
    assert report["kind"] == "image"
    assert report["removable_count"] > 0
    assert any("SECRET" in str(f["value"]) for f in report["fields"])


def test_happy_metadata_read_folder_recursive(tree):
    root, _ = tree
    flat = T.call(_meta(root), "metadata_read", {"path": str(root)})
    deep = T.call(_meta(root), "metadata_read", {"path": str(root), "recursive": True})
    assert {f["name"] for f in flat["files"]} == {"photo.jpg"}
    assert {f["name"] for f in deep["files"]} == {"photo.jpg", "deep.jpg"}


def test_edge_metadata_read_folder_caps_files(tree):
    root, _ = tree
    out = T.call(_meta(root), "metadata_read", {"path": str(root), "recursive": True, "max_files": 1})
    assert len(out["files"]) == 1 and out["truncated"] is True


def test_sad_metadata_read_outside_root_is_refused(tree):
    root, outside = tree
    with pytest.raises(T.RpcError) as err:
        T.call(_meta(root), "metadata_read", {"path": str(outside)})
    assert "escapes" in err.value.message


def test_sad_metadata_read_traversal_is_refused(tree):
    root, _ = tree
    with pytest.raises(T.RpcError) as err:
        T.call(_meta(root), "metadata_read", {"path": str(root / ".." / "outside.jpg")})
    assert "escapes" in err.value.message


def test_edge_symlink_to_outside_is_refused(tree):
    root, outside = tree
    os.symlink(outside, root / "link.jpg")
    with pytest.raises(T.RpcError) as err:
        T.call(_meta(root), "metadata_read", {"path": str(root / "link.jpg")})
    assert "escapes" in err.value.message
    listed = T.call(_meta(root), "metadata_read", {"path": str(root)})
    assert "link.jpg" not in {f["name"] for f in listed["files"]}


def test_sad_metadata_read_rejects_bad_arguments(tree):
    root, _ = tree
    for args in ({}, {"path": 3}, {"path": str(root), "max_files": 0}, {"path": str(root), "x": 1}):
        with pytest.raises(T.RpcError) as err:
            T.call(_meta(root), "metadata_read", args)
        assert err.value.code == M.ERR_INVALID_PARAMS


def test_edge_unsupported_file_reports_instead_of_failing(tree):
    root, _ = tree
    out = T.call(_meta(root), "metadata_read", {"path": str(root / "notes.txt")})
    assert out["files"][0]["error"]


# -- metadata_export --------------------------------------------------------------


def test_happy_metadata_export_json_and_csv(tree):
    root, _ = tree
    tools = _meta(root)
    as_json = T.call(tools, "metadata_export", {"path": str(root), "recursive": True})
    assert as_json["format"] == "json" and as_json["files"] == 2
    assert "SECRET" in as_json["text"]
    as_csv = T.call(tools, "metadata_export", {"path": str(root / "photo.jpg"), "format": "csv"})
    rows = list(csv.reader(io.StringIO(as_csv["text"])))
    assert len(rows) > 1


def test_sad_metadata_export_unknown_format(tree):
    root, _ = tree
    with pytest.raises(T.RpcError) as err:
        T.call(_meta(root), "metadata_export", {"path": str(root), "format": "xml"})
    assert err.value.code == M.ERR_INVALID_PARAMS


# -- metadata_export_file (mutating) -----------------------------------------------


def test_happy_export_file_lands_under_root_and_never_overwrites(tree, caplog):
    root, _ = tree
    T.capture_audit(caplog)
    tools = _meta(root, write=True)
    target = str(root / "meta.json")
    first = T.call(tools, "metadata_export_file", {"path": str(root), "out": target})
    second = T.call(tools, "metadata_export_file", {"path": str(root), "out": target})
    assert first["path"] == target
    assert second["path"] == str(root / "meta (2).json")
    assert "SECRET" in open(target, encoding="utf-8").read()
    assert oct(os.stat(target).st_mode & 0o777) == "0o600"
    lines = T.audit_lines(caplog)
    assert any("tool=metadata_export_file outcome=attempt" in ln for ln in lines)
    assert sum("tool=metadata_export_file outcome=ok" in ln for ln in lines) == 2


def test_sad_export_file_outside_root_is_refused_and_audited(tree, caplog):
    root, outside = tree
    T.capture_audit(caplog)
    with pytest.raises(T.RpcError) as err:
        T.call(
            _meta(root, write=True),
            "metadata_export_file",
            {"path": str(root), "out": str(outside.parent / "x.json")},
        )
    assert "escapes" in err.value.message
    assert not (outside.parent / "x.json").exists()
    assert any("outcome=refused" in ln for ln in T.audit_lines(caplog))


# -- metadata_remove (mutating) -----------------------------------------------------


def test_happy_metadata_remove_writes_a_clean_copy(tree, caplog):
    root, _ = tree
    T.capture_audit(caplog)
    before = (root / "photo.jpg").read_bytes()
    out = T.call(_meta(root, write=True), "metadata_remove", {"path": str(root / "photo.jpg")})
    result = out["results"][0]
    assert result["status"] == "cleaned"
    assert result["output"] == str(root / "photo.clean.jpg")
    assert K.MARK not in (root / "photo.clean.jpg").read_bytes()
    assert (root / "photo.jpg").read_bytes() == before  # the original is untouched
    lines = T.audit_lines(caplog)
    assert any("tool=metadata_remove outcome=attempt" in ln for ln in lines)
    assert any("tool=metadata_remove outcome=ok" in ln and "cleaned=1" in ln for ln in lines)


def test_edge_metadata_remove_twice_never_overwrites(tree):
    root, _ = tree
    tools = _meta(root, write=True)
    T.call(tools, "metadata_remove", {"path": str(root / "photo.jpg")})
    out = T.call(tools, "metadata_remove", {"path": str(root / "photo.jpg")})
    assert out["results"][0]["output"] == str(root / "photo.clean (1).jpg")


def test_happy_metadata_remove_folder_recursive(tree):
    root, _ = tree
    out = T.call(
        _meta(root, write=True), "metadata_remove", {"path": str(root), "recursive": True}
    )
    assert {r["status"] for r in out["results"]} == {"cleaned"}
    assert (root / "sub" / "deep.clean.jpg").exists()


def test_sad_metadata_remove_outside_root(tree):
    root, outside = tree
    with pytest.raises(T.RpcError) as err:
        T.call(_meta(root, write=True), "metadata_remove", {"path": str(outside)})
    assert "escapes" in err.value.message
    assert not outside.with_name("outside.clean.jpg").exists()


def test_sad_metadata_remove_missing_file(tree):
    root, _ = tree
    with pytest.raises(T.RpcError) as err:
        T.call(_meta(root, write=True), "metadata_remove", {"path": str(root / "nope.jpg")})
    assert "nope.jpg" in err.value.message and err.value.code == M.ERR_INTERNAL


# -- file_type -----------------------------------------------------------------


def _ft(root):
    return T.build(root, {"filetype"})


def test_happy_file_type_match_and_mismatch(tmp_path):
    png = K.png_bytes()
    assert png.startswith(PNG_MAGIC)
    (tmp_path / "real.png").write_bytes(png)
    (tmp_path / "fake.txt").write_bytes(png)
    tools = _ft(tmp_path)
    real = T.call(tools, "file_type", {"path": str(tmp_path / "real.png")})
    fake = T.call(tools, "file_type", {"path": str(tmp_path / "fake.txt")})
    assert real["mime"] == "image/png" and real["verdict"] == "match"
    assert fake["mime"] == "image/png" and fake["verdict"] == "mismatch"
    assert fake["mismatch"] is True


def test_edge_file_type_of_folder_and_missing(tmp_path):
    tools = _ft(tmp_path)
    assert T.call(tools, "file_type", {"path": str(tmp_path)})["kind"] == "directory"
    missing = T.call(tools, "file_type", {"path": str(tmp_path / "nope")})
    assert missing["kind"] == "error" and missing["error"]


def test_sad_file_type_outside_root_and_bad_bounds(tmp_path):
    root = tmp_path / "r"
    root.mkdir()
    (tmp_path / "secret.bin").write_bytes(b"x")
    tools = _ft(root)
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "file_type", {"path": str(tmp_path / "secret.bin")})
    assert "escapes" in err.value.message
    for bad in (0, -1, 2**40):
        with pytest.raises(T.RpcError) as err:
            T.call(tools, "file_type", {"path": str(root), "max_bytes": bad})
        assert err.value.code == M.ERR_INVALID_PARAMS


def test_happy_file_type_scan_lists_only_mismatches(tmp_path):
    png = K.png_bytes()
    (tmp_path / "a.png").write_bytes(png)
    (tmp_path / "b.txt").write_bytes(png)
    (tmp_path / "d").mkdir()
    (tmp_path / "d" / "c.jpg").write_bytes(png)
    tools = _ft(tmp_path)
    everything = T.call(tools, "file_type_scan", {"path": str(tmp_path)})
    assert {os.path.basename(e["path"]) for e in everything["entries"]} == {"a.png", "b.txt", "c.jpg"}
    only = T.call(tools, "file_type_scan", {"path": str(tmp_path), "mismatches_only": True})
    assert {os.path.basename(e["path"]) for e in only["entries"]} == {"b.txt", "c.jpg"}
    assert only["files_scanned"] == 3


def test_edge_file_type_scan_cap_and_progress(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}.txt").write_text("x")
    tools = _ft(tmp_path)
    out, frames = T.run_handler(tools, "file_type_scan", {"path": str(tmp_path), "max_files": 2})
    assert len(out["entries"]) == 2 and out["truncated"] is True
    assert frames and frames[-1][0] == 2


def test_edge_file_type_scan_honours_cancel(tmp_path):
    (tmp_path / "f.txt").write_text("x")
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(M.CancelledError):
        T.run_handler(_ft(tmp_path), "file_type_scan", {"path": str(tmp_path)}, cancel=cancel)


def test_edge_file_type_scan_skips_links_out_of_root(tmp_path):
    root = tmp_path / "r"
    root.mkdir()
    (tmp_path / "secret.png").write_bytes(K.png_bytes())
    os.symlink(tmp_path / "secret.png", root / "l.png")
    out = T.call(_ft(root), "file_type_scan", {"path": str(root)})
    assert out["entries"] == []
