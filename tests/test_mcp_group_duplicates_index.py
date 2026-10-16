"""MCP capability groups ``duplicates`` and ``index``.

duplicates: duplicates_scan, duplicates_scans, duplicates_groups (read-only:
they only touch the Duplicate Finder's own index) and duplicates_dedupe
(mutating, dry run by default). index: index_build fills the offline
metadata index that the ``search`` tool reads.
"""

from __future__ import annotations

import os
import threading

import pytest

from core import cas
from core import mcp_server as M
from core.local_fs import LocalFS
from tests import mcp_group_testkit as T


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "a.txt").write_text("same content\n")
    (root / "b.txt").write_text("same content\n")
    (root / "sub" / "d.txt").write_text("same content\n")
    (root / "c.txt").write_text("unique\n")
    os.utime(root / "a.txt", (1_000_000_000, 1_000_000_000))  # the oldest copy stays
    return root


def _dupes(root, write=False):
    return T.build(root, {"duplicates"}, allow_write=write)


def _copies(group):
    return [os.path.basename(c["path"]) for c in group["copies"]]


# -- gating ---------------------------------------------------------------------


def test_happy_dedupe_only_with_write(tree):
    assert "duplicates_dedupe" not in _dupes(tree)
    assert {"duplicates_scan", "duplicates_scans", "duplicates_groups"} <= set(_dupes(tree))
    assert _dupes(tree, write=True)["duplicates_dedupe"].write is True


# -- scan / groups / scans ----------------------------------------------------


def test_happy_scan_then_groups(tree):
    tools = _dupes(tree)
    scan = T.call(tools, "duplicates_scan", {"path": str(tree)})
    assert scan["status"] == "complete" and scan["files_indexed"] == 4
    assert isinstance(scan["scan_id"], int) and scan["scan_id"] > 0
    out = T.call(tools, "duplicates_groups", {"path": str(tree)})
    assert len(out["groups"]) == 1
    group = out["groups"][0]
    assert sorted(_copies(group)) == ["a.txt", "b.txt", "d.txt"]
    assert group["copies"][0]["keep"] is True and os.path.basename(group["copies"][0]["path"]) == "a.txt"
    assert [c["keep"] for c in group["copies"][1:]] == [False, False]
    scans = T.call(tools, "duplicates_scans", {})
    assert scan["scan_id"] in {s["scan_id"] for s in scans["scans"]}


def test_happy_scan_defaults_to_the_root(tree):
    scan = T.call(_dupes(tree), "duplicates_scan", {})
    assert scan["root"] == str(tree)


def test_edge_groups_by_scan_id_and_algorithm(tree):
    tools = _dupes(tree)
    scan = T.call(tools, "duplicates_scan", {"path": str(tree), "algorithm": "md5"})
    by_scan = T.call(tools, "duplicates_groups", {"scan_id": scan["scan_id"], "algorithm": "md5"})
    assert len(by_scan["groups"]) == 1 and by_scan["groups"][0]["algorithm"] == "md5"
    none = T.call(tools, "duplicates_groups", {"algorithm": "sha512"})
    assert none["groups"] == []


def test_edge_group_cap(tmp_path):
    root = tmp_path / "r"
    root.mkdir()
    for n in range(3):
        (root / f"x{n}a").write_text(f"v{n}")
        (root / f"x{n}b").write_text(f"v{n}")
    tools = _dupes(root)
    T.call(tools, "duplicates_scan", {})
    out = T.call(tools, "duplicates_groups", {"max_groups": 2})
    assert len(out["groups"]) == 2 and out["truncated"] is True


def test_sad_scan_outside_root_and_bad_args(tree, tmp_path):
    tools = _dupes(tree)
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "duplicates_scan", {"path": str(tmp_path)})
    assert "escapes" in err.value.message
    for args in ({"algorithm": "crc32"}, {"path": 1}, {"bogus": True}):
        with pytest.raises(T.RpcError) as err:
            T.call(tools, "duplicates_scan", args)
        assert err.value.code == M.ERR_INVALID_PARAMS
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "duplicates_groups", {"scan_id": -1})
    assert err.value.code == M.ERR_INVALID_PARAMS


def test_sad_groups_for_a_folder_outside_root(tree, tmp_path):
    with pytest.raises(T.RpcError) as err:
        T.call(_dupes(tree), "duplicates_groups", {"path": str(tmp_path)})
    assert "escapes" in err.value.message


def test_edge_index_rows_outside_root_never_show(tree, tmp_path):
    # Same content indexed outside the root (e.g. by the GUI): the MCP
    # view stays inside the root, and so does a dedupe.
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    (outside / "z.txt").write_text("same content\n")
    os.utime(outside / "z.txt", (1, 1))  # older than everything in the root
    cas.rebuild(LocalFS(), str(outside), backend_id=cas.backend_id_for(LocalFS()))
    tools = _dupes(tree, write=True)
    T.call(tools, "duplicates_scan", {})
    group = T.call(tools, "duplicates_groups", {})["groups"][0]
    assert "z.txt" not in _copies(group)
    scans = T.call(tools, "duplicates_scans", {})["scans"]
    assert all(s["root"].startswith(str(tree)) for s in scans)
    T.call(tools, "duplicates_dedupe", {"dry_run": False})
    assert (outside / "z.txt").exists()


def test_edge_symlinks_are_not_copies(tree):
    os.symlink(tree / "c.txt", tree / "c-link.txt")
    tools = _dupes(tree)
    T.call(tools, "duplicates_scan", {})
    groups = T.call(tools, "duplicates_groups", {})["groups"]
    assert all("c-link.txt" not in _copies(g) for g in groups)


def test_edge_scan_honours_cancel(tree):
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(M.CancelledError):
        T.run_handler(_dupes(tree), "duplicates_scan", {}, cancel=cancel)


# -- dedupe (mutating) ------------------------------------------------------------


def test_happy_dedupe_is_a_dry_run_by_default(tree, caplog):
    T.capture_audit(caplog)
    tools = _dupes(tree, write=True)
    T.call(tools, "duplicates_scan", {})
    plan = T.call(tools, "duplicates_dedupe", {})
    assert plan["dry_run"] is True and plan["groups"] == 1
    assert [os.path.basename(p) for p in plan["keep"]] == ["a.txt"]
    assert sorted(os.path.basename(p) for p in plan["trash"]) == ["b.txt", "d.txt"]
    assert (tree / "b.txt").exists() and (tree / "sub" / "d.txt").exists()
    assert any("tool=duplicates_dedupe outcome=ok" in ln and "dry_run=True" in ln
               for ln in T.audit_lines(caplog))


def test_happy_dedupe_moves_copies_to_a_trash_under_the_root(tree, caplog):
    T.capture_audit(caplog)
    tools = _dupes(tree, write=True)
    T.call(tools, "duplicates_scan", {})
    done = T.call(tools, "duplicates_dedupe", {"dry_run": False})
    assert done["dry_run"] is False
    assert sorted(os.path.basename(p) for p in done["removed"]) == ["b.txt", "d.txt"]
    assert done["refused"] == [] and done["failed"] == []
    assert (tree / "a.txt").exists()
    assert not (tree / "b.txt").exists() and not (tree / "sub" / "d.txt").exists()
    trash = tree / ".axross-trash"
    assert trash.is_dir() and len([p for p in trash.iterdir() if not p.name.endswith(".json")]) == 2
    lines = T.audit_lines(caplog)
    assert any("outcome=attempt" in ln and "dry_run=False" in ln for ln in lines)
    assert any("outcome=ok" in ln and "removed=2" in ln for ln in lines)


def test_sad_dedupe_refuses_a_copy_that_changed_since_the_scan(tree):
    tools = _dupes(tree, write=True)
    T.call(tools, "duplicates_scan", {})
    (tree / "b.txt").write_text("edited after the scan\n")
    done = T.call(tools, "duplicates_dedupe", {"dry_run": False})
    assert (tree / "b.txt").exists()
    assert any(os.path.basename(r["path"]) == "b.txt" for r in done["refused"])


def test_sad_dedupe_outside_root(tree, tmp_path):
    with pytest.raises(T.RpcError) as err:
        T.call(_dupes(tree, write=True), "duplicates_dedupe", {"path": str(tmp_path)})
    assert "escapes" in err.value.message


# -- index_build ----------------------------------------------------------------


def _idx(root):
    return T.build(root, {"index"})


def test_happy_index_build_feeds_search(tmp_path):
    root = tmp_path / "r"
    (root / "deep").mkdir(parents=True)
    (root / "deep" / "needle-xyz.txt").write_text("x")
    tools = _idx(root)
    assert T.call(tools, "search", {"needle": "needle-xyz"}) == []
    out = T.call(tools, "index_build", {"path": str(root)})
    assert out["indexed"] >= 2 and out["pruned"] == 0
    hits = T.call(tools, "search", {"needle": "needle-xyz"})
    assert [h["name"] for h in hits] == ["needle-xyz.txt"]


def test_happy_index_build_prune_drops_vanished_files(tmp_path):
    root = tmp_path / "r"
    root.mkdir()
    (root / "gone-qq.txt").write_text("x")
    tools = _idx(root)
    T.call(tools, "index_build", {})
    os.unlink(root / "gone-qq.txt")
    out = T.call(tools, "index_build", {"prune": True})
    assert out["pruned"] == 1
    assert T.call(tools, "search", {"needle": "gone-qq"}) == []


def test_edge_index_build_not_recursive(tmp_path):
    root = tmp_path / "r"
    (root / "d").mkdir(parents=True)
    (root / "top-ww.txt").write_text("x")
    (root / "d" / "low-ww.txt").write_text("x")
    tools = _idx(root)
    T.call(tools, "index_build", {"recursive": False})
    names = {h["name"] for h in T.call(tools, "search", {"needle": "-ww"})}
    assert names == {"top-ww.txt"}


def test_sad_index_build_outside_root_or_on_a_file(tmp_path):
    root = tmp_path / "r"
    root.mkdir()
    (root / "f.txt").write_text("x")
    tools = _idx(root)
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "index_build", {"path": str(tmp_path)})
    assert "escapes" in err.value.message
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "index_build", {"path": str(root / "f.txt")})
    assert err.value.code == M.ERR_INVALID_PARAMS and "folder" in err.value.message


def test_edge_index_build_honours_cancel(tmp_path):
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(M.CancelledError):
        T.run_handler(_idx(tmp_path), "index_build", {}, cancel=cancel)
