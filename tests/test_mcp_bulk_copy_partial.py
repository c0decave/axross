"""MCP bulk_copy says when a copy is partial.

Found in review (round 2, data integrity): the directory walk dropped a
folder it could not list (``except OSError: continue``) and every
folder below ``max_depth`` without a record, and answered
``truncated: false`` - an agent read a partial copy as complete. Each
left-out part now has its own entry, a depth cut sets ``truncated``, and
``complete`` says in one field whether everything was copied.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mcp_server as M  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

POSIX_USER = pytest.mark.skipif(
    not hasattr(os, "geteuid") or os.geteuid() == 0, reason="POSIX permissions, not root"
)


def _bulk_copy(root: Path, **arguments) -> dict:
    tools = M._build_tools(LocalFS(), allow_write=True, root=str(root))
    resp = M._handle_request(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "bulk_copy", "arguments": arguments},
        },
        tools,
    )
    assert "result" in resp, resp
    return json.loads(resp["result"]["content"][0]["text"])


def _tree(root: Path) -> tuple[Path, Path]:
    src, dst = root / "src", root / "dst"
    src.mkdir()
    (src / "top.txt").write_text("top")
    (src / "sub").mkdir()
    (src / "sub" / "a.txt").write_text("a")
    return src, dst


def test_happy_full_copy_is_complete(tmp_path):
    src, dst = _tree(tmp_path)
    out = _bulk_copy(tmp_path, src=str(src), dst=str(dst))
    assert out["truncated"] is False
    assert out["complete"] is True
    assert (dst / "sub" / "a.txt").read_text() == "a"


def test_happy_single_file_copy_is_complete(tmp_path):
    src, dst = _tree(tmp_path)
    out = _bulk_copy(tmp_path, src=str(src / "top.txt"), dst=str(dst / "top.txt"))
    assert out["complete"] is True


def test_sad_folders_below_max_depth_are_reported_and_truncate(tmp_path):
    src, dst = _tree(tmp_path)
    deep = src.joinpath(*[f"d{i}" for i in range(4)])
    deep.mkdir(parents=True)
    (deep / "Deep.java").write_text("class Deep {}")
    out = _bulk_copy(tmp_path, src=str(src), dst=str(dst), max_depth=2)
    assert out["truncated"] is True
    assert out["complete"] is False
    cut = [e for e in out["entries"] if e.get("reason") == "max-depth"]
    assert len(cut) == 1
    assert cut[0]["action"] == "skipped"
    assert cut[0]["src"].endswith(os.path.join("d0", "d1"))


@POSIX_USER
def test_sad_unreadable_folder_is_an_error_entry(tmp_path):
    src, dst = _tree(tmp_path)
    locked = src / "locked"
    locked.mkdir()
    (locked / "secret.txt").write_text("s")
    locked.chmod(0o000)
    try:
        out = _bulk_copy(tmp_path, src=str(src), dst=str(dst))
    finally:
        locked.chmod(0o755)
    errors = [e for e in out["entries"] if e["action"] == "error"]
    assert len(errors) == 1
    assert errors[0]["src"].endswith("locked")
    assert errors[0]["error"]
    assert out["complete"] is False
    # Everything else was still copied.
    assert (dst / "sub" / "a.txt").exists()


def test_edge_existing_files_skipped_on_request_still_count_as_complete(tmp_path):
    src, dst = _tree(tmp_path)
    _bulk_copy(tmp_path, src=str(src), dst=str(dst))
    out = _bulk_copy(tmp_path, src=str(src), dst=str(dst))
    assert {e["reason"] for e in out["entries"]} == {"exists"}
    assert out["complete"] is True


def test_edge_too_large_file_makes_it_incomplete(tmp_path):
    src, dst = _tree(tmp_path)
    out = _bulk_copy(tmp_path, src=str(src), dst=str(dst), max_file_bytes=1)
    assert out["truncated"] is False
    assert out["complete"] is False


def test_edge_max_files_cut_is_incomplete(tmp_path):
    src, dst = _tree(tmp_path)
    out = _bulk_copy(tmp_path, src=str(src), dst=str(dst), max_files=1)
    assert out["truncated"] is True
    assert out["complete"] is False
