"""A read-only extra folder inside the writable folder stays untouched by
tools that act on a whole subtree.

The agent's files can be a writable folder with a read-only extra folder
inside it (``main`` writable, ``main/sub/keep`` read-only). A single
file in ``keep`` was refused, but a call on a folder AROUND it was not:

* ``remove main/sub recursive`` deleted ``keep`` with it,
* ``rename main/sub`` moved ``keep`` away,
* ``duplicates_dedupe main`` moved copies in ``keep`` to the trash,
* ``metadata_remove main recursive`` wrote cleaned copies into ``keep``.

An agent tab without a sandbox runs these tools in process; in Auto mode
a write tool is not even asked for, so a prompt hidden in a file the
model read was enough. Each of them now leaves ``keep`` alone.
"""

from __future__ import annotations

import os

import pytest

from tests import mcp_group_testkit as T
from tests import metadata_testkit as K


@pytest.fixture
def main(tmp_path):
    main = tmp_path / "main"
    (main / "sub" / "keep").mkdir(parents=True)
    (main / "sub" / "keep" / "f.txt").write_text("same content\n")
    (main / "sub" / "g.txt").write_text("same content\n")
    os.utime(main / "sub" / "g.txt", (1_000_000_000, 1_000_000_000))
    return main


def _tools(main, groups=()):
    return T.build(main, set(groups), allow_write=True,
                   extra_roots=((str(main / "sub" / "keep"), False),))


def test_sad_removing_a_folder_around_a_read_only_one_is_refused(main):
    with pytest.raises(T.RpcError):
        T.call(_tools(main), "remove", {"path": str(main / "sub"), "recursive": True})
    assert (main / "sub" / "keep" / "f.txt").read_text() == "same content\n"


def test_sad_moving_a_folder_around_a_read_only_one_is_refused(main):
    with pytest.raises(T.RpcError):
        T.call(_tools(main), "rename", {"src": str(main / "sub"), "dst": str(main / "moved")})
    assert (main / "sub" / "keep" / "f.txt").exists()
    assert not (main / "moved").exists()


def test_sad_dedupe_leaves_copies_in_a_read_only_folder(main):
    tools = _tools(main, ["duplicates"])
    T.call(tools, "duplicates_scan", {"path": str(main)})
    out = T.call(tools, "duplicates_dedupe", {"path": str(main), "dry_run": False})
    assert out["removed"] == []
    assert (main / "sub" / "keep" / "f.txt").read_text() == "same content\n"
    assert (main / "sub" / "g.txt").exists()


def test_sad_metadata_remove_writes_nothing_into_a_read_only_folder(main):
    K.write(main / "sub" / "keep" / "photo.jpg", K.jpeg_bytes())
    K.write(main / "photo.jpg", K.jpeg_bytes())
    T.call(_tools(main, ["metadata"]), "metadata_remove",
           {"path": str(main), "recursive": True})
    assert sorted(os.listdir(main / "sub" / "keep")) == ["f.txt", "photo.jpg"]
    assert (main / "photo.clean.jpg").exists()  # the writable part still is cleaned


def test_happy_the_writable_part_still_changes(main):
    """Entries beside the read-only folder are removed and moved as before."""
    (main / "other").mkdir()
    (main / "other" / "x.txt").write_text("x")
    tools = _tools(main)
    T.call(tools, "rename", {"src": str(main / "other"), "dst": str(main / "renamed")})
    T.call(tools, "remove", {"path": str(main / "renamed"), "recursive": True})
    T.call(tools, "remove", {"path": str(main / "sub" / "g.txt")})
    assert not (main / "renamed").exists() and not (main / "sub" / "g.txt").exists()
