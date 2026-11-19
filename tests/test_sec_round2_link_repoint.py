"""Second security review: a symlink whose target passed the check when it was
made led elsewhere later, once a link on its way was re-pointed or a folder
on its way moved: ``a -> b/../..`` with ``b -> c/d`` resolves inside the
root; with ``b`` re-pointed at ``.`` it is the root's parent. A target with
``..`` is no longer made as typed: the link gets the checked target itself
(absolute, every link resolved), so nothing done later in the root can
change where it leads."""

from __future__ import annotations

import os

import pytest

from core import mcp_server as M
from core.local_fs import LocalFS


@pytest.fixture
def tools(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    built = {t.name: t for t in M._build_tools(LocalFS(), allow_write=True, backend_id="local",
                                               root=str(root))}
    return root, lambda name, **args: built[name].handler(args, M._ToolContext())


def test_sad_a_link_through_dotdot_cannot_be_turned_out_of_the_root_by_re_pointing_a_link(tools):
    root, call = tools
    (root / "c" / "d").mkdir(parents=True)
    call("symlink", target="c/d", link_path=str(root / "b"))
    call("symlink", target="b/..", link_path=str(root / "a"))   # root/c when it is made
    assert os.path.realpath(root / "a") == str(root / "c")
    # re-point b at the root itself: b removed, a new checked link made there
    call("remove", path=str(root / "b"))
    call("symlink", target=".", link_path=str(root / "b"))
    real = os.path.realpath(root / "a")
    assert real == str(root) or real.startswith(str(root) + os.sep), real


def test_sad_a_link_with_leading_dotdot_cannot_be_moved_out_of_the_root(tools):
    root, call = tools
    (root / "p" / "q").mkdir(parents=True)
    (root / "x").write_text("in the root")
    call("symlink", target="../../x", link_path=str(root / "p" / "q" / "L"))
    assert os.path.realpath(root / "p" / "q" / "L") == str(root / "x")
    try:
        call("rename", src=str(root / "p" / "q"), dst=str(root / "q"))
    except PermissionError:
        return   # the move is refused (the links of a moved folder are checked)
    real = os.path.realpath(root / "q" / "L")
    assert real == str(root) or real.startswith(str(root) + os.sep), real


def test_happy_a_relative_target_without_dotdot_is_kept_as_typed(tools):
    root, call = tools
    (root / "releases" / "v2").mkdir(parents=True)
    call("symlink", target="releases/v2", link_path=str(root / "current"))
    assert os.readlink(root / "current") == "releases/v2"


def test_happy_a_dotdot_target_is_made_as_the_checked_place(tools):
    root, call = tools
    (root / "shared").mkdir()
    (root / "app").mkdir()
    out = call("symlink", target="../shared", link_path=str(root / "app" / "cfg"))
    assert os.readlink(root / "app" / "cfg") == str(root / "shared")
    assert out.get("target") == str(root / "shared")
