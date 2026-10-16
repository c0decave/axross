"""symlink / hardlink over MCP on a backend without links say so plainly.

The lab matrix (FTP, SMB, WebDAV, S3, rsync, Telnet, IMAP) showed that
these backends have no symlink method; the GUI asks supports_symlinks
first, but the MCP tools called backend.symlink() straight away and the
model got "'FtpSession' object has no attribute 'symlink'" - although
the tool promises to raise on backends without symlink support. Both
tools now refuse with an OSError naming the backend, before any write.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mcp_server as M  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class _NoLinks(LocalFS):
    """A backend that says it has no links (FTP, SMB, S3 ... do)."""

    supports_symlinks = False
    supports_hardlinks = False


class _NoMethods(LocalFS):
    """A backend without the methods at all."""

    symlink = None
    hardlink = None


def _tool(backend, root, name):
    tools = {t.name: t for t in M._build_tools(backend, root=str(root), allow_write=True)}
    return tools[name]


def _call(backend, root, name, **args):
    return _tool(backend, root, name).handler(args, M._ToolContext())


# --- happy ----------------------------------------------------------------


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX links")
def test_happy_a_backend_with_links_still_makes_them(tmp_path):
    (tmp_path / "t.txt").write_text("x")
    _call(LocalFS(), tmp_path, "symlink", target="t.txt", link_path=str(tmp_path / "l"))
    assert os.readlink(tmp_path / "l") == "t.txt"


# --- sad ------------------------------------------------------------------


@pytest.mark.parametrize("cls", [_NoLinks, _NoMethods])
@pytest.mark.parametrize("tool", ["symlink", "hardlink"])
def test_sad_no_link_support_is_a_plain_refusal(tmp_path, cls, tool):
    (tmp_path / "t.txt").write_text("x")
    with pytest.raises(OSError, match="links") as err:
        _call(cls(), tmp_path, tool, target=str(tmp_path / "t.txt"), link_path=str(tmp_path / "l"))
    assert not isinstance(err.value, AttributeError)
    assert not (tmp_path / "l").exists()


# --- edge -----------------------------------------------------------------


def test_edge_the_refusal_names_the_backend(tmp_path):
    with pytest.raises(OSError, match="_NoLinks"):
        _call(_NoLinks(), tmp_path, "symlink", target="x", link_path=str(tmp_path / "l"))
