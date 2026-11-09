"""Who may say yes to a remove that asks (ConfirmationRequired).

Review round 9, maintainer: "Der Mensch kann selber entscheiden, was er
will, aber Hackerangriffen müssen wir vorbeugen." A recursive remove of
IMAP INBOX on a server whose folders live below it, of an SMB DFS link, or
of a Windows name that means the folder above raises ConfirmationRequired
before anything is deleted. The person says yes - in the file pane's
question, or in a script with the keyword the message names. The MCP
``remove`` tool (which the agent uses too) never passes a keyword, not even
when the client sends one: the model gets the explanation as the error.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import mcp_server as M  # noqa: E402
from core import scripting as axross  # noqa: E402
from core.backend import ConfirmationRequired  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class _AsksFS(LocalFS):
    """LocalFS whose recursive remove of a folder named "INBOX" asks, as
    the IMAP backend does for INBOX on a Courier-style server."""

    def __init__(self):
        super().__init__()
        self.calls: list[tuple] = []

    def remove(self, path, recursive=False, *, keep_namespace_root=False):
        self.calls.append((path, recursive, keep_namespace_root))
        if Path(path).name == "INBOX" and recursive and not keep_namespace_root:
            raise ConfirmationRequired(
                "imap_namespace_root", path,
                "INBOX holds 2 other folders. Yes deletes them; INBOX stays.",
                option="keep_namespace_root", details={"subfolders": 2})
        for child in Path(path).iterdir():
            child.unlink()


def _call(tools, name, args):
    return M._handle_request(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call",
         "params": {"name": name, "arguments": args}},
        tools, cancels=M._CancelRegistry())


@pytest.fixture
def inbox(tmp_path):
    folder = tmp_path / "INBOX"
    folder.mkdir()
    (folder / "Sent").write_bytes(b"mail")
    return folder


# -- happy ---------------------------------------------------------------------------------


def test_happy_a_script_says_yes_with_the_keyword(inbox):
    fs = _AsksFS()
    axross.remove(fs, str(inbox), recursive=True, confirm=True, keep_namespace_root=True)
    assert fs.calls == [(str(inbox), True, True)]
    assert list(inbox.iterdir()) == []


# -- sad -----------------------------------------------------------------------------------


def test_sad_a_script_without_the_keyword_is_told_which_one(inbox):
    fs = _AsksFS()
    with pytest.raises(ConfirmationRequired) as info:
        axross.remove(fs, str(inbox), recursive=True, confirm=True)
    assert "keep_namespace_root=True" in str(info.value)
    assert (inbox / "Sent").exists()


def test_sad_mcp_never_says_yes_even_when_the_client_sends_the_keyword(tmp_path, inbox):
    fs = _AsksFS()
    tools = M._build_tools(fs, allow_write=True, root=str(tmp_path))
    resp = _call(tools, "remove", {"path": str(inbox), "recursive": True,
                                   "keep_namespace_root": True, "follow_dfs_link": True})
    result = resp["result"]
    assert result["isError"] is True
    assert result["_meta"]["type"] == "ConfirmationRequired"
    assert "Yes deletes them; INBOX stays." in result["content"][0]["text"]
    assert fs.calls == [(str(inbox), True, False)]
    assert (inbox / "Sent").exists()


# -- edge ----------------------------------------------------------------------------------


def test_edge_the_tool_the_agent_gets_has_no_keyword_to_say_yes(tmp_path):
    # The agent calls these same tools (core.agent -> mcp_server._build_tools).
    tools = M._build_tools(LocalFS(), allow_write=True, root=str(tmp_path))
    remove = tools["remove"] if isinstance(tools, dict) else next(
        t for t in tools if t.name == "remove")
    assert set(remove.schema["properties"]) == {"path", "recursive"}


def test_edge_only_true_counts_in_a_script(inbox):
    fs = _AsksFS()
    with pytest.raises(ConfirmationRequired):
        axross.remove(fs, str(inbox), recursive=True, confirm=True,
                      keep_namespace_root="yes")  # not True: no yes
    assert (inbox / "Sent").exists()
