"""An Agent tab and the remote connections of the panes.

With "Remote files" on in Agent Settings > Access, a tab's agent reaches
every remote connection open in a pane as backend ``pane:<name>``;
with it off, none. The saved profiles (the remote group) need their own
switch - remote commands alone do not bring them in.
"""

from __future__ import annotations

import pytest

from core.profiles import ConnectionProfile
from core.ram_fs import RamFsSession
from tests.test_agent_loop import _call, _tool_messages
from tests.test_agent_tabs import Env, say


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.close()


def _pane(name="box"):
    ram = RamFsSession(f"ram-{name}")
    ram.mkdir("/data")
    with ram.open_write("/data/f.txt") as handle:
        handle.write(f"text of {name}".encode())
    return (
        f"pane:{name}",
        ram,
        ConnectionProfile(name=name, protocol="sftp", host=f"{name}.example"),
    )


def _read(backend="pane:box"):
    return _call("read_file", {"path": "/data/f.txt", "encoding": "text", "backend": backend})


# -- happy ---------------------------------------------------------------------


def test_happy_with_remote_files_on_the_agent_reads_a_pane_connection(env):
    env.settings.access.remote_files = True
    env.remote = [_pane()]
    server = env.fake({"tool_calls": [_read()]}, {"content": "It says text of box."})
    tab = env.dock().current_tab()
    say(tab, "what is in f.txt on box?")
    assert "text of box" in _tool_messages(server.requests[1])[0]["content"]


# -- sad -----------------------------------------------------------------------


def test_sad_with_remote_files_off_no_pane_connection_is_reachable(env):
    env.remote = [_pane()]
    server = env.fake({"tool_calls": [_read()]}, {"content": "cannot"})
    tab = env.dock().current_tab()
    say(tab, "read f.txt on box")
    content = _tool_messages(server.requests[1])[0]["content"]
    assert content.startswith("error") and "text of box" not in content
    assert "list_backends" not in {t["function"]["name"] for t in server.requests[0]["tools"]}


def test_sad_remote_commands_alone_do_not_open_saved_profiles(env, monkeypatch):
    env.settings.access.remote_commands = True
    env.fake({"content": "ok"})
    tab = env.dock().current_tab()
    monkeypatch.setattr(type(tab), "_exec_policy", staticmethod(lambda: True))
    tab.allow_exec.setEnabled(True)
    tab.allow_exec.setChecked(True)
    config = tab._config(tab.profile(), mode="ask")
    assert config.allow_exec and "exec" in config.groups and "remote" not in config.groups


# -- edge ----------------------------------------------------------------------


def test_edge_a_connection_opened_later_reaches_the_next_task(env):
    env.settings.access.remote_files = True
    server = env.fake(
        {"content": "nothing open"}, {"tool_calls": [_read("pane:later")]}, {"content": "read"}
    )
    tab = env.dock().current_tab()
    say(tab, "anything?")
    env.remote = [_pane("later")]
    say(tab, "and now?")
    assert "text of later" in _tool_messages(server.requests[2])[-1]["content"]


def test_sad_attaching_a_remote_file_with_remote_files_off_says_so(env):
    env.fake({"content": "ok"})
    tab = env.dock().current_tab()
    tab.attach(["/srv/report.txt"], "pane:box", False)
    assert "Remote files are off" in tab.transcript.toPlainText()
    env.settings.access.remote_files = True
    tab.clear_attachments()
    tab.transcript.clear()
    tab.attach(["/srv/report.txt"], "pane:box", False)
    assert "Remote files are off" not in tab.transcript.toPlainText()
