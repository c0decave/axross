"""An Agent tab's own access (core.agent_access) in the GUI: the tab's
Access… dialog, the Access and Sessions pages of Agent Settings, and what
the tab's agent then gets. Agent Settings is the ceiling, the tab
chooses within it."""

from __future__ import annotations

from unittest import mock

import pytest
from PyQt6.QtWidgets import QDialog

from core import agent_access as X
from core import agent_sandbox as SB
from core.agent_session import AgentSession, SessionStore
from tests.test_agent_loop import _call, _tool_messages
from tests.test_agent_tab_remote import _pane
from tests.test_agent_settings_dialog import _dialog, _select
from tests.test_agent_tabs import APP, Env, say


@pytest.fixture
def env(tmp_path):
    e = Env(tmp_path)
    yield e
    e.close()


def _offered(request) -> set:
    return {t["function"]["name"] for t in request.get("tools", [])}


def _read(backend="pane:box"):
    return _call("read_file", {"path": "/data/f.txt", "encoding": "text", "backend": backend})


def _open_dialog(tab, edit):
    """Open the tab's Access… dialog, let *edit* change it, press OK."""
    from ui import agent_access_dialog as D

    def run(dialog):
        edit(dialog.editor)
        return QDialog.DialogCode.Accepted

    with mock.patch.object(D.SessionAccessDialog, "exec", run):
        tab.edit_access()


# -- the tab's own switches --------------------------------------------------------


def test_happy_the_access_dialog_is_saved_with_the_session(env, tmp_path):
    env.settings.access.axross_functions = True
    env.fake({"content": "ok"})
    share = tmp_path / "share"
    share.mkdir()
    dock = env.dock()
    tab = dock.current_tab()

    def edit(editor):
        editor.function_checks["extensions"].setChecked(False)
        _select(editor.network_combo, "hosts")
        editor.host_edit.setText("API.example:443")
        editor.add_host()
        editor.add_folder(str(share))
        editor.folders_table.cellWidget(0, 1).setCurrentIndex(1)  # read-write

    _open_dialog(tab, edit)
    back = SessionStore(env.store_dir).load(tab.session.id)
    assert back.access.axross is True
    assert "extensions" not in back.access.functions and "mcp_servers" in back.access.functions
    assert (back.access.network, back.access.hosts) == ("hosts", ("api.example:443",))
    assert (str(share), True) in back.extra_folders
    assert "network: only 1 host" in tab.access_button.toolTip()


def test_sad_the_tabs_master_switch_off_closes_the_pane_connections(env):
    env.settings.access.axross_functions = True
    env.settings.access.remote_files = True
    env.remote = [_pane()]
    server = env.fake({"tool_calls": [_read()]}, {"content": "cannot"})
    tab = env.dock().current_tab()
    _open_dialog(tab, lambda editor: editor.axross_check.setChecked(False))
    say(tab, "read f.txt on box")
    content = _tool_messages(server.requests[1])[0]["content"]
    assert content.startswith("error") and "text of box" not in content
    assert "list_backends" not in _offered(server.requests[0])


def test_sad_the_settings_master_switch_off_leaves_only_the_conversation_tools(env):
    env.settings.access.axross_functions = False
    env.settings.access.remote_files = True
    env.remote = [_pane()]
    server = env.fake({"content": "ok"})
    tab = env.dock().current_tab()
    say(tab, "hi")
    offered = _offered(server.requests[0])
    assert {"ask_user", "update_plan"} <= offered and "list_backends" not in offered


def test_sad_the_tabs_hosts_refuse_another_pane_connection(env):
    env.settings.access.axross_functions = True
    env.settings.access.remote_files = True
    env.remote = [_pane()]
    server = env.fake({"tool_calls": [_read()]}, {"content": "refused"})
    tab = env.dock().current_tab()

    def edit(editor):
        _select(editor.network_combo, "hosts")
        editor.host_edit.setText("other.example:22")
        editor.add_host()

    _open_dialog(tab, edit)
    say(tab, "read f.txt on box")
    content = _tool_messages(server.requests[1])[0]["content"]
    assert "not an allowed host" in content and "text of box" not in content


def test_happy_the_tabs_hosts_let_the_pane_connection_through(env):
    env.settings.access.axross_functions = True
    env.settings.access.remote_files = True
    env.remote = [_pane()]
    port = env.remote[0][2].port
    server = env.fake({"tool_calls": [_read()]}, {"content": "ok"})
    tab = env.dock().current_tab()

    def edit(editor):
        _select(editor.network_combo, "hosts")
        editor.host_edit.setText(f"box.example:{port}")
        editor.add_host()

    _open_dialog(tab, edit)
    say(tab, "read f.txt on box")
    assert "text of box" in _tool_messages(server.requests[1])[0]["content"]


# -- what the dialog offers ----------------------------------------------------------


def test_edge_the_network_choices_follow_the_tabs_sandbox(env):
    env.settings.sandboxes = [SB.SandboxProfile(name="P", level="paranoid"),
                              SB.SandboxProfile(name="N", level="normal")]
    env.fake({"content": "ok"})
    tab = env.dock().current_tab()
    seen = {}

    def look(name):
        tab.sandbox_combo.setCurrentIndex(tab.sandbox_combo.findData(name))

        def edit(editor):
            seen[name] = [
                editor.network_combo.itemData(i) for i in range(editor.network_combo.count())
            ]

        _open_dialog(tab, edit)

    for name in ("P", "N", ""):
        look(name)
    assert seen == {"P": ["profile", "none"], "N": ["profile", "none", "hosts"],
                    "": ["profile", "none", "hosts", "all"]}


def test_edge_functions_off_in_settings_are_shown_but_cannot_be_ticked(env):
    env.settings.access.axross_functions = True
    env.settings.access.remote_commands = False
    env.fake({"content": "ok"})
    tab = env.dock().current_tab()
    state = {}

    def edit(editor):
        box = editor.function_checks["remote_commands"]
        state["enabled"], state["tip"] = box.isEnabled(), box.toolTip()
        editor.axross_check.setChecked(False)
        state["mcp_after_master_off"] = editor.function_checks["mcp_servers"].isEnabled()

    _open_dialog(tab, edit)
    assert state["enabled"] is False and "Agent Settings" in state["tip"]
    assert state["mcp_after_master_off"] is False


def test_edge_a_session_from_before_follows_the_settings(env):
    old = AgentSession(title="old")
    SessionStore(env.store_dir).save(old)
    env.settings.access.axross_functions = False
    env.fake({"content": "ok"})
    dock = env.dock()
    tab = next(t for t in dock.all_tabs() if t.session.id == old.id)
    assert tab.session.access is None
    assert tab.session_access().axross is False
    env.settings.access.axross_functions = True
    assert tab.session_access().axross is True


def test_edge_a_new_tab_takes_the_master_switch_of_the_settings(env):
    env.settings.access.axross_functions = True
    env.fake({"content": "ok"})
    tab = env.dock().new_tab()
    assert tab.session.access == X.SessionAccess(axross=True)


# -- Agent Settings: Access and Sessions ------------------------------------------------


def test_happy_the_access_page_saves_the_master_switch_and_the_functions(tmp_path):
    from core import agent_settings as S

    path = tmp_path / "settings.json"
    dlg = _dialog(path)
    assert not dlg.remote_files_check.isEnabled()  # the master switch is off
    dlg.axross_check.setChecked(True)
    assert dlg.remote_files_check.isEnabled()
    dlg.extensions_check.setChecked(False)
    dlg.remote_files_check.setChecked(True)
    assert dlg.save()
    access = S.AgentSettings.load(path).access
    assert (
        access.axross_functions
        and access.remote_files
        and not access.extensions
        and access.mcp_servers
    )


def test_happy_the_sessions_page_edits_a_tab_and_stores_it(tmp_path):
    a, b = AgentSession(title="disk report"), AgentSession(title="logs")
    stored = []
    dlg = _dialog(tmp_path / "settings.json", sessions=lambda: [a, b], store_session=stored.append)
    assert [dlg.session_list.item(i).text() for i in range(dlg.session_list.count())] == [
        "disk report",
        "logs",
    ]
    dlg.session_list.setCurrentRow(1)
    dlg.session_editor.axross_check.setChecked(True)
    _select(dlg.session_editor.network_combo, "none")
    assert a.access is None and b.access is None  # nothing changes before Save
    assert dlg.save()
    assert stored == [b]
    assert b.access.axross is True and b.access.network == "none"
    assert a.access is None


def test_sad_cancel_on_the_sessions_page_changes_nothing(tmp_path):
    a = AgentSession(title="t")
    stored = []
    dlg = _dialog(tmp_path / "settings.json", sessions=lambda: [a], store_session=stored.append)
    dlg.session_list.setCurrentRow(0)
    dlg.session_editor.axross_check.setChecked(True)
    dlg.reject()
    assert stored == [] and a.access is None


def test_sad_a_bad_host_is_not_added(tmp_path):
    from ui.agent_access_dialog import AccessEditor

    editor = AccessEditor()
    editor.load(X.SessionAccess(network="hosts"), [], ceiling=None, sandbox=None)
    editor.host_edit.setText("no-port.example")
    editor.add_host()
    assert editor.access().hosts == ()
    assert "port" in editor.host_note.text()
    editor.deleteLater()
    APP.processEvents()
