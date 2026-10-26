"""Every setting really works, part 3: Edit > Settings > Agent - all eight
tabs (General, Profiles, Prompts, Access, Sandboxes, MCP Servers, MCP
Sources, Sessions).

Operator: *„alle bereiche der tools plus neue matrix tests auch bei den
einstellungen. wir brauchen eine saubere abdeckung aller hauptfeatures.“*
Each row runs the four steps of tests/test_settings_matrix.py through the
page's real widgets. The effects are what the agent then does: the request
a new Agent tab sends to a recording LLM server (system prompt, user
prompt, tools offered, a tool result cut to its limit), the tab's
functions and sandbox, the sandbox command line, an MCP server started
from its settings (a scripted stdio program or HTTP endpoint: its tools,
environment, token, timeout, confirmations), the catalog sources searched,
the tab an agent profile sets up, an open tab's own access.

A field of a list entry (a prompt profile's name, a server's command) that
is hand-edited into something invalid drops that entry (the readers leave
it out with a log line): those rows read as ``MISSING`` there.
"""

from __future__ import annotations

import dataclasses
import json
import shlex
import sys
import textwrap
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from PyQt6.QtCore import Qt

from core import agent_settings as AGS
from core import mcp_client as MC
from core.agent_sandbox import DEFAULT_IMAGE, ENGINE_PROGRAMS, RULES, sandbox_command
from tests import test_settings_matrix as SMX
from tests import test_settings_matrix_network_llm as NL
from tests.test_settings_matrix import ctx  # noqa: F401 - the fixture of the matrix

APP = SMX.APP
Row, Secret = SMX.Row, SMX.Secret
MISSING = NL.MISSING
_CURRENT: dict = {}
CATALOG = str(SMX.Path(__file__).resolve().parent / "fixtures" / "mcp_hub" / "catalog.json")
DIGEST = "sha256:" + "ab" * 32


def _ctx():
    return _CURRENT["ctx"]


@pytest.fixture(autouse=True)
def _current_ctx(ctx):
    _CURRENT["ctx"] = ctx
    yield
    _CURRENT.clear()


# ---------------------------------------------------------------------------
# Stores
# ---------------------------------------------------------------------------


def _seed_agent(ctx, **data) -> None:
    path = ctx.stores.agent
    path.parent.mkdir(parents=True, exist_ok=True)
    old = SMX._read_json(path) or {"version": 1}
    old.update(data)
    path.write_text(json.dumps(old))


def _edit_agent(*keys):
    """write_bad: the hand-edited value at keys (dict keys, list indexes)."""

    def write(ctx, value) -> None:
        data = SMX._read_json(ctx.stores.agent) or {"version": 1}
        node = data
        for key in keys[:-1]:
            node = node.setdefault(key, {}) if isinstance(key, str) else node[key]
        node[keys[-1]] = value
        ctx.stores.agent.parent.mkdir(parents=True, exist_ok=True)
        ctx.stores.agent.write_text(json.dumps(data))

    return write


def _S():
    return AGS.AgentSettings.load()


def _ap(dialog):
    return dialog.page("agent")


def _seed_llm_two(ctx) -> None:
    """The LLM profiles "rec" (active; the recording server) and "beta"."""
    NL._seed_llm(ctx)
    data = json.loads(ctx.stores.llm.read_text())
    data["profiles"].append({"name": "beta", "provider": "ollama",
                             "endpoint": ctx.extras["llm"].url, "model": "model-b"})
    ctx.stores.llm.write_text(json.dumps(data))


def _seeds(*steps):
    def setup(ctx) -> None:
        for step in steps:
            step(ctx)

    return setup


# ---------------------------------------------------------------------------
# Effects: a new Agent tab
# ---------------------------------------------------------------------------


def _dock(win):
    return win._agent_dock


def _tab(ctx, win):
    dock = _dock(win)
    dock.refresh_profiles()
    return dock.new_tab(folder=str(ctx.tmp_path))


def _wait(tab) -> None:
    end = time.time() + 20
    while time.time() < end and tab.busy():
        APP.processEvents()
        time.sleep(0.01)
    APP.processEvents()
    assert not tab.busy(), "the agent did not finish"


def _send(ctx, win, task="say done", replies=(), tab=None):
    """*task* typed into a new Agent tab and sent, the real way (the tab's
    Send): the chat requests the recording LLM server got."""
    server = ctx.extras["llm"]
    server.replies = [dict(r) for r in replies]
    before = len(server.chats())
    tab = tab or _tab(ctx, win)
    tab.input.setPlainText(task)
    tab.send()
    _wait(tab)
    chats = server.chats()[before:]
    assert chats, tab.transcript.toPlainText()
    return chats


def _tool_names(chat) -> set:
    return {t["function"]["name"] for t in chat.get("tools") or ()}


_GROUP_TOOLS: dict = {}


def _group_tools(group: str, root: str) -> set:
    """The tools the group *group* adds to the core file tools."""
    from core import agent as A
    from core import llm_profiles as LP

    if group not in _GROUP_TOOLS:
        def names(groups):
            config = A.AgentConfig(profile=LP.LLMProfile(name="x"), root=root,
                                   groups=frozenset(groups))
            return {t.name for t in A.build_tools(config)}

        others = set().union(*(names({g}) for g in AGS.OFFERED_GROUPS if g != group))
        _GROUP_TOOLS[group] = names({group}) - names(set()) - others
    return _GROUP_TOOLS[group]


# -- General ----------------------------------------------------------------------


def effect_llm_profile(ctx, win, value) -> None:
    assert _tab(ctx, win).profile().name == (value or "rec")


def effect_allow_bypass(ctx, win, value) -> None:
    dock = _dock(win)
    assert ("bypass" in dock.tab_modes()) is value
    assert (_tab(ctx, win).mode_combo.findData("bypass") >= 0) is value


def _seed_big_file(ctx) -> None:
    (ctx.tmp_path / "big.txt").write_text("0123456789" * 6000)  # 60 000 characters


def effect_max_tool_chars(ctx, win, value) -> None:
    """A tool result longer than the limit reaches the model cut to it."""
    call = {"role": "assistant", "content": "", "tool_calls": [{
        "id": "c1", "type": "function", "function": {
            "name": "read_file",
            "arguments": json.dumps({"path": str(ctx.tmp_path / "big.txt"),
                                     "encoding": "text"})}}]}
    chats = _send(ctx, win, "read big.txt", replies=[call])
    tool = [m for m in chats[-1]["messages"] if m.get("role") == "tool"][-1]
    assert len(tool["content"]) == value, len(tool["content"])
    assert "[truncated:" in tool["content"]


def effect_keep_sessions(ctx, win, value) -> None:
    from core.agent_session import sessions_dir

    tab = _tab(ctx, win)
    kept = {p.stem for p in sessions_dir().glob("*.json")} if sessions_dir().is_dir() else set()
    assert (tab.session.id in kept) is value


def set_checks(widget, value) -> None:
    for i in range(widget.count()):
        item = widget.item(i)
        item.setCheckState(Qt.CheckState.Checked if item.text() in value
                           else Qt.CheckState.Unchecked)


def shown_checks(widget) -> tuple:
    return tuple(widget.item(i).text() for i in range(widget.count())
                 if widget.item(i).checkState() == Qt.CheckState.Checked)


def effect_groups(ctx, win, value) -> None:
    """A new tab offers the groups' tools to the model - and no others."""
    tab = _tab(ctx, win)
    assert sorted(tab.session.groups) == sorted(value)
    sent = _tool_names(_send(ctx, win, tab=tab)[0])
    checked = 0
    for group in AGS.OFFERED_GROUPS:
        tools = _group_tools(group, str(ctx.tmp_path))  # the group's own tools
        if tools:
            checked += 1
            assert (tools <= sent) is (group in value), (group, tools - sent)
    assert checked >= len(AGS.OFFERED_GROUPS) // 2


# -- Access (the ceiling) -----------------------------------------------------------


def effect_files_read_only(ctx, win, value) -> None:
    """Every tab: no tool that may change a file, whatever the tab allows."""
    from core import agent as A

    tab = _tab(ctx, win)
    assert tab.files_read_only() is value
    if tab.allow_write.isEnabled():
        tab.allow_write.setChecked(True)
    config = tab._config(tab.profile(), mode="ask")
    assert config.files_read_only is value
    writers = [t.name for t in A.Agent(config)._tool_list if A.may_change_files(t)]
    assert bool(writers) is (not value), writers


def effect_axross_functions(ctx, win, value) -> None:
    assert _tab(ctx, win).functions() == (
        frozenset({"mcp_servers", "extensions"}) if value else frozenset())


def _access_effect(name):
    def effect(ctx, win, value) -> None:
        assert (name in _tab(ctx, win).functions()) is value

    return effect


def _seed_master_on(ctx) -> None:
    _seed_agent(ctx, access={"axross_functions": True})


# -- Prompts --------------------------------------------------------------------------

TERSE = {"name": "Terse", "system_prompt": "You are terse.", "user_prompt": ""}


def _seed_terse(active: bool):
    def seed(ctx) -> None:
        _seed_agent(ctx, prompt_profiles=[TERSE], **({"prompt_profile": "Terse"} if active
                                                     else {}))

    return seed


def _system_of(chat) -> str:
    return chat["messages"][0]["content"]


def effect_prompt_active(ctx, win, value) -> None:
    from core import agent as A

    system = _system_of(_send(ctx, win)[0])
    assert ("You are terse." in system) is (value == "Terse")
    assert (A.SYSTEM_PROMPT[:80] in system) is (value != "Terse")


def _prompt_entry(dialog, attr, how="text"):
    page = _ap(dialog)
    if page.prompt_list.count() < 2:
        return MISSING
    page.prompt_list.setCurrentRow(1)
    widget = getattr(page, attr)
    return widget.text() if how == "text" else widget.toPlainText()


def _set_prompt_entry(attr, how="text"):
    def set_ui(ctx, dialog, value) -> None:
        page = _ap(dialog)
        page.prompt_list.setCurrentRow(1)
        widget = getattr(page, attr)
        widget.setText(value) if how == "text" else widget.setPlainText(value)

    return set_ui


def _stored_prompt(field):
    def stored(ctx):
        profiles = _S().prompt_profiles
        return getattr(profiles[0], field) if profiles else MISSING

    return stored


def effect_prompt_name(ctx, win, value) -> None:
    """The active choice follows the rename; a dropped entry leaves Default."""
    settings = _dock(win).agent_settings
    assert settings.active_prompts().name == ("Default" if value == MISSING else value)


def effect_prompt_system(ctx, win, value) -> None:
    from core import agent as A

    system = _system_of(_send(ctx, win)[0])
    assert (A.SYSTEM_PROMPT[:80] if value == MISSING else value) in system


def effect_prompt_user(ctx, win, value) -> None:
    from core.agent_prompts import render_task

    chat = _send(ctx, win, "say done")[0]
    sent = [m for m in chat["messages"] if m["role"] == "user"][-1]["content"]
    template = "" if value == MISSING else value
    assert sent.endswith(render_task(template, "say done")), sent


# -- Sandboxes ---------------------------------------------------------------------------


def _seed_box(**over):
    def seed(ctx) -> None:
        _seed_agent(ctx, sandboxes=[{"name": "Box", "engine": "auto", "level": "normal",
                                     **over}])

    return seed


def _box(win):
    return _dock(win).agent_settings.sandbox_profile("Box")


def _argv(ctx, profile, inner=None) -> list:
    return sandbox_command(profile, str(ctx.tmp_path), writable=True, inner=inner)


def effect_default_sandbox(ctx, win, value) -> None:
    profile = _tab(ctx, win).sandbox_profile()
    assert (profile.name if profile else "") == value


def _box_field(dialog, attr, how="text"):
    page = _ap(dialog)
    if page.sandbox_list.count() == 0:
        return MISSING
    page.sandbox_list.setCurrentRow(0)
    widget = getattr(page, attr)
    return widget.text() if how == "text" else widget.currentData()


def _stored_box(field):
    def stored(ctx):
        boxes = _S().sandboxes
        return getattr(boxes[0], field) if boxes else MISSING

    return stored


def _set_box(attr, how="text"):
    def set_ui(ctx, dialog, value) -> None:
        page = _ap(dialog)
        page.sandbox_list.setCurrentRow(0)
        widget = getattr(page, attr)
        widget.setText(value) if how == "text" else SMX._combo_data(widget, value)

    return set_ui


def effect_box_name(ctx, win, value) -> None:
    settings = _dock(win).agent_settings
    if value == MISSING:
        assert settings.sandboxes == []
        return
    assert [p.name for p in settings.sandboxes] == [value]
    assert settings.sandbox_profile(value) is not None


def effect_box_engine(ctx, win, value) -> None:
    profile = _box(win)
    assert profile.engine == value
    argv = _argv(ctx, profile, ["true"])
    program = ENGINE_PROGRAMS[profile.resolved_engine()]
    assert program in argv[:4], argv[:4]  # bwrap runs under prlimit (the level's limits)
    if value != "auto":
        assert program == ENGINE_PROGRAMS[value]


def effect_box_level(ctx, win, value) -> None:
    argv = _argv(ctx, _box(win))
    rules = RULES[value]
    assert ("--network=none" in argv) is (rules.network != "full")
    assert f"--memory={rules.memory}" in argv and f"--pids-limit={rules.pids}" in argv


def _set_box_hosts(ctx, dialog, value) -> None:
    page = _ap(dialog)
    page.sandbox_list.setCurrentRow(0)
    while page.hosts_list.count():
        page.hosts_list.setCurrentRow(0)
        page.host_remove.click()
    for host in value:
        page.host_edit.setText(host)
        page.host_add.click()


def _shown_box_hosts(dialog):
    page = _ap(dialog)
    page.sandbox_list.setCurrentRow(0)
    return tuple(page.hosts_list.item(i).text() for i in range(page.hosts_list.count()))


def effect_box_hosts(ctx, win, value) -> None:
    """The sandbox reaches exactly its allowed hosts."""
    profile = _box(win)
    assert profile.allows("db.example", 5432) is bool(value)
    assert profile.allows("::1", 8080) is ("[::1]:8080" in value)
    assert not profile.allows("evil.example", 443)


def _set_box_mounts(ctx, dialog, value) -> None:
    page = _ap(dialog)
    page.sandbox_list.setCurrentRow(0)
    while page.mounts_table.rowCount():
        page.mounts_table.setCurrentCell(0, 0)
        page.remove_mount()
    for row, (path, writable) in enumerate(value):
        page.add_mount(path)
        page.mounts_table.cellWidget(row, 1).setCurrentIndex(1 if writable else 0)


def _shown_box_mounts(dialog):
    page = _ap(dialog)
    page.sandbox_list.setCurrentRow(0)
    table = page.mounts_table
    return tuple((table.item(r, 0).text(), bool(table.cellWidget(r, 1).currentData()))
                 for r in range(table.rowCount()))


def effect_box_mounts(ctx, win, value) -> None:
    argv = _argv(ctx, _box(win))
    volumes = {argv[i + 1] for i, a in enumerate(argv) if a == "-v"}
    for path, writable in value:
        assert f"{path}:{path}:{'rw' if writable else 'ro'}" in volumes, volumes
    assert not any(v.startswith(("/srv/", "/opt/")) for v in volumes) or value


def effect_box_image(ctx, win, value) -> None:
    assert _argv(ctx, _box(win))[-1] == value  # podman runs the image's own worker


# -- MCP servers -------------------------------------------------------------------------

FAKE_MCP = textwrap.dedent("""
    import json, os, sys, time
    mode = sys.argv[1] if len(sys.argv) > 1 else "normal"
    def send(m):
        sys.stdout.write(json.dumps(m) + "\\n"); sys.stdout.flush()
    for line in sys.stdin:
        m = json.loads(line)
        if "id" not in m:
            continue
        meth, i = m.get("method"), m["id"]
        if meth == "initialize":
            send({"jsonrpc": "2.0", "id": i, "result": {"protocolVersion": "2024-11-05",
                  "capabilities": {"tools": {}}, "serverInfo": {"name": "fake", "version": "1"}}})
        elif meth == "tools/list":
            time.sleep(float(os.environ.get("FAKE_SLOW") or 0))
            seen = " ".join(f"{k}={os.environ.get(k, '')}" for k in ("GREETING", "API_KEY"))
            names = ["alt_tool"] if mode == "alt" else ["look", "change"]
            send({"jsonrpc": "2.0", "id": i, "result": {"tools": [
                {"name": n, "description": seen, "inputSchema": {"type": "object"},
                 **({"annotations": {"readOnlyHint": True}} if n == "look" else {})}
                for n in names]}})
        else:
            send({"jsonrpc": "2.0", "id": i, "result": {"content": [
                {"type": "text", "text": "ok"}]}})
""")


class HttpMcp:
    """An HTTP MCP endpoint that records each request's path and headers."""

    def __init__(self) -> None:
        self.seen: list[tuple[str, dict]] = []
        seen = self.seen

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):  # noqa: N802
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                seen.append((self.path, {k.lower(): v for k, v in self.headers.items()}))
                if "id" not in body:
                    self.send_response(202)
                    self.send_header("Content-Length", "0")
                    self.end_headers()
                    return
                result = {"tools": [{"name": "web_look", "inputSchema": {"type": "object"}}]} \
                    if body.get("method") == "tools/list" else {
                        "protocolVersion": "2024-11-05", "capabilities": {"tools": {}},
                        "serverInfo": {"name": "web", "version": "1"}}
                raw = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_DELETE(self):  # noqa: N802
                self.send_response(200)
                self.send_header("Content-Length", "0")
                self.end_headers()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._server.daemon_threads = True
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self._server.server_address[1]}"

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()


def _mark(ctx, text: str) -> str:
    """PY, SCRIPT and HTTP name this test's interpreter, script and endpoint."""
    for marker, real in _markers(ctx):
        text = text.replace(marker, real)
    return text


def _unmark(ctx, text: str) -> str:
    for marker, real in _markers(ctx):
        text = text.replace(real, marker)
    return text


def _markers(ctx):
    out = [("SCRIPT", ctx.extras.get("script", "\0")), ("PY", sys.executable)]
    if "http" in ctx.extras:
        out.append(("HTTP", ctx.extras["http"].url))
    return [(m, r) for m, r in out if r]


def _seed_server(**over):
    """The MCP server "fake": the scripted stdio program (or, with
    transport http, the recording endpoint)."""

    def seed(ctx) -> None:
        script = ctx.tmp_path / "fake_mcp.py"
        script.write_text(FAKE_MCP)
        ctx.extras["script"] = str(script)
        ctx.extras["http"] = SMX.keep_open(ctx, HttpMcp())
        server = {"name": "fake", "transport": "stdio",
                  "command": [sys.executable, str(script), "normal"], **over}
        server = {k: (_mark(ctx, v) if isinstance(v, str) else v) for k, v in server.items()}
        _seed_agent(ctx, mcp_servers=[server])
        # Servers started by an effect stop with the window's pool.
        SMX.keep_open(ctx, _PoolCloser(ctx))

    return seed


class _PoolCloser:
    def __init__(self, ctx) -> None:
        self._ctx = ctx

    def close(self) -> None:
        from PyQt6 import sip

        for win in self._ctx.stores.windows:
            if not sip.isdeleted(win):
                win._agent_dock.mcp_pool.close_all()


def _server_field(attr, how="text"):
    def shown(dialog):
        page = _ap(dialog)
        if page.server_list.count() == 0:
            return MISSING
        page.server_list.setCurrentRow(0)
        widget = getattr(page, attr)
        value = {"text": lambda: widget.text(), "edit": lambda: widget.currentText(),
                 "data": lambda: widget.currentData(), "check": lambda: widget.isChecked(),
                 "value": lambda: widget.value()}[how]()
        return _unmark(_ctx(), value) if isinstance(value, str) else value

    return shown


def _set_server(attr, how="text"):
    def set_ui(ctx, dialog, value) -> None:
        page = _ap(dialog)
        page.server_list.setCurrentRow(0)
        widget = getattr(page, attr)
        if how == "text":
            widget.setText(_mark(ctx, value))
        elif how == "edit":
            widget.setEditText(value)
        elif how == "data":
            SMX._combo_data(widget, value)
        elif how == "check":
            widget.setChecked(value)
        else:
            widget.setValue(value)

    return set_ui


def _stored_server(read):
    def stored(ctx):
        servers = _S().mcp_servers
        if not servers:
            return MISSING
        value = read(servers[0])
        return _unmark(ctx, value) if isinstance(value, str) else value

    return stored


def _tools(win, name="fake"):
    tools, errors = _dock(win).mcp_tools([name])
    return {t.name: t for t in tools}, errors


def effect_server_name(ctx, win, value) -> None:
    if value == MISSING:
        assert _dock(win).agent_settings.mcp_servers == []
        return
    tools, errors = _tools(win, value)
    assert f"{value}__look" in tools, errors


def effect_server_enabled(ctx, win, value) -> None:
    tools, errors = _tools(win)
    assert bool(tools) is value, errors


def effect_server_category(ctx, win, value) -> None:
    """Agent profiles choose servers by it."""
    from core import agent_profiles as AGP

    profile = AGP.AgentProfile(name="P", mcp_categories=("Security: Web",))
    servers = AGP.resolve(profile, _dock(win).agent_settings).servers
    assert servers == (["fake"] if value else [])


def effect_server_transport(ctx, win, value) -> None:
    http = ctx.extras["http"]
    before = len(http.seen)
    tools, errors = _tools(win)
    if value == "http":
        assert "fake__web_look" in tools and len(http.seen) > before, errors
    else:
        assert "fake__look" in tools and len(http.seen) == before, errors


def effect_server_command(ctx, win, value) -> None:
    if value == MISSING:
        assert _dock(win).agent_settings.mcp_servers == []
        return
    tools, errors = _tools(win)
    assert set(tools) == ({"fake__alt_tool"} if value.endswith("alt")
                          else {"fake__look", "fake__change"}), errors


def effect_server_env(ctx, win, value) -> None:
    tools, errors = _tools(win)
    greeting = value.split("=", 1)[1] if value else ""
    assert f"GREETING={greeting} " in tools["fake__look"].description + " ", errors


def effect_server_sandbox(ctx, win, value) -> None:
    dock = _dock(win)
    wrap = dock._mcp_wrap(dock.agent_settings.mcp_servers[0])
    if not value:
        assert wrap is None
        return
    profile = dock.agent_settings.sandbox_profile(value)
    argv = wrap(["mcp-program"])
    assert ENGINE_PROGRAMS[profile.resolved_engine()] in argv[:4] and "mcp-program" in argv


def effect_server_url(ctx, win, value) -> None:
    http = ctx.extras["http"]
    if value == MISSING:
        assert _dock(win).agent_settings.mcp_servers == []
        return
    tools, errors = _tools(win)
    assert "fake__web_look" in tools, errors
    assert http.seen[-1][0] == value.replace("HTTP", "")


def effect_server_bearer(ctx, win, value) -> None:
    http = ctx.extras["http"]
    tools, errors = _tools(win)
    assert "fake__web_look" in tools, errors
    assert http.seen[-1][1].get("authorization") == ("Bearer tok" if value else None)


def effect_server_confirm(ctx, win, value) -> None:
    """Always: every call asks, also in Auto. Writes: a tool the server
    marks read-only runs without asking; the others ask as the mode says."""
    tools, errors = _tools(win)
    dock = _dock(win)
    assert tools, errors
    for name in ("fake__look", "fake__change"):
        assert dock.always_ask(name) is (value == "always")
    assert tools["fake__look"].write is (value == "always")  # marked read-only
    assert tools["fake__change"].write


def effect_server_timeout(ctx, win, value) -> None:
    """The program answers after 1.5 s: a timeout of 1 s gives up."""
    tools, errors = _tools(win)
    if value < 1.5:
        assert not tools and errors, errors
    else:
        assert "fake__look" in tools, errors


def effect_server_secret_env(ctx, win, value) -> None:
    tools, errors = _tools(win)
    expected = "API_KEY=sv-API_KEY" if value else "API_KEY="
    assert tools["fake__look"].description.endswith(expected), errors


def effect_server_egress(ctx, win, value) -> None:
    """A container on the allowlist network gets the egress proxy of
    exactly these hosts; without one it does not start."""
    from core.agent_net import parse_host
    from core.mcp_egress import shared_proxy

    server = _dock(win).agent_settings.mcp_servers[0]
    if not value:
        with pytest.raises(MC.McpClientError, match="no allowed host"):
            MC._start_container(server, {})
        return
    proxy = shared_proxy(server.egress)
    assert set(proxy.allowed) == {parse_host(h) for h in value.split()}


# -- MCP sources -------------------------------------------------------------------------

SOURCE_IDS = {"builtin": "builtin", "c0decave": "c0decave", "dockerhub": "dockerhub",
              "mcpregistry": "mcpregistry", "discover": "discover"}


def _source_effect(flag):
    def effect(ctx, win, value) -> None:
        ids = [s.id for s in _dock(win).agent_settings.mcp_sources.sources()]
        assert (SOURCE_IDS[flag] in ids) is value

    return effect


def _set_extra_sources(ctx, dialog, value) -> None:
    page = _ap(dialog)
    while page.source_list.count():
        page.source_list.setCurrentRow(0)
        page.remove_source()
    for location in value:
        assert page.add_source_file(CATALOG if location == "CAT" else location)


def _shown_extra(dialog) -> tuple:
    page = _ap(dialog)
    return tuple("CAT" if page.source_list.item(i).text() == CATALOG
                 else page.source_list.item(i).text() for i in range(page.source_list.count()))


def effect_extra_sources(ctx, win, value) -> None:
    """Add from Catalog searches the user's catalog file too."""
    sources = [s for s in _dock(win).agent_settings.mcp_sources.sources()
               if s.id.startswith("file:")]
    assert [s.path for s in sources] == [CATALOG for _v in value]
    for source in sources:
        result = source.search("binwalk")
        assert [e.name for e in result.entries] == ["binwalk"], result.error


# -- Agent profiles ----------------------------------------------------------------------


def _seed_profiles(**profile):
    """A user's agent profile "Triage" (defaults but *profile*), the LLM
    profiles rec and beta, the prompt profile Terse, the server "fake" of
    category Security: Web, and an Access page that allows everything."""

    def seed(ctx) -> None:
        _seed_llm_two(ctx)
        _seed_server(category="Security: Web")(ctx)
        _seed_agent(ctx, prompt_profiles=[TERSE],
                    access={"axross_functions": True, "remote_files": True,
                            "saved_profiles": True, "remote_commands": True},
                    agent_profiles=[{"name": "Triage", **profile}])

    return seed


def _select_profile(page) -> bool:
    rows = page._agent_profile_rows()
    index = next((i for i, p in enumerate(rows) if not p.preset), -1)
    if index < 0:
        return False
    page.agent_profile_list.setCurrentRow(index)
    return True


def _profile_widget(page, attr):
    owner = page
    for part in attr.split("."):
        if "[" in part:
            name, key = part[:-1].split("[")
            owner = getattr(owner, name)[key]
        else:
            owner = getattr(owner, part)
    return owner


def _set_profile(attr, how):
    def set_ui(ctx, dialog, value) -> None:
        page = _ap(dialog)
        assert _select_profile(page)
        widget = _profile_widget(page, attr)
        if how == "text":
            widget.setText(value)
        elif how == "data":
            SMX._combo_data(widget, value)
        elif how == "check":
            widget.setChecked(value)
        elif how == "checks":
            set_checks(widget, value)
        elif how == "hosts":
            editor = page.agent_profile_access
            while editor.hosts_list.count():
                editor.hosts_list.setCurrentRow(0)
                editor.host_remove.click()
            for host in value:
                editor.host_edit.setText(host)
                editor.host_add.click()

    return set_ui


def _shown_profile(attr, how):
    def shown(dialog):
        page = _ap(dialog)
        if not _select_profile(page):
            return MISSING
        widget = _profile_widget(page, attr)
        if how == "text":
            return widget.text()
        if how == "data":
            return widget.currentData()
        if how == "check":
            return widget.isChecked()
        if how == "checks":
            return shown_checks(widget)
        return tuple(widget.item(i).text() for i in range(widget.count()))  # hosts

    return shown


def _stored_profile(field):
    def stored(ctx):
        profiles = _S().agent_profiles
        return getattr(profiles[0], field) if profiles else MISSING

    return stored


def _from_profile(ctx, win):
    tab = _dock(win).new_tab_from_profile("Triage", folder=str(ctx.tmp_path))
    assert tab is not None
    return tab


def _profile_effect(read):
    def effect(ctx, win, value) -> None:
        assert read(_from_profile(ctx, win)) == value

    return effect


def effect_profile_name(ctx, win, value) -> None:
    dock = _dock(win)
    if value == MISSING:
        assert dock.agent_settings.agent_profiles == []
        return
    tab = dock.new_tab_from_profile(value, folder=str(ctx.tmp_path))
    assert tab is not None and tab.session.agent_profile == value


def effect_profile_description(ctx, win, value) -> None:
    from PyQt6.QtWidgets import QMenu

    menu = QMenu()
    _dock(win).fill_new_from_profile_menu(menu)
    tips = {a.text(): a.toolTip() for a in menu.actions() if not a.isSeparator()}
    # Without a tool tip of its own Qt shows the entry's text.
    assert [tip if tip != text else "" for text, tip in tips.items()
            if text.startswith("Triage")] == [value]
    menu.deleteLater()


def effect_profile_default(ctx, win, value) -> None:
    assert _tab(ctx, win).session.agent_profile == value


def _plain_groups(tab) -> tuple:
    """The tool groups of the tab, in the order of the list."""
    chosen = set(tab.session.groups)
    return tuple(g for g in AGS.OFFERED_GROUPS if g in chosen)


def _mcp_chosen(tab) -> bool:
    return "mcp:fake" in tab.session.groups


# -- Sessions (an open tab's own access) -----------------------------------------------

SESSION_ID = "a" * 32


def _seed_session(**access):
    """An open tab "Probe" (a saved session restored at start) with every
    function, and an Access page that allows every function."""

    def seed(ctx) -> None:
        from core.agent_access import FUNCTIONS
        from core.agent_session import sessions_dir

        _seed_agent(ctx, access={"axross_functions": True, **{f: True for f in FUNCTIONS}})
        folder = sessions_dir()
        folder.mkdir(parents=True, exist_ok=True)
        data = {"version": 1, "id": SESSION_ID, "title": "Probe", "folder": str(ctx.tmp_path),
                "access": {"axross": True, "functions": list(FUNCTIONS), "network": "profile",
                           "hosts": [], **access}, "extra_folders": []}
        (folder / f"{SESSION_ID}.json").write_text(json.dumps(data))

    return seed


def _session_file(ctx):
    from core.agent_session import sessions_dir

    return sessions_dir() / f"{SESSION_ID}.json"


def _edit_session(*keys):
    def write(ctx, value) -> None:
        path = _session_file(ctx)
        data = json.loads(path.read_text())
        node = data
        for key in keys[:-1]:
            node = node[key]
        node[keys[-1]] = value
        path.write_text(json.dumps(data))

    return write


def _stored_session(read):
    def stored(ctx):
        from core.agent_session import SessionStore

        return read(SessionStore().load(SESSION_ID))

    return stored


def _editor(dialog):
    page = _ap(dialog)
    page.session_list.setCurrentRow(0)
    assert page.session_editor.isEnabled()
    return page.session_editor


def _set_session(attr, how):
    def set_ui(ctx, dialog, value) -> None:
        editor = _editor(dialog)
        if how == "check":
            _profile_widget(editor, attr).setChecked(value)
        elif how == "data":
            SMX._combo_data(editor.network_combo, value)
        elif how == "hosts":
            while editor.hosts_list.count():
                editor.hosts_list.setCurrentRow(0)
                editor.host_remove.click()
            for host in value:
                editor.host_edit.setText(host)
                editor.host_add.click()
        else:  # folders
            while editor.folders_table.rowCount():
                editor.folders_table.setCurrentCell(0, 0)
                editor.remove_folder()
            for row, (path, writable) in enumerate(value):
                editor.add_folder(path)
                editor.folders_table.cellWidget(row, 1).setCurrentIndex(1 if writable else 0)

    return set_ui


def _shown_session(attr, how):
    def shown(dialog):
        editor = _editor(dialog)
        if how == "check":
            return _profile_widget(editor, attr).isChecked()
        if how == "data":
            return editor.network_combo.currentData()
        if how == "hosts":
            return tuple(editor.access().hosts)
        return tuple(editor.folders())

    return shown


def _open_tab(win):
    tabs = _dock(win).all_tabs()
    assert [t.session.id for t in tabs] == [SESSION_ID]
    return tabs[0]


def _session_effect(read):
    def effect(ctx, win, value) -> None:
        assert read(_open_tab(win)) == value

    return effect


def effect_session_hosts(ctx, win, value) -> None:
    from core import agent_access as X

    tab = _open_tab(win)
    assert tab.session_access().hosts == value
    assert X.firewall(tab.session_access())("db.example", 5432) is bool(value)


def effect_session_folders(ctx, win, value) -> None:
    tab = _open_tab(win)
    assert tuple(tab._config(tab.profile() or _profile_stub(), mode="ask").extra_roots) == value


def _profile_stub():
    from core import llm_profiles as LP

    return LP.LLMProfile(name="stub")


# ---------------------------------------------------------------------------
# The table
# ---------------------------------------------------------------------------


def _row(row_id, widgets, values, default, set_ui, shown, stored, write_bad, bad, effect,
         *, setup=None, store="agent/settings.json", **kw):
    return Row(row_id, "agent", store, values, default, set_ui, shown, stored, write_bad, bad,
               effect, widgets=tuple(f"agent.{w}" for w in widgets), setup=setup,
               edit_needs_start=True, **kw)


def _check_row(row_id, attr, default, stored, keys, effect, *, setup=None, bad=("yes", 1)):
    return _row(row_id, (attr,), (not default,), default, SMX._set_check("agent", attr),
                SMX._page_attr("agent", attr), stored, _edit_agent(*keys), bad, effect,
                setup=setup)


DEFAULTS = AGS.AgentSettings()
FUNCTIONS = ("remote_files", "saved_profiles", "remote_commands", "mcp_servers", "extensions")

GENERAL_ROWS = [
    _row("agent_llm_profile", ("profile_combo",), ("beta",), "",
         SMX._set_combo("agent", "profile_combo"),
         lambda d: _ap(d).profile_combo.currentData() or "", lambda c: _S().profile,
         _edit_agent("profile"), (5, ["beta"]), effect_llm_profile, setup=_seed_llm_two),
    _check_row("agent_allow_bypass", "bypass_check", False, lambda c: _S().allow_bypass,
               ("allow_bypass",), effect_allow_bypass),
    _row("agent_max_tool_chars", ("chars_spin",), (500, 40000), DEFAULTS.max_tool_chars,
         SMX._set_spin("agent", "chars_spin"), SMX._page_attr("agent", "chars_spin", "value"),
         lambda c: _S().max_tool_chars, _edit_agent("max_tool_chars"),
         ("x", 0, 2_000_000, True), effect_max_tool_chars,
         setup=_seeds(NL._seed_llm, _seed_big_file)),
    _check_row("agent_keep_sessions", "keep_check", True, lambda c: _S().keep_sessions,
               ("keep_sessions",), effect_keep_sessions, bad=("no", 0)),
    _row("agent_groups", ("groups_list",), (("duplicates", "index"), ()), DEFAULTS.groups,
         lambda c, d, v: set_checks(_ap(d).groups_list, v),
         lambda d: shown_checks(_ap(d).groups_list), lambda c: _S().groups,
         _edit_agent("groups"), (5, "metadata", None), effect_groups, setup=NL._seed_llm),
]

ACCESS_ROWS = [
    _row("agent_files_read_only", ("files_read_only_check",), (True,), False,
         SMX._set_check("agent", "files_read_only_check"),
         SMX._page_attr("agent", "files_read_only_check"),
         lambda c: _S().access.files_read_only, _edit_agent("access", "files_read_only"),
         ("yes", 1), effect_files_read_only, setup=NL._seed_llm),
    _check_row("agent_axross_functions", "axross_check", False,
               lambda c: _S().access.axross_functions, ("access", "axross_functions"),
               effect_axross_functions),
    *[_check_row(f"agent_access_{name}", f"{name}_check", getattr(DEFAULTS.access, name),
                 (lambda n: lambda c: getattr(_S().access, n))(name), ("access", name),
                 _access_effect(name), setup=_seed_master_on) for name in FUNCTIONS],
]

PROMPT_ROWS = [
    _row("agent_prompt_active", ("prompt_active_combo",), ("Terse",), "",
         SMX._set_combo("agent", "prompt_active_combo"),
         lambda d: _ap(d).prompt_active_combo.currentData() or "",
         lambda c: _S().prompt_profile, _edit_agent("prompt_profile"), (5, "Gone"),
         effect_prompt_active, setup=_seeds(NL._seed_llm, _seed_terse(False))),
    _row("agent_prompt_name", ("prompt_name_edit",), ("Brief",), "Terse",
         _set_prompt_entry("prompt_name_edit"), lambda d: _prompt_entry(d, "prompt_name_edit"),
         _stored_prompt("name"), _edit_agent("prompt_profiles", 0, "name"),
         (5, "", "Default"), effect_prompt_name, setup=_seed_terse(True), bad_reads_as=MISSING),
    _row("agent_prompt_system", ("prompt_system_edit",), ("Answer in haiku.",),
         "You are terse.", _set_prompt_entry("prompt_system_edit", "plain"),
         lambda d: _prompt_entry(d, "prompt_system_edit", "plain"),
         _stored_prompt("system_prompt"), _edit_agent("prompt_profiles", 0, "system_prompt"),
         ("", 5, "   "), effect_prompt_system, setup=_seeds(NL._seed_llm, _seed_terse(True)),
         bad_reads_as=MISSING),
    _row("agent_prompt_user", ("prompt_user_edit",), ("Answer in German: {task}", "Be brief."),
         "", _set_prompt_entry("prompt_user_edit", "plain"),
         lambda d: _prompt_entry(d, "prompt_user_edit", "plain"),
         _stored_prompt("user_prompt"), _edit_agent("prompt_profiles", 0, "user_prompt"),
         (5, ["x"]), effect_prompt_user, setup=_seeds(NL._seed_llm, _seed_terse(True)),
         bad_reads_as=MISSING),
]

SANDBOX_ROWS = [
    _row("agent_default_sandbox", ("default_sandbox_combo",), ("High",), "",
         SMX._set_combo("agent", "default_sandbox_combo"),
         lambda d: _ap(d).default_sandbox_combo.currentData() or "", lambda c: _S().sandbox,
         _edit_agent("sandbox"), (5, "Gone"), effect_default_sandbox),
    _row("agent_sandbox_name", ("name_edit",), ("Wide open",), "Box", _set_box("name_edit"),
         lambda d: _box_field(d, "name_edit"), _stored_box("name"),
         _edit_agent("sandboxes", 0, "name"), ("", 5, "   "), effect_box_name,
         setup=_seed_box(), bad_reads_as=MISSING),
    _row("agent_sandbox_engine", ("engine_combo",), ("podman", "bubblewrap"), "auto",
         _set_box("engine_combo", "data"), lambda d: _box_field(d, "engine_combo", "data"),
         _stored_box("engine"), _edit_agent("sandboxes", 0, "engine"), ("chroot", 5),
         effect_box_engine, setup=_seed_box()),
    _row("agent_sandbox_level", ("level_combo",), ("paranoid", "lax"), "normal",
         _set_box("level_combo", "data"), lambda d: _box_field(d, "level_combo", "data"),
         _stored_box("level"), _edit_agent("sandboxes", 0, "level"), ("extreme", 5),
         effect_box_level, setup=_seed_box(engine="podman")),
    _row("agent_sandbox_hosts", ("hosts_list",),
         (("db.example:5432",), ("db.example:5432", "[::1]:8080")), (),
         _set_box_hosts, _shown_box_hosts, _stored_box("hosts"),
         _edit_agent("sandboxes", 0, "hosts"), ("db.example:5432", 5, ["not a host"]),
         effect_box_hosts, setup=_seed_box()),
    _row("agent_sandbox_mounts", ("mounts_table",),
         ((("/srv/data", False),), (("/srv/data", True), ("/opt/tools", False))), (),
         _set_box_mounts, _shown_box_mounts, _stored_box("mounts"),
         _edit_agent("sandboxes", 0, "mounts"),
         ("/srv/data", [{"path": "relative", "mode": "rw"}], 5), effect_box_mounts,
         setup=_seed_box(engine="podman")),
    _row("agent_sandbox_image", ("image_edit",), ("localhost/my-agent:1",), DEFAULT_IMAGE,
         _set_box("image_edit"), lambda d: _box_field(d, "image_edit"), _stored_box("image"),
         _edit_agent("sandboxes", 0, "image"), ("", 5, "   "), effect_box_image,
         setup=_seed_box(engine="podman")),
]


def _server_row(row_id, attr, how, values, default, read, key, bad, effect, *, seed=None,
                bad_reads_as="default"):
    return _row(row_id, (attr,), values, default, _set_server(attr, how),
                _server_field(attr, how), _stored_server(read),
                _edit_agent("mcp_servers", 0, key), bad, effect,
                setup=seed or _seed_server(), bad_reads_as=bad_reads_as)


def _seed_token(ctx) -> None:
    ctx.monkeypatch.setattr(MC, "get_token", lambda name: "tok" if name == "fake" else "")


def _seed_secret(ctx) -> None:
    ctx.monkeypatch.setattr(MC, "get_secret", lambda name, var: f"sv-{var}")


def _seed_container(ctx) -> None:
    from core import mcp_install as I

    _seed_server(command=I.run_command("fake", "img@" + DIGEST, network="allowlist"),
                 container=True, egress=["api.example.com:443"])(ctx)


SERVER_ROWS = [
    _server_row("mcp_server_name", "server_name_edit", "text", ("renamed",), "fake",
                lambda s: s.name, "name", ("bad name!", 5, ""), effect_server_name,
                bad_reads_as=MISSING),
    _server_row("mcp_server_enabled", "server_enabled_check", "check", (False,), True,
                lambda s: s.enabled, "enabled", ("no", 0), effect_server_enabled),
    _server_row("mcp_server_category", "server_category_combo", "edit", ("Security: Web",), "",
                lambda s: s.category, "category", (5, ["x"], "a\nb"), effect_server_category),
    _server_row("mcp_server_transport", "server_transport_combo", "data", ("http",), "stdio",
                lambda s: s.transport, "transport", ("pigeon", 5), effect_server_transport,
                seed=_seed_server(url="HTTP/mcp")),
    _server_row("mcp_server_command", "server_command_edit", "text", ("PY SCRIPT alt",),
                "PY SCRIPT normal", lambda s: shlex.join(s.command), "command",
                (5, [], ["PY", 5]), effect_server_command, bad_reads_as=MISSING),
    _server_row("mcp_server_env", "server_env_edit", "text", ("GREETING=hello",), "",
                lambda s: " ".join(f"{k}={v}" for k, v in s.env.items()), "env",
                (5, ["x"], {"GREETING": 5}), effect_server_env),
    _server_row("mcp_server_sandbox", "server_sandbox_combo", "data", ("Lax",), "",
                lambda s: s.sandbox, "sandbox", (5, None), effect_server_sandbox),
    _server_row("mcp_server_url", "server_url_edit", "text", ("HTTP/b",), "HTTP/a",
                lambda s: s.url, "url", (5, "ftp://x/"), effect_server_url,
                seed=_seed_server(transport="http", url="HTTP/a", command=[]),
                bad_reads_as=MISSING),
    _server_row("mcp_server_bearer", "server_bearer_check", "check", (True,), False,
                lambda s: s.bearer, "bearer", ("yes", 1), effect_server_bearer,
                seed=_seeds(_seed_token,
                            _seed_server(transport="http", url="HTTP/mcp", command=[]))),
    _server_row("mcp_server_confirm", "server_confirm_combo", "data", ("writes",), "always",
                lambda s: s.confirm, "confirm", ("never", 5), effect_server_confirm),
    _server_row("mcp_server_timeout", "server_timeout_spin", "value", (1.0, 300.0), 120.0,
                lambda s: s.timeout, "timeout", ("x", 0, 9999, True), effect_server_timeout,
                seed=_seed_server(env={"FAKE_SLOW": "1.5"})),
    _server_row("mcp_server_secret_env", "server_secret_env_edit", "text", ("API_KEY",), "",
                lambda s: " ".join(s.secret_env), "secret_env", (5, ["1BAD"]),
                effect_server_secret_env, seed=_seeds(_seed_secret, _seed_server())),
    _server_row("mcp_server_egress", "server_egress_edit", "text",
                ("db.example:5432 api.example.com:443",), "api.example.com:443",
                lambda s: " ".join(s.egress), "egress", (5, "api.example.com:443"),
                effect_server_egress, seed=_seed_container, bad_reads_as=""),
]

SOURCE_ROWS = [
    *[_check_row(f"mcp_source_{flag}", attr, True,
                 (lambda f: lambda c: getattr(_S().mcp_sources, f))(flag), ("mcp_sources", flag),
                 _source_effect(flag), bad=("no", 0))
      for flag, attr in (("builtin", "source_builtin_check"), ("c0decave", "source_hub_check"),
                         ("dockerhub", "source_dockerhub_check"),
                         ("mcpregistry", "source_registry_check"),
                         ("discover", "source_discover_check"))],
    _row("mcp_source_extra", ("source_list",), (("CAT",),), (), _set_extra_sources,
         _shown_extra, lambda c: tuple("CAT" if e == CATALOG else e
                                       for e in _S().mcp_sources.extra),
         _edit_agent("mcp_sources", "extra"), ("CAT", ["relative/catalog.json"], 5),
         effect_extra_sources),
]


def _profile_row(row_id, attr, how, values, default, field, read, bad, *, seed=None,
                 bad_reads_as="default", effect=None):
    return _row(row_id, (attr,), values, default, _set_profile(attr, how),
                _shown_profile(attr, how), _stored_profile(field),
                _edit_agent("agent_profiles", 0, field), bad,
                effect or _profile_effect(read), setup=_seed_profiles(**(seed or {})),
                bad_reads_as=bad_reads_as)


PROFILE_ROWS = [
    _row("agent_profile_default", ("agent_profile_default_combo",), ("Triage",), "",
         SMX._set_combo("agent", "agent_profile_default_combo"),
         lambda d: _ap(d).agent_profile_default_combo.currentData() or "",
         lambda c: _S().agent_profile, _edit_agent("agent_profile"), (5, "Gone"),
         effect_profile_default, setup=_seed_profiles()),
    _profile_row("agent_profile_name", "agent_profile_name_edit", "text", ("Incident",),
                 "Triage", "name", None, ("", 5, "Research"), bad_reads_as=MISSING,
                 effect=effect_profile_name),
    _profile_row("agent_profile_description", "agent_profile_description_edit", "text",
                 ("Look before you touch",), "", "description", None, (5, ["x"], "two\nlines"),
                 effect=effect_profile_description),
    _profile_row("agent_profile_llm", "agent_profile_llm_combo", "data", ("beta",), "",
                 "llm_profile", lambda t: "" if t.profile().name == "rec" else t.profile().name,
                 (5, ["beta"])),
    _profile_row("agent_profile_prompt", "agent_profile_prompt_combo", "data",
                 ("Terse", "Default"), "", "prompt_profile",
                 lambda t: "" if not t.session.prompt_profile else t.prompts().name, (5,)),
    _profile_row("agent_profile_mode", "agent_profile_mode_combo", "data", ("plan", "auto"),
                 "ask", "mode", lambda t: t.session.mode, ("yolo", 5)),
    _profile_row("agent_profile_sandbox", "agent_profile_sandbox_combo", "data", ("High",), "",
                 "sandbox", lambda t: (t.sandbox_profile().name if t.sandbox_profile() else ""),
                 (5,)),
    _profile_row("agent_profile_groups", "agent_profile_groups", "checks", (("index",), ()),
                 AGS.DEFAULT_GROUPS, "groups", _plain_groups, (5, "metadata")),
    _profile_row("agent_profile_files_read_only", "agent_profile_read_only_check", "check",
                 (True,), False, "files_read_only", lambda t: t.session.files_read_only,
                 ("yes", 1)),
    _profile_row("agent_profile_allow_write", "agent_profile_write_check", "check", (True,),
                 False, "allow_write", lambda t: t.session.allow_write, ("yes", 1)),
    _profile_row("agent_profile_allow_exec", "agent_profile_exec_check", "check", (True,), False,
                 "allow_exec", lambda t: t.session.allow_exec, ("yes", 1),
                 seed={"axross": True, "functions": ["remote_commands"]}),
    _profile_row("agent_profile_axross", "agent_profile_access.axross_check", "check", (True,),
                 False, "axross", lambda t: t.session.access.axross, ("yes", 1)),
    *[_profile_row(f"agent_profile_function_{name}",
                   f"agent_profile_access.function_checks[{name}]", "check", (True,), False,
                   "functions", (lambda n: lambda t: n in t.session.access.functions)(name),
                   (name, 5), seed={"axross": True})
      for name in FUNCTIONS],
    _profile_row("agent_profile_network", "agent_profile_access.network_combo", "data",
                 ("none", "hosts"), "profile", "network", lambda t: t.session.access.network,
                 ("everything", 5)),
    _profile_row("agent_profile_hosts", "agent_profile_access.hosts_list", "hosts",
                 (("db.example:5432",),), (), "hosts", lambda t: t.session.access.hosts,
                 ("db.example:5432", 5), seed={"network": "hosts"}),
    _profile_row("agent_profile_categories", "agent_profile_categories", "checks",
                 (("Security: Web",),), (), "mcp_categories",
                 lambda t: ("Security: Web",) if _mcp_chosen(t) else (), (5, "Security: Web")),
    _profile_row("agent_profile_servers", "agent_profile_servers", "checks", (("fake",),), (),
                 "mcp_servers", lambda t: ("fake",) if _mcp_chosen(t) else (), (5, "fake")),
]
# The function rows store a tuple; their check is one function of it.
PROFILE_ROWS = [
    row if not row.id.startswith("agent_profile_function_") else dataclasses.replace(
        row, stored=(lambda n: lambda c: (n in _S().agent_profiles[0].functions))(
            row.id.removeprefix("agent_profile_function_")))
    for row in PROFILE_ROWS]


def _session_row(row_id, attr, how, values, default, read, keys, bad, effect=None, *,
                 seed=None, bad_reads_as="default"):
    return _row(row_id, (f"session_editor.{attr}",), values, default, _set_session(attr, how),
                _shown_session(attr, how), _stored_session(read), _edit_session(*keys), bad,
                effect or _session_effect(read), setup=_seed_session(**(seed or {})),
                store="agent/sessions/<id>.json access", new_window=True,
                bad_reads_as=bad_reads_as)


SESSION_ROWS = [
    _session_row("session_axross", "axross_check", "check", (False,), True,
                 lambda s: s.access.axross, ("access", "axross"), ("no", 0),
                 effect=_session_effect(lambda t: bool(t.functions())),
                 bad_reads_as=False),  # fails closed: no axross functions
    *[_session_row(f"session_function_{name}", f"function_checks[{name}]", "check", (False,),
                   True, (lambda n: lambda s: n in s.access.functions)(name),
                   ("access", "functions"), (name, 5),
                   effect=_session_effect((lambda n: lambda t: n in t.functions())(name)))
      for name in FUNCTIONS],
    _session_row("session_network", "network_combo", "data", ("none", "hosts"), "profile",
                 lambda s: s.access.network, ("access", "network"), ("everything", 5),
                 effect=_session_effect(lambda t: t.session_access().network)),
    _session_row("session_hosts", "hosts_list", "hosts", (("db.example:5432",),), (),
                 lambda s: s.access.hosts, ("access", "hosts"), ("db.example:5432", 5),
                 effect_session_hosts, seed={"network": "hosts"}),
    _session_row("session_folders", "folders_table", "folders",
                 ((("/srv/data", False),), (("/srv/data", True), ("/opt/tools", False))), (),
                 lambda s: tuple(s.extra_folders), ("extra_folders",),
                 ("/srv/data", [{"path": "relative"}], 5), effect_session_folders),
]

#: Every row of the Agent page (the completeness test reads them here). The
#: rows of MCP Servers and Sources, Profiles and Sessions run in files of
#: their own (tests/test_settings_matrix_agent_{mcp,profiles,profile_access,
#: sessions}.py), so that they run side by side, each well within the time
#: limit of one test process.
ROWS = (GENERAL_ROWS + ACCESS_ROWS + PROMPT_ROWS + SANDBOX_ROWS + SERVER_ROWS + SOURCE_ROWS
        + PROFILE_ROWS + SESSION_ROWS)


def params(rows) -> list:
    return [pytest.param(row, id=row.id) for row in rows]


ROW_PARAMS = params(GENERAL_ROWS + ACCESS_ROWS + PROMPT_ROWS + SANDBOX_ROWS)
#: The Profiles rows of a profile's own settings and of what it may reach.
PROFILE_ACCESS_IDS = ("agent_profile_axross", "agent_profile_network", "agent_profile_hosts",
                      "agent_profile_categories", "agent_profile_servers")


def is_profile_access(row) -> bool:
    return row.id in PROFILE_ACCESS_IDS or row.id.startswith("agent_profile_function_")


@pytest.mark.parametrize("row", ROW_PARAMS)
def test_set_store_reload_effect(ctx, row) -> None:
    SMX.check_set_store_reload_effect(ctx, row)


@pytest.mark.parametrize("row", ROW_PARAMS)
def test_hand_edited_value_falls_back(ctx, row) -> None:
    SMX.check_hand_edited_value_falls_back(ctx, row)


# ---------------------------------------------------------------------------
# Secrets: an http server's token
# ---------------------------------------------------------------------------


def _type_token(ctx, dialog, value) -> None:
    page = _ap(dialog)
    page.server_list.setCurrentRow(0)
    assert page.server_token_edit.isEnabled()
    page.server_token_edit.setText(value)


def _effect_token(ctx, win, value) -> None:
    tools, errors = _tools(win)
    assert "fake__web_look" in tools, errors
    assert ctx.extras["http"].seen[-1][1].get("authorization") == f"Bearer {value}"


def _kept_token(ctx) -> str:
    return MC.get_token("fake")


SECRETS = [
    Secret("mcp_server_token", "agent", ("agent.server_token_edit",),
           _seed_server(transport="http", url="HTTP/mcp", command=[], bearer=True),
           _type_token, _kept_token, lambda d: _ap(d).server_token_edit.text(), _effect_token),
]


@pytest.mark.parametrize("secret", [pytest.param(s, id=s.id) for s in SECRETS])
def test_secret_goes_to_the_keyring_and_is_used(ctx, memory_keyring, secret) -> None:
    NL.check_secret(ctx, secret)


memory_keyring = NL.memory_keyring


# ---------------------------------------------------------------------------
# Cross effects
# ---------------------------------------------------------------------------


def test_cross_bypass_switch_off_takes_the_bypass_mode_away(ctx) -> None:
    """General: Bypass mode needs "Bypass may be chosen"; switched off, the
    mode falls back to Ask - on the page, in the store, in a new tab - and a
    hand-edited bypass without the switch reads as Ask."""
    dialog = ctx.dialog()
    page = _ap(dialog)
    page.bypass_check.setChecked(True)
    SMX._combo_data(page.mode_combo, "bypass")
    assert dialog.apply()
    assert (_S().allow_bypass, _S().mode) == (True, "bypass")
    assert _tab(ctx, ctx.win).session.mode == "bypass"
    dialog = ctx.dialog()
    page = _ap(dialog)
    page.bypass_check.setChecked(False)
    assert page.mode_combo.findData("bypass") < 0 and page.mode_combo.currentData() == "ask"
    assert dialog.apply()
    assert (_S().allow_bypass, _S().mode) == (False, "ask")
    assert _tab(ctx, ctx.win).session.mode == "ask"
    _edit_agent("mode")(ctx, "bypass")
    assert _S().mode == "ask"


def test_cross_master_switch_off_locks_every_function(ctx) -> None:
    """Access: a function ticked under a master switch that is off is
    greyed out on the page and reaches no tab; the master switch on, it does."""
    _seed_agent(ctx, access={"axross_functions": False, "remote_files": True})
    SMX._start(ctx)
    page = _ap(ctx.dialog())
    assert page.remote_files_check.isChecked() and not page.remote_files_check.isEnabled()
    assert _tab(ctx, ctx.win).functions() == frozenset()
    dialog = ctx.dialog()
    _ap(dialog).axross_check.setChecked(True)
    assert _ap(dialog).remote_files_check.isEnabled()
    assert dialog.apply()
    assert "remote_files" in _tab(ctx, ctx.win).functions()


def test_cross_the_ceiling_cuts_an_open_tabs_own_access(ctx) -> None:
    """Access x Sessions: the open tab keeps its own choice, but what the
    Access page switches off it no longer gets - and gets back."""
    _seed_session()(ctx)
    SMX._start(ctx)
    tab = _open_tab(ctx.win)
    assert "remote_commands" in tab.functions()
    dialog = ctx.dialog()
    _ap(dialog).remote_commands_check.setChecked(False)
    assert dialog.apply()
    assert "remote_commands" not in tab.functions()
    assert "remote_commands" in tab.session_access().functions  # its own choice is kept
    editor = _editor(ctx.dialog())
    assert not editor.function_checks["remote_commands"].isEnabled()
    dialog = ctx.dialog()
    _ap(dialog).remote_commands_check.setChecked(True)
    assert dialog.apply()
    assert "remote_commands" in tab.functions()


def test_cross_read_only_ceiling_overrides_an_agent_profile_that_writes(ctx) -> None:
    _seed_profiles(allow_write=True, allow_exec=True, axross=True,
                   functions=["remote_commands"])(ctx)
    SMX._start(ctx)
    tab = _from_profile(ctx, ctx.win)
    assert (tab.session.allow_write, tab.session.allow_exec) == (True, True)
    dialog = ctx.dialog()
    _ap(dialog).files_read_only_check.setChecked(True)
    assert dialog.apply()
    tab = _from_profile(ctx, ctx.win)
    assert (tab.session.allow_write, tab.session.allow_exec) == (False, False)
    assert tab.files_read_only()


def test_cross_a_sandbox_renamed_under_its_mcp_server_is_refused(ctx) -> None:
    """Sandboxes x MCP Servers: a server runs in a sandbox profile; renaming
    that profile is refused on save (the server would run without it) and
    nothing is written."""
    _seed_box()(ctx)
    _seed_server(sandbox="Box")(ctx)
    SMX._start(ctx)
    before = ctx.stores.agent.read_text()
    dialog = ctx.dialog()
    _set_box("name_edit")(ctx, dialog, "Renamed")
    assert not dialog.apply()
    assert "missing sandbox" in dialog.error_text() or any(
        "missing sandbox" in text for _kind, text in ctx.stores.messages)
    assert ctx.stores.agent.read_text() == before


def test_cross_a_disabled_server_is_left_out_of_an_agent_profile(ctx) -> None:
    """MCP Servers x Profiles: switched off, the server a profile names is
    missing from the tab it sets up, and the profile says so."""
    _seed_profiles(mcp_servers=["fake"])(ctx)
    SMX._start(ctx)
    assert _mcp_chosen(_from_profile(ctx, ctx.win))
    dialog = ctx.dialog()
    _set_server("server_enabled_check", "check")(ctx, dialog, False)
    assert dialog.apply()
    tab = _from_profile(ctx, ctx.win)
    assert not _mcp_chosen(tab)
    res = _dock(ctx.win).resolve_profile(_dock(ctx.win).agent_settings.agent_profiles[0])
    assert [(m.kind, m.name, m.why) for m in res.missing] == [("server", "fake", "switched off")]


# ---------------------------------------------------------------------------
# Settings of their own dialogs: Set Secret… and a tab's Access…
# ---------------------------------------------------------------------------


def _set_secret(ctx, dialog, value) -> None:
    """MCP Servers > Set Secret…: the variable, then its value (the two
    input dialogs answered as a user would)."""
    from unittest import mock

    page = _ap(dialog)
    page.server_list.setCurrentRow(0)
    with mock.patch("PyQt6.QtWidgets.QInputDialog.getItem", return_value=("API_KEY", True)), \
            mock.patch("PyQt6.QtWidgets.QInputDialog.getText", return_value=(value, True)):
        page.server_secret_button.click()


def test_set_secret_value_goes_to_the_keyring_and_reaches_the_program(ctx,
                                                                      memory_keyring) -> None:
    """Cancel keeps the keyring; OK stores the value there (in no file) and
    the program gets it; a new value replaces it; "" deletes it."""
    _seed_server(secret_env=["API_KEY"])(ctx)
    SMX._start(ctx)
    dialog = ctx.dialog()
    _set_secret(ctx, dialog, "first")
    dialog.reject()
    assert MC.get_secret("fake", "API_KEY") == ""
    for value in ("first", "second", ""):
        dialog = ctx.dialog()
        _set_secret(ctx, dialog, value)
        assert dialog.dirty_page_ids() == ["agent"] and dialog.apply(), dialog.error_text()
        assert MC.get_secret("fake", "API_KEY") == value
        if value:
            assert value not in ctx.stores.agent.read_text()
        tools, errors = _tools(ctx.win)
        assert tools["fake__look"].description.endswith(f"API_KEY={value}"), errors


def test_set_secret_without_a_secret_variable_says_what_is_missing(ctx) -> None:
    """Sad: no variable named under Secret environment - the page says so
    and changes nothing."""
    _seed_server()(ctx)
    SMX._start(ctx)
    dialog = ctx.dialog()
    _ap(dialog).server_list.setCurrentRow(0)
    _ap(dialog).server_secret_button.click()
    assert any("Secret environment first" in text for _kind, text in ctx.stores.messages)
    assert dialog.dirty_page_ids() == []


def _edit_tab_access(tab, change, accept: bool) -> None:
    """The tab's Access… dialog: *change(editor)*, then OK or Cancel."""
    from unittest import mock

    from PyQt6.QtWidgets import QDialog

    from ui.agent_access_dialog import SessionAccessDialog

    def run(dialog):
        change(dialog.editor)
        return QDialog.DialogCode.Accepted if accept else QDialog.DialogCode.Rejected

    with mock.patch.object(SessionAccessDialog, "exec", run):
        tab.access_button.click()


def test_tab_access_dialog_stores_the_tabs_own_access(ctx) -> None:
    """A tab's Access… (the same editor as Settings > Agent > Sessions):
    Cancel changes nothing; OK keeps the choice in the tab's session file;
    the next start restores it; the function is gone from the tab, and
    comes back with the default choice again."""
    _seed_session()(ctx)
    SMX._start(ctx)
    tab = _open_tab(ctx.win)
    off = lambda editor: editor.function_checks["remote_files"].setChecked(False)  # noqa: E731
    on = lambda editor: editor.function_checks["remote_files"].setChecked(True)  # noqa: E731
    stored = _stored_session(lambda s: "remote_files" in s.access.functions)
    _edit_tab_access(tab, off, accept=False)
    assert stored(ctx) and "remote_files" in tab.functions()
    for change, value in ((off, False), (on, True)):
        _edit_tab_access(_open_tab(ctx.win), change, accept=True)
        assert ("remote_files" in _open_tab(ctx.win).functions()) is value
        assert stored(ctx) is value
        SMX._start(ctx)  # the next start restores the tab as it was left
        assert ("remote_files" in _open_tab(ctx.win).functions()) is value
        assert _editor(ctx.dialog()).function_checks["remote_files"].isChecked() is value
