"""MCP servers already on this machine (core.mcp_detect): the configurations
of other clients (Claude Desktop, Claude Code, VS Code, Cursor) read as
untrusted data, and podman images axross installed. Every file here is written into a temporary home in the format of its client; the
local programs they name are empty executables on the scan's PATH."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import mcp_detect as D  # noqa: E402
from core import mcp_install as I  # noqa: E402
from tests.mcp_podman_testkit import fake_podman  # noqa: E402

TOKEN = "ghp_" + "Z9" * 18  # looks like a GitHub token


def _write(path: Path, data) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(data if isinstance(data, str) else json.dumps(data), encoding="utf-8")
    return path


LOCAL_PROGRAMS = ("mcp-git", "ok-mcp", "pg-mcp", "docs-mcp", "mcp-fs", "api-mcp", "srv", "a",
                  "other-git", "x")


def _detect(home: Path, **kw) -> D.DetectResult:
    kw.setdefault("podman", None)
    bin_dir = home / "bin"
    if not bin_dir.exists():
        bin_dir.mkdir(parents=True)
        for name in LOCAL_PROGRAMS:
            (bin_dir / name).write_text("#!/bin/sh\n")
            (bin_dir / name).chmod(0o755)
    return D.detect(home=home, env={"PATH": str(bin_dir)}, **kw)


def _by_name(result) -> dict:
    return {s.name: s for s in result.servers}


# -- happy ----------------------------------------------------------------------------


def test_happy_claude_desktop_with_a_secret_kept_apart(tmp_path):
    _write(tmp_path / ".config/Claude/claude_desktop_config.json", {"mcpServers": {
        "github": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-github"],
                   "env": {"GITHUB_PERSONAL_ACCESS_TOKEN": TOKEN, "LANG": "C.UTF-8"}}}})
    result = _detect(tmp_path)
    assert result.warnings == []
    (server,) = result.servers
    assert (server.name, server.transport, server.clients) == ("github", "stdio",
                                                              ("Claude Desktop",))
    assert server.command == ("npx", "-y", "@modelcontextprotocol/server-github")
    assert server.env == {"LANG": "C.UTF-8"}
    assert server.secrets == {"GITHUB_PERSONAL_ACCESS_TOKEN": TOKEN}
    assert TOKEN not in repr(server) and TOKEN not in server.describe()
    # npx downloads code: never a host command, a contained install instead.
    assert server.usable and server.needs_install and not server.local
    assert (server.plan.kind, server.plan.package) == ("npm", "@modelcontextprotocol/server-github")
    assert "never runs on this machine" in server.describe()
    with pytest.raises(ValueError, match="container"):
        server.config(name="github", sandbox="Normal")


def test_happy_claude_code_user_project_and_folder_servers(tmp_path):
    work = tmp_path / "work"
    _write(tmp_path / ".claude.json", {
        "numStartups": 3,
        "mcpServers": {"time": {"type": "stdio", "command": "uvx", "args": ["mcp-server-time"]}},
        "projects": {str(work): {"mcpServers": {
            "remote": {"type": "http", "url": "https://mcp.example/mcp",
                       "headers": {"Authorization": f"Bearer {TOKEN}"}}}}}})
    _write(work / ".mcp.json", {"mcpServers": {"fs": {"command": "mcp-fs", "args": [str(work)]}}})
    _detect(tmp_path)  # makes the local programs
    result = _detect(tmp_path, folders=[work])
    by = _by_name(result)
    assert set(by) == {"time", "remote", "fs"}
    assert by["time"].clients == ("Claude Code",) and by["time"].needs_install
    remote = by["remote"]
    assert (remote.transport, remote.url, remote.token) == ("http", "https://mcp.example/mcp",
                                                            TOKEN)
    config = remote.config(name="remote", sandbox="Normal")
    assert config.transport == "http" and config.bearer and config.sandbox == ""
    assert TOKEN not in json.dumps(config.to_dict())
    assert any(str(work / ".mcp.json") in o for o in by["fs"].origins)
    assert by["fs"].local and "not in a container" in by["fs"].describe()
    fs = by["fs"].config(name="fs", sandbox="Normal")
    assert fs.sandbox == "Normal" and fs.command == ("mcp-fs", str(work)) and not fs.container


def test_happy_vs_code_settings_with_comments_and_mcp_json(tmp_path):
    _write(tmp_path / ".config/Code/User/settings.json", """{
  // the editor's settings
  "editor.fontSize": 13, /* a block
  comment */ "mcp": {"servers": {
      "git": {"type": "stdio", "command": "mcp-git", "args": ["--url", "https://x//y"],},
  }},
}""")
    _write(tmp_path / ".config/Code/User/mcp.json", {"servers": {
        "api": {"type": "stdio", "command": "api-mcp",
                "env": {"API_TOKEN": "${input:api-token}"}}},
        "inputs": [{"id": "api-token", "type": "promptString", "password": True}]})
    by = _by_name(_detect(tmp_path))
    assert by["git"].command == ("mcp-git", "--url", "https://x//y")
    assert by["git"].clients == ("VS Code",)
    assert by["api"].missing == ("API_TOKEN",) and by["api"].secrets == {}
    assert "API_TOKEN" in by["api"].notes
    assert by["api"].config(name="api", sandbox="").secret_env == ("API_TOKEN",)


def test_happy_cursor(tmp_path):
    _write(tmp_path / ".cursor/mcp.json", {"mcpServers": {"pg": {"command": "pg-mcp"}}})
    (server,) = _detect(tmp_path).servers
    assert server.clients == ("Cursor",) and server.command == ("pg-mcp",)


def test_happy_podman_images_axross_installed_also_without_settings(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch)
    state = podman.state
    state["images"]["b" * 64] = {
        "Id": "b" * 64, "Names": ["localhost/axross-mcp:tz-0.1.0"], "Digest": "",
        "RepoDigests": [], "RepoTags": [],
        "Labels": {"io.axross.mcp.package": "npm:tz-mcp@0.1.0"}}
    state["images"]["c" * 64] = {
        "Id": "c" * 64, "Names": ["docker.io/mcp/time:latest"], "Digest": "sha256:" + "d" * 64,
        "RepoDigests": ["docker.io/mcp/time@sha256:" + "d" * 64], "RepoTags": [],
        "Labels": {}}
    state["images"]["e" * 64] = {
        "Id": "e" * 64, "Names": ["docker.io/library/alpine:latest"], "Digest": "",
        "RepoDigests": [], "RepoTags": [], "Labels": {}}
    podman.state_file.write_text(json.dumps(state))
    result = D.detect(home=tmp_path, env={}, podman=I.Podman())
    by = _by_name(result)
    assert set(by) == {"tz", "time"}
    tz = by["tz"]
    assert tz.clients == ("podman (axross)",) and tz.image_id == "b" * 64
    config = tz.config(name="tz", sandbox="Normal")
    assert config.container and config.sandbox == "" and config.command[-1] == "b" * 64
    assert "--network=none" in config.command and config.package["image"] == "b" * 64
    time_config = by["time"].config(name="time", sandbox="")
    assert time_config.command[-1] == "docker.io/mcp/time@sha256:" + "d" * 64
    # One the settings still have is not offered again.
    from core import mcp_client as C

    kept = C.McpServerConfig(name="tz", command=("podman", "run", "b" * 64), container=True,
                             package={"image": "b" * 64})
    again = D.detect(home=tmp_path, env={}, podman=I.Podman(), configured=[kept])
    assert "tz" not in _by_name(again) or _by_name(again)["tz"].configured == "tz"


def test_happy_a_docker_run_line_is_rerun_hardened_and_says_what_it_drops(tmp_path):
    _write(tmp_path / ".cursor/mcp.json", {"mcpServers": {"gh": {
        "command": "docker", "args": ["run", "-i", "--rm", "--privileged", "--network=host",
                                      "-v", "/:/host", "-e", "GITHUB_TOKEN",
                                      "ghcr.io/github/github-mcp-server"]}}})
    (server,) = _detect(tmp_path).servers
    assert server.needs_install and server.plan.kind == "oci"
    assert server.missing == ("GITHUB_TOKEN",)
    shown = server.describe()
    assert "Not taken over" in shown and "--privileged" in shown and "-v /:/host" in shown
    assert "never runs on this machine" in shown


def test_sad_a_runner_that_cannot_be_contained_is_shown_not_usable(tmp_path):
    _write(tmp_path / ".cursor/mcp.json", {"mcpServers": {
        "git": {"command": "npx", "args": ["github:o/repo"]},
        "script": {"command": "uv", "args": ["run", "server.py"]},
        "gone": {"command": "not-installed-mcp"}}})
    by = _by_name(_detect(tmp_path))
    assert "git URL" in by["git"].why_not and "never runs on this machine" in by["git"].why_not
    assert "uv run" in by["script"].why_not
    assert "not on this machine" in by["gone"].why_not
    assert not any(s.usable for s in by.values())


# -- sad ------------------------------------------------------------------------------


def test_sad_a_broken_file_is_named_and_the_others_are_read(tmp_path):
    _write(tmp_path / ".cursor/mcp.json", "{broken")
    _write(tmp_path / ".config/Claude/claude_desktop_config.json",
           {"mcpServers": {"ok": {"command": "ok-mcp"}}})
    result = _detect(tmp_path)
    assert [s.name for s in result.servers] == ["ok"]
    assert any("mcp.json" in w and "JSON" in w for w in result.warnings), result.warnings


def test_sad_a_huge_file_is_not_read(tmp_path):
    big = _write(tmp_path / ".cursor/mcp.json", " " * (D.MAX_CONFIG_BYTES + 1))
    result = _detect(tmp_path)
    assert result.servers == [] and any("larger than" in w for w in result.warnings)
    assert big.exists()  # read-only: nothing is changed


def test_sad_a_fifo_or_folder_is_skipped_without_hanging(tmp_path):
    (tmp_path / ".cursor").mkdir()
    os.mkfifo(tmp_path / ".cursor/mcp.json")
    (tmp_path / ".claude.json").mkdir()
    result = _detect(tmp_path)
    assert result.servers == []
    assert sum("not a regular file" in w for w in result.warnings) == 2


@pytest.mark.parametrize("servers, why", [
    ([{"command": "x"}], "an object"),
    ({"a": "npx something"}, "an object"),
    ({"a": {"command": 5}}, "command"),
    ({"a": {"command": "x\ny"}}, "command"),
    ({"a": {"command": "x", "args": "not a list"}}, "args"),
    ({"a": {"command": "x", "args": ["ok", {"no": 1}]}}, "args"),
    ({"a": {"command": "x", "env": {"BAD NAME": "1"}}}, "env"),
    ({"a": {"command": "x", "env": {"A": 5}}}, "env"),
    ({"a": {"nothing": True}}, "command or a url"),
    ({"a": {"url": "file:///etc/passwd"}}, "url"),
])
def test_sad_an_unknown_shape_is_skipped_with_a_reason(tmp_path, servers, why):
    _write(tmp_path / ".cursor/mcp.json", {"mcpServers": servers})
    result = _detect(tmp_path)
    assert result.servers == []
    assert any(why in w for w in result.warnings), result.warnings


def test_sad_what_axross_cannot_run_says_why(tmp_path):
    _write(tmp_path / ".cursor/mcp.json", {"mcpServers": {
        "events": {"type": "sse", "url": "https://x.example/sse"},
        "custom": {"url": "https://x.example/mcp", "headers": {"X-Api-Key": "k"}}}})
    by = _by_name(_detect(tmp_path))
    assert "sse" in by["events"].why_not.lower()
    assert "X-Api-Key" in by["custom"].why_not


def test_sad_secrets_never_reach_the_log(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    _write(tmp_path / ".cursor/mcp.json", {"mcpServers": {
        "a": {"command": "a", "env": {"SERVICE_PASSWORD": "hunter2-hunter2"}},
        "b": {"command": 5, "env": {"API_KEY": TOKEN}}}})
    result = _detect(tmp_path)
    assert result.servers[0].secrets == {"SERVICE_PASSWORD": "hunter2-hunter2"}
    text = caplog.text + " ".join(result.warnings) + repr(result)
    assert TOKEN not in text and "hunter2" not in text


# -- edge -----------------------------------------------------------------------------


def test_edge_the_same_server_in_two_clients_is_one(tmp_path):
    spec = {"command": "mcp-git", "args": ["--repo", "/srv/r"]}
    _write(tmp_path / ".config/Claude/claude_desktop_config.json", {"mcpServers": {"git": spec}})
    _write(tmp_path / ".cursor/mcp.json", {"mcpServers": {"repo-git": spec,
                                                          "git": {"command": "other-git"}}})
    result = _detect(tmp_path)
    same = [s for s in result.servers if s.command == ("mcp-git", "--repo", "/srv/r")]
    assert len(same) == 1 and same[0].clients == ("Claude Desktop", "Cursor")
    assert len(result.servers) == 2
    assert len({s.key for s in result.servers}) == 2


def test_edge_an_already_configured_server_is_marked(tmp_path):
    from core import mcp_client as C

    _write(tmp_path / ".cursor/mcp.json", {"mcpServers": {"git": {"command": "mcp-git"}}})
    mine = C.McpServerConfig(name="mygit", command=("mcp-git",))
    (server,) = _detect(tmp_path, configured=[mine]).servers
    assert server.configured == "mygit"


def test_edge_names_are_made_valid_and_placeholders_noted(tmp_path):
    _write(tmp_path / ".cursor/mcp.json", {"mcpServers": {
        "../../etc/My Server!": {"command": "x", "args": ["${workspaceFolder}"]}}})
    (server,) = _detect(tmp_path).servers
    assert server.name == "My-Server"
    assert "${workspaceFolder}" in server.notes


def test_edge_nothing_installed_is_no_error(tmp_path):
    assert _detect(tmp_path) == D.DetectResult([], [])


def test_edge_jsonc_comments_and_commas_inside_strings_stay():
    text = '{"a": "x,}", "b": "//not a comment", "c": "/* no */", "d": [1, 2,],}'
    assert json.loads(D.strip_jsonc(text)) == {"a": "x,}", "b": "//not a comment",
                                               "c": "/* no */", "d": [1, 2]}


def test_sad_secret_arguments_are_masked_in_what_is_shown(tmp_path):
    _write(tmp_path / ".cursor/mcp.json", {"mcpServers": {"s": {
        "command": "srv", "args": ["--api-key=hunter2-hunter2", TOKEN, "--port", "8080"]}}})
    (server,) = _detect(tmp_path).servers
    shown = server.describe()
    assert "hunter2" not in shown and TOKEN not in shown and "--port 8080" in shown
    assert server.command[1] == "--api-key=hunter2-hunter2"  # it still runs as written


def test_sad_the_key_holds_no_hash_of_a_secret_value(tmp_path):
    keys = []
    for value in ("hunter2-hunter2", "other-password-1"):
        _write(tmp_path / ".cursor/mcp.json", {"mcpServers": {
            "s": {"command": "srv", "env": {"DB_PASSWORD": value}}}})
        keys.append(_detect(tmp_path).servers[0].key)
    assert keys[0] == keys[1]
