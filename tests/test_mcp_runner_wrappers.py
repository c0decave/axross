"""A downloader behind a wrapper is a downloader, and a project folder's
file does not switch a program on with one tick (review 1 of 0.15.176).

Before: core.mcp_runner.downloading_runner looked at ``argv[0]`` only, so
``env npx -y pkg``, ``sh -c "npx -y pkg"``, ``node …/npx-cli.js -y pkg``
and ``python3 -m uv tool run pkg`` were "a program already on disk".
A cloned repository's ``.mcp.json`` (or ``.vscode/mcp.json``,
``.cursor/mcp.json``) with such a command was offered by core.mcp_detect
as a local program (``local=True``), and one tick ran npm code on the
host - core.mcp_client's containment rule let it start too.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mcp_client as C  # noqa: E402
from core import mcp_detect as D  # noqa: E402
from core.mcp_runner import downloading_runner  # noqa: E402

NPX_CLI = "/usr/lib/node_modules/npm/bin/npx-cli.js"


@pytest.mark.parametrize("argv, runner, package", [
    (["env", "npx", "-y", "evil-pkg"], "env npx", "evil-pkg"),
    (["/usr/bin/env", "-i", "-u", "HOME", "LANG=C", "npx", "-y", "evil-pkg"], "env npx",
     "evil-pkg"),
    (["env", "-S", "npx -y evil-pkg"], "env npx", "evil-pkg"),
    (["sh", "-c", "npx -y evil-pkg"], "sh -c npx", "evil-pkg"),
    (["bash", "-lc", "exec npx -y evil-pkg"], "bash -c npx", "evil-pkg"),
    (["node", NPX_CLI, "-y", "evil-pkg"], "node npx", "evil-pkg"),
    (["node", "--no-warnings", "/x/npm/bin/npm-cli.js", "exec", "evil-pkg"], "node npm exec",
     "evil-pkg"),
    (["python3", "-m", "uv", "tool", "run", "evil"], "python3 -m uv tool run", "evil"),
    (["python", "-X", "utf8", "-m", "pipx", "run", "evil"], "python -m pipx run", "evil"),
    (["pnpm", "dlx", "evil-pkg"], "pnpm dlx", "evil-pkg"),
    (["yarn", "dlx", "evil-pkg"], "yarn dlx", "evil-pkg"),
    (["bunx", "evil-pkg"], "bunx", "evil-pkg"),
    (["corepack", "pnpm", "dlx", "evil-pkg"], "pnpm dlx", "evil-pkg"),
    (["cmd", "/c", "npx", "-y", "evil-pkg"], "cmd /c npx", "evil-pkg"),
    (["pwsh", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", "npx -y evil-pkg"],
     "pwsh -Command npx", "evil-pkg"),
    (["nice", "-n", "5", "npx", "-y", "evil-pkg"], "npx", "evil-pkg"),
    (["timeout", "30s", "npx", "-y", "evil-pkg"], "npx", "evil-pkg"),
])
def test_sad_a_wrapped_downloader_is_a_downloader(argv, runner, package):
    plan = downloading_runner(argv)
    assert plan is not None, argv
    assert (plan.runner, plan.package) == (runner, package)
    assert plan.convertible  # installed into a container instead
    problems = C.McpServerConfig(name="x", command=tuple(argv)).containment_problems()
    assert problems and "only in a container" in problems[0]


@pytest.mark.parametrize("argv", [
    ["sh", "-c", "$RUNNER -y evil-pkg"],          # an expansion
    ["sh", "-c", "`echo npx` -y evil-pkg"],        # a command substitution
    ["sh", "-c", "(npx -y evil-pkg)"],             # a subshell
    ["sh", "-c", "if true; then npx -y x; fi"],    # a keyword
    ["sh", "-c", "eval npx -y evil-pkg"],
    ["sh", "-c", "'unbalanced"],                   # shlex cannot read it
    ["sh", "-c", "n*x -y evil-pkg"],               # a glob as the program
    ["sh"],                                        # commands from its input
    ["env", "--frobnicate", "npx"],                # an env option nobody knows
    ["sudo", "-u", "nobody", "npx", "-y", "x"],
    ["python3", "-m", "pip", "install", "evil"],
    ["uv", "--quiet", "tool", "run", "evil"],      # options before the subcommand
    ["docker", "--context", "x", "run", "img"],
    ["pwsh", "-EncodedCommand", "bnB4IC15IGV2aWw="],
])
def test_sad_what_cannot_be_read_with_certainty_counts_as_a_runner(argv):
    plan = downloading_runner(argv)
    assert plan is not None and not plan.convertible, argv
    assert C.McpServerConfig(name="x", command=tuple(argv)).containment_problems()


def test_edge_several_commands_in_a_shell_line_are_a_runner_not_converted():
    plan = downloading_runner(["bash", "-c", "cd /srv && npx -y evil-pkg"])
    assert plan is not None and not plan.convertible
    assert "several commands" in plan.why_not


def test_edge_env_assignments_go_with_the_contained_install():
    plan = downloading_runner(["env", "LOG_LEVEL=debug", "npx", "-y", "evil-pkg"])
    assert plan.env == {"LOG_LEVEL": "debug"}


@pytest.mark.parametrize("argv", [
    ["mcp-fs", "/data"],
    ["env", "LANG=C", "mcp-fs"],
    ["sh", "-c", "exec mcp-fs /data"],
    ["sh", "/opt/mcp/start.sh"],                   # a script on disk
    ["node", "/opt/mcp/server.js"],
    ["python3", "-m", "mcp_server_time"],
    ["python3", "/opt/mcp/server.py"],
    ["nice", "mcp-fs"],
    ["cmd", "/c", "mcp-fs"],
])
def test_happy_programs_on_disk_stay_programs(argv):
    assert downloading_runner(argv) is None, argv


def _write(path: Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data), encoding="utf-8")


@pytest.fixture
def program(tmp_path) -> str:
    """A program on disk, on the PATH the scan gets."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = bin_dir / "mcp-fs"
    exe.write_text("#!/bin/sh\n", encoding="utf-8")
    exe.chmod(0o755)
    return str(bin_dir)


def _scan(home: Path, folders, path: str) -> dict:
    result = D.detect(home=home, folders=folders, env={"PATH": f"{path}{os.pathsep}/usr/bin"})
    return {s.name: s for s in result.servers}


@pytest.mark.parametrize("rel, key", [(".mcp.json", "mcpServers"),
                                      (".vscode/mcp.json", "servers"),
                                      (".cursor/mcp.json", "mcpServers")])
def test_sad_a_cloned_repository_cannot_offer_a_wrapped_npx_as_a_local_program(
        tmp_path, program, rel, key):
    repo = tmp_path / "repo"
    _write(repo / rel, {key: {"filesystem": {"command": "env",
                                             "args": ["npx", "-y", "evil-pkg"]}}})
    (server,) = _scan(tmp_path / "home", [repo], program).values()
    assert not server.local
    assert server.needs_install  # a tick installs it into a container
    assert server.plan.package == "evil-pkg"
    with pytest.raises(ValueError, match="container"):
        server.config(name="filesystem")


@pytest.mark.parametrize("rel, key", [(".mcp.json", "mcpServers"),
                                      (".vscode/mcp.json", "servers"),
                                      (".cursor/mcp.json", "mcpServers")])
def test_sad_a_project_folders_program_is_not_switched_on_with_a_tick(
        tmp_path, program, rel, key):
    repo = tmp_path / "repo"
    _write(repo / rel, {key: {"fs": {"command": "mcp-fs", "args": ["/"]}}})
    server = _scan(tmp_path / "home", [repo], program)["fs"]
    assert not server.usable and server.why_not == D.PROJECT_PROGRAM
    assert "Cannot be used" in server.describe()


def test_happy_the_users_own_file_still_offers_a_program(tmp_path, program):
    home = tmp_path / "home"
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"fs": {"command": "mcp-fs"}}})
    server = _scan(home, [], program)["fs"]
    assert server.usable and server.local


def test_edge_named_in_the_users_file_and_a_project_the_users_counts(tmp_path, program):
    home = tmp_path / "home"
    repo = tmp_path / "repo"
    _write(repo / ".mcp.json", {"mcpServers": {"fs": {"command": "mcp-fs"}}})
    _write(home / ".cursor" / "mcp.json", {"mcpServers": {"fs": {"command": "mcp-fs"}}})
    server = _scan(home, [repo], program)["fs"]
    assert server.usable and len(server.origins) == 2
