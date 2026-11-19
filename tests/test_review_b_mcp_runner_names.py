"""Review B, items 6 and 13: what runs an MCP server's line on the host.

6 - "no downloader runs on the host" was passed by versioned names and
direct paths: ``python3 /usr/bin/pip3.11 install x``, pip's
``__pip-runner__.py``, ``gem3.1``, ``ansible-galaxy``, ``java -jar
jbang.jar``. Program names now lose their version (and script) suffix, and
a script under site-packages / dist-packages counts as ``-m <package>``.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.mcp_runner import downloading_runner, host_launcher  # noqa: E402

CAUGHT = [
    ["python3", "/usr/bin/pip3.11", "install", "x"],
    ["python3", "/usr/lib/python3/dist-packages/pip/__pip-runner__.py", "install", "x"],
    ["python3", "/usr/lib/python3/dist-packages/pip/__main__.py", "install", "x"],
    ["/usr/bin/python3", "-I", "/usr/lib/python3/dist-packages/pip/__main__.py", "install", "x"],
    ["python3", "/usr/local/lib/python3.11/site-packages/uv/__main__.py", "tool", "run", "x"],
    ["python3", "/usr/lib/python3/dist-packages/setuptools/_distutils/spawn.py"],
    ["python3", "/usr/bin/ansible-galaxy", "install", "x"],
    ["/usr/bin/ansible-galaxy", "install", "x"],
    ["ruby", "/usr/bin/gem3.1", "install", "x"],
    ["gem3.1", "install", "x"],
    ["java", "-jar", "/opt/jbang/jbang.jar", "x@y"],
    ["java", "-jar", "/opt/jbang/jbang-0.110.1.jar", "x@y"],
    ["pip3.12", "install", "x"],
]


@pytest.mark.parametrize("line", CAUGHT, ids=lambda c: " ".join(c))
def test_sad_a_versioned_or_direct_downloader_never_runs_on_the_host(line):
    assert not host_launcher(line)


@pytest.mark.parametrize("line", [
    ["python3", "/usr/bin/pip3.11", "install", "x"],
    ["python3", "/usr/lib/python3/dist-packages/pip/__pip-runner__.py", "install", "x"],
    ["ruby", "/usr/bin/gem3.1", "install", "x"],
    ["python3", "/usr/bin/ansible-galaxy", "install", "x"],
    ["java", "-jar", "/opt/jbang/jbang.jar", "x@y"],
], ids=lambda c: " ".join(c))
def test_sad_they_are_runners(line):
    assert downloading_runner(line) is not None


@pytest.mark.parametrize("line", [
    ["python3", "/home/u/srv/server.py"],
    ["python3.12", "/home/u/srv/server.py"],
    ["node", "/home/u/srv/index.js"],
    ["java", "-jar", "/home/u/srv/server-1.2.jar"],
    ["python3", "/home/u/venv/lib/python3.12/site-packages/mcp_server_git/__main__.py"],
], ids=lambda c: " ".join(c))
def test_happy_a_server_script_stays_a_pure_launcher(line):
    assert downloading_runner(line) is None and host_launcher(line)


# -- item 13: the podman of a container server ---------------------------------------------


def _line(program):
    from core import mcp_install as I

    return I.run_command("x-1", "img", program=program)


def test_sad_a_podman_of_the_users_own_is_no_container_line(tmp_path):
    from core.mcp_runner import container_flag_problems

    fake = tmp_path / "bin" / "podman"
    fake.parent.mkdir()
    fake.write_text("#!/bin/sh\nid > /tmp/pwn\n")
    fake.chmod(0o755)
    problems = container_flag_problems(_line(str(fake)))
    assert problems and "podman" in problems[0]


@pytest.mark.parametrize("program", ["podman", "/usr/bin/podman", "/usr/local/bin/podman"])
def test_happy_the_systems_podman_is(program):
    from core.mcp_runner import container_flag_problems

    assert container_flag_problems(_line(program)) == []


def test_sad_a_bare_podman_found_in_a_users_folder_on_path_is_not_started(tmp_path,
                                                                            monkeypatch):
    from core import mcp_client as C
    from core.mcp_runner import container_program

    fake = tmp_path / "bin" / "podman"
    fake.parent.mkdir()
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake.parent}{os.pathsep}/usr/bin")
    with pytest.raises(C.McpClientError, match="podman"):
        container_program("podman", C.McpClientError)
