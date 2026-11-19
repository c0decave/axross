"""Second security review: downloaders the runner check missed by their
names - ``node …/nlx.mjs`` (@antfu/ni's npx), ``java -jar
…/maven-wrapper.jar`` (and Gradle's wrapper), ``python3
/usr/bin/pip3.11-wrapper``: a runner's name with a suffix of its own
(``-wrapper``, ``-cli``, ``.real``) is that runner. Each line is a runner
and never a pure launcher on the host."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.mcp_runner import downloading_runner, host_launcher  # noqa: E402

CAUGHT = [
    ["node", "/usr/lib/node_modules/@antfu/ni/bin/nlx.mjs", "evil-pkg"],
    ["node", "/home/u/.local/bin/nlx.mjs", "evil-pkg"],
    ["node", "/usr/lib/node_modules/@antfu/ni/bin/nr.mjs", "start"],
    ["nlx", "evil-pkg"],
    ["/usr/local/bin/nlx", "evil-pkg"],
    ["ni", "evil-pkg"],
    ["java", "-jar", "/home/u/proj/.mvn/wrapper/maven-wrapper.jar", "exec:java"],
    ["java", "-jar", "/home/u/proj/gradle/wrapper/gradle-wrapper.jar", "run"],
    ["python3", "/usr/bin/pip3.11-wrapper", "install", "x"],
    ["/usr/bin/pip3.11-wrapper", "install", "x"],
    ["python3", "/usr/bin/pip.real", "install", "x"],
    ["node", "/opt/tools/npx-wrapper.js", "-y", "evil"],
    ["python3", "/opt/tools/uvx_shim.py", "evil"],
]


@pytest.mark.parametrize("line", CAUGHT, ids=lambda c: " ".join(c))
def test_sad_a_downloader_by_another_name_is_a_runner(line):
    assert downloading_runner(line) is not None


@pytest.mark.parametrize("line", CAUGHT, ids=lambda c: " ".join(c))
def test_sad_a_downloader_by_another_name_never_runs_on_the_host(line):
    assert not host_launcher(line)


@pytest.mark.parametrize("line", [
    ["node", "/home/u/srv/index.js"],
    ["node", "/home/u/srv/node-server.js"],
    ["python3", "/home/u/srv/pipeline_server.py"],
    ["python3", "/home/u/srv/server.py"],
    ["java", "-jar", "/home/u/srv/server-1.2.jar"],
    ["node", "/home/u/srv/gemini-mcp.js"],
    ["node", "/home/u/srv/uvicorn-bridge.js"],
], ids=lambda c: " ".join(c))
def test_happy_a_server_script_is_still_a_pure_launcher(line):
    assert downloading_runner(line) is None and host_launcher(line)
