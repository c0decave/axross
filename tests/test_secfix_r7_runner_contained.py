"""Round-7 security M7: MCP server commands are contained by default.

Round 6 listed the build tools that fetch and run code (``cargo``, ``mvn``,
``gradle`` …) as runners; the review found the list never complete
(``bazel run``, ``mix run``, ``swift run``, ``conan install``, ``brew``,
``make`` …): every program not on it ran on the host with the user's rights.
Now only a short allow-list of pure launchers - an interpreter running a
script or a module already on disk - runs as it is; any other program
starts in its sandbox profile or a container, or when the user marked the
server trusted (McpServerConfig.trusted, the Trusted box of Agent Settings).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mcp_client as C  # noqa: E402
from core.mcp_runner import downloading_runner, host_launcher  # noqa: E402

#: From the round-7 security review: these ran on the host.
RAN_ON_THE_HOST = [
    "bazel run //srv:main", "buck2 run //x", "pants run x", "stack run", "mix run",
    "rebar3 shell", "bundle exec srv", "rake build", "swift run srv", "dart run x",
    "flutter pub get", "nuget install x", "msbuild /t:Run x.csproj", "conan install .",
    "vcpkg install x", "cmake --build .", "make srv", "ninja srv", "opam install x",
    "brew install x", "guix shell -- srv", "spack install x", "zig build run",
    "crystal run x.cr", "/usr/local/bin/some-mcp-server --stdio", "python3 -V",
]


def _config(line: str, **kw) -> C.McpServerConfig:
    return C.McpServerConfig(name="srv", command=tuple(line.split()), **kw)


@pytest.mark.parametrize("line", ["node /srv/srv.js",
                                  "nodejs --enable-source-maps /srv/dist/srv.js",
                                  "python3 -u /srv/srv.py", "python -m mcp_server_git",
                                  "/usr/bin/python3.12 -I /srv/srv.py --repo /srv/x",
                                  "java -Dx=1 -jar /srv/srv.jar", "dotnet /srv/srv.dll",
                                  "bash /srv/srv.sh", "ruby /srv/srv.rb", "perl /srv/srv.pl",
                                  "php /srv/srv.php"])
def test_happy_a_pure_launcher_still_runs_as_it_is(line, monkeypatch):
    # Round 8: scripts by their absolute path; where the launcher itself is
    # installed is checked apart (tests/test_r8_mcp_host_run.py).
    from core import mcp_runner

    monkeypatch.setattr(mcp_runner, "launcher_place_problem", lambda *a, **k: "")
    assert host_launcher(line.split())
    assert _config(line).host_run_problem() == ""


@pytest.mark.parametrize("line", RAN_ON_THE_HOST)
def test_sad_a_program_off_the_allow_list_is_contained(line):
    assert downloading_runner(line.split()) is None  # not a known runner ...
    problem = _config(line).host_run_problem()
    assert "sandbox profile" in problem and "trusted" in problem  # ... still not run as it is


def test_sad_the_client_refuses_to_start_it_without_a_sandbox(tmp_path):
    marker = tmp_path / "ran"
    script = tmp_path / "make"
    script.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
    script.chmod(0o755)
    with pytest.raises(C.McpClientError, match="no known launcher"):
        C.McpClient(C.McpServerConfig(name="b", command=(str(script), "srv")))
    assert not marker.exists()


def test_happy_a_sandbox_wrap_or_the_trusted_mark_lets_it_start():
    config = _config("bazel run //srv:main")
    assert config.host_run_problem(sandboxed=True) == ""
    config.sandbox = "Normal"
    assert config.host_run_problem() == ""
    config.sandbox = ""
    config.trusted = True
    assert config.host_run_problem() == ""


def test_edge_trusted_never_lets_a_downloading_runner_onto_the_host():
    config = _config("npx -y @scope/srv", trusted=True)
    assert config.containment_problems()  # the operator rule stays
    assert C.McpServerConfig.from_dict(config.to_dict()) is None


def test_edge_trusted_is_saved_and_a_contained_server_is_kept_in_the_settings():
    config = _config("bazel run //srv:main", trusted=True)
    back = C.McpServerConfig.from_dict(config.to_dict())
    assert back is not None and back.trusted
    assert back.signature() != _config("bazel run //srv:main").signature()
    untrusted = C.McpServerConfig.from_dict(_config("bazel run //srv:main").to_dict())
    assert untrusted is not None  # kept (refused at its start), never dropped silently


@pytest.mark.parametrize("line", ["python -c pass", "node -e 1", "python -X importtime srv.py",
                                  "node --import ./x.mjs srv.js", "java -cp lib Main",
                                  "python3 -m", "node", "sh -c 'srv'", "bash -i srv.sh",
                                  "node https://evil.example/x.js", "python srv.py;id"])
def test_edge_launcher_lines_that_are_not_plain_are_contained(line):
    assert not host_launcher(line.split())


def test_happy_agent_settings_show_contained_and_save_the_trusted_mark(tmp_path):
    """The MCP page says why a program does not start and offers Trusted;
    the mark is saved and changes what the list says."""
    import os

    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtWidgets import QApplication

    from core import agent_settings as S
    from tests.test_agent_settings_dialog import _dialog

    QApplication.instance() or QApplication([])
    path = tmp_path / "settings.json"
    dlg = _dialog(path)
    dlg.add_server()
    dlg.server_name_edit.setText("bz")
    dlg.server_command_edit.setText("bazel run //srv:main")
    assert "not started" in dlg.server_list.currentItem().text()
    assert "contained by default" in dlg.server_runner_label.text()
    assert not dlg.server_contain_button.isVisibleTo(dlg)  # nothing to install: no runner
    assert dlg.server_trusted_check.isEnabled()
    dlg.server_trusted_check.setChecked(True)
    assert "trusted" in dlg.server_list.currentItem().text()
    assert dlg.server_runner_label.text() == ""
    assert dlg.save()
    (server,) = S.AgentSettings.load(path).mcp_servers
    assert server.trusted and server.host_run_problem() == ""
