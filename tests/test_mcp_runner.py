"""Commands that download code at start (core.mcp_runner): recognised, and
turned into what core.mcp_install runs in a container - or refused with a
reason. Nothing here starts a program."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.mcp_runner import downloading_runner  # noqa: E402

# -- happy ----------------------------------------------------------------------------


def test_happy_npx_becomes_an_npm_package():
    plan = downloading_runner(["npx", "-y", "@modelcontextprotocol/server-github", "--flag"])
    assert plan.convertible and (plan.kind, plan.package, plan.version) == (
        "npm", "@modelcontextprotocol/server-github", "")
    assert plan.args == ("--flag",) and plan.spec == "@modelcontextprotocol/server-github@latest"


@pytest.mark.parametrize("argv, runner", [
    (["bunx", "srv@1.2.3"], "bunx"), (["pnpm", "dlx", "srv@1.2.3"], "pnpm dlx"),
    (["yarn", "dlx", "srv@1.2.3"], "yarn dlx"), (["npm", "exec", "--", "srv@1.2.3"], "npm exec"),
    (["bun", "x", "srv@1.2.3"], "bun x"), (["pnpx", "srv@1.2.3"], "pnpx"),
])
def test_happy_every_npx_like_runner(argv, runner):
    plan = downloading_runner(argv)
    assert (plan.runner, plan.kind, plan.package, plan.version) == (runner, "npm", "srv", "1.2.3")


@pytest.mark.parametrize("argv, runner, version", [
    (["uvx", "mcp-server-time"], "uvx", ""), (["uvx", "mcp-server-time@0.6.2"], "uvx", "0.6.2"),
    (["uv", "tool", "run", "mcp-server-time==0.6.2"], "uv tool run", "0.6.2"),
    (["pipx", "run", "mcp-server-time"], "pipx run", ""),
])
def test_happy_uvx_like_runners_become_a_pypi_package(argv, runner, version):
    plan = downloading_runner([*argv, "--local-timezone", "UTC"])
    assert (plan.runner, plan.kind, plan.package, plan.version) == (
        runner, "pypi", "mcp-server-time", version)
    assert plan.args == ("--local-timezone", "UTC")


def test_happy_docker_run_keeps_image_args_and_env_and_drops_its_flags():
    plan = downloading_runner([
        "docker", "run", "-i", "--rm", "--privileged", "--network=host", "-v", "/:/host",
        "--cap-add", "SYS_ADMIN", "--device=/dev/kmsg", "--pid=host", "--security-opt",
        "seccomp=unconfined", "-e", "GITHUB_TOKEN", "-e", "MODE=fast",
        "ghcr.io/github/github-mcp-server:v1", "stdio"])
    assert plan.convertible and plan.kind == "oci"
    assert (plan.package, plan.tag, plan.digest) == ("ghcr.io/github/github-mcp-server", "v1", "")
    assert plan.args == ("stdio",) and plan.env == {"MODE": "fast"}
    assert plan.env_names == ("GITHUB_TOKEN",)
    assert plan.dropped == ("--privileged", "--network=host", "-v /:/host", "--cap-add SYS_ADMIN",
                            "--device=/dev/kmsg", "--pid=host", "--security-opt seccomp=unconfined")


def test_happy_a_local_program_is_no_runner():
    for argv in (["/usr/local/bin/mcp-git", "--repo", "/srv"], ["python3", "/opt/srv.py"],
                 ["node", "/opt/srv/index.js"], ["npm", "start"], [sys.executable]):
        assert downloading_runner(argv) is None, argv


# -- sad ------------------------------------------------------------------------------


@pytest.mark.parametrize("argv, why", [
    (["npx", "-p", "pkg", "bin"], "--package"),
    (["npx", "github:user/repo"], "git URL"),
    (["npx", "git+https://x/y.git"], "git URL"),
    (["npx", "./local"], "path"),
    (["npx", "srv@^1.0.0"], "exact version"),
    (["npx", "--registry=https://evil", "srv"], "not understood"),
    (["npx", "-y"], "no package"),
    (["npx", "Bad_Name!"], "npm package name"),
    (["uvx", "--from", "pkg", "cmd"], "another package"),
    (["uvx", "pkg[extra]"], "extras"),
    (["uvx", "git+https://x/y"], "URL"),
    (["uvx", "pkg==1.*"], "exact version"),
    (["uv", "run", "server.py"], "uv run"),
    (["deno", "run", "https://x/srv.ts"], "deno"),
    (["go", "run", "example.com/srv@latest"], "go run"),
    (["npm", "install", "-g", "x"], "may install"),
    (["docker", "run", "--entrypoint", "sh", "img"], "entrypoint"),
    (["docker", "run", "--weird", "value", "img"], "not known"),
    (["podman", "run", "-i", "--rm"], "no image"),
    (["docker", "run", "-e"], "without a value"),
    (["docker", "run", "-i", "-oevil"], "not known"),
    (["docker", "run", "UPPER/Case"], "image"),
])
def test_sad_what_cannot_be_converted_says_why(argv, why):
    plan = downloading_runner(argv)
    assert plan is not None and not plan.convertible and why in plan.why_not, plan


# -- edge -----------------------------------------------------------------------------


def test_edge_windows_spellings_and_pinned_images():
    assert downloading_runner(["C:\\nodejs\\npx.cmd", "srv"]).kind == "npm"
    assert downloading_runner(["/usr/bin/uvx", "srv"]).kind == "pypi"
    plan = downloading_runner(["podman", "run", "-i", "docker.io/mcp/time@sha256:" + "a" * 64])
    assert plan.digest == "sha256:" + "a" * 64 and plan.spec.endswith("@sha256:" + "a" * 64)
    assert downloading_runner(["npx", "srv@latest"]).version == ""
    assert downloading_runner([]) is None and downloading_runner(None) is None


# -- the second layer: the settings and the client --------------------------------------


def test_sad_a_host_command_that_downloads_is_refused_by_the_config_and_on_load(caplog):
    import logging

    from core import mcp_client as C

    config = C.McpServerConfig(name="gh", command=("npx", "-y", "@scope/srv"))
    assert any("downloads" in p and "container" in p for p in config.problems())
    caplog.set_level(logging.WARNING)
    assert C.McpServerConfig.from_dict({"name": "gh", "command": ["uvx", "srv"]}) is None
    assert "gh" in caplog.text and "uvx" in caplog.text
    assert C.McpServerConfig.from_dict({"name": "ok", "command": ["/usr/bin/mcp-git"]})


def test_sad_the_client_never_starts_a_downloading_command(monkeypatch):
    import subprocess

    from core import mcp_client as C

    started = []
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: started.append(a) or 1 / 0)
    for argv in (("npx", "-y", "srv"), ("uvx", "srv"), ("docker", "run", "--privileged", "img")):
        with pytest.raises(C.McpClientError, match="container"):
            C.McpClient(C.McpServerConfig(name="x", command=argv))
    assert started == []


@pytest.mark.parametrize("flag", [
    "--privileged", "--cap-add=SYS_ADMIN", "--device=/dev/kmsg", "--pid=host", "--ipc=host",
    "--network=host", "--security-opt=seccomp=unconfined", "--volume=/:/host",
    "-v", "--mount=type=bind,src=/,dst=/h", "--userns=host",
])
def test_sad_a_container_line_with_dangerous_flags_is_refused(flag):
    from core import mcp_client as C
    from core import mcp_install as I

    line = I.run_command("x", "img@sha256:" + "a" * 64)
    bad = C.McpServerConfig(name="x", command=(*line[:2], flag, *line[2:]), container=True)
    assert any("not allowed" in p for p in bad.problems()), bad.problems()
    good = C.McpServerConfig(name="x", command=tuple(I.run_command(
        "x", "img@sha256:" + "a" * 64, mounts=[("/srv/a", "/data", False)])), container=True)
    assert good.problems() == []


# -- the contained install (core.mcp_install.install_plan) -------------------------------


@pytest.fixture
def host_exec(monkeypatch):
    """Every program started, to prove that npx/uvx never run on the host."""
    import subprocess

    seen = []
    real_popen, real_run = subprocess.Popen, subprocess.run

    def popen(args, *a, **k):
        seen.append(list(args) if not isinstance(args, str) else [args])
        return real_popen(args, *a, **k)

    def run(args, *a, **k):
        seen.append(list(args) if not isinstance(args, str) else [args])
        return real_run(args, *a, **k)

    monkeypatch.setattr(subprocess, "Popen", popen)
    monkeypatch.setattr(subprocess, "run", run)
    yield seen
    hosts = {Path(str(argv[0])).name for argv in seen if argv}
    assert not hosts & {"npx", "uvx", "pipx", "bunx", "npm", "pip", "uv", "docker"}, hosts


def test_happy_npx_installs_into_the_node_container(tmp_path, monkeypatch, host_exec):
    from core import mcp_install as I
    from tests.mcp_podman_testkit import fake_podman
    from tests.test_mcp_catalog import FakeOpener

    podman = fake_podman(tmp_path, monkeypatch,
                         entry_line="AXROSS_ENTRY=/opt/mcp/node_modules/srv/index.js")
    plan = I.downloading_runner(["npx", "-y", "@scope/srv", "--stdio"])
    opener = FakeOpener({"registry.npmjs.org/@scope%2Fsrv/latest": b'{"version": "2.1.0"}'})
    config = I.install_plan(plan, name="srv", env={"MODE": "x"}, secrets={"API_TOKEN": "t0k"},
                            missing=("OTHER_KEY",), podman=I.Podman(), opener=opener,
                            entry_key="detected:abc")
    assert config.container and config.enabled and config.sandbox == ""
    assert "--network=none" in config.command and config.command[-1] == "--stdio"
    assert config.package["kind"] == "npm" and config.package["version"] == "2.1.0"
    assert config.package["source"] == "detected" and config.package["entry"] == "detected:abc"
    assert config.env == {"MODE": "x"} and config.secret_env == ("API_TOKEN", "OTHER_KEY")
    build = next(c for c in podman.calls("run") if any("install" in a for a in c))
    assert "@scope/srv@2.1.0" in build and I.NODE_IMAGE in build


def test_happy_uvx_installs_wheels_only_into_the_python_container(tmp_path, monkeypatch,
                                                                  host_exec):
    from core import mcp_install as I
    from tests.mcp_podman_testkit import fake_podman

    podman = fake_podman(tmp_path, monkeypatch, entry_line="AXROSS_ENTRY=/opt/mcp/bin/srv")
    plan = I.downloading_runner(["uvx", "mcp-server-time==0.6.2", "--local-timezone=UTC"])
    config = I.install_plan(plan, name="time", podman=I.Podman())
    build = next(c for c in podman.calls("run") if any("install" in a for a in c))
    assert "mcp-server-time==0.6.2" in build and I.PYTHON_IMAGE in build
    assert any("--only-binary=:all:" in a for a in build)
    assert config.package["kind"] == "pypi" and config.command[-1] == "--local-timezone=UTC"


def test_happy_docker_run_is_rerun_with_the_hardened_line(tmp_path, monkeypatch, host_exec):
    from core import mcp_install as I
    from tests.mcp_podman_testkit import fake_podman

    fake_podman(tmp_path, monkeypatch)
    plan = I.downloading_runner(["docker", "run", "-i", "--rm", "--privileged", "--network=host",
                                 "-v", "/:/host", "-e", "MODE=fast", "ghcr.io/o/srv:v1", "stdio"])
    config = I.install_plan(plan, name="srv", env=dict(plan.env), podman=I.Podman())
    for flag in I.RUN_FLAGS:
        assert flag in config.command
    assert "--privileged" not in config.command and "--network=host" not in config.command
    assert not any("/host" in a for a in config.command) and "--network=none" in config.command
    assert config.command[-1] == "stdio" and config.package["kind"] == "oci"
    assert config.problems() == []


def test_sad_what_cannot_be_converted_is_not_installed(tmp_path, monkeypatch, host_exec):
    from core import mcp_install as I
    from tests.test_mcp_catalog import FakeOpener

    with pytest.raises(I.InstallError, match="git URL"):
        I.install_plan(I.downloading_runner(["npx", "github:o/r"]), name="x")
    opener = FakeOpener({"registry.npmjs.org": b'{"version": "^1"}'})
    with pytest.raises(I.InstallError, match="latest version"):
        I.install_plan(I.downloading_runner(["npx", "srv"]), name="x", opener=opener)
