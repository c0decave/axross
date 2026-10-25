"""Installing an MCP server from a catalog into podman (core.mcp_install),
how the client runs it (core.mcp_client: environment through a pipe, the
allowlist proxy, a unique container name, a clean stop) and how it is kept
(core.agent_settings).

Offline tests use the stand-in podman of tests/mcp_podman_testkit.py. The
``live`` tests pull real images into the user's rootless podman, run them
and remove what they pulled by image ID; they skip without podman."""

from __future__ import annotations

import json
import os
import pwd
import shutil
import socket
import subprocess
import sys
import threading
import time
import urllib.error
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import agent_settings as S  # noqa: E402
from core import mcp_catalog as M  # noqa: E402
from core import mcp_client as C  # noqa: E402
from core import mcp_install as I  # noqa: E402
from tests.mcp_podman_testkit import fake_podman  # noqa: E402
from tests.test_mcp_catalog import FakeOpener, _Response  # noqa: E402

DIGEST = "sha256:" + "b" * 64


def _builtin(name: str) -> M.CatalogEntry:
    entries, _ = M.load_builtin()
    return next(e for e in entries if e.name == name)


def _entry(**kw) -> M.CatalogEntry:
    values = dict(id="x", name="x", title="X", kind="oci", identifier="docker.io/mcp/x",
                  tag="latest", digest=DIGEST, source="builtin")
    values.update(kw)
    return M.CatalogEntry(**values)


def _call_env(client) -> dict:
    tool = next(t for t in client.tools() if t.remote_name == "env")
    outcome, text = tool.call({})
    assert outcome == "ok", text
    return json.loads(text)


# -- happy -----------------------------------------------------------------------------


def test_happy_the_run_command_is_hardened():
    argv = I.run_command("time", "docker.io/mcp/time@" + DIGEST, network="none")
    assert argv[:2] == ["podman", "run"]
    for flag in ("--rm", "-i", "--init", "--pull=never", "--cap-drop=ALL",
                 "--security-opt=no-new-privileges", "--read-only", "--network=none",
                 f"--env-file=/dev/fd/{C.TOKEN_ENV_FD}", f"--name=axross-mcp-time-{C.TOKEN_RUN}",
                 "--label=io.axross.mcp=time"):
        assert flag in argv, flag
    assert any(a.startswith("--tmpfs=/tmp:") and "noexec" in a for a in argv)
    assert any(a.startswith("--pids-limit=") for a in argv)
    assert any(a.startswith("--memory=") for a in argv)
    assert argv[-1] == "docker.io/mcp/time@" + DIGEST
    assert not any(a.startswith("--user") or a.startswith("--volume") for a in argv)


def test_happy_the_runtime_tmp_starts_empty():
    """Found with rea-agents: its install left 115 MB of npm cache in the
    image's /tmp; podman copied it into the 64 MB tmpfs and the server
    never started. The tmpfs copies nothing up now."""
    argv = I.run_command("time", "docker.io/mcp/time@" + DIGEST)
    tmpfs = next(a for a in argv if a.startswith("--tmpfs=/tmp:"))
    assert "notmpcopyup" in tmpfs.split(":", 1)[1].split(",")


@pytest.mark.parametrize("script", [I._NPM_SCRIPT, I._PYPI_SCRIPT])
def test_happy_a_build_leaves_nothing_in_tmp(script):
    """Second layer: the image itself carries no cache in /tmp."""
    last = [line for line in script.strip().splitlines() if line.strip()][-1]
    assert last.startswith(I.TMP_CLEANUP.split()[0]) and "/tmp" in last
    assert script.rstrip().endswith(I.TMP_CLEANUP)


def test_edge_the_cleanup_runs_after_the_entry_point_is_printed():
    for script in (I._NPM_SCRIPT, I._PYPI_SCRIPT):
        assert script.index("AXROSS_ENTRY=") < script.rindex(I.TMP_CLEANUP)


def test_happy_network_modes_and_mounts(tmp_path):
    full = I.run_command("f", "img@" + DIGEST, network="full")
    assert not any(a.startswith("--network") for a in full)
    allow = I.run_command("f", "img@" + DIGEST, network="allowlist")
    (net,) = [a for a in allow if a.startswith("--network=")]
    assert net == ("--network=pasta:--no-map-gw,--no-udp,--no-icmp,--ipv4-only,-o,127.0.0.1,-T,"
                   + C.TOKEN_EGRESS)
    ro, rw = tmp_path / "ro", tmp_path / "rw"
    argv = I.run_command("f", "img@" + DIGEST, network="none",
                         mounts=[(str(ro), "/data", False), (str(rw), "/out", True)],
                         args=["--db", "/data/x"])
    assert "--user=0:0" in argv
    assert f"--volume={ro}:/data:ro" in argv and f"--volume={rw}:/out:rw" in argv
    assert argv[-3:] == ["img@" + DIGEST, "--db", "/data/x"]


def test_happy_install_a_builtin_image(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch)
    lines = []
    entry = _builtin("time")
    config = I.install(entry, I.InstallChoice(name="time"), on_line=lines.append)
    assert ["pull", entry.image_ref] in podman.calls("pull")
    assert any("Copying blob" in line for line in lines)
    assert config.container and config.transport == "stdio" and not config.enabled
    assert config.command[-1] == entry.image_ref
    assert config.sandbox == "" and config.egress == ()
    pkg = config.package
    assert (pkg["kind"], pkg["source"], pkg["entry"], pkg["digest"], pkg["tag"]) == (
        "oci", "builtin", "time", entry.digest, "latest")
    assert len(pkg["image"]) == 64 and pkg["network"] == "none"
    assert not config.problems()


def test_happy_a_container_server_gets_its_environment_through_a_pipe(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch)
    entry = _entry(env=(M.EnvSpec("MODE", default="fast"), M.EnvSpec("TOKEN", secret=True)))
    config = I.install(entry, I.InstallChoice(name="x", env={"MODE": "fast"},
                                             secrets={"TOKEN": "s3cr3t"}))
    assert config.env == {"MODE": "fast"} and config.secret_env == ("TOKEN",)
    client = C.McpClient(config, secrets={"TOKEN": "s3cr3t"})
    try:
        seen = _call_env(client)
    finally:
        client.close()
    assert "MODE=fast\n" in seen["envfile"] and "TOKEN=s3cr3t\n" in seen["envfile"]
    assert seen["secret_in_env"] is False  # not in podman's own environment
    (run,) = podman.calls("run")
    assert not any("s3cr3t" in a for a in run)
    assert not any(C.TOKEN_RUN in a or C.TOKEN_ENV_FD in a for a in run)
    env_file = next(a for a in run if a.startswith("--env-file="))
    assert env_file.split("/dev/fd/")[1].isdigit()


def test_happy_an_allowlist_server_reaches_only_the_proxy(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch)
    config = I.install(_entry(), I.InstallChoice(name="x", network="allowlist",
                                                 hosts=("example.com:443",)))
    assert config.egress == ("example.com:443",)
    client = C.McpClient(config)
    try:
        seen = _call_env(client)
    finally:
        client.close()
    (run,) = podman.calls("run")
    (net,) = [a for a in run if a.startswith("--network=")]
    port = int(net.rsplit(",", 1)[1])
    assert f"HTTPS_PROXY=http://127.0.0.1:{port}\n" in seen["envfile"]
    sock = socket.create_connection(("127.0.0.1", port), timeout=5)
    sock.sendall(b"CONNECT evil.example:443 HTTP/1.1\r\n\r\n")
    assert sock.recv(4096).startswith(b"HTTP/1.1 403")
    sock.close()


def test_happy_an_npm_package_is_built_into_an_image(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch,
                         entry_line="AXROSS_ENTRY=/opt/mcp/node_modules/@a/srv/dist/index.js")
    entry = _entry(id="mcpregistry:io.x/srv", name="srv", kind="npm", identifier="@a/srv",
                   version="1.2.3", digest="", tag="", source="mcpregistry")
    config = I.install(entry, I.InstallChoice(name="srv"))
    assert ["pull", I.NODE_IMAGE] in podman.calls("pull")
    (build,) = [a for a in podman.calls("run") if any(x.startswith("--name=axross-mcp-install-")
                                                      for x in a)]
    joined = " ".join(build)
    assert "--cap-drop=ALL" in build and "--security-opt=no-new-privileges" in build
    assert "--ignore-scripts" in joined and "@a/srv@1.2.3" in build
    assert I.NODE_IMAGE in build
    (net,) = [a for a in build if a.startswith("--network=pasta:")]
    port = int(net.rsplit(",", 1)[1])
    assert f"--env=HTTPS_PROXY=http://127.0.0.1:{port}" in build
    (commit,) = podman.calls("commit")
    assert any('"node", "/opt/mcp/node_modules/@a/srv/dist/index.js"' in a for a in commit)
    install_name = next(x for x in build if x.startswith("--name=")).split("=", 1)[1]
    assert ["rm", "-f", install_name] in podman.calls("rm")
    pkg = config.package
    assert (pkg["kind"], pkg["identifier"], pkg["version"], pkg["base"]) == (
        "npm", "@a/srv", "1.2.3", I.NODE_IMAGE)
    assert config.command[-1] == pkg["image"] and len(pkg["image"]) == 64


def test_happy_a_pypi_package_takes_wheels_only(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch, entry_line="AXROSS_ENTRY=/opt/mcp/bin/srv")
    entry = _entry(kind="pypi", identifier="mcp-srv", version="0.7.0", digest="", tag="",
                   name="srv", source="mcpregistry")
    config = I.install(entry, I.InstallChoice(name="srv"))
    (build,) = [a for a in podman.calls("run") if any(x.startswith("--name=axross-mcp-install-")
                                                      for x in a)]
    assert I.PYTHON_IMAGE in build and "mcp-srv==0.7.0" in build
    assert "--only-binary=:all:" in " ".join(build)
    (commit,) = podman.calls("commit")
    assert "--change=ENV PYTHONPATH=/opt/mcp" in commit
    assert config.package["base"] == I.PYTHON_IMAGE


def test_happy_a_remote_entry_is_an_http_server(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch)
    entry = _entry(kind="remote", url="https://mcp.example/mcp", bearer=True, identifier="",
                   digest="", network="full")
    config = I.install(entry, I.InstallChoice(name="web", token="tok"))
    assert (config.transport, config.url, config.bearer, config.container) == (
        "http", "https://mcp.example/mcp", True, False)
    assert podman.log() == []


def test_happy_uninstall_removes_the_image_by_id(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch)
    config = I.install(_builtin("time"), I.InstallChoice(name="time"))
    ok, message = I.uninstall(config)
    assert ok, message
    assert ["rmi", config.package["image"]] in podman.calls("rmi")
    assert podman.state["images"] == {}


def test_happy_an_image_used_by_another_server_stays(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch)
    one = I.install(_builtin("time"), I.InstallChoice(name="time"))
    two = I.install(_builtin("time"), I.InstallChoice(name="time2"))
    ok, message = I.uninstall(one, others=[two])
    assert ok and "time2" in message
    assert podman.calls("rmi") == []


def test_happy_an_image_that_was_there_before_stays(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch)
    entry = _builtin("time")
    podman.add_image("f" * 64, [entry.image_ref], [entry.image_ref])
    config = I.install(entry, I.InstallChoice(name="time"))
    assert config.package["preexisting"] == "true"
    ok, message = I.uninstall(config)
    assert ok and "before" in message
    assert podman.calls("rmi") == []


def test_happy_update_checks(monkeypatch):
    npm = C.McpServerConfig(name="n", command=("podman",), container=True,
                            package={"kind": "npm", "identifier": "@a/srv", "version": "1.2.3"})
    pypi = C.McpServerConfig(name="p", command=("podman",), container=True,
                             package={"kind": "pypi", "identifier": "mcp-srv", "version": "0.7.0"})
    oci = C.McpServerConfig(name="o", command=("podman",), container=True,
                            package={"kind": "oci", "identifier": "docker.io/mcp/time",
                                     "tag": "latest", "digest": DIGEST})
    newer = "sha256:" + "c" * 64

    class Registry(FakeOpener):
        def open(self, request, timeout=None):
            url = request.full_url
            self.urls.append(url)
            if "registry.npmjs.org/@a%2Fsrv/latest" in url:
                return _Response(b'{"version": "1.3.0"}')
            if "pypi.org/pypi/mcp-srv/json" in url:
                return _Response(b'{"info": {"version": "0.7.0"}}')
            if "auth.docker.io/token" in url:
                assert "scope=repository%3Amcp%2Ftime%3Apull" in url
                return _Response(b'{"token": "anon"}')
            if url == "https://registry-1.docker.io/v2/mcp/time/manifests/latest":
                if request.get_header("Authorization") != "Bearer anon":
                    raise urllib.error.HTTPError(url, 401, "auth", {
                        "WWW-Authenticate": 'Bearer realm="https://auth.docker.io/token",'
                                            'service="registry.docker.io",'
                                            'scope="repository:mcp/time:pull"'}, None)
                assert request.get_method() == "HEAD"
                return _Response(b"", headers={"Docker-Content-Digest": newer})
            raise urllib.error.HTTPError(url, 404, "nf", {}, None)

    opener = Registry({})
    a = I.check_update(npm, opener=opener)
    assert (a.current, a.latest, a.newer) == ("1.2.3", "1.3.0", True)
    b = I.check_update(pypi, opener=opener)
    assert (b.latest, b.newer, b.error) == ("0.7.0", False, "")
    c = I.check_update(oci, opener=opener)
    assert (c.current, c.latest, c.newer) == (DIGEST, newer, True)


def test_happy_settings_keep_container_servers_and_sources(tmp_path):
    path = tmp_path / "settings.json"
    s = S.AgentSettings()
    config = C.McpServerConfig(name="time", command=("podman", "run", "img"), container=True,
                               secret_env=("TOKEN",), egress=("example.com:443",),
                               package={"kind": "oci", "identifier": "docker.io/mcp/time",
                                        "digest": DIGEST, "image": "a" * 64})
    s.mcp_servers.append(config)
    s.mcp_sources = M.CatalogSources(dockerhub=False, extra=("/srv/c.json",))
    s.save(path)
    loaded = S.AgentSettings.load(path)
    (server,) = loaded.mcp_servers
    assert server.container and server.secret_env == ("TOKEN",)
    assert server.egress == ("example.com:443",) and server.package["image"] == "a" * 64
    assert loaded.mcp_sources == s.mcp_sources
    assert loaded.mcp_wrap(server) is None
    data = json.loads(path.read_text())
    assert data["mcp_sources"]["dockerhub"] is False


def test_happy_the_image_index_marks_what_is_present(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch)
    entry = _builtin("time")
    podman.add_image("f" * 64, [entry.image_ref], [entry.image_ref])
    podman.add_image("e" * 64, ["docker.io/mcp/git:latest"], ["docker.io/mcp/git@" + DIGEST])
    index = I.Podman().index()
    assert index.has(entry) == "pinned"
    assert index.has(_entry(identifier="docker.io/mcp/git", digest="")) == "other"
    assert index.has(_entry(identifier="docker.io/mcp/nothing")) == ""
    assert index.has_id("f" * 64)


# -- sad -------------------------------------------------------------------------------


@pytest.mark.parametrize("change, why", [
    (dict(name="taken"), "already"),
    (dict(name="bad name"), "name"),
    (dict(network="host"), "network"),
    (dict(network="allowlist"), "host"),
    (dict(network="allowlist", hosts=("nohost",)), "host"),
    (dict(env={"MODE": "a\nb"}), "line"),
    (dict(env={}), "MODE"),
    (dict(secrets={}), "TOKEN"),
    (dict(mounts=()), "/data"),
    (dict(mounts=(I.Mount("relative", "/data"),)), "absolute"),
    (dict(mounts=(I.Mount("/tmp/a:b", "/data"),)), "':'"),
    (dict(mounts=(I.Mount("/", "/data"),)), "whole"),
    (dict(mounts=(I.Mount("/tmp", "/data"), I.Mount("/var", "/data"))), "one folder"),
    (dict(mounts=(I.Mount("/tmp", "/elsewhere"),)), "/elsewhere"),
])
def test_sad_a_bad_choice_is_refused_with_a_reason(change, why):
    entry = _entry(env=(M.EnvSpec("MODE", required=True), M.EnvSpec("TOKEN", secret=True,
                                                                    required=True)),
                   mounts=(M.MountSpec("/data", required=True),))
    values = dict(name="x", env={"MODE": "fast"}, secrets={"TOKEN": "t"},
                  mounts=(I.Mount("/tmp", "/data"),))
    values.update(change)
    problems = I.choice_problems(entry, I.InstallChoice(**values), taken={"taken"})
    assert problems and any(why in p for p in problems), problems


def test_sad_an_entry_that_cannot_be_installed_is_refused(tmp_path, monkeypatch):
    fake_podman(tmp_path, monkeypatch)
    entry = _entry(kind="mcpb", why_not="package type mcpb is not supported")
    assert any("mcpb" in p for p in I.choice_problems(entry, I.InstallChoice(name="x")))
    with pytest.raises(I.InstallError, match="mcpb"):
        I.install(entry, I.InstallChoice(name="x"))


def test_sad_no_podman_is_a_clear_error(monkeypatch, tmp_path):
    monkeypatch.setenv("PATH", str(tmp_path))
    assert not I.Podman().available
    with pytest.raises(I.InstallError, match="podman is not installed"):
        I.install(_builtin("time"), I.InstallChoice(name="time"))


def test_sad_a_failed_pull_says_why(tmp_path, monkeypatch):
    fake_podman(tmp_path, monkeypatch, fail={"pull": "Error: manifest unknown"})
    with pytest.raises(I.InstallError, match="manifest unknown"):
        I.install(_builtin("time"), I.InstallChoice(name="time"))


def test_sad_a_pull_can_be_cancelled(tmp_path, monkeypatch):
    fake_podman(tmp_path, monkeypatch, hang={"pull": 30})
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    start = time.monotonic()
    with pytest.raises(I.InstallError, match="cancelled"):
        I.install(_builtin("time"), I.InstallChoice(name="time"), cancel=cancel)
    assert time.monotonic() - start < 10


def test_sad_a_build_without_an_entry_point_is_refused_and_cleaned(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch, entry_line="")
    entry = _entry(kind="npm", identifier="srv", version="1.0.0", digest="", tag="")
    with pytest.raises(I.InstallError, match="entry point"):
        I.install(entry, I.InstallChoice(name="srv"))
    assert podman.calls("commit") == []
    assert any(c[:2] == ["rm", "-f"] for c in podman.calls("rm"))


def test_sad_a_failing_build_reports_its_output(tmp_path, monkeypatch):
    fake_podman(tmp_path, monkeypatch, fail={"build": "npm ERR! 404 Not Found - srv"})
    entry = _entry(kind="npm", identifier="srv", version="1.0.0", digest="", tag="")
    with pytest.raises(I.InstallError, match="404"):
        I.install(entry, I.InstallChoice(name="srv"))


def test_sad_a_refused_rmi_keeps_the_image_and_says_why(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch)
    config = I.install(_builtin("time"), I.InstallChoice(name="time"))
    podman.update(fail={"rmi": "Error: image is in use by a container"})
    ok, message = I.uninstall(config)
    assert not ok and "in use" in message


def test_sad_mounts_need_rootless_podman(tmp_path, monkeypatch):
    fake_podman(tmp_path, monkeypatch, rootless=False)
    entry = _entry(mounts=(M.MountSpec("/data"),))
    with pytest.raises(I.InstallError, match="rootless"):
        I.install(entry, I.InstallChoice(name="x", mounts=(I.Mount(str(tmp_path), "/data"),)))


def test_sad_broken_container_configs_are_cleaned_or_refused():
    data = {"name": "c", "command": ["podman", "run", "img"], "container": True,
            "sandbox": "High", "secret_env": ["OK", "BAD NAME", 5],
            "egress": ["example.com:443", "nohost"], "package": {"kind": "oci", "x": "y" * 900,
                                                                "image": 7}}
    config = C.McpServerConfig.from_dict(data)
    assert config is not None
    assert config.sandbox == ""  # a container is its own sandbox
    assert config.secret_env == ("OK",) and config.egress == ("example.com:443",)
    assert config.package == {"kind": "oci"}
    assert C.McpServerConfig(name="h", transport="http", url="https://x/",
                             container=True).problems()
    assert C.McpServerConfig.from_dict({**data, "package": "nope"}).package == {}


def test_sad_the_client_refuses_what_it_cannot_deliver(tmp_path, monkeypatch):
    fake_podman(tmp_path, monkeypatch)
    config = C.McpServerConfig(name="c", command=("podman", "run", "img"), container=True,
                               env={"A": "two\nlines"})
    with pytest.raises(C.McpClientError, match="line"):
        C.McpClient(config)
    no_hosts = C.McpServerConfig(name="c", container=True,
                                 command=("podman", "run", f"-T,{C.TOKEN_EGRESS}", "img"))
    with pytest.raises(C.McpClientError, match="allowed host"):
        C.McpClient(no_hosts)


def test_sad_an_unreachable_registry_is_an_update_error():
    config = C.McpServerConfig(name="n", command=("podman",), container=True,
                               package={"kind": "npm", "identifier": "srv", "version": "1.0.0"})
    info = I.check_update(config, opener=FakeOpener({"npmjs": urllib.error.URLError("down")}))
    assert info.error and "down" in info.error and not info.newer
    assert I.check_update(C.McpServerConfig(name="m", command=("x",))).error


# -- edge ------------------------------------------------------------------------------


def test_edge_mount_targets_take_the_folder_names(tmp_path):
    entry = _entry(mounts=(M.MountSpec("/projects/{name}", repeat=True),))
    a, b, c = tmp_path / "a" / "data", tmp_path / "b" / "data", tmp_path / "wé ird!"
    choice = I.InstallChoice(name="x", mounts=(I.Mount(str(a), "/projects/{name}"),
                                               I.Mount(str(b), "/projects/{name}", True),
                                               I.Mount(str(c), "/projects/{name}")))
    assert I.mount_targets(entry, choice) == [
        (str(a), "/projects/data", False), (str(b), "/projects/data-2", True),
        (str(c), "/projects/w-ird", False)]


def test_edge_every_start_has_its_own_container_name(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch)
    config = I.install(_entry(), I.InstallChoice(name="x"))
    for _ in range(2):
        C.McpClient(config).close()
    names = [next(a for a in run if a.startswith("--name=")) for run in podman.calls("run")]
    assert len(set(names)) == 2


def test_edge_a_server_that_ignores_its_input_stops_on_sigterm(tmp_path):
    script = tmp_path / "srv.py"
    script.write_text(
        "import json, signal, sys, time\n"
        "line = sys.stdin.readline()\n"
        "i = json.loads(line)['id']\n"
        "sys.stdout.write(json.dumps({'jsonrpc': '2.0', 'id': i, 'result': {"
        "'protocolVersion': '2024-11-05', 'capabilities': {}, 'serverInfo': {}}}) + '\\n')\n"
        "sys.stdout.flush()\n"
        "while True:\n    time.sleep(1)\n")  # EOF ignored; SIGTERM ends it (default action)
    client = C.McpClient(C.McpServerConfig(name="s", command=(sys.executable, str(script))))
    proc = client._transport._proc
    start = time.monotonic()
    client.close()
    assert proc.poll() is not None and time.monotonic() - start < 8


def test_edge_a_stuck_container_is_removed_by_name(tmp_path, monkeypatch):
    # This "podman run" ignores EOF and SIGTERM: close() kills it and removes
    # the container by its name, as a killed podman client leaves it running.
    podman = fake_podman(tmp_path, monkeypatch, server_mode="stuck")
    config = I.install(_entry(), I.InstallChoice(name="s"))
    client = C.McpClient(config)
    client.close()
    (run,) = podman.calls("run")
    name = next(a for a in run if a.startswith("--name=")).split("=", 1)[1]
    assert ["rm", "-f", "-t", "0", name] in podman.calls("rm")
    assert name.startswith("axross-mcp-s-") and C.TOKEN_RUN not in name


def test_edge_secrets_live_in_the_keyring(monkeypatch):
    store = {}
    import keyring

    monkeypatch.setattr(keyring, "set_password", lambda s, u, p: store.__setitem__((s, u), p))
    monkeypatch.setattr(keyring, "get_password", lambda s, u: store.get((s, u)))
    monkeypatch.setattr(keyring, "delete_password", lambda s, u: store.pop((s, u)))
    C.set_secret("shodan", "SHODAN_API_KEY", "k")
    assert store == {("axross-mcp-server/shodan", "env:SHODAN_API_KEY"): "k"}
    config = C.McpServerConfig(name="shodan", command=("x",), secret_env=("SHODAN_API_KEY",
                                                                           "MISSING"))
    assert C.secrets_of(config) == {"SHODAN_API_KEY": "k"}
    C.set_secret("shodan", "SHODAN_API_KEY", "")
    assert store == {}


def test_edge_a_digest_is_resolved_and_pinned_at_install(tmp_path, monkeypatch):
    podman = fake_podman(tmp_path, monkeypatch)
    entry = _entry(identifier="docker.io/formatho/runtime", tag="0.3.0", digest="",
                   source="mcpregistry")
    config = I.install(entry, I.InstallChoice(name="rt"))
    assert ["pull", "docker.io/formatho/runtime:0.3.0"] in podman.calls("pull")
    digest = config.package["digest"]
    assert digest.startswith("sha256:") and config.command[-1] == (
        f"docker.io/formatho/runtime@{digest}")


# -- live ------------------------------------------------------------------------------

# The live tests share the user's podman store with everything else on the
# machine. Found: the clean-up removed every image that appeared while a
# live test ran - images another program built in those seconds too.
# Only what these tests pull or commit is theirs to remove.

#: Prefix of the images an npm/pypi install commits (core.mcp_install).
LIVE_COMMIT_PREFIX = "localhost/axross-mcp:live-"


def _live_refs() -> set:
    """The references the live tests pull: their catalog images and the
    base images of an npm/pypi build."""
    return {_builtin("time").image_ref, _builtin("fetch").image_ref,
            I.NODE_IMAGE, I.PYTHON_IMAGE}


def _made_by_live_tests(image: dict, refs: set) -> bool:
    names = [*(image.get("Names") or ()), *(image.get("RepoDigests") or ())]
    return any(n in refs or n.startswith(LIVE_COMMIT_PREFIX) for n in names)


def test_happy_the_live_clean_up_takes_what_the_tests_pulled_or_committed():
    refs = _live_refs()
    time_ref = _builtin("time").image_ref
    assert _made_by_live_tests({"Names": [], "RepoDigests": [time_ref]}, refs)
    assert _made_by_live_tests({"Names": ["localhost/axross-mcp:live-tz-0.1.0"]}, refs)
    assert _made_by_live_tests({"RepoDigests": [I.NODE_IMAGE]}, refs)


def test_sad_an_image_another_program_built_meanwhile_stays():
    refs = _live_refs()
    assert not _made_by_live_tests({"Names": ["localhost/axross-mcp-hub/radare2:local"]}, refs)
    assert not _made_by_live_tests({"Names": ["localhost/axross-mcp:tz-0.1.0"]}, refs)  # a user's
    assert not _made_by_live_tests({"Names": [], "RepoDigests": []}, refs)  # dangling: not ours


def test_edge_another_digest_of_the_same_repository_is_not_ours():
    refs = _live_refs()
    repo = _builtin("time").image_ref.split("@")[0]
    assert not _made_by_live_tests({"RepoDigests": [f"{repo}@sha256:{'0' * 64}"]}, refs)
    assert not _made_by_live_tests({"Names": [f"{repo}:latest"]}, refs)


def _clean_live_images(podman, before: set) -> None:
    """Remove, by ID, the images the live tests pulled or committed that
    were not there *before*; whatever else appeared meanwhile stays."""
    refs = _live_refs()
    after = {img.get("Id") for img in podman.images() if _made_by_live_tests(img, refs)}
    for ident in after - before:
        subprocess.run(["podman", "rmi", ident], capture_output=True, timeout=120,
                       env=dict(os.environ))


@pytest.fixture
def real_podman(monkeypatch):
    """The user's rootless podman with its real store (trun.sh moves HOME
    and XDG_* to a temporary folder); skips without it."""
    if not shutil.which("podman"):
        pytest.skip("podman is not installed")
    user = pwd.getpwuid(os.getuid())
    home = user.pw_dir
    for name, value in (("HOME", home), ("XDG_CONFIG_HOME", f"{home}/.config"),
                        ("XDG_DATA_HOME", f"{home}/.local/share"),
                        ("XDG_CACHE_HOME", f"{home}/.cache"),
                        ("XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}")):
        monkeypatch.setenv(name, value)
    podman = I.Podman()
    if not podman.available or podman.rootless() is not True:
        pytest.skip("no rootless podman")
    before = {img.get("Id") for img in podman.images()}
    yield podman
    _clean_live_images(podman, before)
    # --rm removes a server's container after its process ended, a moment
    # after the client closed (longer under load): wait for it, then judge.
    deadline = time.monotonic() + 30
    while True:
        left = subprocess.run(["podman", "ps", "-a", "--filter", "label=io.axross.mcp",
                               "--format", "{{.Names}}"], capture_output=True, text=True,
                              timeout=60, env=dict(os.environ)).stdout.split()
        left = [n for n in left if n.startswith("axross-mcp-live")]
        if not left or time.monotonic() > deadline:
            break
        time.sleep(0.5)
    assert not left, left


def _no_containers_of(name: str) -> bool:
    out = subprocess.run(["podman", "ps", "-a", "--filter", f"label=io.axross.mcp={name}",
                          "--format", "{{.Names}}"], capture_output=True, text=True,
                         timeout=60, env=dict(os.environ)).stdout.strip()
    return out == ""


def test_live_an_image_built_meanwhile_survives_the_clean_up(real_podman, tmp_path):
    before = {img.get("Id") for img in real_podman.images()}
    (tmp_path / "Containerfile").write_text(f"FROM scratch\nLABEL axross.test={tmp_path.name}\n")
    tag = f"localhost/axross-live-bystander:{os.getpid()}"
    built = subprocess.run(["podman", "build", "-q", "-t", tag, str(tmp_path)],
                           capture_output=True, text=True, timeout=120, env=dict(os.environ))
    assert built.returncode == 0, built.stderr
    try:
        _clean_live_images(real_podman, before)
        exists = subprocess.run(["podman", "image", "exists", tag], timeout=60,
                                env=dict(os.environ))
        assert exists.returncode == 0, "the clean-up removed an image that was not the tests'"
    finally:
        subprocess.run(["podman", "rmi", tag], capture_output=True, timeout=60,
                       env=dict(os.environ))


def test_live_the_time_image_runs_in_podman(real_podman):
    entry = _builtin("time")
    name = "live-time"
    config = I.install(entry, I.InstallChoice(name=name), podman=real_podman)
    client = C.McpClient(config)
    try:
        tools = {t.remote_name: t for t in client.tools()}
        assert {"get_current_time", "convert_time"} <= set(tools)
        outcome, text = tools["get_current_time"].call({"timezone": "Europe/Berlin"})
        assert outcome == "ok" and "Europe/Berlin" in text
    finally:
        client.close()
    deadline = time.monotonic() + 20
    while not _no_containers_of(name) and time.monotonic() < deadline:
        time.sleep(0.5)
    assert _no_containers_of(name)
    ok, message = I.uninstall(config, podman=real_podman)
    assert ok, message


def test_live_an_allowlisted_fetch_reaches_only_its_host(real_podman):
    entry = _builtin("fetch")
    config = I.install(entry, I.InstallChoice(name="live-fetch", network="allowlist",
                                              hosts=("example.com:443",)), podman=real_podman)
    client = C.McpClient(config)
    try:
        fetch = next(t for t in client.tools() if t.remote_name == "fetch")
        outcome, text = fetch.call({"url": "https://example.com/", "max_length": 300})
        assert outcome == "ok" and "Example Domain" in text, text
        outcome, text = fetch.call({"url": "https://www.iana.org/", "max_length": 300})
        assert outcome == "error", text
    finally:
        client.close()
    I.uninstall(config, podman=real_podman)


def test_live_search_the_registries_and_install_an_npm_server(real_podman):
    hub = M.DockerHubSource().search("time")
    assert hub.error == "" and any(e.identifier == "docker.io/mcp/time" for e in hub.entries)
    wanted = "mcpregistry:io.github.MukundaKatta/timezone-mcp"
    registry = M.McpRegistrySource().search("time")
    assert registry.error == "", registry.error
    entry = next((e for e in registry.entries if e.id == wanted), None)
    if entry is None:  # beyond the first pages for "time"
        entry = next((e for e in M.McpRegistrySource().search("timezone-mcp").entries
                      if e.id == wanted), None)
    if entry is None:
        pytest.skip(f"{wanted} is no longer in the MCP Registry")
    assert entry.kind == "npm" and entry.installable
    lines: list[str] = []
    config = I.install(entry, I.InstallChoice(name="live-tz"), podman=real_podman,
                       on_line=lines.append)
    assert config.package["kind"] == "npm" and config.package["base"] == I.NODE_IMAGE
    client = C.McpClient(config)
    try:
        tools = client.tools()
        assert tools, "no tools"
        names = [t.remote_name for t in tools]
        # timezone-mcp 0.1.0: convert_tz, now_in, tz_offset - "now_in" needs a zone only.
        tool = next((t for t in tools if t.remote_name == "now_in"), tools[0])
        props = tool.schema.get("properties") or {}
        args = {key: "Europe/Berlin" for key in props
                if "zone" in key.lower() or "tz" in key.lower()}
        outcome, text = tool.call(args)
        assert outcome in ("ok", "error") and text, (names, text)
        assert outcome == "ok", (names, args, text)
    finally:
        client.close()
    ok, message = I.uninstall(config, podman=real_podman)
    assert ok, message
    left = subprocess.run(["podman", "ps", "-a", "--format", "{{.Names}}"], capture_output=True,
                          text=True, timeout=60, env=dict(os.environ)).stdout.split()
    assert not [n for n in left if n.startswith("axross-mcp-install-")]


def test_live_rea_from_the_shipped_catalog_runs_and_answers(real_podman, tmp_path):
    """A third-party npm server with a big install (rea-agents): its build
    left 115 MB in /tmp, the server did not start before notmpcopyup."""
    work = tmp_path / "work"
    work.mkdir()
    (work / "app.js").write_text("function add(a, b) { return a + b }\nmodule.exports = {add}\n")
    entry = next(e for e in M.load_builtin()[0] if e.name == "rea")
    config = I.install(entry, I.InstallChoice(name="live-rea", mounts=(
        I.Mount(host=str(work), target="/work"),)), podman=real_podman)
    config.timeout = 300
    client = C.McpClient(config)
    try:
        tools = {t.remote_name: t for t in client.tools()}
        assert {"inspect_byte_entropy", "inspect_native_exports"} <= set(tools)
        outcome, text = tools["inspect_byte_entropy"].call({"path": "/work/app.js"})
        assert outcome == "ok" and "entropy" in text.lower(), text[:500]
        outcome, text = tools["inspect_byte_entropy"].call({"path": "/work/missing.bin"})
        assert outcome == "error" or "not" in text.lower(), text[:500]
    finally:
        client.close()
    ok, message = I.uninstall(config, podman=real_podman)
    assert ok, message
