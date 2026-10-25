"""Every server of the c0decave MCP Hub works with axross.

Asked for: the MCP servers in axross's hub must really work with axross -
test cases, TDD, e2e and regressions. The hub ships a machine-readable
smoke spec per server (``tests/axross-smoke.json`` in the hub repository);
copies of it and of the catalog live in ``tests/fixtures/mcp_hub``.

Offline, always: the hub's real catalog is accepted by axross's HubSource
in full, and catalog and smoke spec name the same servers (a server added
to the hub without a smoke spec fails here).

Live, with ``AXROSS_HUB_LIVE=1`` and rootless podman: the live catalog
equals the copy (a hub change shows up here first), and every server is
installed from the live hub the way the catalog dialog does it
(core.mcp_install.install), started through core.mcp_client with axross's
hardened podman line, inspected while it runs (no capabilities, read-only
root, no new privileges, the expected network), asked for its tools, given
its setup calls, a real call and a refused one, then uninstalled with
nothing of its own left behind. A server that needs something to talk to
(nmap, nuclei, sqlmap, ffuf) runs with axross's run line unchanged - axross
refuses a widened line such as --network=container:... - and the spec's
target joins the server's network namespace instead: the server reaches it
on 127.0.0.1, and nothing outside reaches the deliberately vulnerable
target (pasta forwards no port in).
"""

from __future__ import annotations

import base64
import copy
import gzip
import json
import os
import shutil
import subprocess
import time
import uuid
from pathlib import Path

import pytest

from core import mcp_catalog as M
from core import mcp_client as C
from core import mcp_install as I

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "mcp_hub"
CATALOG_RAW = (FIXTURES / "catalog.json").read_bytes()
CATALOG = json.loads(CATALOG_RAW)
SPEC = json.loads((FIXTURES / "axross-smoke.json").read_text("utf-8"))
SERVERS = {s["name"]: s for s in SPEC["servers"]}
LIVE = os.environ.get("AXROSS_HUB_LIVE") == "1"


class _Response:
    def __init__(self, data: bytes) -> None:
        self._data = data

    def read(self, size: int = -1) -> bytes:
        data, self._data = (self._data, b"") if size < 0 else (self._data[:size],
                                                                self._data[size:])
        return data

    def geturl(self) -> str:
        return M.HUB_URL

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc) -> None:
        pass

    headers: dict = {}
    status = 200


class _Opener:
    def __init__(self, data: bytes) -> None:
        self.data = data

    def open(self, request, timeout=None):
        return _Response(self.data)


def _hub(data: bytes = CATALOG_RAW) -> M.SearchResult:
    return M.HubSource(opener=_Opener(data)).search("")


def _subst(value, variables: dict):
    if isinstance(value, str):
        for key, text in variables.items():
            value = value.replace("${" + key + "}", text)
        return value
    if isinstance(value, list):
        return [_subst(v, variables) for v in value]
    if isinstance(value, dict):
        return {k: _subst(v, variables) for k, v in value.items()}
    return value


def _file_bytes(item: dict) -> bytes:
    data = base64.b64decode(item["base64"])
    return gzip.decompress(data) if item.get("gzip") else data


# -- offline: catalog and spec -------------------------------------------------------------


def test_happy_axross_accepts_every_server_of_the_hub_catalog():
    result = _hub()
    assert result.error == "", result.error
    names = sorted(e.name for e in result.entries)
    assert names == sorted(e["name"] for e in CATALOG["entries"])
    for entry in result.entries:
        assert entry.kind == "oci" and entry.identifier.startswith(M.HUB_IMAGE_PREFIX)
        assert entry.digest.startswith("sha256:") and len(entry.digest) == 71
        assert entry.installable, entry.name


def test_happy_every_hub_server_has_a_smoke_spec_and_back():
    catalog_names = {e["name"] for e in CATALOG["entries"]}
    assert set(SERVERS) == catalog_names


def test_sad_a_spec_must_name_its_tools_its_calls_and_existing_mount_targets():
    entries = {e.name: e for e in _hub().entries}
    problems = []
    for name, spec in SERVERS.items():
        tools = set(spec["tools_required"])
        for key in ("call", "refused"):
            if spec[key]["tool"] not in tools and key == "call":
                problems.append(f"{name}: {key} tool {spec[key]['tool']} not in tools_required")
            if not spec[key].get("expect_substring"):
                problems.append(f"{name}: {key} has no expect_substring")
        targets = {m.target for m in entries[name].mounts}
        for item in spec.get("files", ()):
            if item["target"] not in targets:
                problems.append(f"{name}: file for {item['target']}, mounts are {sorted(targets)}")
        if spec.get("target") and spec["target"] not in SPEC["targets"]:
            problems.append(f"{name}: unknown target {spec['target']}")
    assert problems == []


@pytest.mark.parametrize("change, why", [
    (lambda e: e.pop("digest"), "digest"),
    (lambda e: e.update(image="ghcr.io/someone-else/radare2"), "ghcr.io/c0decave/"),
    (lambda e: e.update(digest="sha256:" + "0" * 63), "digest"),
])
def test_sad_a_tampered_hub_entry_is_refused(change, why):
    tampered = copy.deepcopy(CATALOG)
    change(tampered["entries"][0])
    result = _hub(json.dumps(tampered).encode())
    names = {e.name for e in result.entries}
    assert tampered["entries"][0]["name"] not in names
    assert any(why in w for w in result.warnings), result.warnings
    assert len(names) == len(CATALOG["entries"]) - 1  # the others still come


def test_edge_every_fixture_file_decodes():
    for name, spec in SERVERS.items():
        for item in spec.get("files", ()):
            assert _file_bytes(item), f"{name}: {item['path']} is empty"
    for key, target in SPEC["targets"].items():
        for item in target["files"]:
            assert _file_bytes(item), f"target {key}: {item['path']}"


# -- live ----------------------------------------------------------------------------------

live = pytest.mark.skipif(not LIVE, reason="AXROSS_HUB_LIVE=1 runs the hub's servers in podman")


@pytest.fixture(scope="module")
def podman():
    import pwd

    if not shutil.which("podman"):
        pytest.skip("podman is not installed")
    # The user's podman store: tests/conftest.py moved HOME to a temporary
    # folder; podman needs the real one (the store is not axross's settings).
    home = pwd.getpwuid(os.getuid()).pw_dir
    saved = {k: os.environ.get(k) for k in ("HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME",
                                             "XDG_CACHE_HOME", "XDG_RUNTIME_DIR")}
    os.environ.update(HOME=home, XDG_CONFIG_HOME=f"{home}/.config",
                      XDG_DATA_HOME=f"{home}/.local/share", XDG_CACHE_HOME=f"{home}/.cache",
                      XDG_RUNTIME_DIR=f"/run/user/{os.getuid()}")
    try:
        engine = I.Podman()
        if not engine.available or engine.rootless() is not True:
            pytest.skip("no rootless podman")
        yield engine
    finally:
        for key, value in saved.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


@pytest.fixture(scope="module")
def live_entries():
    result = M.HubSource().search("")
    assert result.error == "", result.error
    return {e.name: e for e in result.entries}


def _podman(*args, timeout=120) -> subprocess.CompletedProcess:
    return subprocess.run(["podman", *args], capture_output=True, text=True, timeout=timeout,
                          env=dict(os.environ))


class _Target:
    """The spec's target, in the network namespace of the server's container."""

    def __init__(self, key: str, folder: Path, server_container: str) -> None:
        spec = SPEC["targets"][key]
        self.name = f"axross-hub-e2e-target-{key}-{uuid.uuid4().hex[:8]}"
        files = folder / f"target-{key}"
        files.mkdir()
        for item in spec["files"]:
            (files / item["path"]).write_bytes(_file_bytes(item))
            (files / item["path"]).chmod(0o644)
        image = f"{spec['image']}@{spec['digest']}"
        self.pulled = _podman("image", "exists", image).returncode != 0
        self.image = image
        done = _podman("run", "-d", "--rm", f"--name={self.name}",
                       f"--network=container:{server_container}",
                       "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only",
                       "--memory=256m", f"--volume={files}:{spec['files'][0]['target']}:ro",
                       image, *spec["command"], timeout=600)
        assert done.returncode == 0, done.stderr
        self.port = spec["port"]
        deadline = time.monotonic() + 60
        while _podman("exec", self.name, "python3", "-c",
                      f"import socket; socket.create_connection(('127.0.0.1', {self.port}), 2)"
                      ).returncode != 0:
            assert time.monotonic() < deadline, f"target {key} does not answer"
            time.sleep(0.5)

    def stop(self) -> None:
        _podman("rm", "-f", self.name)
        if self.pulled:
            _podman("rmi", self.image)


def _running_container(name: str) -> str:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        out = _podman("ps", "--filter", f"label=io.axross.mcp={name}", "--format",
                      "{{.Names}}").stdout.split()
        if out:
            return out[0]
        time.sleep(0.2)
    raise AssertionError(f"no running container of {name}")


def _assert_hardened(container: str, network: str) -> None:
    data = json.loads(_podman("inspect", container).stdout)[0]
    host = data["HostConfig"]
    assert host["Privileged"] is False and not host.get("CapAdd")
    assert host["ReadonlyRootfs"] is True
    assert "no-new-privileges" in (host.get("SecurityOpt") or [])
    assert host["PidsLimit"] == 128 and host["Memory"] == 512 * 1024 * 1024
    with open(f"/proc/{data['State']['Pid']}/status") as fh:
        status = dict(line.split(":", 1) for line in fh if ":" in line)
    assert status["CapEff"].strip() == "0000000000000000"
    assert status["NoNewPrivs"].strip() == "1"
    mode = host["NetworkMode"]
    if network == "none":
        assert mode == "none", mode
    elif network.startswith("container:"):
        assert mode.startswith("container:"), mode
    else:
        assert mode not in ("host",), mode


@live
@pytest.mark.parametrize("name", sorted(SERVERS))
def test_live_the_hub_server_works_with_axross(name, podman, live_entries, tmp_path):
    spec = SERVERS[name]
    if spec.get("live_needs_network") and os.environ.get("AXROSS_HUB_OFFLINE") == "1":
        pytest.skip("needs the internet")
    entry = live_entries[name]
    mounts = []
    for target in sorted({f["target"] for f in spec.get("files", ())}):
        folder = tmp_path / target.strip("/").replace("/", "_")
        folder.mkdir()
        for item in spec["files"]:
            if item["target"] == target:
                (folder / item["path"]).write_bytes(_file_bytes(item))
                (folder / item["path"]).chmod(0o644)
        mounts.append(I.Mount(host=str(folder), target=target))
    network = spec["network"]
    hosts = tuple(network["allowlist"]) if isinstance(network, dict) else ()
    mode = "allowlist" if hosts else network
    server = f"hube2e-{name}"
    config = I.install(entry, I.InstallChoice(name=server, network=mode, hosts=hosts,
                                              mounts=tuple(mounts)), podman=podman)
    installed = config.package.get("image", "")
    config.timeout = float(spec.get("timeout_s", 120))
    target = None
    container = ""
    client = C.McpClient(config)
    try:
        tools = {t.remote_name: t for t in client.tools()}
        missing = set(spec["tools_required"]) - set(tools)
        assert not missing, f"tools missing: {missing}"
        container = _running_container(server)
        _assert_hardened(container, mode)
        variables = {}
        if spec.get("target"):
            target = _Target(spec["target"], tmp_path, container)
            variables = {"TARGET_HOST": "127.0.0.1", "TARGET_PORT": str(target.port)}
        for step in spec.get("setup", ()):
            outcome, text = tools[step["tool"]].call(_subst(step["args"], variables))
            assert outcome == "ok", f"setup {step['tool']}: {text[:500]}"
        call = spec["call"]
        outcome, text = tools[call["tool"]].call(_subst(call["args"], variables))
        assert outcome == "ok", text[:800]
        assert _subst(call["expect_substring"], variables) in text, text[:800]
        refused = spec["refused"]
        outcome, text = tools[refused["tool"]].call(_subst(refused["args"], variables))
        assert _subst(refused["expect_substring"], variables) in text, (outcome, text[:800])
    finally:
        # The target first: it lives in the server's network namespace, and
        # podman removes the server's --rm container only once nothing does.
        if target is not None:
            target.stop()
        client.close()
    # This run's container by name (an earlier run's leftover with the same
    # label is not this run's), gone once --rm has removed it.
    deadline = time.monotonic() + 30
    while _podman("container", "exists", container).returncode == 0:
        assert time.monotonic() < deadline, f"{container} was left behind"
        time.sleep(0.5)
    ok, message = I.uninstall(config, podman=podman)
    assert ok, message
    # Only what this test made is judged: other programs build images on the
    # same store meanwhile (a window-based check failed on one of theirs).
    if installed and config.package.get("preexisting") != "true":
        assert _podman("image", "exists", installed).returncode != 0, "the server's image stayed"
    if target is not None and target.pulled:
        assert _podman("image", "exists", target.image).returncode != 0, "the target image stayed"


@live
def test_live_the_hub_catalog_is_the_copy_under_test(live_entries):
    """A change of the hub shows up here: refresh tests/fixtures/mcp_hub."""
    copied = {e.name: e.digest for e in _hub().entries}
    assert {n: e.digest for n, e in live_entries.items()} == copied
