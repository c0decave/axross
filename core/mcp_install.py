"""Installing an MCP server from a catalog (core.mcp_catalog) into podman.

What an install makes is an ordinary :class:`core.mcp_client.McpServerConfig`
whose program is a ``podman run`` line (``container``), so the client, the
Test button, the confirm modes and the pool work unchanged. The server is
added switched off; Agent Settings tests it and switches it on.

* **oci** - ``podman pull <image>@<digest>``. The shipped catalog pins the
  digest; for Docker Hub the tag's digest is asked first; any other image
  is pulled by tag and pinned to the digest podman then reports.
* **npm / pypi** - never npx, uvx, npm or pip on the host: a runtime image
  pinned by digest (:data:`NODE_IMAGE`, :data:`PYTHON_IMAGE`) is pulled and
  an install container runs ``npm install --ignore-scripts`` or ``pip
  install --only-binary=:all:``, without capabilities, under limits, and
  with a network that reaches the package registry only (pasta bound to
  the host's loopback, core.mcp_egress allowing :data:`REGISTRY_HOSTS`).
  ``podman commit`` turns it into ``localhost/axross-mcp:<name>-<version>``
  with the package's entry point; the install container is removed.
* **remote** - a Streamable HTTP endpoint (https): an http config.

The run line (:func:`run_command`): ``--rm -i --init --pull=never``, no
capabilities, no new privileges, a read-only root with a small noexec
/tmp, process and memory limits, ``--network=none`` unless the user chose
"allowlist" (only the hosts given, through the proxy; for programs that
honour HTTPS_PROXY) or "full"; folders only as the user chose them,
read-only unless ticked writable (then the container runs as its root,
which rootless podman maps to the user - the image's own user could not
read the user's folders). The environment and secrets come through a pipe
(core.mcp_client). axross runs these containers with **rootless** podman
only.

Uninstall removes the image by ID with ``podman rmi`` - never forced: an
image that is tagged otherwise or in use stays, and the reason is shown;
an image that was there before the install stays as well.
Runtime images are never removed. Updates are only looked up
(:func:`check_update`), never applied.
"""

from __future__ import annotations

import datetime
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Callable

from core import mcp_catalog as M
from core import mcp_client as C
from core.subprocess_env import clean_child_env

log = logging.getLogger(__name__)

#: node:22-slim and python:3.13-slim, by the digest of their image index
#: (Docker Hub tag API and registry manifest, read 2026-10-25).
NODE_IMAGE = ("docker.io/library/node@sha256:"
              "de170b39439eb0e5a3444ad7d60b015614a381e10fecae2e30ec9e735122f38d")
PYTHON_IMAGE = ("docker.io/library/python@sha256:"
                "d98cc29d3266e535dd9da1099688d9cb3ca4753813571e071763d17725460962")
#: What an install container may reach, per package kind.
REGISTRY_HOSTS = {
    "npm": ("registry.npmjs.org:443",),
    "pypi": ("pypi.org:443", "files.pythonhosted.org:443"),
}
#: The flags of every server's ``podman run``.
RUN_FLAGS = (
    "--rm", "-i", "--init", "--pull=never", "--log-driver=none",
    "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only",
    "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m", "--pids-limit=128", "--memory=512m",
)
#: The network of the allowlist: the container's only way out is the
#: proxy's port on the host's loopback (core.mcp_egress).
ALLOWLIST_NETWORK = ("--network=pasta:--no-map-gw,--no-udp,--no-icmp,--ipv4-only,"
                     "-o,127.0.0.1,-T," + C.TOKEN_EGRESS)
#: Seconds a pull or a package install may take.
PULL_TIMEOUT = 1800.0
BUILD_TIMEOUT = 900.0
_ENTRY = re.compile(r"^/opt/mcp/[A-Za-z0-9@._/+-]+$")

_NPM_SCRIPT = r"""set -eu
mkdir -p /opt/mcp
cd /opt/mcp
npm install --prefix /opt/mcp --no-audit --no-fund --ignore-scripts --omit=dev \
    --no-update-notifier --loglevel=warn "$1"
node -e '
const path = require("path");
const dir = path.join("/opt/mcp/node_modules", process.argv[1]);
const p = require(path.join(dir, "package.json"));
const short = process.argv[1].split("/").pop();
let bin = p.bin;
if (typeof bin === "string") bin = {[short]: bin};
bin = bin || {};
const keys = Object.keys(bin).sort();
const pick = keys.length === 1 ? keys[0] : (keys.includes(short) ? short : keys[0]);
const file = pick ? bin[pick] : (p.main || "index.js");
console.log("AXROSS_ENTRY=" + path.resolve(dir, file));
' "$2"
"""

_PYPI_SCRIPT = r"""set -eu
python -m pip install --no-cache-dir --disable-pip-version-check --no-input \
    --only-binary=:all: --target /opt/mcp "$1"
python - "$2" <<'PY'
import os, re, sys
want = re.sub(r"[-_.]+", "-", sys.argv[1]).lower()
names = sorted(os.listdir("/opt/mcp/bin")) if os.path.isdir("/opt/mcp/bin") else []
norm = {re.sub(r"[-_.]+", "-", n).lower(): n for n in names}
pick = norm.get(want) or (names[0] if len(names) == 1 else "")
if not pick:
    pick = next((n for n in names if "mcp" in n.lower()), names[0] if names else "")
if pick:
    print("AXROSS_ENTRY=/opt/mcp/bin/" + pick)
PY
"""


class InstallError(RuntimeError):
    """The install did not happen; the text says why."""


@dataclass(frozen=True)
class Mount:
    host: str
    #: The entry's mount target (core.mcp_catalog.MountSpec.target).
    target: str
    writable: bool = False


@dataclass
class InstallChoice:
    """What the user chose for an install."""

    name: str
    network: str = "none"
    hosts: tuple[str, ...] = ()
    mounts: tuple[Mount, ...] = ()
    #: Values of the entry's plain environment variables.
    env: dict = field(default_factory=dict)
    #: Values of its secret ones (they go to the keyring, never the file).
    secrets: dict = field(default_factory=dict)
    #: The arguments after the image (None: the entry's).
    args: tuple[str, ...] | None = None
    confirm: str = "always"
    timeout: float = 120.0
    #: remote: the bearer token (to the keyring).
    token: str = ""


def _one_line(value) -> bool:
    return isinstance(value, str) and not any(c in value for c in "\n\r\x00")


def choice_problems(entry: M.CatalogEntry, choice: InstallChoice, *,
                    taken=()) -> list[str]:
    """Why *choice* cannot install *entry* ([] = it can)."""
    out: list[str] = []
    if entry.why_not:
        out.append(f"cannot be installed: {entry.why_not}")
    if not re.match(r"^[A-Za-z0-9_-]{1,32}$", choice.name or ""):
        out.append("the name: 1-32 letters, digits, '-' or '_'")
    elif choice.name in set(taken):
        out.append(f"a server named {choice.name} is already configured")
    if entry.kind == "remote":
        return out
    if choice.network not in M.NETWORKS:
        out.append("the network: none, allowlist or full")
    if choice.network == "allowlist":
        if not choice.hosts:
            out.append("the allowlist needs at least one allowed host (host:port)")
        from core.agent_net import parse_host

        for host in choice.hosts:
            try:
                parse_host(host)
            except ValueError as exc:
                out.append(f"allowed host {exc}")
    for spec in entry.env:
        values = choice.secrets if spec.secret else choice.env
        value = values.get(spec.name, "" if spec.secret else spec.default)
        if spec.required and not value:
            out.append(f"{spec.name} needs a value" + (" (a secret)" if spec.secret else ""))
    for name, value in [*choice.env.items(), *choice.secrets.items()]:
        if not _one_line(value):
            out.append(f"{name}: a value on a single line")
    targets = {m.target: m for m in entry.mounts}
    counts: dict[str, int] = {}
    for mount in choice.mounts:
        counts[mount.target] = counts.get(mount.target, 0) + 1
        if mount.target not in targets:
            out.append(f"{mount.target} is not a folder this server takes")
        host = mount.host
        if not os.path.isabs(host):
            out.append(f"{host}: an absolute folder")
        elif os.path.normpath(host) == os.sep:
            out.append("not the whole file system (/)")
        elif ":" in host or "," in host or not _one_line(host):
            out.append(f"{host}: a folder may not contain ':' or ','")
        elif not os.path.isdir(host):
            out.append(f"{host} is not a folder")
    for target, spec in targets.items():
        if spec.required and not counts.get(target):
            out.append(f"needs a folder at {target}")
        if not spec.repeat and counts.get(target, 0) > 1:
            out.append(f"takes one folder at {target}")
    args = entry.args if choice.args is None else choice.args
    if not all(_one_line(a) for a in args):
        out.append("arguments: each on a single line")
    return list(dict.fromkeys(out))


def mount_targets(entry: M.CatalogEntry, choice: InstallChoice) -> list[tuple[str, str, bool]]:
    """``(host folder, container path, writable)`` of the chosen folders:
    ``{name}`` becomes the folder's name (made safe, made unique)."""
    out: list[tuple[str, str, bool]] = []
    used: set[str] = set()
    for mount in choice.mounts:
        target = mount.target
        if "{name}" in target:
            base = os.path.basename(os.path.normpath(mount.host))
            safe = re.sub(r"[^A-Za-z0-9._-]+", "-", base).strip("-.") or "folder"
            candidate, n = target.replace("{name}", safe), 1
            while candidate in used:
                n += 1
                candidate = target.replace("{name}", f"{safe}-{n}")
            target = candidate
        used.add(target)
        out.append((os.path.normpath(mount.host), target, bool(mount.writable)))
    return out


def run_command(name: str, image: str, *, network: str = "none", mounts=(), args=(),
                program: str = "podman") -> list[str]:
    """The ``podman run`` line of a container server (see the module)."""
    argv = [program, "run", *RUN_FLAGS, f"--name=axross-mcp-{name}-{C.TOKEN_RUN}",
            f"--label=io.axross.mcp={name}", f"--env-file=/dev/fd/{C.TOKEN_ENV_FD}"]
    if network == "none":
        argv.append("--network=none")
    elif network == "allowlist":
        argv.append(ALLOWLIST_NETWORK)
    if mounts:
        argv.append("--user=0:0")
        for host, target, writable in mounts:
            argv.append(f"--volume={host}:{target}:{'rw' if writable else 'ro'}")
    return [*argv, image, *args]


# -- podman --------------------------------------------------------------------------------


@dataclass
class ImageIndex:
    """The images podman has, to show what is pulled already."""

    ids: set = field(default_factory=set)
    digests: set = field(default_factory=set)
    repos: set = field(default_factory=set)

    @classmethod
    def of(cls, images: list[dict]) -> ImageIndex:
        out = cls()
        for img in images:
            if not isinstance(img, dict):
                continue
            if isinstance(img.get("Id"), str):
                out.ids.add(img["Id"])
            for ref in [*(img.get("RepoDigests") or ()), *(img.get("Names") or ())]:
                if not isinstance(ref, str):
                    continue
                if "@" in ref:
                    out.digests.add(ref)
                repo = ref.split("@", 1)[0]
                if ":" in repo.rsplit("/", 1)[-1]:
                    repo = repo.rsplit(":", 1)[0]
                out.repos.add(repo)
        return out

    def has(self, entry: M.CatalogEntry) -> str:
        """"pinned" (this very image), "other" (another of its images) or ""."""
        if entry.kind != "oci":
            return ""
        if entry.digest and entry.image_ref in self.digests:
            return "pinned"
        return "other" if entry.identifier in self.repos else ""

    def has_id(self, ident: str) -> bool:
        return bool(ident) and ident in self.ids


class Podman:
    """The user's podman. Calls run with the user's environment (minus a
    frozen build's loader paths)."""

    def __init__(self, program: str | None = None, env: dict | None = None) -> None:
        self.program = program or shutil.which("podman") or ""
        self._env = env

    @property
    def available(self) -> bool:
        return bool(self.program)

    def env(self) -> dict:
        return dict(self._env) if self._env is not None else clean_child_env()

    def _run(self, args: list[str], timeout: float = 120.0) -> subprocess.CompletedProcess:
        if not self.available:
            raise InstallError("podman is not installed")
        try:
            return subprocess.run([self.program, *args], capture_output=True, text=True,
                                  timeout=timeout, env=self.env())
        except subprocess.TimeoutExpired:
            raise InstallError(f"podman {args[0]} did not finish within {timeout:g} s") from None
        except OSError as exc:
            raise InstallError(f"cannot run podman: {exc}") from None

    def rootless(self) -> bool | None:
        done = self._run(["info", "--format", "{{.Host.Security.Rootless}}"])
        text = done.stdout.strip().lower()
        return True if text == "true" else False if text == "false" else None

    def images(self) -> list[dict]:
        done = self._run(["images", "--format", "json"])
        if done.returncode != 0:
            raise InstallError(f"podman images failed: {_tail(done.stderr)}")
        try:
            data = json.loads(done.stdout or "[]")
        except ValueError:
            raise InstallError("podman images did not answer JSON") from None
        return data if isinstance(data, list) else []

    def index(self) -> ImageIndex:
        return ImageIndex.of(self.images())

    def inspect(self, ref: str) -> dict | None:
        done = self._run(["image", "inspect", "--format", "json", ref])
        if done.returncode != 0:
            return None
        try:
            data = json.loads(done.stdout)
        except ValueError:
            return None
        return data[0] if isinstance(data, list) and data and isinstance(data[0], dict) else None

    def _stream(self, args: list[str], *, on_line, cancel, timeout: float,
                cleanup: Callable[[], None] | None = None) -> tuple[int, list[str]]:
        """Run podman, hand every output line to *on_line*; Cancel or the
        timeout end it (InstallError) after *cleanup*."""
        if not self.available:
            raise InstallError("podman is not installed")
        try:
            proc = subprocess.Popen([self.program, *args], stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    text=True, errors="replace", env=self.env(),
                                    start_new_session=True)
        except OSError as exc:
            raise InstallError(f"cannot run podman: {exc}") from None
        lines: list[str] = []

        def read() -> None:
            for raw in proc.stdout:
                line = raw.rstrip()[:2000]
                lines.append(line)
                del lines[:-400]
                if on_line is not None and line:
                    try:
                        on_line(line)
                    except Exception:  # noqa: BLE001 - a listener must not stop the install
                        log.debug("mcp install: progress listener failed", exc_info=True)

        reader = threading.Thread(target=read, daemon=True, name="mcp-install-output")
        reader.start()
        deadline = time.monotonic() + timeout
        stopped = ""
        while proc.poll() is None:
            if cancel is not None and cancel.is_set():
                stopped = "cancelled"
            elif time.monotonic() > deadline:
                stopped = f"did not finish within {timeout:g} s"
            if stopped:
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait(timeout=10)
                break
            time.sleep(0.1)
        reader.join(timeout=5)
        if stopped:
            if cleanup is not None:
                cleanup()
            raise InstallError(stopped)
        return proc.returncode, lines

    def pull(self, ref: str, *, on_line=None, cancel=None) -> str:
        """Pull *ref*; the image's ID."""
        if on_line is not None:
            on_line(f"podman pull {ref}")
        rc, lines = self._stream(["pull", ref], on_line=on_line, cancel=cancel,
                                 timeout=PULL_TIMEOUT)
        if rc != 0:
            raise InstallError(f"podman pull {ref} failed: {_tail(lines)}")
        info = self.inspect(ref)
        if info is None or not isinstance(info.get("Id"), str):
            raise InstallError(f"{ref} was pulled but podman does not know it")
        return info["Id"]

    def remove(self, image_id: str) -> tuple[bool, str]:
        """``podman rmi`` by ID, never forced: (removed, what podman said)."""
        done = self._run(["rmi", image_id])
        text = _tail(done.stderr or done.stdout)
        return done.returncode == 0, text

    def remove_container(self, name: str) -> None:
        try:
            self._run(["rm", "-f", name], timeout=60)
        except InstallError as exc:
            log.warning("mcp install: could not remove %s: %s", name, exc)

    def build(self, entry: M.CatalogEntry, name: str, *, on_line=None,
              cancel=None) -> tuple[str, str]:
        """An npm or pypi package installed into its runtime image and
        committed; ``(image ID, image name)``."""
        from core.mcp_egress import EgressProxy

        base = NODE_IMAGE if entry.kind == "npm" else PYTHON_IMAGE
        self.pull(base, on_line=on_line, cancel=cancel)
        proxy = EgressProxy(REGISTRY_HOSTS[entry.kind])
        port = proxy.start()
        container = f"axross-mcp-install-{os.urandom(6).hex()}"
        proxy_url = f"http://127.0.0.1:{port}"
        if entry.kind == "npm":
            spec, script = f"{entry.identifier}@{entry.version}", _NPM_SCRIPT
            extra = ["--env=npm_config_registry=https://registry.npmjs.org/",
                     "--env=npm_config_cache=/tmp/npm-cache",
                     f"--env=npm_config_https_proxy={proxy_url}",
                     f"--env=npm_config_proxy={proxy_url}"]
        else:
            spec, script = f"{entry.identifier}=={entry.version}", _PYPI_SCRIPT
            extra = ["--env=PIP_INDEX_URL=https://pypi.org/simple"]
        args = ["run", f"--name={container}", "--cap-drop=ALL",
                "--security-opt=no-new-privileges", "--pids-limit=512", "--memory=2g",
                ALLOWLIST_NETWORK.replace(C.TOKEN_EGRESS, str(port)),
                "--env=HOME=/tmp", f"--env=HTTPS_PROXY={proxy_url}",
                f"--env=https_proxy={proxy_url}", "--env=NO_PROXY=", *extra,
                "--entrypoint=sh", base, "-c", script, "sh", spec, entry.identifier]
        if on_line is not None:
            on_line(f"installing {spec} in a container (network: {entry.kind} registry only)")
        try:
            rc, lines = self._stream(args, on_line=on_line, cancel=cancel,
                                     timeout=BUILD_TIMEOUT,
                                     cleanup=lambda: self.remove_container(container))
            if rc != 0:
                raise InstallError(f"installing {spec} failed: {_tail(lines)}")
            found = [line.split("=", 1)[1] for line in lines if line.startswith("AXROSS_ENTRY=")]
            entry_point = found[-1] if found else ""
            if not _ENTRY.match(entry_point) or ".." in entry_point.split("/"):
                raise InstallError(f"{spec} was installed, but its entry point was not found")
            tag = re.sub(r"[^A-Za-z0-9_.-]+", "-", f"{name}-{entry.version}")[:128]
            image = f"localhost/axross-mcp:{tag}"
            if entry.kind == "npm":
                changes = [f"--change=ENTRYPOINT {json.dumps(['node', entry_point])}",
                           "--change=ENV NODE_ENV=production"]
            else:
                changes = [f"--change=ENTRYPOINT {json.dumps([entry_point])}",
                           "--change=ENV PYTHONPATH=/opt/mcp"]
            changes += ["--change=CMD []", "--change=WORKDIR /tmp",
                        f"--change=LABEL io.axross.mcp.package={entry.kind}:{spec}"]
            done = self._run(["commit", "--quiet", *changes, container, image], timeout=600)
            if done.returncode != 0:
                raise InstallError(f"podman commit failed: {_tail(done.stderr)}")
            info = self.inspect(image)
            if info is None or not isinstance(info.get("Id"), str):
                raise InstallError(f"{image} was made but podman does not know it")
            return info["Id"], image
        finally:
            proxy.close()
            self.remove_container(container)


def _tail(lines, limit: int = 600) -> str:
    if isinstance(lines, str):
        lines = lines.splitlines()
    text = " | ".join(line.strip() for line in lines if line and line.strip())
    return text[-limit:] or "no output"


# -- install / uninstall -------------------------------------------------------------------


def _now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def install(entry: M.CatalogEntry, choice: InstallChoice, *, podman: Podman | None = None,
            source: M.Source | None = None, on_line=None, cancel=None,
            taken=()) -> C.McpServerConfig:
    """Pull or build *entry* and return its server config (switched off;
    secrets and token are the caller's to store). InstallError says why not."""
    problems = choice_problems(entry, choice, taken=taken)
    if problems:
        raise InstallError("; ".join(problems))
    record = {"source": entry.source, "entry": entry.id, "kind": entry.kind,
              "installed": _now()}
    if entry.kind == "remote":
        return C.McpServerConfig(name=choice.name, transport="http", url=entry.url,
                                 bearer=entry.bearer, enabled=False, confirm=choice.confirm,
                                 timeout=choice.timeout, package=record)
    podman = podman or Podman()
    if not podman.available:
        raise InstallError("podman is not installed - container MCP servers need rootless "
                           "podman (https://podman.io)")
    if podman.rootless() is not True:
        raise InstallError("axross runs MCP containers with rootless podman only")
    mounts = mount_targets(entry, choice)
    record["network"] = choice.network
    if entry.kind == "oci":
        if not entry.digest and source is not None:
            try:
                entry = source.resolve(entry)
            except M.CatalogError as exc:
                log.info("mcp install: %s not resolved first: %s", entry.id, exc)
        if podman.inspect(entry.image_ref) is not None:
            record["preexisting"] = "true"  # the user's: an uninstall keeps it
        image_id = podman.pull(entry.image_ref, on_line=on_line, cancel=cancel)
        digest = entry.digest
        if not digest:
            info = podman.inspect(entry.image_ref) or {}
            candidates = [info.get("Digest")] + [
                d.split("@", 1)[1] for d in info.get("RepoDigests") or ()
                if isinstance(d, str) and d.startswith(entry.identifier + "@")]
            digest = next((d for d in candidates
                           if isinstance(d, str) and re.match(r"^sha256:[a-f0-9]{64}$", d)), "")
            if not digest:
                raise InstallError(f"podman names no digest for {entry.image_ref}")
        image = f"{entry.identifier}@{digest}"
        record.update(identifier=entry.identifier, tag=entry.tag, digest=digest,
                      image=image_id)
    elif entry.kind in ("npm", "pypi"):
        image_id, _name = podman.build(entry, choice.name, on_line=on_line, cancel=cancel)
        image = image_id
        record.update(identifier=entry.identifier, version=entry.version, image=image_id,
                      base=NODE_IMAGE if entry.kind == "npm" else PYTHON_IMAGE)
    else:
        raise InstallError(f"package type {entry.kind} is not supported")
    args = entry.args if choice.args is None else tuple(choice.args)
    env = {}
    for spec in entry.env:
        if not spec.secret:
            value = choice.env.get(spec.name, spec.default)
            if value:
                env[spec.name] = value
    secret_env = tuple(s.name for s in entry.env if s.secret and choice.secrets.get(s.name))
    return C.McpServerConfig(
        name=choice.name, transport="stdio",
        command=tuple(run_command(choice.name, image, network=choice.network, mounts=mounts,
                                  args=args, program=podman.program or "podman")),
        env=env, secret_env=secret_env, enabled=False, confirm=choice.confirm,
        timeout=choice.timeout, container=True,
        egress=C._egress_entries(choice.hosts) if choice.network == "allowlist" else (),
        package=record,
    )


def uninstall(config: C.McpServerConfig, *, podman: Podman | None = None,
              others=()) -> tuple[bool, str]:
    """Remove the image a container server was installed with, by ID and
    never forced. ``(done, message)``; *others* are the servers that stay
    (an image one of them uses stays too)."""
    image = config.package.get("image", "") if config.container else ""
    if not image:
        return True, ""
    users = [o.name for o in others if o is not config and o.package.get("image") == image]
    if users:
        return True, f"the image stays: {', '.join(users)} use it"
    if config.package.get("preexisting") == "true":
        return True, "the image was there before the install - it stays"
    podman = podman or Podman()
    if not podman.available:
        return False, "podman is not installed - the image was not removed"
    try:
        ok, text = podman.remove(image)
    except InstallError as exc:
        return False, str(exc)
    if ok:
        return True, f"image {image[:12]} removed"
    return False, f"image {image[:12]} kept: {text}"


# -- updates -------------------------------------------------------------------------------


@dataclass
class UpdateInfo:
    kind: str = ""
    current: str = ""
    latest: str = ""
    newer: bool = False
    error: str = ""


_ACCEPT_MANIFEST = ", ".join((
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
))


def _bearer_challenge(header: str) -> dict:
    if not header.lower().startswith("bearer "):
        return {}
    return dict(re.findall(r'(\w+)="([^"]*)"', header[7:]))


def remote_digest(image: str, tag: str, *, opener=None,
                  timeout: float = M.REQUEST_TIMEOUT) -> str:
    """The digest *image*:*tag* points at in its registry now (a HEAD of the
    manifest; an anonymous token when the registry asks for one)."""
    host, _, repo = image.partition("/")
    api = "registry-1.docker.io" if host == "docker.io" else host
    url = f"https://{api}/v2/{repo}/manifests/{urllib.parse.quote(tag or 'latest')}"
    opener = opener if opener is not None else M.default_opener()

    def head(token: str = ""):
        headers = {"Accept": _ACCEPT_MANIFEST, "User-Agent": M._user_agent()}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(url, headers=headers, method="HEAD")
        with opener.open(request, timeout=timeout) as response:
            return response.headers.get("Docker-Content-Digest") or ""

    try:
        try:
            digest = head()
        except urllib.error.HTTPError as exc:
            if exc.code != 401:
                raise
            challenge = _bearer_challenge(str((exc.headers or {}).get("WWW-Authenticate") or ""))
            realm = challenge.get("realm", "")
            if not realm.startswith("https://"):
                raise M.CatalogError(f"{api} asks for a login axross cannot give") from None
            query = {k: challenge[k] for k in ("service", "scope") if k in challenge}
            data = M.http_get_json(f"{realm}?{urllib.parse.urlencode(query)}", opener=opener,
                                   timeout=timeout, max_bytes=64 * 1024)
            token = data.get("token") or data.get("access_token") if isinstance(data, dict) \
                else ""
            if not isinstance(token, str) or not token:
                raise M.CatalogError(f"{api} gave no token") from None
            digest = head(token)
    except urllib.error.HTTPError as exc:
        raise M.CatalogError(f"{api} answered HTTP {exc.code}") from None
    except (urllib.error.URLError, OSError) as exc:
        raise M.CatalogError(f"cannot reach {api}: {getattr(exc, 'reason', exc)}") from None
    if not re.match(r"^sha256:[a-f0-9]{64}$", digest or ""):
        raise M.CatalogError(f"{api} names no digest for {image}:{tag}")
    return digest


def check_update(config: C.McpServerConfig, *, opener=None) -> UpdateInfo:
    """What the package of an installed server is upstream now; never
    changes anything."""
    pkg = config.package if config.container else {}
    kind = pkg.get("kind", "")
    info = UpdateInfo(kind=kind)
    try:
        if kind == "oci":
            info.current = pkg.get("digest", "")
            info.latest = remote_digest(pkg.get("identifier", ""), pkg.get("tag") or "latest",
                                        opener=opener)
        elif kind == "npm":
            info.current = pkg.get("version", "")
            name = urllib.parse.quote(pkg.get("identifier", ""), safe="@")
            data = M.http_get_json(f"{M.NPM_REGISTRY}/{name}/latest", opener=opener)
            info.latest = str(data.get("version") or "") if isinstance(data, dict) else ""
        elif kind == "pypi":
            info.current = pkg.get("version", "")
            name = urllib.parse.quote(pkg.get("identifier", ""))
            data = M.http_get_json(f"{M.PYPI}/pypi/{name}/json", opener=opener)
            meta = data.get("info") if isinstance(data, dict) else None
            info.latest = str(meta.get("version") or "") if isinstance(meta, dict) else ""
        else:
            info.error = "not installed from a catalog package"
            return info
    except M.CatalogError as exc:
        info.error = str(exc)
        return info
    info.latest = M.clean_text(info.latest, 80)
    info.newer = bool(info.latest) and info.latest != info.current
    return info
