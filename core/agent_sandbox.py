"""The agent harness in a sandbox: bubblewrap, podman or docker.

Configured, the whole agent - the loop of :class:`core.agent.Agent` and
every tool it calls - runs in a process of its own (:mod:`core.agent_worker`)
inside a sandbox, and axross talks to it over the process's stdin/stdout.

A **sandbox profile** names its engine, a level, the hosts it may reach
and extra folders (read-only or read-write). Every tab picks a profile;
the profile is read again before every task, and a change that needs a
new sandbox (engine, level, image, folders, hosts) starts one - with the
conversation, which axross keeps - before the task runs. A host removed
from the list is refused at the next connection, with no restart.

The levels, loosest first:

========  ===========================  ==============  ===============  ==================
level     network                      agent folder    extra folders    limits
========  ===========================  ==============  ===============  ==================
lax       the host's network           rw if allowed   as configured    caps dropped
normal    allowed hosts only           rw if allowed   as configured    + read-only image
high      allowed hosts only           rw if allowed   all read-only    + tighter, no IPC
paranoid  the LLM only                 read-only       all read-only    tightest
========  ===========================  ==============  ===============  ==================

On every level the model's requests come back over the channel and
axross posts them to the profile's ``/chat/completions``: the API key and
the consent never enter the sandbox. "Allowed hosts only" means no
network of the sandbox's own: the worker resolves each allowed
``host:port`` to a loopback listener whose connections axross opens
(:mod:`core.agent_net`).

Who asks: everything that leaves the sandbox - host tools, remote work,
MCP servers, extension tools - is confirmed by axross itself, which
trusts nothing the worker says. A change inside the sandbox's own
writable folder is confirmed by the worker; a subverted worker could
skip that, which is why the level decides what is writable at all.
"""

from __future__ import annotations

import collections
import dataclasses
import functools
import json
import logging
import os
import queue
import shutil
import signal
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Callable

from axross._version import __version__
from core import agent as A
from core import process_launcher
from core.agent_net import HostRelay, parse_hosts
from core.subprocess_env import clean_child_env

log = logging.getLogger(__name__)

ENGINES: tuple[str, ...] = ("auto", "bubblewrap", "podman", "docker")
LEVELS: tuple[str, ...] = ("lax", "normal", "high", "paranoid")
#: The program each engine needs.
ENGINE_PROGRAMS = {"bubblewrap": "bwrap", "podman": "podman", "docker": "docker"}
DEFAULT_IMAGE = f"localhost/axross-agent:{__version__}"
#: Groups that need credentials on the host: never run inside a sandbox.
SANDBOX_REFUSED_GROUPS = frozenset({"remote", "exec"})
#: Read-only system paths a bubblewrapped Python needs.
_SYSTEM_PATHS = ("/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc/ld.so.cache",
                 "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives", "/etc/localtime")
#: What name resolution and TLS need, for a sandbox with the host's network.
_NETWORK_PATHS = ("/etc/resolv.conf", "/etc/hosts", "/etc/nsswitch.conf", "/etc/gai.conf",
                  "/etc/ssl", "/etc/ca-certificates", "/etc/pki")
#: The axross packages a bubblewrapped worker imports.
_PACKAGES = ("core", "models", "axross")
#: Most stderr lines of the worker kept for an error message.
_STDERR_LINES = 40
#: Longest line read from the worker (a model request carries the
#: conversation); a longer one ends the worker (core.agent_worker.MAX_LINE).
MAX_LINE = 64 * 1024 * 1024
#: Host calls (host tools, relayed connections) a worker may have running
#: at once; more are refused.
MAX_HOST_CALLS = 8
#: Bytes queued for a worker that does not read them before it is ended.
MAX_QUEUED_BYTES = 256 * 1024 * 1024


@dataclass(frozen=True)
class LevelRules:
    network: str  # "full", "allowlist" or "none"
    folder_writable: bool  # the agent's folder may be read-write (changes allowed)
    extra_writable: bool  # extra folders keep their read-write flag
    memory: str
    pids: int
    tmp_size: str
    ipc_none: bool
    no_userns: bool
    cpus: str | None


#: How open a network is: a tab may only go down this scale.
_NETWORK_RANK = {"none": 0, "allowlist": 1, "full": 2}

RULES: dict[str, LevelRules] = {
    "lax": LevelRules("full", True, True, "8g", 1024, "512m", False, False, None),
    "normal": LevelRules("allowlist", True, True, "4g", 256, "256m", False, False, None),
    "high": LevelRules("allowlist", True, False, "2g", 128, "128m", True, True, "4"),
    "paranoid": LevelRules("none", False, False, "1g", 64, "64m", True, True, "2"),
}


def _list_of(data: dict, key: str) -> list:
    """*data[key]* when it is a list, else [] - a hand-edited ``"hosts": 5``
    must not stop the start, nor a string be read one character a host."""
    value = data.get(key)
    return value if isinstance(value, list) else []


@dataclass
class SandboxProfile:
    name: str = "Normal"
    engine: str = "auto"
    level: str = "normal"
    #: ``host:port`` entries (core.agent_net.parse_host); used on normal and high.
    hosts: tuple[str, ...] = ()
    #: Extra folders: ``(absolute path, writable)``.
    mounts: tuple[tuple[str, bool], ...] = ()
    image: str = DEFAULT_IMAGE
    #: A tab's narrower network ("none" or "allowlist", core.agent_access);
    #: "" = the level's. Never saved with the profile, never wider.
    net: str = ""

    @property
    def rules(self) -> LevelRules:
        return RULES[self.level]

    @property
    def network(self) -> str:
        """The network this sandbox has: the level's, or the tab's if narrower."""
        level = self.rules.network
        return self.net if _NETWORK_RANK.get(self.net, 99) < _NETWORK_RANK[level] else level

    @classmethod
    def from_dict(cls, data) -> SandboxProfile | None:
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("name"), str)
            or not data["name"].strip()
        ):
            return None
        mounts: list[tuple[str, bool]] = []
        for item in _list_of(data, "mounts"):
            if (
                isinstance(item, dict)
                and isinstance(item.get("path"), str)
                and os.path.isabs(item["path"])
            ):
                pair = (os.path.normpath(item["path"]), item.get("mode") == "rw")
                if pair[0] not in (m[0] for m in mounts):
                    mounts.append(pair)
        hosts = tuple(
            f"[{h}]:{p}" if ":" in h else f"{h}:{p}"
            for h, p in parse_hosts(h for h in _list_of(data, "hosts") if isinstance(h, str))
        )
        image = data.get("image")
        return cls(
            name=data["name"].strip(),
            engine=data.get("engine") if data.get("engine") in ENGINES else "auto",
            level=data.get("level") if data.get("level") in LEVELS else "normal",
            hosts=hosts,
            mounts=tuple(mounts),
            image=image.strip() if isinstance(image, str) and image.strip() else DEFAULT_IMAGE,
        )

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "engine": self.engine,
            "level": self.level,
            "hosts": list(self.hosts),
            "mounts": [
                {"path": path, "mode": "rw" if writable else "ro"} for path, writable in self.mounts
            ],
            "image": self.image,
        }

    def resolved_engine(self) -> str:
        """The engine to run: "auto" takes the first one installed."""
        if self.engine != "auto":
            return self.engine
        return next((e for e in ("bubblewrap", "podman", "docker") if available(e)), "")

    def allows(self, host: str, port: int) -> bool:
        if self.network == "full":
            return True
        if self.network == "none":
            return False
        return (str(host).lower(), int(port)) in parse_hosts(self.hosts)

    def effective_mounts(self) -> tuple[tuple[str, bool], ...]:
        """The extra folders as the level lets them be."""
        return tuple(
            (path, writable and self.rules.extra_writable) for path, writable in self.mounts
        )


def default_profiles() -> list[SandboxProfile]:
    return [SandboxProfile(name=name, level=level) for name, level in
            (("Lax", "lax"), ("Normal", "normal"), ("High", "high"), ("Paranoid", "paranoid"))]


def available(engine: str) -> bool:
    program = ENGINE_PROGRAMS.get(engine)
    return bool(program and shutil.which(program))


def writes_allowed(profile: SandboxProfile | None) -> bool:
    """Whether a tab in this sandbox may be offered changes in its folder."""
    return profile is None or profile.rules.folder_writable


def allowed_groups(groups: frozenset) -> frozenset:
    return frozenset(groups) - SANDBOX_REFUSED_GROUPS


def _package_root() -> Path:
    import core

    return Path(core.__file__).resolve().parent.parent


def worker_argv() -> list[str]:
    """The worker on this machine, without a sandbox."""
    if getattr(sys, "frozen", False):
        return [sys.executable, "--agent-worker"]
    return [sys.executable, "-m", "core.agent_worker"]


def _python_paths() -> tuple[list[str], list[str]]:
    """(directories to mount read-only, PYTHONPATH entries) for the
    Python running axross: the interpreter's own folders, its
    site-packages and axross' packages - never the start folder ('' or
    $HOME under ``python -m``), PYTHONPATH extras or what a .pth file added
    (editable installs of other projects). A frozen build: its executable
    and its bundle."""
    import site

    pkg = _package_root()
    if getattr(sys, "frozen", False):
        mounts = [os.path.abspath(sys.executable)]
        bundle = getattr(sys, "_MEIPASS", None)
        if bundle and os.path.isdir(bundle):
            mounts.append(os.path.abspath(bundle))
        return mounts, []
    home = os.path.abspath(str(Path.home()))

    def holds_home(path: str) -> bool:
        return home == path or home.startswith(path.rstrip(os.sep) + os.sep)

    # A prefix that is $HOME or above it (an interpreter installed into the
    # home folder) is not mounted whole: only its Python folders below.
    prefixes = [
        os.path.abspath(p)
        for p in (sys.prefix, sys.base_prefix, sys.exec_prefix, sys.base_exec_prefix)
        if p and os.path.isdir(p) and not holds_home(os.path.abspath(p))
    ]
    lib_dirs = [os.path.abspath(p) for p in (sys.prefix, sys.base_prefix) if p]
    sites = list(site.getsitepackages()) if hasattr(site, "getsitepackages") else []
    user_site = site.getusersitepackages() if hasattr(site, "getusersitepackages") else ""
    allowed_sites = {os.path.abspath(p) for p in [*sites, user_site] if p}

    def interpreter_owned(path: str) -> bool:
        if holds_home(path):
            return False
        if path in allowed_sites or any(path == p or path.startswith(p.rstrip(os.sep) + os.sep)
                                        for p in prefixes):
            return True
        # Below a prefix that is not mounted whole: its lib/pythonX.Y tree.
        return any(path.startswith(os.path.join(p, "lib", "python")) for p in lib_dirs)

    mounts: list[str] = list(prefixes)
    pythonpath = [str(pkg)]
    for entry in sys.path:
        if not entry or not os.path.isdir(entry):
            continue
        path = os.path.abspath(entry)
        if Path(path) == pkg or pkg in Path(path).parents:
            continue  # the source tree: only its packages go in
        if not interpreter_owned(path):
            continue
        mounts.append(path)
        pythonpath.append(path)
    for name in _PACKAGES:
        if (pkg / name).is_dir():
            mounts.append(str(pkg / name))
    seen: set[str] = set()
    return [m for m in mounts if not (m in seen or seen.add(m))], pythonpath


def _bytes(size: str) -> int:
    """"64m", "2g", "512k" or plain bytes."""
    text = str(size).strip().lower()
    factor = {"k": 1 << 10, "m": 1 << 20, "g": 1 << 30}.get(text[-1:], 1)
    return int(float(text[:-1] if factor > 1 else text) * factor)


@functools.lru_cache(maxsize=1)
def _user_scope_works() -> bool:
    """Whether a transient systemd user scope can be made here (the cgroup
    limits of a bubblewrap sandbox)."""
    if not shutil.which("systemd-run"):
        return False
    try:
        done = subprocess.run(["systemd-run", "--user", "--scope", "--quiet", "--collect", "true"],
                              capture_output=True, timeout=15, env=clean_child_env())
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


def _limits_prefix(rules: LevelRules) -> list[str]:
    """bubblewrap has no resource limits: a systemd user scope gives memory,
    tasks and CPU (cgroups); without one, prlimit caps the address space."""
    if _user_scope_works():
        argv = ["systemd-run", "--user", "--scope", "--quiet", "--collect",
                "-p", f"MemoryMax={_bytes(rules.memory)}", "-p", f"TasksMax={rules.pids}"]
        if rules.cpus:
            argv += ["-p", f"CPUQuota={int(float(rules.cpus) * 100)}%"]
        return [*argv, "--"]
    if shutil.which("prlimit"):
        return ["prlimit", f"--as={_bytes(rules.memory)}", "--"]
    log.warning("agent sandbox: neither systemd-run nor prlimit - bubblewrap runs without limits")
    return []


def _agent_mounts(
    profile: SandboxProfile, root: str, writable: bool, extra=()
) -> list[tuple[str, bool]]:
    """The agent's folder, the profile's folders and *extra* (a tab's
    folders: ``(path, writable)``, writable only where the level lets
    extra folders be and the tab may change files), parents first: a
    read-only folder inside a writable one is mounted after it and stays
    read-only."""
    extra_rw = writable and profile.rules.extra_writable
    mounts = [(root, writable), *profile.effective_mounts(),
              *((os.path.abspath(p), bool(rw) and extra_rw) for p, rw in extra)]
    seen: dict[str, bool] = {}
    for path, rw in mounts:
        seen[path] = rw and seen.get(path, True)  # named twice: read-only wins
    return sorted(seen.items(), key=lambda item: (item[0].rstrip(os.sep).count(os.sep), item[0]))


def _bwrap_command(profile: SandboxProfile, root: str, writable: bool, inner: list[str],
                   extra=()) -> list[str]:
    rules = profile.rules
    mounts, pythonpath = _python_paths()
    argv = [
        "bwrap",
        "--die-with-parent",
        "--new-session",
        "--unshare-all",
        "--cap-drop",
        "ALL",
        "--clearenv",
        "--setenv",
        "PATH",
        "/usr/local/bin:/usr/bin:/bin",
        "--setenv",
        "HOME",
        "/tmp",
        "--setenv",
        "LANG",
        "C.UTF-8",
        "--setenv",
        "PYTHONDONTWRITEBYTECODE",
        "1",
        "--setenv",
        "PYTHONNOUSERSITE",
        "1",
        "--setenv",
        "PYTHONPATH",
        os.pathsep.join(pythonpath),
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--size",
        str(_bytes(rules.tmp_size)),
        "--tmpfs",
        "/tmp",
    ]
    if profile.network == "full":
        argv.append("--share-net")
    if rules.no_userns:
        argv += ["--unshare-user", "--disable-userns"]
    system = _SYSTEM_PATHS + (_NETWORK_PATHS if profile.network == "full" else ())
    for path in system:
        if os.path.islink(path):
            argv += ["--symlink", os.readlink(path), path]
        elif os.path.exists(path):
            argv += ["--ro-bind", path, path]
    for path in mounts:
        argv += ["--ro-bind", path, path]
    for path, rw in _agent_mounts(profile, root, writable, extra):
        argv += ["--bind" if rw else "--ro-bind", path, path]
    argv += ["--chdir", root, "--", *inner]
    return [*_limits_prefix(rules), *argv]


def _container_command(profile: SandboxProfile, engine: str, root: str, writable: bool,
                       inner: list[str] | None, name: str | None = None, extra=()) -> list[str]:
    rules = profile.rules
    argv = [engine, "run", "--rm", "-i"]
    if name:
        argv.append(f"--name={name}")  # so that a stuck one can be removed by name
    if profile.network != "full":
        argv.append("--network=none")
    argv += [
        "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only",
        f"--tmpfs=/tmp:rw,nosuid,nodev,noexec,size={rules.tmp_size}",
        f"--memory={rules.memory}", f"--pids-limit={rules.pids}",
        "--env=HOME=/tmp", "--env=PYTHONDONTWRITEBYTECODE=1",
    ]
    if engine == "podman":
        argv.append("--userns=keep-id")  # the user's uid inside is the user's uid outside
    getuid, getgid = getattr(os, "getuid", None), getattr(os, "getgid", None)
    if getuid is not None and getgid is not None:  # POSIX only
        # The folder's owner - not the image's user, who could not even
        # enter a 0700 parent of the folder.
        argv.append(f"--user={getuid()}:{getgid()}")
    if rules.ipc_none:
        argv.append("--ipc=none")
    if rules.cpus:
        argv.append(f"--cpus={rules.cpus}")
    for path, rw in _agent_mounts(profile, root, writable, extra):
        argv += ["-v", f"{path}:{path}:{'rw' if rw else 'ro'}"]
    argv += [f"--workdir={root}"]
    if inner:
        argv += ["--entrypoint", inner[0], profile.image, *inner[1:]]
    else:
        argv.append(profile.image)  # its entrypoint is the worker
    return argv


def sandbox_command(profile: SandboxProfile, root: str, *, writable: bool,
                    inner: list[str] | None = None, name: str | None = None, extra=()) -> list[str]:
    """The command that runs *inner* (default: the agent worker) in the
    profile's sandbox with *root*, the profile's folders and *extra*
    (``(path, writable)`` pairs: a tab's folders) mounted. *writable* is
    honoured only where the level allows it, and an extra folder is
    writable only with it."""
    root = os.path.abspath(root)
    writable = bool(writable) and profile.rules.folder_writable
    engine = profile.resolved_engine()
    if engine == "bubblewrap":
        return _bwrap_command(profile, root, writable, inner or worker_argv(), extra)
    if engine in ("podman", "docker"):
        return _container_command(profile, engine, root, writable, inner, name, extra)
    raise A.AgentError("no sandbox engine is installed (bubblewrap, podman or docker)")


#: Files a container engine leaves in its containers (podman, docker).
_CONTAINER_MARKERS = ("/run/.containerenv", "/.dockerenv")
#: Worker errors of a sandbox that cannot start, and what is missing
#: (measured 2026-10-17 with rootless podman): (texts, only when axross
#: itself runs in a container, advice).
_START_ADVICE = (
    (("Can't mount proc", "/proc/sys/user/max_user_namespaces"), True,
     "axross runs in a container that masks /proc: start it with --security-opt unmask=/proc/* "
     "(scripts/axross-podman.sh --agent-sandbox) for the bubblewrap sandbox"),
    (("newuidmap", "newgidmap", "cannot set up namespace"), True,
     "axross runs in a container, where podman cannot start containers of its own: "
     "choose a sandbox profile with the bubblewrap engine"),
    (("rootless needs no limits",), False,
     "podman cannot apply the level's memory and process limits without cgroup delegation "
     "(no systemd user session): start axross in a desktop session, or choose bubblewrap"),
)


def in_container() -> bool:
    """Whether axross itself runs in a podman or docker container."""
    return any(os.path.exists(marker) for marker in _CONTAINER_MARKERS)


def _start_advice(text: str) -> str:
    """What the sandbox is missing, if *text* is a known start failure."""
    if not text:
        return ""
    return next((advice for needles, container_only, advice in _START_ADVICE
                 if any(n in text for n in needles) and (not container_only or in_container())), "")


#: What a tab's sandbox profile is once it was renamed or deleted in Agent
#: Settings: everything closed (paranoid), and no new worker starts.
VANISHED = SandboxProfile(name="(missing sandbox profile)", level="paranoid")


#: The events a worker may report, and how long their texts may be. The
#: rest (confirmations, run_started/finished, auto_approved, notices) are
#: axross's own: a worker's version of them is dropped.
_WORKER_EVENTS = frozenset({"assistant", "reasoning", "tool_call", "tool_result", "usage"})
_OUTCOMES = ("ok", "error", "declined", "unavailable")
_MAX_EVENT_TEXT = 200_000
_MAX_EVENT_ARGS = 20_000


def _clean_event(event: dict) -> dict | None:
    """A worker's event as the tab may show it, or None."""
    kind = event.get("type")
    if kind not in _WORKER_EVENTS:
        return None
    if kind in ("assistant", "reasoning"):
        return {"type": kind, "text": str(event.get("text") or "")[:_MAX_EVENT_TEXT]}
    if kind == "usage":
        out: dict = {"type": kind}
        for key in ("prompt_tokens", "completion_tokens"):
            value = event.get(key)
            if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 10**9:
                out[key] = value
        return out
    name = str(event.get("name") or "")[:200]
    if kind == "tool_result":
        outcome = event.get("outcome")
        reason = event.get("reason")
        outcome = outcome if outcome in _OUTCOMES else "error"
        return {"type": kind, "name": name, "outcome": outcome,
                "reason": reason if reason in A.REFUSAL_REASONS else "",
                # The worker's text, cleaned again here: it crosses a trust line.
                "detail": A.tool_result_detail(outcome, event.get("detail"))}
    args = event.get("args") if isinstance(event.get("args"), dict) else {}
    try:
        size = len(json.dumps(args, ensure_ascii=False))
    except (TypeError, ValueError):
        args, size = {}, 0
    if size > _MAX_EVENT_ARGS:
        args = {"(arguments)": f"{size} characters, not shown"}
    return {"type": kind, "name": name, "args": args}


class LocalFilesRefused(AttributeError):
    """Raised by :class:`_SandboxLocal` - an AttributeError, so a feature
    probe (``hasattr``) sees "not supported" instead of failing."""


class _SandboxLocal:
    """The default backend of the host tools: the local files are the
    sandbox's, never reached through axross."""

    name = "local files (in the sandbox)"

    def __getattr__(self, attr):
        raise LocalFilesRefused(
            "the local files are reached inside the sandbox, not through axross"
        )


def _names_backend(tool) -> bool:
    props = (tool.schema or {}).get("properties", {})
    return bool(getattr(tool, "accepts_backend", False)) or any(k in props for k in A.BACKEND_ARGS)


class SandboxedAgent:
    """:class:`core.agent.Agent`'s interface, with the agent in a worker
    process - sandboxed by *profile* (a :class:`SandboxProfile`, or a
    callable that returns the profile as it is now), or plain with
    *command* (tests, and a tab without a sandbox that still wants a
    process of its own)."""

    def __init__(
        self,
        config: A.AgentConfig,
        profile,
        *,
        confirm=None,
        on_event=None,
        cancel: threading.Event | None = None,
        command: list[str] | None = None,
        history: list | None = None,
    ) -> None:
        config = self.config = A.restrict(config)
        self._profile_source: Callable[[], SandboxProfile | None] = (
            profile if callable(profile) else (lambda: profile)
        )
        #: Given a sandbox, a later None means it vanished - never "no sandbox".
        self._bound = profile is not None
        self._confirm = confirm
        self._on_event = on_event or (lambda event: None)
        self.cancel = cancel or threading.Event()
        self._command = command
        self._context_watch = A.OllamaContextWatch(config.profile, config.api_key)
        #: The worker masks the arguments of a question with the tool schema.
        self._tools: dict = {}
        #: The conversation, as the worker last reported it: a new sandbox
        #: (a changed profile, a crash) continues from here.
        self.messages: list = list(history or [])
        self._proc: subprocess.Popen | None = None
        self._signature: tuple | None = None
        self._stderr: collections.deque = collections.deque(maxlen=_STDERR_LINES)
        self._stderr_thread: threading.Thread | None = None
        self._send_lock = threading.Lock()
        #: What goes to the worker's stdin, written by a thread of its own: a
        #: worker that stops reading never blocks a caller (the GUI thread).
        self._out: queue.Queue | None = None
        self._queued = 0
        self._writer: threading.Thread | None = None
        self._host_slots = threading.BoundedSemaphore(MAX_HOST_CALLS)
        #: (engine, name) of a podman/docker worker, removed on a hard stop.
        self._container: tuple[str, str] | None = None
        self._relay = HostRelay(self._send, self._host_allowed)
        # Remote connections and their credentials stay here: the worker
        # reaches them through host tools (a "host_tool" message).
        self._host_registry = A.remote_registry(config, gate=self._gate)
        self._host_tools: list = (
            A.build_tools(config, self._host_registry, backend=_SandboxLocal(), extra_roots=())
            if self._host_registry is not None else []
        )
        #: The tools of further MCP servers (core.mcp_client), loaded at the
        #: first task; they run here too.
        self._external: list | None = None

    # -- the profile --------------------------------------------------------------

    def profile(self) -> SandboxProfile | None:
        current = self._profile_source()
        return VANISHED if current is None and self._bound else current

    def _host_allowed(self, host: str, port: int) -> bool:
        profile = self.profile()
        return profile is not None and profile.allows(host, port)

    def _gate(self, connection_profile) -> None:
        """May a host tool use this connection? The sandbox's level and
        allowed hosts, as they are now, decide - like for the worker's own
        connections."""
        refusal = A.firewall_refusal(
            self.config.firewall,
            str(getattr(connection_profile, "host", "") or ""),
            getattr(connection_profile, "port", 0),
        )
        if refusal is not None:
            raise PermissionError(refusal)
        sandbox = self.profile()
        if sandbox is None or sandbox.network == "full":
            return
        if sandbox.network == "none":
            raise PermissionError(
                f"the sandbox {sandbox.name!r} ({sandbox.level}) reaches no remote host")
        host = str(getattr(connection_profile, "host", "") or "")
        port = getattr(connection_profile, "port", 0)
        if not host or not isinstance(port, int) or not sandbox.allows(host, port):
            raise PermissionError(
                f"{host or 'this connection'}:{port} is not an allowed host of the sandbox "
                f"{sandbox.name!r}; add it in Agent Settings")

    def _host_specs(self, sandbox: SandboxProfile | None) -> list:
        """What the worker may hand to axross. Paranoid: only the tools that
        reach nothing outside (ask_user, update_plan)."""
        external = [t for t in self._external or () if self._external_refusal(t, sandbox) is None]
        remote = [] if sandbox is not None and sandbox.network == "none" else self._host_tools
        return [A.tool_spec(t) for t in [*remote, *external]]

    def _load_external(self) -> None:
        if self._external is not None:
            return
        self._external = []
        if self.config.external_tools is None:
            return
        try:
            tools, errors = self.config.external_tools()
        except Exception as exc:  # noqa: BLE001 - a broken server must not stop the agent
            log.warning("agent sandbox: the MCP servers could not be read: %s", exc)
            tools, errors = [], [str(exc)]
        for error in errors:
            self._on_event({"type": "notice", "text": f"MCP server not available: {error}"})
        self._external = [t for t in tools if A.tool_allowed(t, self.config.functions)
                          and A.external_refusal(t, self.config.firewall) is None]

    @staticmethod
    def _external_refusal(tool, sandbox: SandboxProfile | None) -> str | None:
        """Why the sandbox's level keeps an MCP server's tool out, or None.
        An http server is a host like any other: allowed hosts only."""
        if sandbox is None or sandbox.network == "full" or not getattr(tool, "outside", True):
            return None
        if sandbox.network == "none":
            return f"the sandbox {sandbox.name!r} ({sandbox.level}) reaches no tool outside it"
        client = getattr(tool, "client", None)
        if client is None:
            return None  # axross's own (an extension's): no host to check
        server = client.config
        where = server.host_port()
        if where is not None and not sandbox.allows(*where):
            return (
                f"{where[0]}:{where[1]} (MCP server {server.name!r}) is not an allowed host of the "
                f"sandbox {sandbox.name!r}; add it in Agent Settings"
            )
        return None

    def _signature_of(self, profile: SandboxProfile | None) -> tuple:
        if profile is None:
            return ("none",)
        return (profile.resolved_engine(), profile.level, profile.network, profile.image,
                profile.effective_mounts(), tuple(profile.hosts))

    # -- the process ----------------------------------------------------------------

    def _mounted(self, profile: SandboxProfile | None) -> SandboxProfile | None:
        """*profile* as this agent mounts it: with Files read-only its own
        folders are read-only too, whatever the level lets them be - the
        mount is the layer that does not trust the worker."""
        if profile is None or not self.config.files_read_only:
            return profile
        return dataclasses.replace(
            profile, mounts=tuple((path, False) for path, _writable in profile.mounts)
        )

    def _argv(self, profile: SandboxProfile | None) -> list[str]:
        if self._command is not None:
            return list(self._command)
        profile = self._mounted(profile)
        if profile is None:
            return worker_argv()
        engine = profile.resolved_engine()
        if not engine or not available(engine):
            name = ENGINE_PROGRAMS.get(engine or profile.engine, "bubblewrap, podman or docker")
            raise A.AgentError(
                f"{name} is not installed: the sandbox {profile.name!r} cannot start"
            )
        for path, _rw in profile.mounts:
            if not os.path.isdir(path):
                raise A.AgentError(
                    f"the folder {path} of the sandbox {profile.name!r} does not exist"
                )
        self._container = (
            (engine, f"axross-agent-{uuid.uuid4().hex[:12]}")
            if engine in ("podman", "docker")
            else None
        )
        return sandbox_command(profile, self.config.root, writable=self.config.allow_write,
                               name=self._container[1] if self._container else None,
                               extra=tuple(self.config.extra_roots))

    def _start(self, profile: SandboxProfile | None) -> None:
        argv = self._argv(profile)
        env = {
            k: v
            for k, v in os.environ.items()
            if k in ("PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "SYSTEMROOT", "XDG_RUNTIME_DIR")
        }
        env["PYTHONPATH"] = str(_package_root())
        log.info(
            "agent sandbox: starting %s (%s)", argv[0], profile.level if profile else "no sandbox"
        )
        try:
            # From the launcher thread: bwrap's --die-with-parent watches the
            # thread that forks it, and a task's run thread ends after the task.
            self._proc = process_launcher.popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                cwd=str(_package_root()), env=env, start_new_session=True,
            )
        except OSError as exc:
            raise A.AgentError(f"the agent sandbox cannot start: {exc}") from None
        self._signature = self._signature_of(profile)
        self._stderr.clear()
        self._stderr_thread = threading.Thread(
            target=self._drain_stderr, args=(self._proc,), daemon=True
        )
        self._stderr_thread.start()
        self._out = queue.Queue()
        self._queued = 0
        self._writer = threading.Thread(target=self._write_loop, args=(self._proc, self._out),
                                        name="agent-worker-stdin", daemon=True)
        self._writer.start()
        self._start_message(profile)

    def _start_message(self, profile: SandboxProfile | None) -> None:
        profile = self._mounted(profile)
        prof = self.config.profile
        sandboxed = profile is not None
        writable = self.config.allow_write and (not sandboxed or profile.rules.folder_writable)
        groups = allowed_groups(self.config.groups) if sandboxed else self.config.groups
        extra_rw = writable and sandboxed and profile.rules.extra_writable
        extra = (
            (
                *profile.effective_mounts(),
                *((p, bool(rw) and extra_rw) for p, rw in self.config.extra_roots),
            )
            if sandboxed
            else tuple(self.config.extra_roots)
        )
        hosts = list(profile.hosts) if sandboxed and profile.network == "allowlist" else []
        self._send({"type": "start", "config": {
            # No endpoint, no key, no consent: those stay here.
            "profile": {"name": prof.name, "provider": prof.provider, "model": prof.model,
                        "temperature": prof.temperature, "timeout": prof.timeout,
                        "max_output_tokens": prof.max_output_tokens},
            "root": self.config.root,
            "extra_roots": [[path, bool(rw)] for path, rw in extra],
            "groups": sorted(groups),
            "allow_write": bool(writable),
            # The worker's own agent applies it as well (core.agent.read_only).
            "files_read_only": bool(self.config.files_read_only),
            "max_steps": self.config.max_steps,
            "max_tool_chars": self.config.max_tool_chars,
            "system_prompt": self.config.system_prompt,
            "hosts": hosts,
            "host_tools": self._host_specs(profile),
            "messages": self.messages,
        }})

    def _drain_stderr(self, proc: subprocess.Popen) -> None:
        for raw in iter(proc.stderr.readline, b""):
            self._stderr.append(raw.decode("utf-8", "replace").rstrip())

    def _send(self, message: dict) -> None:
        """Queue *message* for the worker; never blocks. A worker that lets
        more than MAX_QUEUED_BYTES pile up is ended."""
        proc, out = self._proc, self._out
        if proc is None or proc.stdin is None or out is None:
            return
        data = (json.dumps(message, ensure_ascii=False) + "\n").encode("utf-8")
        with self._send_lock:
            if self._queued + len(data) > MAX_QUEUED_BYTES:
                log.warning("agent sandbox: the worker does not read its input - ending it")
                self._kill(proc)
                return
            self._queued += len(data)
            out.put(data)

    def _write_loop(self, proc: subprocess.Popen, out: queue.Queue) -> None:
        while True:
            data = out.get()
            if data is None:
                return
            with self._send_lock:
                self._queued = max(0, self._queued - len(data))
            try:
                proc.stdin.write(data)
                proc.stdin.flush()
            except (BrokenPipeError, OSError, ValueError):
                return

    def _kill(self, proc: subprocess.Popen) -> None:
        """End the worker at once: its process group, and a container by name
        (killing the podman/docker client alone leaves the container)."""
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (OSError, AttributeError):
            try:
                proc.kill()
            except OSError:
                pass
        if self._container is not None:
            engine, name = self._container
            try:
                subprocess.run(
                    [ENGINE_PROGRAMS.get(engine, engine), "rm", "-f", name],
                    capture_output=True,
                    timeout=20,
                    env=clean_child_env(),
                )
            except (OSError, subprocess.SubprocessError) as exc:
                log.warning("agent sandbox: removing the container %s failed: %s", name, exc)

    def _ended(self) -> A.AgentError:
        proc = self._proc
        code = proc.wait(timeout=5) if proc is not None else None
        if self._stderr_thread is not None:
            self._stderr_thread.join(timeout=2)  # the last words of the worker
        tail = " | ".join(line for line in self._stderr if line)[-800:]
        self._proc = None
        self._relay.close_all()
        advice = _start_advice(tail)
        return A.AgentError(
            f"the sandboxed agent ended (exit {code})"
            + (f": {tail}" if tail else "")
            + (f" - {advice}" if advice else "")
        )

    def close(self) -> None:
        self._stop()
        if self._host_registry is not None:
            self._host_registry.close_all()

    def _stop(self) -> None:
        self._relay.close_all()
        proc, self._proc = self._proc, None
        out, writer = self._out, self._writer
        self._out = self._writer = None
        if proc is None:
            return
        if out is not None:
            out.put(None)  # after what is queued
        if writer is not None:
            writer.join(timeout=2)
            if writer.is_alive():  # the worker stopped reading: the write blocks
                self._kill(proc)
                writer.join(timeout=2)
        try:
            proc.stdin.close()
        except (OSError, ValueError):
            pass
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._kill(proc)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                log.warning("agent sandbox: the worker %s did not end", proc.pid)

    # -- a task -----------------------------------------------------------------------

    def run(self, task: str) -> A.AgentResult:
        profile = self.config.profile
        if profile.needs_consent():
            raise A.AgentError(
                f"the profile {profile.name!r} sends to {profile.host() or 'an unknown host'}, "
                "which has no consent yet: confirm it in the LLM settings first"
            )
        sandbox = self.profile()
        if sandbox is VANISHED:
            raise A.AgentError(
                "the sandbox profile of this tab no longer exists (renamed or deleted in "
                "Agent Settings): choose a sandbox for the tab"
            )
        if self._proc is not None and self._proc.poll() is None \
                and self._signature != self._signature_of(sandbox):
            log.info(
                "agent sandbox: the profile changed - a new sandbox continues the conversation"
            )
            self._stop()
        self._load_external()
        if self._proc is None or self._proc.poll() is not None:
            self._start(sandbox)
        # The worker sends through axross: axross asks what is loaded - after
        # the sandbox's own problems, which say more.
        refusal = A.model_load_refusal(profile, self.config.api_key)
        if refusal:
            raise A.AgentError(refusal)
        done = threading.Event()

        def forward_cancel() -> None:
            while not done.is_set():
                if self.cancel.wait(0.1):
                    self._send({"type": "cancel"})
                    return

        threading.Thread(target=forward_cancel, daemon=True).start()
        try:
            self._send({"type": "task", "text": task})
            return self._serve()
        finally:
            done.set()

    def _serve(self) -> A.AgentResult:
        proc = self._proc
        while True:
            line = proc.stdout.readline(MAX_LINE + 1) if proc is not None else b""
            if not line:
                raise self._ended()
            if len(line) > MAX_LINE:
                self._kill(proc)
                self._stop()
                raise A.AgentError(
                    f"the sandboxed agent sent a line too long (over {MAX_LINE} bytes): ended"
                )
            try:
                message = json.loads(line)
            except ValueError:
                continue
            if not isinstance(message, dict):
                continue
            kind = message.get("type")
            if kind == "event" and isinstance(message.get("event"), dict):
                event = _clean_event(message["event"])
                if event is not None:
                    self._on_event(event)
            elif kind == "confirm":
                self._answer_confirm(message)
            elif kind == "llm":
                self._answer_llm(message)
            elif kind == "tcp_open":
                self._answer_tcp_open(message)
            elif kind == "host_tool":
                self._answer_host_tool(message)
            elif kind == "tcp_data":
                self._relay.write(message.get("stream"), message.get("data") or "")
            elif kind == "tcp_close":
                self._relay.close(message.get("stream"))
            elif kind == "history" and isinstance(message.get("messages"), list):
                self.messages = [m for m in message["messages"] if isinstance(m, dict)]
            elif kind == "result":
                calls = [c for c in message.get("calls") or [] if isinstance(c, dict)]
                stopped = message.get("stopped")
                return A.AgentResult(
                    answer=str(message.get("answer") or ""),
                    stopped=stopped
                    if stopped in ("answered", "max_steps", "cancelled")
                    else "answered",
                    calls=calls,
                )
            elif kind == "failed":
                raise A.AgentError(str(message.get("error") or "the sandboxed agent failed"))

    def _answer_confirm(self, message: dict) -> None:
        name = message.get("name")
        args = message.get("args")
        yes = False
        if isinstance(name, str) and isinstance(args, dict) and self._confirm is not None:
            try:
                yes = bool(self._confirm(name, args))
            except Exception as exc:  # noqa: BLE001 - a broken prompt is a "no"
                log.warning("agent sandbox: the confirmation of %s failed: %s", name, exc)
        if self.cancel.is_set():
            # The cancel must reach the worker before the answer it decides.
            self._send({"type": "cancel"})
            yes = False
        self._send({"type": "answer", "id": message.get("id"), "value": yes})

    def _answer_llm(self, message: dict) -> None:
        body = message.get("body")
        if not isinstance(body, dict):
            self._send(
                {"type": "answer", "id": message.get("id"), "error": "a broken model request"}
            )
            return
        # axross sends for the worker: its own word on the connection, the
        # worker's is dropped (_WORKER_EVENTS).
        self._on_event({"type": "connection", "state": "trying"})
        try:
            value = A.post_chat(self.config.profile, self.config.api_key, body,
                                cancel=self.cancel)
        except A.AgentCancelled as exc:
            self._on_event({"type": "connection", "state": "cancelled"})
            # The cancel must reach the worker before the error it reads as
            # the end of the task (its agent then says "stopped").
            self._send({"type": "cancel"})
            self._send({"type": "answer", "id": message.get("id"), "error": str(exc)})
            return
        except A.AgentError as exc:
            self._on_event({"type": "connection", "state": "failed", "detail": str(exc)})
            self._send({"type": "answer", "id": message.get("id"), "error": str(exc)})
            return
        self._on_event({"type": "connection", "state": "connected"})
        self._send({"type": "answer", "id": message.get("id"), "value": value})
        usage = value.get("usage") if isinstance(value, dict) else None
        if isinstance(usage, dict):
            # The worker cannot reach the server to ask its context: axross does.
            notice = self._context_watch.notice(usage)
            if notice:
                self._on_event({"type": "notice", "text": notice})

    def _answer_host_tool(self, message: dict, *, wait: bool = False) -> None:
        def run() -> None:
            value = self._run_host_tool(message.get("name"), message.get("args"))
            self._send({"type": "answer", "id": message.get("id"), "value": value})

        if wait:
            run()
        else:
            # A remote call can take long: not on the loop that reads the worker.
            self._in_thread(run, message, "agent-host-tool")

    def _in_thread(self, work, message: dict, name: str) -> None:
        """Run *work* on a thread of its own - at most MAX_HOST_CALLS at once."""
        if not self._host_slots.acquire(blocking=False):
            self._send({"type": "answer", "id": message.get("id"),
                        "error": f"too many calls at once (at most {MAX_HOST_CALLS})"})
            return

        def guarded() -> None:
            try:
                work()
            finally:
                self._host_slots.release()

        threading.Thread(target=guarded, name=name, daemon=True).start()

    def _run_host_tool(self, name, args) -> dict:
        """Run a host tool for the worker: only on a remote backend, with
        the gate and the user's yes. The worker is not trusted to have
        checked any of it."""
        from core import mcp_server

        external_tool = next((t for t in self._external or () if t.name == name), None)
        external = external_tool is not None
        tool = external_tool or next((t for t in self._host_tools if t.name == name), None)
        if (
            tool is None
            or not isinstance(args, dict)
            or not A.tool_allowed(tool, self.config.functions)
        ):
            return {
                "outcome": "unavailable",
                "text": f"error: axross runs no tool {name!r} for you",
            }
        args_text = json.dumps(args, ensure_ascii=False)
        fields = (
            f"tool={name} args_sha256={A._digest(args_text)} args_len={len(args_text)} where=host"
        )
        if self.config.files_read_only and A.may_change_files(tool):
            A.audit.info("%s outcome=declined read_only=1", fields)
            return {"outcome": "declined", "text": A.READ_ONLY_REFUSAL}
        if external:
            refusal = self._external_refusal(tool, self.profile())
            if refusal is not None:
                A.audit.info("%s outcome=refused", fields)
                return {"outcome": "error", "text": f"error: {refusal}"}
        elif _names_backend(tool) and not A.remote_args(args):
            A.audit.info("%s outcome=refused", fields)
            return {
                "outcome": "error",
                "text": "error: the local files are reached inside the sandbox; axross only runs "
                "calls on a remote backend",
            }
        sandbox = self.profile()
        if not external and sandbox is not None and sandbox.network == "none":
            A.audit.info("%s outcome=refused", fields)
            return {"outcome": "error", "text": "error: this sandbox reaches no remote host"}
        if A.needs_confirmation(name, write=tool.write, group=tool.group):
            yes = False
            if self._confirm is not None:
                try:
                    yes = bool(self._confirm(name, A._shown(args, tool.schema)))
                except Exception as exc:  # noqa: BLE001 - a broken prompt is a "no"
                    log.warning("agent sandbox: the confirmation of %s failed: %s", name, exc)
            if not yes or self.cancel.is_set():
                A.audit.info("%s outcome=declined", fields)
                return {"outcome": "declined", "text": "declined: the user did not allow this call"}
        if external:
            outcome, text = tool.call(args)
            A.audit.info("%s outcome=%s", fields, outcome)
            return {"outcome": outcome, "text": text}
        response = mcp_server._handle_request(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": args},
            },
            self._host_tools,
            cancels=mcp_server._CancelRegistry(),
        )
        if "error" in response:
            A.audit.info("%s outcome=error", fields)
            return {
                "outcome": "error",
                "text": f"error: {response['error'].get('message', 'failed')}",
            }
        A.audit.info("%s outcome=ok", fields)
        parts = [item.get("text", "") if item.get("type") == "text"
                 else f"[{item.get('type', 'binary')} result, not shown]"
                 for item in response.get("result", {}).get("content", [])]
        return {"outcome": "ok", "text": self._only_allowed(name, "\n".join(parts))}

    def _allowed(self, profile) -> bool:
        try:
            self._gate(profile)
        except PermissionError:
            return False
        return True

    def _only_allowed(self, name: str, text: str) -> str:
        """The tools that list connections list only those the sandbox may
        reach: not even names of the others."""
        if name not in ("remote_profiles", "exec_backends", "list_backends"):
            return text
        try:
            data = json.loads(text)
        except ValueError:
            return text
        profiles = dict(self._host_registry.entries()) if self._host_registry is not None else {}

        def registry_ok(bid) -> bool:
            opened = profiles.get(bid)
            return opened is None or self._allowed(opened.profile)

        if (
            name == "remote_profiles"
            and isinstance(data, dict)
            and isinstance(data.get("profiles"), list)
        ):
            data["profiles"] = [
                row
                for row in data["profiles"]
                if isinstance(row, dict)
                and self._allowed(
                    SimpleNamespace(host=row.get("host") or "", port=row.get("port") or 0)
                )
            ]
        elif (
            name == "exec_backends"
            and isinstance(data, dict)
            and isinstance(data.get("backends"), list)
        ):
            data["backends"] = [row for row in data["backends"]
                                if isinstance(row, dict) and registry_ok(row.get("backend"))]
        elif name == "list_backends" and isinstance(data, list):
            data = [row for row in data if not isinstance(row, dict) or registry_ok(row.get("id"))]
        return json.dumps(data, ensure_ascii=False)

    def _answer_tcp_open(self, message: dict) -> None:
        host, port = message.get("host"), message.get("port")
        if not isinstance(host, str) or not isinstance(port, int) or isinstance(port, bool):
            self._send(
                {"type": "answer", "id": message.get("id"), "error": "a broken connection request"}
            )
            return

        def open_stream() -> None:
            try:
                stream = self._relay.open(host, port)
            except (OSError, ValueError) as exc:
                log.warning("agent sandbox: %s:%s refused: %s", host, port, exc)
                self._send({"type": "answer", "id": message.get("id"), "error": str(exc)})
                return
            self._send({"type": "answer", "id": message.get("id"), "value": {"stream": stream}})

        # Connecting can take seconds: not on the loop that reads the worker.
        self._in_thread(open_stream, message, "agent-tcp-open")
