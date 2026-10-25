"""Does an MCP server's command download code when it starts?

``npx some-server``, ``uvx some-server``, ``docker run image`` … fetch a
package or an image at start and run it with the user's rights. axross
never runs such a command on the host (operator rule: servers that are
downloaded always run in a container, under restricted rules).
:func:`downloading_runner` recognises them; core.mcp_install turns a
recognised one into its contained install (an npm or pypi package built in
the pinned runtime container, an image pulled and run with the hardened
podman line, no network by default), and core.mcp_client refuses to start
one on the host - also from a hand-edited settings file.

A command that is not recognised as a runner (a program or script already
on disk) is left alone: it runs as it is, in a sandbox profile if one is
chosen.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from core import mcp_catalog as M

#: Flags of npx-like runners that change nothing about what runs.
_NPM_QUIET = frozenset({"-y", "--yes", "-q", "--quiet", "--silent", "--no-install"})
_PYPI_QUIET = frozenset({"-q", "--quiet", "--isolated", "--no-cache"})
#: ``docker run`` flags axross's own podman line has anyway.
_RUN_SAME = frozenset({"-i", "--interactive", "--rm", "--init"})
#: ``docker run`` flags without a value that are dropped.
_RUN_BOOL = frozenset({"-t", "--tty", "-d", "--detach", "--privileged", "--read-only", "-P",
                       "--publish-all", "--no-healthcheck", "--sig-proxy", "-it", "-ti"})
#: ``docker run`` flags with a value that are dropped (``-e``/``--env`` are kept).
_RUN_VALUE = frozenset({
    "--name", "--network", "--net", "-v", "--volume", "--mount", "--cap-add", "--cap-drop",
    "--device", "--pid", "--ipc", "--uts", "--cgroupns", "--security-opt", "-u", "--user",
    "-p", "--publish", "-w", "--workdir", "--pull", "--platform", "-m", "--memory", "--cpus",
    "-l", "--label", "-h", "--hostname", "--add-host", "--dns", "--tmpfs", "--userns",
    "--group-add", "--restart", "--log-driver", "--log-opt", "--env-file", "--pids-limit",
    "--ulimit", "--shm-size", "--stop-signal", "--stop-timeout", "--expose", "--sysctl",
    "--runtime", "--gpus", "--volumes-from", "--link", "--cidfile", "--health-cmd",
})


@dataclass(frozen=True)
class RunnerPlan:
    """A command that downloads code, and how axross runs it instead."""

    #: The runner as typed: "npx", "uvx", "docker run", …
    runner: str
    #: npm, pypi or oci; "" when it cannot be converted (see why_not).
    kind: str = ""
    #: The package name or the image (normalized, without tag or digest).
    package: str = ""
    #: An exact version ("" = the latest, looked up at install).
    version: str = ""
    tag: str = ""
    digest: str = ""
    #: The arguments after the package or image.
    args: tuple[str, ...] = ()
    #: ``docker run -e NAME=value`` / ``-e NAME`` (from the host: no value).
    env: dict = field(default_factory=dict, repr=False)
    env_names: tuple[str, ...] = ()
    #: ``docker run`` flags that are not taken over.
    dropped: tuple[str, ...] = ()
    #: Why it cannot be converted ("" = it can).
    why_not: str = ""

    @property
    def convertible(self) -> bool:
        return bool(self.kind) and not self.why_not

    @property
    def spec(self) -> str:
        """What it installs, as text."""
        if self.kind == "oci":
            pin = f"@{self.digest}" if self.digest else f":{self.tag or 'latest'}"
            return f"{self.package}{pin}"
        if self.kind:
            sep = "==" if self.kind == "pypi" else "@"
            return f"{self.package}{sep}{self.version or 'latest'}"
        return self.runner


def _program(argv) -> str:
    name = re.split(r"[\\/]", str(argv[0] if argv else ""))[-1].lower()
    for suffix in (".exe", ".cmd", ".bat", ".ps1"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


def _npm(runner: str, rest: list[str]) -> RunnerPlan:
    for index, arg in enumerate(rest):
        if arg == "--":
            continue
        if arg in ("-p", "--package") or arg.startswith("--package="):
            return RunnerPlan(runner, why_not=f"{runner} names its package with --package: "
                                              "not converted (its program is not known)")
        if arg.startswith("-"):
            if arg in _NPM_QUIET:
                continue
            return RunnerPlan(runner, why_not=f"{runner} option {M.clean_text(arg, 40)} is "
                                              "not understood: not converted")
        return _npm_spec(runner, arg, rest[index + 1:])
    return RunnerPlan(runner, why_not=f"{runner} names no package")


def _npm_spec(runner: str, spec: str, args: list[str]) -> RunnerPlan:
    if any(mark in spec for mark in ("://", ":")) or spec.startswith((".", "/", "~", "git")):
        return RunnerPlan(runner, why_not=f"{M.clean_text(spec, 80)} is a git URL or a path, "
                                          "not a package of the npm registry")
    at = spec.rfind("@")
    name, version = (spec[:at], spec[at + 1:]) if at > 0 else (spec, "")
    if version == "latest":
        version = ""
    if len(name) > 214 or not M._NPM.match(name):
        return RunnerPlan(runner, why_not=f"{M.clean_text(name, 80)} is not an npm package name")
    if version and not M._SEMVER.match(version):
        return RunnerPlan(runner, why_not=f"{M.clean_text(version, 40)} is a range or tag, not "
                                          "an exact version")
    return RunnerPlan(runner, kind="npm", package=name, version=version, args=tuple(args))


def _pypi(runner: str, rest: list[str]) -> RunnerPlan:
    for index, arg in enumerate(rest):
        if arg == "--":
            continue
        if arg in ("--from", "--with", "--spec") or arg.startswith(("--from=", "--with=",
                                                                     "--spec=")):
            return RunnerPlan(runner, why_not=f"{runner} {arg.split('=', 1)[0]} names another "
                                              "package than its program: not converted")
        if arg.startswith("-"):
            if arg in _PYPI_QUIET:
                continue
            return RunnerPlan(runner, why_not=f"{runner} option {M.clean_text(arg, 40)} is "
                                              "not understood: not converted")
        return _pypi_spec(runner, arg, rest[index + 1:])
    return RunnerPlan(runner, why_not=f"{runner} names no package")


def _pypi_spec(runner: str, spec: str, args: list[str]) -> RunnerPlan:
    if "://" in spec or spec.startswith((".", "/", "~", "git+")) or "[" in spec:
        return RunnerPlan(runner, why_not=f"{M.clean_text(spec, 80)} is a URL, a path or has "
                                          "extras, not a plain package of PyPI")
    for sep in ("==", "@"):
        if sep in spec:
            name, version = spec.split(sep, 1)
            break
    else:
        name, version = spec, ""
    if version == "latest":
        version = ""
    if len(name) > 100 or not M._PYPI.match(name):
        return RunnerPlan(runner, why_not=f"{M.clean_text(name, 80)} is not a PyPI package name")
    if version and not M._PEP440.match(version):
        return RunnerPlan(runner, why_not=f"{M.clean_text(version, 40)} is not an exact version")
    return RunnerPlan(runner, kind="pypi", package=name, version=version, args=tuple(args))


def _oci(runner: str, rest: list[str]) -> RunnerPlan:
    env: dict[str, str] = {}
    env_names: list[str] = []
    dropped: list[str] = []
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg == "--":
            i += 1
            break
        if not arg.startswith("-") or arg == "-":
            break
        flag, has_value, value = arg.partition("=")
        if flag in _RUN_SAME:
            i += 1
            continue
        if flag in ("-e", "--env"):
            if not has_value:
                if i + 1 >= len(rest):
                    return RunnerPlan(runner, why_not=f"{flag} without a value")
                value = rest[i + 1]
                i += 1
            name, has_eq, val = value.partition("=")
            if not M._ENV_NAME.match(name):
                return RunnerPlan(runner, why_not="an environment name of letters, digits, _")
            if has_eq:
                env[name] = val
            else:
                env_names.append(name)
            i += 1
            continue
        if flag == "--entrypoint":
            return RunnerPlan(runner, why_not="--entrypoint changes what the image runs: not "
                                              "taken over")
        if flag in _RUN_BOOL:
            dropped.append(arg)
            i += 1
            continue
        if flag in _RUN_VALUE:
            if has_value:
                dropped.append(arg)
                i += 1
            elif i + 1 < len(rest):
                dropped.append(f"{arg} {rest[i + 1]}")
                i += 2
            else:
                return RunnerPlan(runner, why_not=f"{flag} without a value")
            continue
        if has_value:
            dropped.append(arg)
            i += 1
            continue
        return RunnerPlan(runner, why_not=f"the option {M.clean_text(arg, 40)} is not known: "
                                          "its value cannot be told from the image")
    if i >= len(rest):
        return RunnerPlan(runner, why_not=f"{runner} names no image")
    try:
        image, tag, digest = M.split_image(rest[i])
    except ValueError as exc:
        return RunnerPlan(runner, why_not=f"the image: {exc}")
    return RunnerPlan(runner, kind="oci", package=image, tag=tag or "latest", digest=digest,
                      args=tuple(rest[i + 1:]), env=env, env_names=tuple(env_names),
                      dropped=tuple(M.clean_text(d, 200) for d in dropped))


def downloading_runner(argv) -> RunnerPlan | None:
    """A :class:`RunnerPlan` when *argv* starts a runner that downloads code
    (npx, bunx, pnpx, ``npm exec``, ``pnpm dlx``, ``yarn dlx``, ``bun x``,
    uvx, ``uv tool run``, ``uv run``, ``pipx run``, ``docker``/``podman``/
    ``nerdctl run``, deno, ``go run``); None for any other program."""
    argv = [str(a) for a in (argv or ())]
    if not argv:
        return None
    program = _program(argv)
    sub = argv[1] if len(argv) > 1 else ""
    rest = argv[1:]
    if program in ("npx", "bunx", "pnpx"):
        return _npm(program, rest)
    if program == "npm" and sub in ("exec", "x"):
        return _npm(f"npm {sub}", argv[2:])
    if program in ("pnpm", "yarn") and sub == "dlx":
        return _npm(f"{program} dlx", argv[2:])
    if program == "bun" and sub == "x":
        return _npm("bun x", argv[2:])
    if program == "uvx":
        return _pypi("uvx", rest)
    if program == "uv" and argv[1:3] == ["tool", "run"]:
        return _pypi("uv tool run", argv[3:])
    if program == "pipx" and sub == "run":
        return _pypi("pipx run", argv[2:])
    if program in ("docker", "podman", "nerdctl") and sub == "run":
        return _oci(f"{program} run", argv[2:])
    if program == "uv" and sub == "run":
        return RunnerPlan("uv run", why_not="uv run installs the packages a script asks for: "
                                            "not converted")
    if program in ("npm", "pnpm", "yarn", "bun"):
        if sub in ("start", "run", "run-script"):
            return None  # a script of a project already on disk
        return RunnerPlan(f"{program} {M.clean_text(sub, 20)}".strip(),
                          why_not=f"{program} {M.clean_text(sub, 20)} may install packages: "
                                  "not converted")
    if program in ("deno",):
        return RunnerPlan("deno", why_not="deno fetches code by URL: not converted")
    if program == "go" and sub == "run":
        return RunnerPlan("go run", why_not="go run fetches modules: not converted")
    return None


#: Container options a server's podman line may never carry (the line of a
#: hand-edited settings file is checked too).
_FORBIDDEN = frozenset({
    "--privileged", "-v", "--mount", "--cap-add", "--device", "--pid", "--ipc", "--uts",
    "--userns", "--cgroupns", "--add-host", "--volumes-from", "--gpus", "--sysctl",
    "--entrypoint", "--group-add", "--runtime",
})
_VOLUME = re.compile(r"^/[^:,]*:/[^:,]*:(?:ro|rw)$")


def container_flag_problems(argv) -> list[str]:
    """Why the podman line *argv* of a container server is not allowed:
    options that widen the container (privileged, capabilities, devices,
    host namespaces, host network, other security options, mounts other
    than core.mcp_install's ``--volume=HOST:TARGET:ro|rw``)."""
    from core.mcp_install import ALLOWLIST_NETWORK

    argv = [str(a) for a in (argv or ())]
    tokens = argv[2:] if len(argv) > 1 and argv[1] == "run" else argv[1:]
    out: list[str] = []
    for arg in tokens:
        if not arg.startswith("-"):
            break  # the image: what follows are the server's arguments
        flag, _, value = arg.partition("=")
        bad = flag in _FORBIDDEN
        if flag == "--volume":
            bad = not _VOLUME.match(value)
        elif flag == "--security-opt":
            bad = value != "no-new-privileges"
        elif flag in ("--network", "--net"):
            bad = value != "none" and arg != ALLOWLIST_NETWORK
        if bad:
            out.append(f"the container option {M.clean_text(arg, 60)} is not allowed")
    return out
