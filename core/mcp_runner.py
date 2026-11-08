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

The check fails closed. A command counts as a runner when any of its words
names a runner or a downloader (``strace -f npx …``, ``xvfb-run npx …``,
``script -qc "npx …"``: a wrapper axross does not know is no way around it),
when it starts a package tool that fetches what it runs (``nix run``,
``pixi exec``, ``pkgx``, ``dnx``), or when an interpreter runs code from its
line (``python -c``, ``node -e``, ``perl -e``, ``ruby -e``, ``php -r`` …),
which nobody can read with certainty. Only what is left (a program or script
already on disk, ``npm start`` of a project on disk, ``python -m module``) runs
as it is, in a sandbox profile if one is chosen.
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
            name = name[: -len(suffix)]
            break
    return _SCRIPT_PROGRAMS.get(name, name)


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


# -- what only starts another program ---------------------------------------------------------

#: Wrappers inside wrappers are read this deep; deeper counts as a runner.
_MAX_DEPTH = 8
_NO_WRAPPER = object()
#: Scripts that are a runner when started directly or by node / python
#: (``node …/npm/bin/npx-cli.js``, ``python -m pip``).
_SCRIPT_PROGRAMS = {
    "npx-cli.js": "npx", "npm-cli.js": "npm", "npx-cli": "npx", "npm-cli": "npm",
    "npx.js": "npx", "npm.js": "npm", "pnpm.cjs": "pnpm", "pnpm.js": "pnpm",
    "pnpx.cjs": "pnpx", "yarn.js": "yarn", "yarn.cjs": "yarn", "bunx.js": "bunx",
}
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "yash", "fish", "csh",
                     "tcsh", "busybox"})
_POWERSHELLS = frozenset({"powershell", "pwsh"})
_PYTHONS = re.compile(r"(?:python(?:[0-9][0-9.]*)?w?|py|pypy[0-9.]*)")
_NODES = frozenset({"node", "nodejs"})
#: Interpreters whose options can carry code on the command line: the code
#: options, the letters of a one-letter option cluster that mean code, and
#: the letters that take the rest of the cluster as their value.
_CODE_INTERPRETERS = {
    "perl": (frozenset({"-e", "-E"}), "eE", "IMmxDiC"),
    "ruby": (frozenset({"-e", "--eval"}), "e", "IrCEFxK"),
    "php": (frozenset({"-r", "-B", "-R", "-E", "-F"}), "", ""),
    "lua": (frozenset({"-e"}), "e", "l"),
    "luajit": (frozenset({"-e"}), "e", "lbj"),
    "rscript": (frozenset({"-e", "--expr"}), "", ""),
    "julia": (frozenset({"-e", "--eval", "-E", "--print"}), "eE", "JLp"),
    "osascript": (frozenset({"-e"}), "e", "lis"),
    "tclsh": (frozenset({"-c"}), "", ""),
    "gawk": (frozenset({"--source", "-e"}), "", ""),
}
#: Letters of a one-letter option cluster whose optional value is digits
#: only (``perl -l``, ``-0777``, ``ruby -T1``; ``perl -d`` takes ``:Module``
#: or ``t``): after them the cluster goes on (``perl -le CODE``, ``-de 0``).
_DIGIT_LETTERS = {"perl": "l0d", "ruby": "0Tl"}
#: Programs that download files: any line with one is a runner.
_DOWNLOADERS = frozenset({"curl", "wget", "aria2c"})
#: Package and tool managers that fetch or install what they run.
_PACKAGE_TOOLS = frozenset({
    "gem", "pip-run", "jbang", "cs", "coursier", "mise", "asdf", "volta", "hatch", "pdm",
    "poetry", "conda", "mamba", "micromamba", "pipenv", "rye", "dotnet",
})
#: Programs that download (or install) what they run, wherever they stand
#: in a command line: a word naming one makes the command a runner.
_RUNNER_NAMES = frozenset({
    "npx", "bunx", "pnpx", "npm", "pnpm", "yarn", "bun", "uvx", "uv", "pipx", "pip", "pip3",
    "docker", "podman", "nerdctl", "docker-compose", "deno", "go", "nix", "nix-shell",
    "nix-env", "nix-build", "nix-store", "pixi", "pkgx", "dnx", "corepack",
    *_DOWNLOADERS, *_PACKAGE_TOOLS,
})
#: Node options whose value is code when it is a data: or a remote URL.
_NODE_MODULE_OPTIONS = frozenset({"--import", "--loader", "--experimental-loader", "-r",
                                  "--require"})
_CODE_URL = re.compile(r"^\s*(?:data|https?):", re.IGNORECASE)
#: Python modules that are package tools (``python -m pdm run …``).
_PYTHON_TOOL_MODULES = frozenset({"pdm", "poetry", "hatch", "conda", "mamba", "ensurepip",
                                   "pixi", "virtualenv", "venv"})
#: What makes a word of a command line a line of its own (``script -qc "npx x"``).
_LINE_MARKS = re.compile(r"[\s;&|()<>$`'\"\\]")
#: Programs that start the rest of their line.
_PLAIN_PREFIXES = frozenset({"exec", "command", "nohup", "setsid", "time", "builtin",
                             "corepack", "sudo", "doas", "chronic", "unbuffer"})
#: Programs that start a command after options and maybe one value.
_VALUE_PREFIXES = frozenset({"nice", "timeout", "stdbuf", "ionice", "chrt", "taskset",
                             "xargs", "flock", "cgexec", "systemd-run", "firejail", "watch"})
_PREFIX_VALUED = frozenset({"-n", "-s", "-k", "--signal", "--kill-after", "-c", "-p", "-i",
                            "-o", "-e", "-I", "-L", "-g", "--cpu-list", "--adjustment", "-d",
                            "-w", "--unit", "-u", "--uid", "--gid", "-P", "-a", "-E"})
_ENV_FLAGS = frozenset({"-i", "--ignore-environment", "-0", "--null", "-v", "--debug", "-"})
_ENV_VALUED = frozenset({"-u", "--unset", "-C", "--chdir"})
_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
#: Words of a shell line that make it more than plain commands.
_SHELL_KEYWORDS = frozenset({"if", "then", "else", "elif", "fi", "for", "while", "until", "do",
                             "done", "case", "esac", "select", "function", "{", "}", "[[",
                             "]]", "!", "coproc", "eval", "source", ".", "alias", "trap"})
_PS_VALUED = frozenset({"-executionpolicy", "-ep", "-ex", "-windowstyle", "-w", "-version",
                        "-v", "-configurationname", "-outputformat", "-of", "-inputformat",
                        "-if", "-workingdirectory", "-wd", "-settingsfile", "-psconsolefile"})
_PS_FLAGS = frozenset({"-noprofile", "-nop", "-noninteractive", "-noni", "-nologo", "-mta",
                       "-sta", "-noexit", "-noe", "-login", "-l", "-interactive", "-i"})
#: Node options that take the next word as their value.
_NODE_VALUED = frozenset({"-r", "--require", "--import", "--loader", "--experimental-loader",
                          "--input-type", "--env-file", "-C", "--conditions", "--title",
                          "--inspect-port", "--openssl-config", "--icu-data-dir"})


#: ssh-family programs whose ``-o`` options can name a command run on THIS
#: host (``ssh -o ProxyCommand="sh -c '…'" x``).
_SSH_PROGRAMS = frozenset({"ssh", "scp", "sftp", "autossh"})
_SSH_COMMAND_OPTIONS = frozenset({"proxycommand", "localcommand", "knownhostscommand"})
#: git config keys (``git -c key=value``) whose value is a command git runs.
_GIT_COMMAND_KEYS = frozenset({
    "core.sshcommand", "core.pager", "core.editor", "core.fsmonitor", "core.hookspath",
    "core.gitproxy", "core.askpass", "credential.helper", "diff.external", "gpg.program",
    "gpg.ssh.program", "gpg.x509.program", "sequence.editor", "protocol.ext.allow",
    "protocol.allow", "uploadpack.packobjectshook", "pager.log", "web.browser",
    "remote.origin.uploadpack", "remote.origin.receivepack",
})
#: git options whose value is a program run for the transport.
_GIT_COMMAND_OPTIONS = frozenset({"--upload-pack", "--receive-pack", "--exec",
                                  "--config-env"})
#: gdb options whose value is a gdb command (``shell id`` runs one).
_GDB_CODE_OPTIONS = frozenset({"-ex", "--ex", "-eval-command", "--eval-command", "-iex",
                               "--iex", "-init-eval-command", "--init-eval-command"})
#: php -d settings that cannot load or run anything.
_PHP_HARMLESS_SETTINGS = frozenset({
    "memory_limit", "display_errors", "display_startup_errors", "error_reporting",
    "max_execution_time", "date.timezone", "html_errors", "log_errors", "output_buffering",
    "short_open_tag", "default_charset", "precision", "serialize_precision",
    "implicit_flush", "zend.assertions", "assert.active",
})


def _command_option(program: str, rest: list[str]) -> RunnerPlan | None:
    """A program whose options carry a command or code for THIS host:
    ``ssh -o ProxyCommand=…``, ``git -c core.sshCommand=…`` / an ``ext::``
    URL, ``gdb -ex 'shell …'``, ``php -d auto_prepend_file=https://…``.
    They were classified as "runs as it is"."""
    def refused(option: str) -> RunnerPlan:
        return _unreadable(f"{program} {option}",
                           f"{program} {option} runs a command from its command line")

    if program in _SSH_PROGRAMS:
        for k, arg in enumerate(rest):
            if arg == "--":
                break
            if arg == "-o" and k + 1 < len(rest):
                value = rest[k + 1]
            elif arg.startswith("-o") and len(arg) > 2:
                value = arg[2:]
            else:
                continue
            # "ProxyCommand=…", "ProxyCommand …" (ssh_config takes both)
            parts = re.split(r"\s*=\s*|\s+", value.strip(), maxsplit=1)
            key = parts[0].lower()
            setting = parts[1] if len(parts) > 1 else ""
            if key in _SSH_COMMAND_OPTIONS and setting.strip().strip("'\"").lower() != "none":
                return refused(f"-o {key}")
        return None
    if program == "git":
        for k, arg in enumerate(rest):
            if "ext::" in arg:
                return refused("ext::")
            name = arg.split("=", 1)[0]
            if name in _GIT_COMMAND_OPTIONS and arg.startswith("-"):
                return refused(name)
            if arg == "-c" and k + 1 < len(rest):
                key, _, value = rest[k + 1].partition("=")
                key = key.strip().lower()
                if key in _GIT_COMMAND_KEYS or key.endswith((".uploadpack", ".receivepack",
                                                              ".proxy", ".command",
                                                              ".textconv", ".driver",
                                                              ".clean", ".smudge",
                                                              ".process", ".helper")) \
                        or (key.startswith("alias.") and value.lstrip().startswith("!")):
                    return refused(f"-c {key}")
        return None
    if program == "gdb":
        for arg in rest:
            if arg.split("=", 1)[0] in _GDB_CODE_OPTIONS:
                return refused(arg.split("=", 1)[0])
        return None
    if program == "php":
        for k, arg in enumerate(rest):
            if arg == "--" or not arg.startswith("-") or arg == "-":
                break
            if arg == "-d" and k + 1 < len(rest):
                setting = rest[k + 1]
            elif arg.startswith("-d") and len(arg) > 2:
                setting = arg[2:]
            else:
                continue
            if setting.split("=", 1)[0].strip().lower() not in _PHP_HARMLESS_SETTINGS:
                return refused("-d")
        return None
    return None


def _unreadable(runner: str, why: str) -> RunnerPlan:
    return RunnerPlan(runner, why_not=f"{why}: it may download code, so it is treated as a "
                                      "command that does - not converted")


def _unwrap(program: str, argv: list[str], depth: int):
    """The plan of the program a wrapper *argv* starts, None when that is no
    runner, :data:`_NO_WRAPPER` when *program* is no wrapper."""
    rest = argv[1:]
    if program == "env":
        return _env(rest, depth)
    if program in _SHELLS:
        if program == "busybox":
            if rest and _program(rest) in _SHELLS:
                return _shell(_program(rest), rest[1:], depth)
            return _runner(rest, depth + 1)
        return _shell(program, rest, depth)
    if program == "cmd":
        return _cmd(rest, depth)
    if program in _POWERSHELLS:
        return _powershell(program, rest, depth)
    if program in _NODES:
        return _node(rest, depth)
    if _PYTHONS.fullmatch(program):
        return _python(program, rest, depth)
    if program in _CODE_INTERPRETERS:
        return _command_option(program, rest) or _code_interpreter(program, rest)
    if program in _PLAIN_PREFIXES:
        return _prefix(program, rest, depth)
    if program in _VALUE_PREFIXES:
        return _value_prefix(rest, depth)
    return _NO_WRAPPER


def _prefix(program: str, rest: list[str], depth: int):
    """``exec x``, ``nohup x``, ``corepack pnpm dlx x``: the rest is the
    command. sudo / doas / corepack options are not read (a runner)."""
    i = 0
    while i < len(rest) and rest[i].startswith("-"):
        if program in ("sudo", "doas", "corepack"):
            return _unreadable(program, f"{program} {M.clean_text(rest[i], 20)} is not "
                                        "understood")
        if rest[i] == "--":
            i += 1
            break
        i += 2 if (program, rest[i]) == ("exec", "-a") else 1
    return _runner(rest[i:], depth + 1)


def _value_prefix(rest: list[str], depth: int):
    """``nice -n 5 x``, ``timeout -k 5 30s x``, ``taskset -c 0 x``, ``xargs
    x``: options (and their values) are skipped, and the command is one of
    the next two words (the first may be a duration, a priority or a mask)."""
    i = 0
    while i < len(rest) and rest[i].startswith("-") and rest[i] != "--":
        i += 2 if rest[i] in _PREFIX_VALUED else 1
    if i < len(rest) and rest[i] == "--":
        i += 1
    tried = 0
    for k in range(i, len(rest)):
        if tried >= 2:
            break
        if rest[k].startswith("-"):
            continue
        tried += 1
        plan = _runner(rest[k:], depth + 1, scan=False)
        if plan is not None:
            return plan
    # Fail closed: a runner anywhere in what follows.
    return _runner(rest[i:], depth + 1) if i < len(rest) else None


def _env(rest: list[str], depth: int):
    assigned: dict[str, str] = {}
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg == "--":
            i += 1
            break
        if arg in _ENV_FLAGS or arg.startswith(("--default-signal", "--ignore-signal",
                                                 "--block-signal", "--list-signal-handling")):
            i += 1
            continue
        if arg in _ENV_VALUED:
            i += 2
            continue
        if arg.startswith(("--unset=", "--chdir=")) or (len(arg) > 2 and arg[:2] in ("-u", "-C")):
            i += 1
            continue
        if arg in ("-S", "--split-string") or arg.startswith(("--split-string=", "-S")):
            text = arg.split("=", 1)[1] if arg.startswith("--split-string=") else (
                arg[2:] if arg.startswith("-S") and len(arg) > 2 else
                (rest[i + 1] if i + 1 < len(rest) else ""))
            skip = 1 if (arg.startswith("--split-string=") or len(arg) > 2 and
                         arg.startswith("-S")) else 2
            words = _shell_words(text)
            if words is None or len(words) != 1:
                return _unreadable("env -S", "the line of env -S cannot be read with certainty")
            return _env(words[0] + rest[i + skip:], depth + 1)
        if arg.startswith("-"):
            return _unreadable("env", f"env option {M.clean_text(arg, 20)} is not understood")
        break
    while i < len(rest) and _ASSIGNMENT.match(rest[i]):
        name, _, value = rest[i].partition("=")
        assigned[name] = value
        i += 1
    if i >= len(rest):
        return None  # env alone prints the environment
    return _with_env(_runner(rest[i:], depth + 1), assigned, "env")


def _with_env(plan, assigned: dict, wrapper: str):
    """*plan* as started by *wrapper*, with the variables it set."""
    if not isinstance(plan, RunnerPlan):
        return plan
    from dataclasses import replace

    env = {k: v for k, v in assigned.items() if M._ENV_NAME.match(k)}
    return replace(plan, runner=f"{wrapper} {plan.runner}"[:80], env={**env, **plan.env})


def _shell(shell: str, rest: list[str], depth: int):
    """``sh -c 'line' …``: the line's commands. Without ``-c`` the shell runs
    a script on disk (None) - or reads its commands from its input, which
    nobody can tell (a runner)."""
    command = False
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg == "--" or arg == "-":
            i += 1
            break
        if arg.startswith("--"):
            if arg in ("--rcfile", "--init-file"):
                i += 1
            i += 1
            continue
        if arg[:1] in ("-", "+") and len(arg) > 1:
            letters = arg[1:]
            if "c" in letters:
                command = True
            if "s" in letters:
                return _unreadable(f"{shell} -s", f"{shell} -s reads its commands from its input")
            i += 1 + sum(letters.count(x) for x in "oO")
            continue
        break
    if not command:
        if i >= len(rest):
            return _unreadable(shell, f"{shell} reads its commands from its input")
        return None  # sh script.sh: a script on disk
    if i >= len(rest):
        return _unreadable(f"{shell} -c", f"{shell} -c names no command")
    return _shell_line(f"{shell} -c", rest[i], depth)


def _shell_line(wrapper: str, text: str, depth: int):
    commands = _shell_words(text)
    if commands is None:
        return _unreadable(wrapper, f"the {wrapper} line cannot be read with certainty")
    found = None
    for words in commands:
        plan = _runner(words, depth + 1)
        if plan is not None:
            found = plan
            break
    if found is None:
        return None
    if len(commands) > 1 and found.convertible:
        from dataclasses import replace

        found = replace(found, why_not=f"{found.runner} is one of several commands of a "
                                       f"{wrapper} line: not converted")
    return _with_env(found, {}, wrapper)


def _shell_words(text: str) -> list[list[str]] | None:
    """The simple commands of a shell line, each as its words; None when
    the line holds what only a shell can resolve (expansions, subshells,
    here-documents, keywords, globs in a program name)."""
    import shlex

    if any(c in text for c in "$`\n\r\\") or "<(" in text or ">(" in text:
        return None
    lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    lexer.commenters = ""
    try:
        tokens = list(lexer)
    except ValueError:
        return None
    commands: list[list[str]] = []
    words: list[str] = []
    skip = False
    for token in tokens:
        if skip:
            skip = False
            continue
        if token and set(token) <= set(";&|"):
            if words:
                commands.append(words)
            words = []
            continue
        if token and set(token) <= set("<>&") and ("<" in token or ">" in token):
            if "<<" in token:
                return None  # a here-document
            skip = True
            continue
        if token and set(token) <= set("()"):
            return None  # a subshell
        if not words and _ASSIGNMENT.match(token):
            continue  # NAME=value before the program
        if not words and (token in _SHELL_KEYWORDS or any(c in token for c in "*?[~{")):
            return None
        words.append(token)
    if skip:
        return None
    if words:
        commands.append(words)
    return commands


def _cmd(rest: list[str], depth: int):
    """``cmd /c npx -y x`` (cmd.exe runs the rest of its line)."""
    for i, arg in enumerate(rest):
        if arg.lower() in ("/c", "/k", "/r"):
            line = " ".join(rest[i + 1:])
            if any(c in line for c in "&|%^<>()!\n"):
                return _unreadable("cmd /c", "the cmd /c line cannot be read with certainty")
            words = _shell_words(line.replace("\\", "/"))
            if words is None or len(words) != 1:
                return _unreadable("cmd /c", "the cmd /c line cannot be read with certainty")
            return _with_env(_runner(words[0], depth + 1), {}, "cmd /c")
        if not arg.startswith("/"):
            break
    return None


def _powershell(shell: str, rest: list[str], depth: int):
    """``pwsh -NoProfile -Command "npx -y x"`` (and a command without
    -Command, which is what PowerShell assumes)."""
    i = 0
    while i < len(rest):
        low = rest[i].lower()
        if low in ("-encodedcommand", "-enc", "-e", "-ec"):
            return _unreadable(shell, f"{shell} -EncodedCommand cannot be read")
        if low in ("-file", "-f"):
            return None  # a script on disk
        if low in ("-command", "-c", "-commandwithargs", "-cwa"):
            i += 1
            break
        if low in _PS_VALUED:
            i += 2
            continue
        if low in _PS_FLAGS:
            i += 1
            continue
        if low.startswith("-"):
            return _unreadable(shell, f"{shell} option {M.clean_text(rest[i], 30)} is not "
                                      "understood")
        break
    line = " ".join(rest[i:])
    if not line.strip():
        return _unreadable(shell, f"{shell} reads its commands from its input")
    if any(c in line for c in "@{}()%&"):
        return _unreadable(f"{shell} -Command", f"the {shell} -Command line cannot be read "
                                                "with certainty")
    return _shell_line(f"{shell} -Command", line.replace("\\", "/"), depth)


def _node(rest: list[str], depth: int):
    """``node [options] …/npx-cli.js -y x``: the script node runs."""
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg == "--":
            i += 1
            break
        if arg in ("-e", "--eval", "-p", "--print") or arg.startswith(("--eval=", "--print=")) \
                or (len(arg) > 2 and arg[0] == "-" and arg[1] != "-" and set(arg[1:]) & set("ep")):
            # -pe / -ep: one-letter options in one word, one of them code.
            return _unreadable("node -e", "node runs code from its command line")
        name, eq, value = arg.partition("=")
        if name in _NODE_MODULE_OPTIONS:
            value = value if eq else (rest[i + 1] if i + 1 < len(rest) else "")
            if _CODE_URL.match(value):
                return _unreadable(f"node {name}", f"node {name} loads code from a "
                                                   "data: or remote URL")
        if arg in _NODE_VALUED:
            i += 2
            continue
        if arg.startswith("-"):
            i += 1
            continue
        break
    if i >= len(rest):
        return None
    script = _program(rest[i:])
    if script in ("npx", "npm", "pnpm", "pnpx", "yarn", "bunx", "corepack"):
        return _with_env(_runner([script, *rest[i + 1:]], depth + 1), {}, "node")
    return None


def _python(program: str, rest: list[str], depth: int):
    """``python [-I…] -m pip|uv|uvx|pipx …``: the module python runs."""
    i = 0
    while i < len(rest):
        arg = rest[i]
        if arg == "-":
            return _unreadable(program, f"{program} - reads its code from its input")
        if arg == "--" or not arg.startswith("-"):
            return None  # a script on disk
        if arg.startswith("--"):
            i += 1
            continue
        letters = arg[1:]
        for at, letter in enumerate(letters):
            if letter == "c":
                return _unreadable(f"{program} -c", f"{program} -c runs code from its "
                                                    "command line")
            if letter == "m":
                module = letters[at + 1:] or (rest[i + 1] if i + 1 < len(rest) else "")
                after = rest[i + 1:] if letters[at + 1:] else rest[i + 2:]
                name = module.split(".", 1)[0].lower()
                if name in ("pip", "uv", "uvx", "pipx", "pip3"):
                    return _with_env(_runner([name, *after], depth + 1), {}, f"{program} -m")
                if name in _PYTHON_TOOL_MODULES:
                    return _unreadable(f"{program} -m {name}", f"{program} -m {name} is a "
                                                               "package tool")
                return None
            if letter in ("X", "W", "Q"):
                if not letters[at + 1:]:
                    i += 1  # the value is the next word
                break
        i += 1
    return None


def _code_interpreter(program: str, rest: list[str]):
    """``perl -e '…'``, ``ruby -e``, ``php -r`` …: code on the command line
    is a runner that cannot be converted (it may start anything); a script
    on disk is not."""
    flags, code_letters, value_letters = _CODE_INTERPRETERS[program]
    digit_letters = _DIGIT_LETTERS.get(program, "")
    for arg in rest:
        if arg == "--" or not arg.startswith("-") or arg == "-":
            break
        name = arg.split("=", 1)[0]
        if name in flags:
            return _unreadable(f"{program} {name}", f"{program} {name} runs code from its "
                                                    "command line")
        if arg.startswith("--") or not code_letters:
            continue
        letters = arg[1:]
        at = 0
        while at < len(letters):
            letter = letters[at]
            at += 1
            if letter in code_letters:
                return _unreadable(f"{program} -{letter}", f"{program} -{letter} runs code "
                                                           "from its command line")
            if letter in digit_letters:
                if letter == "d" and letters[at:at + 1] == ":":
                    break  # perl -d:Module
                if letter == "d" and letters[at:at + 1] == "t":
                    at += 1
                    continue
                if letter == "0" and letters[at:at + 1] in ("x", "X"):
                    at += 1  # perl -0xHHH: hexadecimal digits
                    while at < len(letters) and letters[at] in "0123456789abcdefABCDEF":
                        at += 1
                while at < len(letters) and letters[at].isdigit():
                    at += 1
                continue
            if letter in value_letters:
                break  # the rest of the cluster is this option's value
    return None


def _scan(program: str, words: list[str], depth: int):
    """Fail closed: the plan of the first word of *words* (the arguments of
    a program that is no known runner) that names a runner or a downloader,
    an interpreter with options, or that is a command line of its own
    (``strace -f npx x``, ``xvfb-run python3 -c …``, ``script -qc "npx x"``,
    ``--exec=npx``). None when no word does."""
    for k, word in enumerate(words):
        if _LINE_MARKS.search(word):
            commands = _shell_words(word)
            if commands is not None:
                plan = _shell_line(program, word, depth)
                if plan is None and any(_embedded_runner(w) for c in commands for w in c):
                    # socat STDIO "EXEC:npx -y x": a runner inside a word of the line
                    plan = _unreadable(program, f"an argument of {program} names a runner "
                                                "inside a word")
            else:
                # A line only a shell can read: any runner name in it counts.
                bare = word.replace("'", "").replace('"', "").replace("\\", "")
                names = {_program([t]) for t in re.split(r"[\s;&|()<>$`{}=,:]+", bare) if t}
                plan = (_unreadable(program, f"an argument of {program} is a command line "
                                             "that cannot be read with certainty")
                        if names & _RUNNER_NAMES else None)
            if plan is not None:
                return plan
            continue
        name = _program([word.rsplit("=", 1)[-1]]) if word.startswith("-") else _program([word])
        if name in _RUNNER_NAMES:
            start = [word.rsplit("=", 1)[-1]] if word.startswith("-") else [word]
            # The runner's own parse has scanned the words after it.
            return _with_env(_runner([*start, *words[k + 1:]], depth + 1), {}, program)
        embedded = _embedded_runner(word)
        if embedded:
            # EXEC:npx, --opt=x,uvx: a runner inside a word.
            return _unreadable(program, f"an argument of {program} names {embedded} inside "
                                        "a word")
        if (name in _SHELLS or name in _POWERSHELLS or name in _NODES or name == "cmd"
                or name in _CODE_INTERPRETERS or _PYTHONS.fullmatch(name)) and \
                k + 1 < len(words) and words[k + 1][:1] in ("-", "/"):
            return _with_env(_runner(words[k:], depth + 1), {}, program)
    return None


def _embedded_runner(word: str) -> str:
    """The runner a word names in one of its ``=`` / ``:`` / ``,`` parts
    (``EXEC:npx``, ``cmd=uvx``), "" when none does."""
    if not any(c in word for c in "=:,"):
        return ""
    for piece in re.split(r"[=:,]", word):
        name = _program([piece.strip()]) if piece.strip() else ""
        if name in _RUNNER_NAMES:
            return name
    return ""


def downloading_runner(argv) -> RunnerPlan | None:
    """A :class:`RunnerPlan` when *argv* starts a runner that downloads code
    (npx, bunx, pnpx, ``npm exec``, ``pnpm dlx``, ``yarn dlx``, ``bun x``,
    uvx, ``uv tool run``, ``uv run``, ``pipx run``, ``docker``/``podman``/
    ``nerdctl run``, deno, ``go run``); None for any other program.

    A runner is found behind what only starts it: ``env`` (its options and
    ``NAME=value`` words), a shell's ``-c`` line (``sh``, ``bash``, ``zsh``,
    ``dash``, ``ksh``, ``ash``; ``cmd /c``, PowerShell ``-Command``),
    ``exec`` / ``nohup`` / ``nice`` / ``timeout`` and the like, ``node``
    running npm's ``npx-cli.js`` / ``npm-cli.js``, ``python -m
    pip|uv|uvx|pipx`` and ``corepack``. A wrapper whose line cannot be read
    with certainty (a shell line with ``$``, backquotes, a subshell or a
    keyword, an unknown ``env`` option) counts as a runner that cannot be
    converted: it never runs on the host.

    It fails closed: behind any other program, a word that names a runner
    or a downloader (``strace -f npx x``, ``script -qc "npx x"``,
    ``--exec=npx``) still makes a runner, and so do ``nix``, ``pixi``,
    ``pkgx``, ``dnx`` and an interpreter with code on its line (``python
    -c``, ``python -``, ``node -e``, ``perl -e``, ``ruby -e``, ``php -r``)."""
    return _runner([str(a) for a in (argv or ())], 0)


def _runner(argv: list[str], depth: int, scan: bool = True) -> RunnerPlan | None:
    if not argv:
        return None
    program = _program(argv)
    if depth > _MAX_DEPTH:
        return RunnerPlan(program or "?", why_not="wrapped too deeply to be read: not converted")
    plan = _direct(program, argv, depth)
    if plan is None and scan:
        plan = _scan(program, argv[1:], depth)
    return plan


def _direct(program: str, argv: list[str], depth: int) -> RunnerPlan | None:
    """The plan of *argv* read by its program alone (None: not a runner by
    what its program is - its words are scanned after that)."""
    wrapped = _unwrap(program, argv, depth)
    if wrapped is not _NO_WRAPPER:
        return wrapped
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
    if program in ("docker", "podman", "nerdctl") and argv[1:3] == ["container", "run"]:
        return _oci(f"{program} run", argv[3:])
    if program in ("docker", "podman", "nerdctl") and sub.startswith("-"):
        return RunnerPlan(program, why_not=f"{program} options before its command are not "
                                           "understood: not converted")
    if program == "docker-compose" or (program in ("docker", "podman", "nerdctl")
                                       and sub == "compose"):
        return RunnerPlan("docker-compose" if program == "docker-compose" else f"{program} compose",
                          why_not="compose pulls the images of its file: not converted")
    if program == "uv" and sub == "run":
        return RunnerPlan("uv run", why_not="uv run installs the packages a script asks for: "
                                            "not converted")
    if program in ("uv", "pipx", "pip", "pip3"):
        # uv --quiet tool run x, uv pip install, pipx install, pip install …
        return RunnerPlan(f"{program} {M.clean_text(sub, 20)}".strip(),
                          why_not=f"{program} {M.clean_text(sub, 20)} may install packages: "
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
    if program in ("nix", "nix-shell", "nix-env", "nix-build", "nix-store"):
        return RunnerPlan(f"{program} {M.clean_text(sub, 20)}".strip(),
                          why_not=f"{program} fetches and builds what it runs: not converted")
    if program in ("pixi", "pkgx", "dnx"):
        return RunnerPlan(f"{program} {M.clean_text(sub, 20)}".strip(),
                          why_not=f"{program} fetches the packages it runs: not converted")
    if program in _DOWNLOADERS:
        return RunnerPlan(program, why_not=f"{program} downloads files: a line with it may run "
                                           "what it fetched - not converted")
    if program == "dotnet" and sub.lower().endswith(".dll") and not sub.startswith("-"):
        return None  # dotnet server.dll: an assembly on disk
    if program in _PACKAGE_TOOLS:
        return RunnerPlan(f"{program} {M.clean_text(sub, 20)}".strip(),
                          why_not=f"{program} fetches or installs what it runs: not converted")
    return _command_option(program, rest)


#: The server name in a container's --name / --label (core.mcp_client's names).
_CONTAINER_SERVER = r"[A-Za-z0-9_-]{1,32}"


def _volume_problem(value: str) -> str:
    """Why ``--volume=VALUE`` is not one of run_command's folders ("" = it
    is): ``HOST:TARGET:ro|rw``, both absolute and normalized, the host
    folder never the whole file system (core.mcp_install.choice_problems
    takes no other at install)."""
    import posixpath

    parts = value.split(":")
    if len(parts) != 3 or parts[2] not in ("ro", "rw"):
        return "a folder as HOST:TARGET:ro or :rw"
    host, target, _mode = parts
    for path in (host, target):
        if not path.startswith("/") or posixpath.normpath(path) != path or "," in path \
                or any(ord(c) < 32 or c == "\x7f" for c in path):
            return "absolute, normalized folders"
    if host == "/":
        return "never the whole file system (/)"
    if target == "/":
        return "never over the container's root"
    return ""


def container_flag_problems(argv) -> list[str]:
    """Why *argv* is not the podman line of a container server ([] = it is).
    An allow-list: only the shape core.mcp_install.run_command writes -
    ``podman run`` (no options before ``run``), every one of RUN_FLAGS, its
    ``--name`` / ``--label`` / ``--env-file``, ``--network=none`` or the
    allowlist network (or none: full network, chosen at install),
    ``--user=0:0`` and ``--volume=HOST:TARGET:ro|rw``; each option one
    ``--opt=value`` word (a spaced value, combined short options or any
    other option is refused); then the image and the server's arguments. A
    settings file edited by hand is checked the same way."""
    import posixpath

    from core.mcp_client import TOKEN_ENV_FD, TOKEN_RUN
    from core.mcp_install import ALLOWLIST_NETWORK, RUN_FLAGS

    argv = [str(a) for a in (argv or ())]
    program = argv[0] if argv else ""
    if posixpath.basename(program) != "podman" or ("/" in program and not program.startswith("/")):
        return ["a container server runs only on the podman line axross writes "
                "(Install in a Container)"]
    if len(argv) < 2 or argv[1] != "run":
        return [f"podman options before run are not allowed "
                f"({M.clean_text(argv[1] if len(argv) > 1 else '', 60)})"]
    out: list[str] = []
    seen: dict[str, int] = {}
    image = None
    names = {"--name": "", "--label": ""}
    for arg in argv[2:]:
        if not arg.startswith("-"):
            image = arg
            break  # the image: what follows are the server's arguments
        flag, eq, value = arg.partition("=")
        key = arg if arg in RUN_FLAGS else flag
        seen[key] = seen.get(key, 0) + 1
        problem = ""
        if arg in RUN_FLAGS:
            pass
        elif not eq or not flag.startswith("--"):
            problem = "not an option axross writes (each is one --option=value word)"
        elif flag == "--name":
            m = re.fullmatch(rf"axross-mcp-({_CONTAINER_SERVER})-{re.escape(TOKEN_RUN)}", value)
            names["--name"] = m.group(1) if m else ""
            problem = "" if m else "not the name axross gives"
        elif flag == "--label":
            m = re.fullmatch(rf"io\.axross\.mcp=({_CONTAINER_SERVER})", value)
            names["--label"] = m.group(1) if m else ""
            problem = "" if m else "not the label axross gives"
        elif flag == "--env-file":
            problem = "" if value == f"/dev/fd/{TOKEN_ENV_FD}" else "only axross's environment pipe"
        elif flag == "--network":
            problem = "" if arg in ("--network=none", ALLOWLIST_NETWORK) else "only none or the allowlist"
        elif flag == "--user":
            problem = "" if value == "0:0" else "only 0:0 (the user's own id in rootless podman)"
        elif flag == "--volume":
            problem = _volume_problem(value)
        else:
            problem = "not an option axross writes"
        if problem:
            out.append(f"the container option {M.clean_text(arg, 60)} is not allowed: {problem}")
    for key, count in seen.items():
        if count > 1 and key != "--volume":
            out.append(f"the container option {M.clean_text(key, 60)} is given {count} times")
    missing = [f for f in RUN_FLAGS if f not in seen]
    missing += [f for f in ("--name", "--label", "--env-file") if f not in seen]
    if missing:
        out.append("the container line lacks " + ", ".join(missing))
    elif names["--name"] and names["--label"] and names["--name"] != names["--label"]:
        out.append("the container's name and label differ")
    if image is None:
        out.append("the container line names no image")
    return out
