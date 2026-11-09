"""Places under the home folder the agent never writes, moves or deletes.

Changed, they run code or widen the agent's rights with no prompt: its own
settings and MCP servers, its caches of code it runs (compiled extension
code, downloaded updates, MCP server discovery: ``~/.cache/axross``), shell
and session start files, autostart entries, user services, commands on
PATH, Python start hooks, Git and pip settings, SSH and GnuPG keys.
core.mcp_server refuses tool writes there whatever the root, and
core.agent_sandbox mounts them read-only - the missing ones too, so that an
agent cannot create them (how: see that module).

Places under ``~/.config``, ``~/.local/share``, ``~/.local/state`` and
``~/.cache`` are also protected where ``$XDG_CONFIG_HOME``,
``$XDG_DATA_HOME``, ``$XDG_STATE_HOME`` and ``$XDG_CACHE_HOME`` move them
(both locations count).

Every platform's places count on every platform (:data:`MACOS_DIRS`,
:data:`WINDOWS_DIRS`, ...; inert where they mean nothing). Computed at
check time: the home's folders on PATH and its site-packages on sys.path
(:func:`_dynamic_dirs`), and the XDG folders the user's session sets even
when this process lacks the variables (:func:`remember_xdg`, the shell and
session files). A Python start file (``*.pth``, ``sitecustomize.py``) is
refused wherever it is.

A path names a place when it is the place or lies inside it, compared
component by component (Windows separators included), case-insensitively
where the file system usually is (Windows, macOS), and also through each
place's resolved path (a symlink at ``~/.config`` would otherwise lead
around ``~/.config/autostart``).

Inside the agent sandbox HOME is ``/tmp`` while the host's home is mounted
at its own path: the sandbox passes that path in :data:`HOST_HOME_ENV`.

The read side is a list of its own (:data:`SECRET_DIRS` and the ones after
it, :func:`read_refusal`): secret files whose contents no tool hands out -
axross's tokens and keys, SSH and GnuPG private keys. Their names may be
listed; the write list above is not changed by it.
"""

from __future__ import annotations

import os
import sys

#: Folders (relative to the home folder, "/"-separated).
HOME_DIRS = (
    ".config/axross", ".local/share/axross", ".local/state/axross",
    # code axross runs from its cache: compiled extensions (core.extension_code_cache),
    # updates (update/) and MCP server discovery (mcp-discover/)
    ".cache/axross",
    ".config/autostart", ".config/autostart-scripts", ".config/systemd",
    ".config/environment.d", ".config/fish",
    ".config/plasma-workspace", ".config/git", ".config/pip", ".config/containers",
    ".ssh", ".gnupg", ".local/share/applications",
    # user services and D-Bus activation (both start programs on demand)
    ".local/share/systemd/user", ".local/share/dbus-1/services",
    # commands on PATH and the user site-packages (a .pth file runs at every Python start)
    ".local/bin", ".local/lib",
    # shell, editor and window-manager start code
    ".bashrc.d", ".oh-my-zsh", ".vim", ".config/nvim",
    ".config/i3", ".config/sway", ".config/hypr", ".ipython",
    # other agents' and editors' settings: their MCP servers and hooks run code
    ".claude", ".config/Claude", ".cursor", ".config/Code/User", ".vscode/extensions",
    # container CLI plugins and credential helpers
    ".docker",
    # more commands on PATH: ~/bin (Debian's ~/.profile adds it once it
    # exists), language tool chains, and the pipx / uv tool venvs (axross
    # itself, installed with pipx; their site-packages run .pth files)
    "bin", ".cargo/bin", "go/bin", ".deno/bin", ".bun/bin", ".npm-global/bin", ".pyenv/shims",
    ".local/share/pipx", ".local/pipx", ".local/share/uv/tools",
    # more editors, terminal multiplexers and window managers that run code at start
    ".config/tmux", ".emacs.d", ".config/emacs", ".config/openbox", ".config/lxsession",
    ".config/awesome", ".config/bspwm", ".config/sxhkd", ".config/qtile",
    ".config/herbstluftwm", ".xmonad", ".config/xmonad", ".config/labwc", ".config/river",
    ".config/niri", ".kde/Autostart", ".kde4/Autostart", ".config/upstart",
    # file-manager actions (a menu entry runs the command it names)
    ".local/share/kio/servicemenus", ".local/share/kservices5/ServiceMenus",
    ".local/share/nautilus/scripts",
)
#: Files (relative to the home folder).
HOME_FILES = (
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".bash_aliases", ".profile",
    ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout", ".xprofile", ".xsession",
    ".xsessionrc", ".xinitrc", ".pam_environment", ".inputrc", ".gitconfig", ".pip/pip.conf",
    ".vimrc", ".npmrc", ".claude.json",
    ".tmux.conf", ".emacs", ".emacs.el", ".gvimrc", ".exrc", ".screenrc", ".gdbinit",
    ".xbindkeysrc", ".mailcap", ".config/mimeapps.list", ".config/wayfire.ini",
)
#: macOS (relative to the home folder): launchd agents, login items, axross's
#: own folders and preferences, the user site-packages, other agents' settings.
MACOS_DIRS = (
    "Library/LaunchAgents", "Library/LaunchDaemons", "Library/Application Support/axross",
    "Library/Application Support/com.apple.backgroundtaskmanagementagent",
    "Library/Application Support/Claude", "Library/Application Support/Code/User",
    "Library/Python", "Library/Services",
)
MACOS_FILES = (
    "Library/Preferences/com.axross.Axross.plist",
    "Library/Preferences/com.apple.loginitems.plist",
)
#: Windows (relative to the home folder): the Startup folder, PowerShell
#: profiles (Documents may be moved into OneDrive), axross's own folders,
#: the user site-packages, commands on PATH, other agents' settings.
WINDOWS_DIRS = (
    "AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup",
    "AppData/Roaming/axross", "AppData/Local/axross",
    "Documents/PowerShell", "Documents/WindowsPowerShell",
    "OneDrive/Documents/PowerShell", "OneDrive/Documents/WindowsPowerShell",
    "AppData/Roaming/Python", "AppData/Local/Microsoft/WindowsApps",
    "AppData/Roaming/Claude", "AppData/Roaming/Code/User",
)
WINDOWS_FILES: tuple[str, ...] = ()
#: ``(variable, folders below it)``: where Windows' own variables move them.
WINDOWS_ENV_DIRS = (
    ("APPDATA", ("Microsoft/Windows/Start Menu/Programs/Startup", "axross", "Python",
                 "Claude", "Code/User")),
    ("LOCALAPPDATA", ("axross", "Microsoft/WindowsApps")),
)
#: File names Python runs at start wherever they lie in a site folder: no
#: tool writes them anywhere (a site folder outside the lists - a venv -
#: is not known here).
START_NAMES = ("*.pth", "sitecustomize.py", "usercustomize.py")
#: Names of the folders whose .pth files Python runs (found on sys.path).
SITE_DIR_NAMES = ("site-packages", "dist-packages")
#: Default-deny for writes: besides the places above, no tool changes a
#: hidden entry directly in a home folder (``~/.pdbrc``, ``~/.wezterm.lua``,
#: ``~/.aliases``, ``~/.jupyter``, ...) or any entry of the folders below
#: (``~/.config/kitty``, ``~/.local/share/gnome-shell``, ...) - too many
#: programs run code from there to list them all. A folder there that the
#: user grants explicitly (the MCP root, a folder of the agent) is writable
#: below it (the places above stay protected): :func:`refusal` *granted*.
DENY_ALL_BELOW = (".config", ".local/share", ".local/state",
                  # snap packages' own homes (~/snap/<app>/<revision>/.config, ...)
                  "snap")
#: The same for macOS (all of ~/Library) and Windows (%APPDATA%).
MACOS_DENY_ALL_BELOW = ("Library",)
WINDOWS_DENY_ALL_BELOW = ("AppData/Roaming",)
#: Default-deny for reads (core.mcp_server, the agent's tools): the contents
#: of a hidden entry of a home folder (``~/.config/<app>``, ``~/.mozilla``,
#: ``~/.local/share/TelegramDesktop``) and of ``~/snap`` (the snap packages'
#: homes: Firefox and Chromium profiles) are not handed out unless they lie
#: in a folder the user granted (the MCP root or an extra folder inside such
#: a place) - too many programs keep sessions, tokens and keys there to list
#: them all. Names stay listable; the user's other files are read as before.
READ_DENY_ALL_BELOW = ("snap",)
#: Hidden entries of the home folder that writes may change anyway
#: (reviewed: nothing runs code from them). Compared case-folded.
HIDDEN_WRITABLE: tuple[str, ...] = ()
#: Git runs code from these wherever a repository is (hooks, ``core.fsmonitor``,
#: ``core.pager`` and filters in the config, submodule URLs): refused anywhere.
#: Names below a Git folder; a ``.git`` entry itself (a folder or a
#: ``gitdir:`` file) is refused too, or a folder renamed to ``.git`` brings
#: a config along. ``commondir`` and ``gitdir`` point Git at another folder
#: whose config and hooks it then uses. A Git folder is any ``.git`` folder,
#: any ``*.git`` folder (a bare repository) and any folder Git would take for
#: one (:data:`GIT_SHAPE`: ``HEAD``, ``objects/`` and ``refs/`` - Git finds a
#: bare repository by its shape when a shell's prompt runs ``git status`` in it).
GIT_DIR = ".git"
GIT_CODE_NAMES = ("config", "config.worktree", "hooks", "info", "commondir", "gitdir")
GIT_TREE_NAMES = (".gitmodules",)
#: What makes a folder a Git folder to Git: a ``HEAD`` file and the folders
#: ``objects`` and ``refs``. No tool creates the last of them in a folder
#: that is not one yet (a folder of the project made into a repository Git
#: finds before the real one).
GIT_SHAPE = ("HEAD", "objects", "refs")
#: Mercurial and Jujutsu: ``(folder, paths directly below it)`` that run code
#: or point at a folder whose settings do (``.hg/hgrc`` hooks,
#: ``.hg/sharedpath``, ``.jj/repo`` - a file in a workspace -, and
#: ``.jj/repo/config.toml``).
VCS_CODE = ((".hg", (("hgrc",), ("sharedpath",))),
            (".jj", (("repo",), ("repo", "config.toml"))))
#: axross's trash folder (core.trash): no tool writes there wherever it is
#: (a planted entry is restored by the user with axross's rights), and its
#: contents are secret (a trashed key is still a key).
TRASH_NAME = ".axross-trash"
#: zsh's start files, also in ``$ZDOTDIR`` (set in ``~/.zshenv``, often
#: ``~/.config/zsh``): protected there too.
ZSH_FILES = (".zshenv", ".zprofile", ".zshrc", ".zlogin", ".zlogout")
#: Where ZDOTDIR is commonly set, besides each home's ``.zshenv``.
ZDOTDIR_SYSTEM_FILES = ("/etc/zsh/zshenv", "/etc/zshenv")
#: Where axross remembers the XDG folders it ran with (below the default
#: ``~/.config/axross``, a protected place wherever XDG points): an MCP
#: server started without the user's XDG variables (by a desktop client)
#: still protects them (:func:`remember_xdg`).
XDG_RECORD = ".config/axross/xdg-locations.json"
#: Shell and session files the XDG variables are commonly set in: read
#: (line by line, ``XDG_..._HOME=value`` anywhere in a line, fish's
#: ``set -gx XDG_..._HOME value``) for the same reason. A folder: its files
#: with the suffix of :data:`XDG_PROFILE_DIRS`.
XDG_PROFILE_FILES = (".profile", ".bash_profile", ".bash_login", ".bashrc", ".zshenv",
                     ".zprofile", ".zshrc", ".zlogin", ".xprofile", ".xsessionrc", ".xsession",
                     ".xinitrc", ".pam_environment", ".config/environment.d",
                     ".config/plasma-workspace/env", ".config/fish/config.fish",
                     ".config/fish/conf.d")
#: ``folder -> file suffix`` read in the folders of :data:`XDG_PROFILE_FILES`.
XDG_PROFILE_DIRS = {".config/environment.d": ".conf", ".config/plasma-workspace/env": ".sh",
                    ".config/fish/conf.d": ".fish"}
#: The PATH of the host (its entries in the home folder), for the worker
#: in the agent sandbox, whose PATH is the sandbox's.
HOST_PATH_ENV = "AXROSS_AGENT_HOST_PATH"
#: The host's home folder, set by core.agent_sandbox for the worker.
HOST_HOME_ENV = "AXROSS_AGENT_HOST_HOME"
#: ``(home-relative prefix, XDG variable, variable naming the host's value
#: in the agent sandbox)``: where XDG moves the places below the prefix.
XDG_PLACES = (
    (".config", "XDG_CONFIG_HOME", "AXROSS_AGENT_HOST_XDG_CONFIG_HOME"),
    (".local/share", "XDG_DATA_HOME", "AXROSS_AGENT_HOST_XDG_DATA_HOME"),
    (".local/state", "XDG_STATE_HOME", "AXROSS_AGENT_HOST_XDG_STATE_HOME"),
    (".cache", "XDG_CACHE_HOME", "AXROSS_AGENT_HOST_XDG_CACHE_HOME"),
)

def _case_insensitive() -> bool:
    return sys.platform in ("win32", "darwin")


def _windows_names() -> bool:
    return sys.platform == "win32"


def _key(path: str) -> tuple[str, ...]:
    """*path* as comparable components: normcase, casefolded where names
    are case-insensitive, NFC (macOS stores names decomposed), and on
    Windows without what the OS drops when it opens a name - trailing dots
    and spaces (``.claude.json.`` is ``.claude.json``) and an alternate
    data stream (``name:stream``)."""
    import unicodedata

    text = unicodedata.normalize("NFC", os.path.normcase(os.path.abspath(path)))
    if _case_insensitive():
        text = text.casefold()
    parts = [part for part in text.replace("\\", "/").split("/") if part]
    if _windows_names():
        cleaned = []
        for i, part in enumerate(parts):
            if i > 0 and ":" in part:  # the first part is the drive ("c:")
                part = part.split(":", 1)[0]
            cleaned.append(part.rstrip(". ") or part)
        parts = cleaned
    return tuple(parts)


def _resolver():
    """``os.path.realpath`` for many absolute paths that share folders: each
    folder on the way is looked at once (``lstat``), and only a symlink is
    resolved with realpath. A new one per check (nothing is kept across
    tool calls)."""
    memo: dict[str, str] = {}

    def real(path: str) -> str:
        path = os.path.abspath(path)
        done = memo.get(path)
        if done is not None:
            return done
        parent, name = os.path.split(path)
        if parent == path or not name:
            memo[path] = path
            return path
        joined = os.path.join(real(parent), name)
        if os.path.islink(joined):
            joined = os.path.realpath(joined)
        memo[path] = joined
        return joined

    return real


def homes(environ=os.environ) -> list[str]:
    """The home folders to protect: this process's, and the host's when
    running in the agent sandbox."""
    found = [os.path.expanduser("~"), environ.get(HOST_HOME_ENV, "")]
    out: list[str] = []
    for home in found:
        if home and os.path.isabs(home):
            for variant in (os.path.abspath(home), os.path.realpath(home)):
                if variant not in out:
                    out.append(variant)
    return out


def places(home: str) -> list[str]:
    """Every protected place of *home*, as typed and as resolved."""
    out: list[str] = []
    for rel in HOME_DIRS + HOME_FILES:
        place = os.path.join(home, *rel.split("/"))
        for variant in (place, os.path.realpath(place)):
            if variant not in out:
                out.append(variant)
    return out


def _home_rel(home: str, rel: str) -> str:
    return os.path.join(home, *rel.split("/"))


def _inside_key(inner: tuple[str, ...], outer: tuple[str, ...]) -> bool:
    """Whether the key *inner* lies strictly below *outer*."""
    return len(inner) > len(outer) and inner[:len(outer)] == outer


#: ``path -> ((mtime_ns, size), {variable: [values]})``: profile files read.
_PROFILE_CACHE: dict[str, tuple[tuple[int, int], dict[str, list[str]]]] = {}
_XDG_VARS = tuple(var for _prefix, var, _host in XDG_PLACES)


def _xdg_owner_names(home: str) -> list[str]:
    """The user names ``$USER`` / ``$LOGNAME`` may stand for in *home*'s
    files: the folder's owner and its name."""
    names = [os.path.basename(os.path.normpath(home))]
    try:
        import pwd

        names.insert(0, pwd.getpwuid(os.stat(home).st_uid).pw_name)
    except (ImportError, KeyError, OSError):
        pass
    return [n for i, n in enumerate(names) if n and n not in names[:i]]


def _xdg_expand(value: str, home: str) -> list[str]:
    """The absolute folders a profile's raw *value* names: quotes removed,
    ``${XDG_..:-default}`` as its default, ``$HOME`` / ``~`` / ``@{HOME}``
    and ``$USER`` / ``$LOGNAME`` replaced (each user name the home may
    belong to). Another variable or a relative path names nothing (the XDG
    spec ignores those)."""
    import re

    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    value = value.replace('"', "").replace("'", "")
    value = re.sub(r"\$\{XDG_(?:CONFIG|DATA|STATE|CACHE)_HOME:?[-=]([^}]*)\}", r"\1", value)
    for token in ("${HOME}", "$HOME", "@{HOME}"):
        value = value.replace(token, home)
    if value == "~" or value.startswith("~/"):
        value = home + value[1:]
    out: list[str] = []
    user_var = r"\$\{?(?:USER|LOGNAME)\b\}?"
    texts = [value]
    if re.search(user_var, value):
        texts = [re.sub(user_var, user, value) for user in _xdg_owner_names(home)]
        # "/home/$USER/x": the folder named after the user is the home folder
        texts.append(re.sub(r"^/[^$]*?/" + user_var, lambda _m: home, value))
    for text in texts:
        if "$" in text or "`" in text or not os.path.isabs(text):
            continue
        text = os.path.normpath(text)
        if text not in out:
            out.append(text)
    return out


#: An assignment anywhere in a line (``export A=1 XDG_CONFIG_HOME=~/x``,
#: ``[ -z ... ] && export XDG_DATA_HOME="$HOME/d"``, pam's ``VAR DEFAULT=``)
#: and fish's ``set -gx XDG_CONFIG_HOME ~/x``.
_XDG_ASSIGN = None
_XDG_FISH = None


def _profile_values(path: str, home: str) -> dict[str, list[str]]:
    """The absolute XDG folders *path* (a shell or session file) sets."""
    global _XDG_ASSIGN, _XDG_FISH
    import re

    try:
        st = os.stat(path)
    except OSError:
        return {}
    stamp = (st.st_mtime_ns, st.st_size)
    cached = _PROFILE_CACHE.get(path)
    if cached is not None and cached[0] == stamp:
        return cached[1]
    if _XDG_ASSIGN is None:
        value = r"((?:\"[^\"]*\"|'[^']*'|\$\{[^}\s]*\}|[^\s;&|#'\"])+)"
        _XDG_ASSIGN = re.compile(r"(?<![\w${])(XDG_(?:CONFIG|DATA|STATE|CACHE)_HOME)"
                                 r"(?:\s+(?:DEFAULT|OVERRIDE))?\s*=\s*" + value)
        _XDG_FISH = re.compile(r"\bset\s+(?:-{1,2}[A-Za-z]+\s+)*"
                               r"(XDG_(?:CONFIG|DATA|STATE|CACHE)_HOME)\s+" + value)
    found: dict[str, list[str]] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read(256 * 1024)
    except OSError:
        text = ""
    for line in text.splitlines():
        if "XDG_" not in line:
            continue
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        for pattern in (_XDG_ASSIGN, _XDG_FISH):
            for match in pattern.finditer(line):
                for folder in _xdg_expand(match.group(2), home):
                    values = found.setdefault(match.group(1), [])
                    if folder not in values:
                        values.append(folder)
    _PROFILE_CACHE[path] = (stamp, found)
    return found


def _recorded_xdg(home: str) -> dict[str, list[str]]:
    """The XDG folders axross ran with (:func:`remember_xdg`) and the ones
    *home*'s shell and session files set."""
    import json

    out: dict[str, list[str]] = {}

    def add(var: str, values) -> None:
        if var not in _XDG_VARS or not isinstance(values, list):
            return
        for value in values[:16]:
            if isinstance(value, str) and os.path.isabs(value):
                out.setdefault(var, []).append(value)

    try:
        with open(_home_rel(home, XDG_RECORD), encoding="utf-8") as fh:
            data = json.loads(fh.read(64 * 1024))
    except (OSError, ValueError, RecursionError):
        data = None
    if isinstance(data, dict):
        for var, values in data.items():
            add(var, values)
    files = []
    for rel in XDG_PROFILE_FILES:
        path = _home_rel(home, rel)
        if os.path.isdir(path):
            suffix = XDG_PROFILE_DIRS.get(rel, ".conf")
            try:
                files += sorted(os.path.join(path, n) for n in os.listdir(path)
                                if n.endswith(suffix))[:64]
            except OSError:
                pass
        else:
            files.append(path)
    for path in files:
        for var, values in _profile_values(path, home).items():
            add(var, values)
    return out


def remember_xdg(environ=os.environ) -> None:
    """Record this process's XDG folders below the home folder
    (:data:`XDG_RECORD`), so that an MCP server started without them still
    protects the places they move. Called by the GUI at start; never raises."""
    import json
    import tempfile

    try:
        home = os.path.expanduser("~")
        if not os.path.isabs(home):
            return
        path = _home_rel(home, XDG_RECORD)
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.loads(fh.read(64 * 1024))
        except (OSError, ValueError, RecursionError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        before = json.dumps(data, sort_keys=True)
        for var in _XDG_VARS:
            value = environ.get(var, "")
            if not value or not os.path.isabs(value):
                continue
            value = os.path.abspath(value)
            known = [v for v in data.get(var, []) if isinstance(v, str) and v != value]
            data[var] = [value, *known][:4]
        if json.dumps(data, sort_keys=True) == before:
            return
        folder = os.path.dirname(path)
        os.makedirs(folder, mode=0o700, exist_ok=True)
        fd, tmp = tempfile.mkstemp(prefix=".xdg-locations-", dir=folder)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(data, fh, indent=1, sort_keys=True)
            os.replace(tmp, path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    except Exception:  # noqa: BLE001 - a missing record only loses the extra protection
        import logging

        logging.getLogger(__name__).debug("remember_xdg failed", exc_info=True)


def _xdg_bases(environ) -> list[tuple[str, str]]:
    """``(home-relative prefix, folder)`` of every XDG location set to an
    absolute path - this process's and, in the agent sandbox, the host's;
    also the ones axross ran with and the user's shell and session files set
    (an MCP server started by a desktop client may lack the variables)."""
    out: list[tuple[str, str]] = []
    recorded = [_recorded_xdg(home) for home in homes(environ)]
    for prefix, var, host_var in XDG_PLACES:
        values = [environ.get(var, ""), environ.get(host_var, "")]
        for found in recorded:
            values += found.get(var, [])
        for value in values:
            if value and os.path.isabs(value):
                base = (prefix, os.path.abspath(value))
                if base not in out:
                    out.append(base)
    return out


#: ``path -> ((mtime_ns, size), [raw values])``: ZDOTDIR lines read.
_ZDOT_CACHE: dict[str, tuple[tuple[int, int], list[str]]] = {}


def _zdotdir_lines(path: str) -> list[str]:
    """The raw values of the ``ZDOTDIR=...`` lines of *path* (cached by
    modification time and size)."""
    import re

    try:
        st = os.stat(path)
    except OSError:
        return []
    stamp = (st.st_mtime_ns, st.st_size)
    cached = _ZDOT_CACHE.get(path)
    if cached is not None and cached[0] == stamp:
        return cached[1]
    found: list[str] = []
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read(256 * 1024)
    except OSError:
        text = ""
    line_re = re.compile(r"\s*(?:export\s+)?ZDOTDIR\s*=\s*(\S+?)\s*;?\s*(?:#.*)?")
    for line in text.splitlines():
        match = line_re.fullmatch(line)
        if match:
            found.append(match.group(1).strip("'\""))
    _ZDOT_CACHE[path] = (stamp, found[:16])
    return found[:16]


def _expand_zdotdir(value: str, home: str, config_dirs: list[str]) -> list[str]:
    """The absolute folders *value* (a ZDOTDIR line's value) may name: with
    ``$HOME`` / ``~`` replaced and ``$XDG_CONFIG_HOME`` (or
    ``${XDG_CONFIG_HOME:-default}``) as each of *config_dirs* and the default."""
    import re

    xdg = re.compile(r"\$\{XDG_CONFIG_HOME(?::?-([^}]*))?\}|\$XDG_CONFIG_HOME\b")
    out: list[str] = []
    for config in config_dirs:
        text = xdg.sub(lambda m: m.group(1) if m.group(1) is not None and config == "" else
                       (config or os.path.join(home, ".config")), value)
        for token in ("${HOME}", "$HOME"):
            text = text.replace(token, home)
        if text.startswith("~/"):
            text = home + text[1:]
        if "$" in text or not os.path.isabs(text):
            continue
        text = os.path.normpath(text)
        if text not in out:
            out.append(text)
    return out


def zdotdirs(environ=os.environ) -> list[str]:
    """The folders zsh may read its start files from (``$ZDOTDIR``): this
    process's, and the ones each home's ``.zshenv`` and the system's zshenv
    set (an MCP server started by a desktop client lacks the variable)."""
    out: list[str] = []
    value = environ.get("ZDOTDIR", "")
    if value and os.path.isabs(value):
        out.append(os.path.normpath(value))
    for home in homes(environ):
        configs = [""] + [base for prefix, base in _xdg_bases(environ) if prefix == ".config"]
        for path in (_home_rel(home, ".zshenv"), *ZDOTDIR_SYSTEM_FILES):
            for raw in _zdotdir_lines(path):
                for folder in _expand_zdotdir(raw, home, configs):
                    if folder not in out:
                        out.append(folder)
    return out


def _platform_lists() -> tuple[list[tuple[str, bool]], list[tuple[str, bool]]]:
    """``(this platform's entries, the other platforms' entries)`` beyond
    :data:`HOME_DIRS` / :data:`HOME_FILES` (``(home-relative, is_folder)``)."""
    own: list[tuple[str, bool]] = []
    foreign: list[tuple[str, bool]] = []
    for platform, dirs, files in (("darwin", MACOS_DIRS, MACOS_FILES),
                                  ("win32", WINDOWS_DIRS, WINDOWS_FILES)):
        entries = [(rel, True) for rel in dirs] + [(rel, False) for rel in files]
        (own if sys.platform == platform else foreign).extend(entries)
    return own, foreign


def _dynamic_dirs(environ, home_list: list[str]) -> list[str]:
    """Folders of a home that are protected because of where they are
    used: the PATH's (a new file there is a command) and the site-packages
    on sys.path (their .pth files run at every Python start). A PATH entry
    that is a home folder itself is left out (it would protect all of it)."""
    candidates: list[str] = []
    for value in (environ.get("PATH", ""), environ.get(HOST_PATH_ENV, "")):
        candidates += [e for e in value.split(os.pathsep) if e and os.path.isabs(e)]
    candidates += [e for e in sys.path if isinstance(e, str) and os.path.isabs(e)
                   and os.path.basename(os.path.normpath(e)) in SITE_DIR_NAMES]
    home_keys = [_key(h) for h in home_list]
    out: list[str] = []
    for entry in candidates:
        entry = os.path.normpath(entry)
        ek = _key(entry)
        if any(_inside_key(ek, hk) for hk in home_keys) and entry not in out:
            out.append(entry)
    return out


def home_path_dirs(environ=os.environ) -> list[str]:
    """The PATH entries inside a home folder (for :data:`HOST_PATH_ENV`)."""
    home_keys = [_key(h) for h in homes(environ)]
    out = []
    for e in environ.get("PATH", "").split(os.pathsep):
        if e and os.path.isabs(e) and any(_inside_key(_key(e), hk) for hk in home_keys):
            out.append(os.path.normpath(e))
    return out


def protected_paths(environ=os.environ, *, foreign_missing: bool = True
                    ) -> list[tuple[str, bool]]:
    """``(path, is_folder)`` of every protected place as typed: below each
    home, where the XDG (and on Windows APPDATA / LOCALAPPDATA) variables
    move them, the home's folders on PATH and its site-packages on sys.path.
    Every platform's places count (inert elsewhere, cheap to refuse);
    *foreign_missing* False lists another platform's places only where they
    exist (core.agent_sandbox makes no mount points for them)."""
    out: list[tuple[str, bool]] = []
    seen: set[str] = set()

    def add(path: str, folder: bool) -> None:
        if path not in seen:
            seen.add(path)
            out.append((path, folder))

    entries = [(rel, True) for rel in HOME_DIRS] + [(rel, False) for rel in HOME_FILES]
    own, foreign = _platform_lists()
    home_list = homes(environ)
    for home in home_list:
        for rel, folder in entries + own:
            add(_home_rel(home, rel), folder)
        for rel, folder in foreign:
            path = _home_rel(home, rel)
            if foreign_missing or os.path.lexists(path):
                add(path, folder)
    for prefix, base in _xdg_bases(environ):
        for rel, folder in entries:
            if rel.startswith(prefix + "/"):
                add(os.path.join(base, *rel[len(prefix) + 1:].split("/")), folder)
    for var, rels in WINDOWS_ENV_DIRS:
        value = environ.get(var, "")
        if not value or not os.path.isabs(value):
            continue
        for rel in rels:
            path = _home_rel(value, rel)
            if foreign_missing or sys.platform == "win32" or os.path.lexists(path):
                add(path, True)
    for path in _dynamic_dirs(environ, home_list):
        add(path, True)
    for folder in zdotdirs(environ):
        for name in ZSH_FILES:
            add(os.path.join(folder, name), False)
    return out


#: Most hidden entries of one home folder :func:`write_deny_places` lists.
MAX_HIDDEN_ENTRIES = 4096


def write_deny_places(environ=os.environ, *, foreign_missing: bool = True
                      ) -> list[tuple[str, bool]]:
    """``(path, is_folder)`` of the default-deny places of the write side
    (:data:`DENY_ALL_BELOW`), for core.agent_sandbox: each home's existing
    hidden entries and the folders whose every entry is denied (as typed;
    *foreign_missing* False: another platform's only where they exist).
    A hidden entry that does not exist yet cannot be listed - the sandbox
    keeps the home folder itself from getting new entries."""
    out: list[tuple[str, bool]] = []

    def add(path: str, folder: bool) -> None:
        if (path, folder) not in out and (path, not folder) not in out:
            out.append((path, folder))

    own_platform = {"darwin": MACOS_DENY_ALL_BELOW, "win32": WINDOWS_DENY_ALL_BELOW}
    for home in homes(environ):
        if not _key(home):
            continue
        try:
            names = sorted(n for n in os.listdir(home) if _hidden_name(n))
        except OSError:
            names = []
        for name in names[:MAX_HIDDEN_ENTRIES]:
            path = os.path.join(home, name)
            add(path, os.path.isdir(path) and not os.path.islink(path))
        for rel in DENY_ALL_BELOW:
            add(_home_rel(home, rel), True)
        for rel in MACOS_DENY_ALL_BELOW + WINDOWS_DENY_ALL_BELOW:
            path = _home_rel(home, rel)
            if (foreign_missing or rel in own_platform.get(sys.platform, ())
                    or os.path.lexists(path)):
                add(path, True)
    for prefix, base in _xdg_bases(environ):
        if prefix in DENY_ALL_BELOW:
            add(base, True)
    appdata = environ.get("APPDATA", "")
    if appdata and os.path.isabs(appdata) and (foreign_missing or os.path.lexists(appdata)):
        add(appdata, True)
    return out


def grant_lifts(place: str, granted, environ=os.environ) -> bool:
    """Whether a *granted* folder lifts default-deny for *place* (a place of
    :func:`write_deny_places`): it lies in a granted folder that is at or
    below the denied entry (the user named it). A settings folder itself
    (``~/.config``) is lifted only by granting that very folder - a grant
    of ``~/.local`` does not open ``~/.local/share``."""
    areas = _deny_areas(environ)
    grants = _granted_keys(granted)
    pk = _key(os.path.abspath(place))
    if _denied(pk, areas, grants):
        return False
    all_bases = {base for base, kind in areas if kind == "all"}
    if pk in all_bases:
        return pk in grants
    return bool(_denials(pk, areas))


def _all_places(environ) -> list[str]:
    """Every protected place, as typed and as resolved."""
    out: list[str] = []
    real = _resolver()
    for place, _folder in protected_paths(environ):
        for variant in (place, real(place)):
            if variant not in out:
                out.append(variant)
    return out


def existing_places(environ=os.environ) -> list[str]:
    """The protected places that exist now (as typed, not resolved)."""
    return [place for place, _folder in protected_paths(environ) if os.path.lexists(place)]


def _start_name(name: str) -> bool:
    import fnmatch

    if _windows_names():
        name = name.split(":", 1)[0].rstrip(". ") or name
    if _case_insensitive():
        name = name.casefold()
    return any(fnmatch.fnmatchcase(name, pattern) for pattern in START_NAMES)


def _deny_areas(environ) -> list[tuple[tuple[str, ...], str]]:
    """``(key of a folder, kind)`` of the default-deny areas for writes:
    kind "hidden" (each home: its hidden entries) or "all" (every entry of
    ~/.config, ~/.local/share, ~/.local/state - also where XDG moves them -,
    ~/Library, %APPDATA%). As typed and as resolved."""
    areas: list[tuple[tuple[str, ...], str]] = []

    def add(path: str, kind: str) -> None:
        for variant in (os.path.abspath(path), os.path.realpath(path)):
            item = (_key(variant), kind)
            if item[0] and item not in areas:
                areas.append(item)

    for home in homes(environ):
        add(home, "hidden")
        for rel in DENY_ALL_BELOW + MACOS_DENY_ALL_BELOW + WINDOWS_DENY_ALL_BELOW:
            add(_home_rel(home, rel), "all")
    for prefix, base in _xdg_bases(environ):
        if prefix in DENY_ALL_BELOW:
            add(base, "all")
    appdata = environ.get("APPDATA", "")
    if appdata and os.path.isabs(appdata):
        add(appdata, "all")
    return areas


def _hidden_name(name: str) -> bool:
    allowed = {n.casefold() for n in HIDDEN_WRITABLE}
    return name.startswith(".") and name not in (".", "..") and name.casefold() not in allowed


def _denials(ck: tuple[str, ...], areas) -> list[tuple[int, str]]:
    """``(length of the area's key, kind)`` of each default-deny area *ck*
    lies in (strictly below its folder: a hidden entry of a home, any entry
    of a settings folder)."""
    out = []
    for base, kind in areas:
        n = len(base)
        if len(ck) > n and ck[:n] == base and (kind == "all" or _hidden_name(ck[n])):
            out.append((n, kind))
    return out


def _granted_keys(granted) -> list[tuple[str, ...]]:
    """The keys of the *granted* folders, as typed and resolved."""
    out: list[tuple[str, ...]] = []
    for folder in granted or ():
        if not folder or not isinstance(folder, str) or not os.path.isabs(folder):
            continue
        for variant in (os.path.abspath(folder), os.path.realpath(folder)):
            gk = _key(variant)
            if gk and gk not in out:
                out.append(gk)
    return out


def _lifted(ck: tuple[str, ...], n: int, kind: str, grants) -> bool:
    """Whether a granted folder lifts the area (key length *n*, *kind*) for
    *ck*: it holds *ck* and lies at or below the denied entry (``ck[:n+1]``)
    - or is the settings folder itself (kind "all"). A granted home folder,
    or a folder above the area, lifts nothing."""
    return any(ck[:len(g)] == g and (len(g) > n or (kind == "all" and len(g) == n))
               for g in grants)


def _denied(ck: tuple[str, ...], areas, grants) -> bool:
    """Whether default-deny refuses *ck*: it lies in an area no grant lifts."""
    return any(not _lifted(ck, n, kind, grants) for n, kind in _denials(ck, areas))


def _denied_entry(ck: tuple[str, ...], areas) -> tuple[str, ...] | None:
    """The key of the default-deny entry *ck* is (or lies in), or None."""
    for n, _kind in _denials(ck, areas):
        return ck[:n + 1]
    return None


#: Most symlinks followed for one path (Linux's own limit is 40).
MAX_LINK_HOPS = 40


def _link_chain(path: str, readlink=None) -> list[str]:
    """Every name a write or read of *path* goes by: the absolute path as
    typed, the path after each symlink on the way is followed (one hop at a
    time, the rest of the path joined on), and the resolved path. A missing
    component ends nothing (the rest is joined as it is). *readlink(path)*
    returns a link's target or None (memoised by the caller)."""
    path = os.path.abspath(path)
    out = [path]
    if os.name != "posix":
        real = os.path.realpath(path)
        if real != path:
            out.append(real)
        return out
    if readlink is None:
        readlink = _readlink_or_none
    todo = [part for part in path.split("/") if part]
    done = "/"
    hops = 0
    while todo:
        name = todo.pop(0)
        if name == ".":
            continue
        if name == "..":
            done = os.path.dirname(done)
            continue
        here = os.path.join(done, name)
        target = readlink(here) if hops < MAX_LINK_HOPS else None
        if target is None:
            done = here
            continue
        hops += 1
        base = target if os.path.isabs(target) else os.path.join(done, target)
        variant = os.path.normpath(os.path.join(base, *todo))
        if variant not in out:
            out.append(variant)
        if os.path.isabs(target):
            done = "/"
        todo = [part for part in target.split("/") if part] + todo
    if done not in out:
        out.append(done)
    if hops >= MAX_LINK_HOPS:  # a loop: what the OS would make of it
        real = os.path.realpath(path)
        if real not in out:
            out.append(real)
    return out


def _readlink_or_none(path: str) -> str | None:
    try:
        return os.readlink(path)
    except (OSError, ValueError):
        return None


def _memo_readlink():
    memo: dict[str, str | None] = {}

    def readlink(path: str) -> str | None:
        if path not in memo:
            memo[path] = _readlink_or_none(path)
        return memo[path]

    return readlink


#: Folders the link scan (:func:`_area_links`) does not look into: caches
#: and package stores (many entries, links of their own that name nothing
#: of the user's).
LINK_SCAN_SKIP = ("cache", ".cache", "caches", "node_modules", "site-packages",
                  "dist-packages", "__pycache__", ".git", "registry", "toolchains",
                  "_cacache", "repository", "versions")
#: Most entries the link scan looks at per call.
MAX_LINK_SCAN = 8192
#: ``folder -> ((mtime_ns, ino), [(name, is_link, is_dir)])``: folders listed.
_SCAN_CACHE: dict[str, tuple[tuple[int, int], list[tuple[str, bool, bool]]]] = {}


def _scan_dir(folder: str) -> list[tuple[str, bool, bool]]:
    """``(name, is_link, is_dir)`` of *folder*'s entries (cached by the
    folder's modification time: an entry made, removed or re-pointed
    changes it)."""
    try:
        st = os.stat(folder)
    except OSError:
        return []
    stamp = (st.st_mtime_ns, st.st_ino)
    cached = _SCAN_CACHE.get(folder)
    if cached is not None and cached[0] == stamp:
        return cached[1]
    entries: list[tuple[str, bool, bool]] = []
    try:
        with os.scandir(folder) as it:
            for entry in it:
                try:
                    is_link = entry.is_symlink()
                    is_dir = not is_link and entry.is_dir(follow_symlinks=False)
                except OSError:
                    continue
                entries.append((entry.name, is_link, is_dir))
                if len(entries) >= MAX_LINK_SCAN:
                    break
    except OSError:
        return []
    entries.sort()
    if len(_SCAN_CACHE) > 4096:
        _SCAN_CACHE.clear()
    _SCAN_CACHE[folder] = (stamp, entries)
    return entries


def _area_links(environ) -> list[tuple[str, str]]:
    """``(link, its resolved target)`` of the symlinks among each home's
    hidden entries and up to two folders below them, and among the entries
    of the settings folders (and one folder below): GNU stow and chezmoi
    put ``~/.config/kitty -> ~/dotfiles/kitty`` and
    ``~/.ssh/id_ed25519 -> ~/keys/id_ed25519`` there. Their targets count as
    the places themselves (:func:`write_checker`, :func:`secret_checker`).
    Bounded (:data:`MAX_LINK_SCAN` entries); caches are not looked into."""
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    budget = [MAX_LINK_SCAN]

    def walk(folder: str, depth: int, hidden_only: bool) -> None:
        if folder in seen or budget[0] <= 0:
            return
        seen.add(folder)
        for name, is_link, is_dir in _scan_dir(folder):
            if budget[0] <= 0:
                return
            budget[0] -= 1
            if hidden_only and not _hidden_name(name):
                continue
            path = os.path.join(folder, name)
            if is_link:
                found.append((path, os.path.realpath(path)))
            elif is_dir and depth > 0 and name.casefold() not in LINK_SCAN_SKIP:
                walk(path, depth - 1, False)

    for home in homes(environ):
        if _key(home):
            walk(os.path.realpath(home), 3, True)
        for rel in DENY_ALL_BELOW:
            walk(os.path.realpath(_home_rel(home, rel)), 1, False)
    for prefix, base in _xdg_bases(environ):
        if prefix in DENY_ALL_BELOW:
            walk(os.path.realpath(base), 1, False)
    if budget[0] <= 0:
        import logging

        logging.getLogger(__name__).debug(
            "symlinks of the hidden folders: stopped after %d entries", MAX_LINK_SCAN)
    return found


def _home_or_above(tk: tuple[str, ...], home_keys) -> bool:
    return any(hk[:len(tk)] == tk for hk in home_keys)


def _git_shaped(path: str, memo: dict) -> bool:
    """Whether Git takes the folder *path* for a repository (:data:`GIT_SHAPE`)."""
    done = memo.get(path)
    if done is None:
        done = (os.path.lexists(os.path.join(path, "HEAD"))
                and os.path.isdir(os.path.join(path, "objects"))
                and os.path.isdir(os.path.join(path, "refs")))
        memo[path] = done
    return done


def _path_parts(path: str) -> list[str]:
    return [part for part in os.path.abspath(path).replace("\\", "/").split("/") if part]


def _git_code(ck: tuple[str, ...], path: str | None = None, memo: dict | None = None) -> bool:
    """Whether *ck* (the key of *path*) is a Git, Mercurial or Jujutsu file
    that runs code: :data:`GIT_CODE_NAMES` anywhere below a Git folder (a
    ``.git`` or ``*.git`` folder, or one shaped like a repository - looked
    up on disk when *path* is given) or directly in a folder that holds a
    ``HEAD``; a ``.git`` entry itself, a folder shaped like a repository or
    holding ``HEAD`` beside a config or hooks; ``.gitmodules``; the entry
    that would make a folder a repository (:data:`GIT_SHAPE`: ``HEAD`` beside
    a config or hooks, or the last of the three); :data:`VCS_CODE`. Folders
    made on the way (a copy's or an archive's) cannot complete one: ``HEAD``
    and the config are files, and whichever comes second is refused."""
    names = {n.casefold() for n in GIT_CODE_NAMES}
    if ck and ck[-1] in {n.casefold() for n in GIT_TREE_NAMES}:
        return True
    for i, part in enumerate(ck):
        for folder, rels in VCS_CODE:
            if part == folder and any(ck[i + 1:] == rel for rel in rels):
                return True
    parts = _path_parts(path) if path is not None else None
    if parts is not None and len(parts) != len(ck):
        parts = None
    memo = {} if memo is None else memo
    fold = str.casefold if _case_insensitive() else str

    def real(i: int) -> str:
        return os.sep + os.sep.join(parts[:i + 1]) if os.name == "posix" else \
            os.sep.join(parts[:i + 1])

    def lexists(folder: str, name: str) -> bool:
        key = (folder, name)
        if key not in memo:
            memo[key] = os.path.lexists(os.path.join(folder, name))
        return memo[key]

    def holds_code(folder: str) -> bool:
        return any(lexists(folder, n) for n in GIT_CODE_NAMES)

    def by_name(part: str) -> bool:
        return part == GIT_DIR or (part.endswith(".git") and len(part) > len(".git"))

    last_i = len(ck) - 1
    for i, part in enumerate(ck):
        named = by_name(part)
        shaped = not named and parts is not None and _git_shaped(real(i), memo)
        head = not (named or shaped) and parts is not None and lexists(real(i), "HEAD")
        if not (named or shaped or head):
            continue
        if i == last_i:
            if part == GIT_DIR or shaped or (head and holds_code(real(i))):
                return True
            continue
        if head:
            if ck[i + 1].casefold() in names:
                return True
            continue
        if any(later.casefold() in names for later in ck[i + 1:]):
            return True
    # The entry that would make its folder a repository: HEAD beside a
    # config or hooks (or beside objects/ and refs/), or the last of HEAD,
    # objects/ and refs/.
    if parts is not None and len(ck) >= 2:
        last = fold(parts[-1])
        folder = real(len(parts) - 2)
        if (last in {fold(n) for n in GIT_SHAPE} and not by_name(ck[-2])
                and not _git_shaped(folder, memo)):
            if last == fold("HEAD") and holds_code(folder):
                return True
            others = [n for n in GIT_SHAPE if fold(n) != last]
            checks = {"HEAD": os.path.lexists, "objects": os.path.isdir,
                      "refs": os.path.isdir}
            if all(checks[n](os.path.join(folder, n)) for n in others):
                return True
    return False


def _git_message(path: str) -> str:
    return (f"{path}: the agent does not change Git's settings, hooks or submodules "
            "(config, hooks, info, commondir, gitdir of a .git or *.git folder or of a "
            "folder shaped like a repository or holding a HEAD, .gitmodules, a .git "
            "entry, a HEAD beside a config or hooks, the last of HEAD/objects/refs that "
            "would make a folder a repository; .hg/hgrc, .jj/repo): Git, Mercurial and "
            "Jujutsu run code from them")


def _link_target_denials(environ, areas, home_keys) -> list[tuple[tuple[str, ...], tuple[str, ...]]]:
    """``(key of a link's target, key of the link)`` for the symlinks in the
    default-deny areas (:func:`_area_links`): writing the target changes
    what the link's place holds."""
    out = []
    for link, target in _area_links(environ):
        lk, tk = _key(link), _key(target)
        if not tk or _home_or_above(tk, home_keys) or not _denials(lk, areas):
            continue
        if (tk, lk) not in out:
            out.append((tk, lk))
    return out


def deny_link_targets(environ=os.environ, *, granted=()) -> list[str]:
    """The resolved targets of the symlinks in the default-deny places
    (``~/.config/kitty -> ~/dotfiles/kitty``) that no *granted* folder lifts,
    for core.agent_sandbox: read-only there as well. Never a home folder or
    a folder above one."""
    areas = _deny_areas(environ)
    grants = _granted_keys(granted)
    home_keys = [_key(h) for h in homes(environ)]
    out: list[str] = []
    for link, target in _area_links(environ):
        lk, tk = _key(link), _key(target)
        if (not tk or _home_or_above(tk, home_keys) or not _denials(lk, areas)
                or not _denied(lk, areas, grants)):
            continue
        if target not in out:
            out.append(target)
    return out


def write_checker(environ=os.environ, *, granted=()):
    """:func:`refusal` with the places resolved once - for the many paths of
    one tool call (an archive's members); a new one per call."""
    places = [(_key(place), place) for place in _all_places(environ)]
    areas = _deny_areas(environ)
    grants = _granted_keys(granted)
    home_keys = [_key(h) for h in homes(environ)]
    targets = _link_target_denials(environ, areas, home_keys)
    readlink = _memo_readlink()
    shape_memo: dict[str, bool] = {}

    def check(path: str, *, entry: bool = False) -> str | None:
        absolute = os.path.abspath(path)
        candidates = list(_link_chain(absolute, readlink))
        parent_real = os.path.join(os.path.realpath(os.path.dirname(absolute)),
                                   os.path.basename(absolute))
        if parent_real not in candidates:
            candidates.append(parent_real)
        for candidate in candidates:
            if _start_name(os.path.basename(candidate)):
                return (f"{path}: the agent does not write Python start files "
                        f"({', '.join(START_NAMES)}): Python runs them at every start")
        keyed = [(_key(c), c) for c in candidates]
        for pk, place in places:
            for ck, _c in keyed:
                if ck[:len(pk)] == pk:
                    return (f"{path}: the agent does not change {place} (it could run code "
                            "or widen its own rights from there)")
                if entry and len(ck) < len(pk) and pk[:len(ck)] == ck:
                    return f"{path} holds {place}, which the agent does not change"
        for ck, candidate in keyed:
            if _git_code(ck, candidate, shape_memo):
                return _git_message(path)
            if TRASH_NAME in ck:
                return (f"{path}: the agent does not change axross's trash ({TRASH_NAME}): "
                        "what is restored from it is put back with axross's rights")
            if _denied(ck, areas, grants):
                return (f"{path}: the agent does not change hidden entries of the home "
                        "folder or entries of the settings and data folders (~/.config, "
                        "~/.local/share, ~/.local/state, ~/snap, ~/Library, %APPDATA%) "
                        "unless that folder is granted to it: programs run code from many "
                        "of them")
            for tk, lk in targets:
                if (ck[:len(tk)] == tk and _denied(lk, areas, grants)
                        and not any(ck[:len(g)] == g and len(g) >= len(tk) for g in grants)):
                    return (f"{path}: the agent does not change "
                            f"{os.sep + os.sep.join(tk) if os.name == 'posix' else tk}: "
                            "a symlink in a hidden folder of the home or a settings folder "
                            "points there (a program reads it as its settings)")
        return None

    return check


def refusal(path: str, *, entry: bool = False, environ=os.environ,
            granted=()) -> str | None:
    """Why *path* must not be changed, or None. *entry*: the path's entry
    is created, removed or moved, so a folder that holds a protected place
    is refused too (deleting or replacing ~/.config takes ~/.config/autostart).
    A Python start file (:data:`START_NAMES`), a Git file that runs code
    (:data:`GIT_CODE_NAMES`) and axross's trash are refused wherever they
    are. Default-deny (:data:`DENY_ALL_BELOW`): a hidden entry of a home
    folder and every entry of its settings and data folders are refused
    unless they lie in a *granted* folder (the MCP root, the agent's
    folders) that is itself in such a place. Each name the path goes by
    counts - as typed, after each symlink on the way, resolved - and the
    target of a symlink in those places counts as the place."""
    return write_checker(environ, granted=granted)(path, entry=entry)


# -- the read side: secrets --------------------------------------------------------------
#
# Read, these turn "read my files" into the user's accounts: axross's OAuth
# refresh tokens (Google Drive, OneDrive, Dropbox), its MCP HTTP token, its
# chat accounts' encryption keys and sync tokens, Bluetooth link keys, the
# ADB key it made, the key of its extension code cache, and the SSH and
# GnuPG private keys. core.mcp_server refuses to hand their contents to a
# tool (read_file, grep, checksum, preview, copies, the groups' readers)
# unless the operator opts in.

#: Folders whose every file is secret (relative to the home folder).
SECRET_DIRS = (".local/state/axross/chat", ".gnupg/private-keys-v1.d",
               ".gnupg/openpgp-revocs.d",
               # the desktop's keyrings (GNOME Keyring, KWallet)
               ".local/share/keyrings", ".local/share/kwalletd",
               # axross's trash: a trashed key is still a key (core.trash)
               ".axross-trash",
               # other programs' credential stores: cloud and cluster CLIs,
               # password managers, messengers
               ".aws", ".azure", ".kube", ".config/gh", ".config/gcloud", ".config/rclone",
               ".terraform.d", ".password-store", ".config/op", ".config/Signal",
               ".config/sops", ".config/age",
               # browser and mail profiles: saved passwords, cookies, session keys
               ".mozilla", ".thunderbird", ".icedove", ".config/google-chrome",
               ".config/google-chrome-beta", ".config/google-chrome-unstable",
               ".config/chromium", ".config/BraveSoftware", ".config/microsoft-edge",
               ".config/vivaldi", ".config/opera", ".var/app/org.mozilla.firefox",
               ".var/app/com.google.Chrome", ".var/app/org.chromium.Chromium",
               ".var/app/com.brave.Browser", ".snap/firefox", ".snap/chromium",
               # snap packages keep their profiles below ~/snap (Ubuntu's Firefox)
               "snap/firefox", "snap/chromium", "snap/thunderbird", "snap/brave",
               "snap/telegram-desktop", "snap/discord", "snap/signal-desktop", "snap/slack",
               # messengers' sessions (an account taken over)
               ".local/share/TelegramDesktop", ".var/app/org.telegram.desktop",
               ".config/discord", ".config/discordcanary", ".config/discordptb",
               ".var/app/com.discordapp.Discord", ".config/Element", ".config/Element-Nightly",
               ".var/app/im.riot.Riot", ".config/Slack", ".purple",
               # more CLIs' tokens, saved connections and VPN keys
               ".config/glab-cli", ".config/doctl", ".config/hcloud", ".fly",
               ".config/ngrok", ".ngrok2", ".config/filezilla", ".filezilla",
               ".config/remmina", ".local/share/remmina", ".wireguard")
#: Secret files (relative to the home folder).
SECRET_FILES = (".gnupg/secring.gpg", ".android/adbkey",
                # the key that authenticates the extension code cache
                ".config/axross/extension-code.key",
                ".local/share/axross/bluetooth-direct-keys.json",
                # passwords and tokens other programs keep in plain text
                ".netrc", ".git-credentials", ".pypirc", ".npmrc", ".yarnrc", ".yarnrc.yml",
                ".docker/config.json", ".cargo/credentials", ".cargo/credentials.toml",
                ".vault-token", ".config/hub", ".claude/.credentials.json", ".pgpass",
                ".my.cnf", ".s3cfg", ".boto", ".config/containers/auth.json",
                ".local/share/fish/fish_history", ".terraformrc",
                ".m2/settings.xml", ".m2/settings-security.xml", ".gradle/gradle.properties")
#: macOS and Windows (relative to the home folder; every platform's count):
#: the keychains, browser profiles, cookies.
PLATFORM_SECRET_DIRS = (
    "Library/Keychains", "Library/Cookies", "Library/Application Support/Google/Chrome",
    "Library/Application Support/Chromium", "Library/Application Support/BraveSoftware",
    "Library/Application Support/Microsoft Edge", "Library/Application Support/Firefox",
    "Library/Thunderbird", "Library/Application Support/Signal",
    "AppData/Local/Google/Chrome/User Data", "AppData/Local/Chromium/User Data",
    "AppData/Local/BraveSoftware", "AppData/Local/Microsoft/Edge/User Data",
    "AppData/Roaming/Mozilla", "AppData/Roaming/Thunderbird", "AppData/Roaming/Signal",
    "AppData/Roaming/gcloud",
)
#: Names (case-folded) of files that are secret anywhere below a hidden
#: entry of the home folder (``~/.foo/.../name``; also the hidden entry
#: itself, with all it holds when it is a folder - ``~/.bash_history``,
#: ``~/.secrets/``): credential and token files, private keys, password
#: databases, shell and REPL histories (commands typed with tokens in them),
#: cookie jars. Folders deeper down are not matched by name, nor are files
#: of code (:data:`SECRET_CODE_SUFFIXES`: a Python under ``~/.pyenv`` has
#: ``tokenize.py`` and ``secrets.py``, packages ``credentials.py``) or public
#: keys (``id_ed25519.pub``).
SECRET_HIDDEN_PATTERNS = ("*credential*", "*token*", "*secret*", "*.pem", "*.key",
                          "*key*.json", "id_*", "*.kdbx", "*history*", "cookies*")
SECRET_CODE_SUFFIXES = (".py", ".pyc", ".pyi", ".pyd", ".pyo", ".so", ".dll", ".dylib",
                        ".js", ".mjs", ".cjs", ".ts", ".map", ".rb", ".go", ".rs", ".java",
                        ".class", ".jar", ".h", ".hpp", ".c", ".cc", ".cpp", ".lua", ".pm",
                        ".el", ".elc", ".vim", ".css", ".html", ".d")
#: Folders the agent sandbox does not look into for those names (code and
#: package caches: many files, no credentials) - by name anywhere, and by
#: place below the home folder.
SECRET_WALK_SKIP = ("site-packages", "dist-packages", "node_modules", "__pycache__", ".git",
                    ".venv", "venv")
SECRET_WALK_SKIP_PATHS = (".cargo/registry", ".cargo/git", ".rustup", ".npm/_cacache",
                          ".gradle/caches", ".gradle/wrapper", ".m2/repository",
                          ".pyenv/versions", ".nvm/versions", ".local/lib")
#: Hidden entries of the home looked at last (big caches: they should not
#: use up the walk before the folders that hold settings).
SECRET_WALK_LAST = (".cache", ".var", ".local")
#: Folders whose entries are walked (and covered) one by one, each with a
#: budget of its own, like the hidden entries of the home: a big
#: ``~/.local/share/Steam`` is covered, not all of ``~/.local``.
SECRET_WALK_CONTAINERS = (".config", ".local", ".local/share", ".local/state", ".var",
                          ".var/app", ".cache")
#: Most entries the agent sandbox looks at for :data:`SECRET_HIDDEN_PATTERNS`
#: (:func:`secret_hides`) below one hidden entry of the home, in all, and
#: how deep. A hidden entry whose walk does not end in its budget is covered
#: whole (the sandbox cannot tell what is in the rest of it).
MAX_SECRET_WALK_ENTRY = 25_000
MAX_SECRET_WALK = 200_000
MAX_SECRET_DEPTH = 8
#: Most files the agent sandbox covers for the patterns (a mount each).
MAX_SECRET_PATTERN_HIDES = 1024
#: ``(folder, patterns)``: the entries of *folder* whose name matches
#: (core.connection_manager names a token file ``gdrive_token.<profile>-<hash>.json``,
#: core.mcp_http's is ``mcp-http-<port>.token``; their temporary siblings too).
SECRET_NAMES = ((".config/axross", ("*token*",)),)
#: ``(folder, patterns)``: every entry of *folder* but those whose name
#: matches - a private key in ~/.ssh may have any name.
SECRET_UNLESS = ((".ssh", ("*.pub", "known_hosts", "known_hosts.old", "authorized_keys",
                           "authorized_keys2", "config")),)


def _secret_rules(environ) -> list[tuple[tuple[str, ...], str, tuple[str, ...]]]:
    """``(key of a folder or file, kind, patterns)`` of every secret place:
    kind "all" (the place and all below it), "names" (entries matching
    *patterns*) or "unless" (entries not matching them)."""
    rules: list[tuple[tuple[str, ...], str, tuple[str, ...]]] = []
    real = _resolver()

    def add(path: str, kind: str, patterns: tuple[str, ...] = ()) -> None:
        for variant in (path, real(path)):
            rule = (_key(variant), kind, patterns)
            if rule not in rules:
                rules.append(rule)

    for home in homes(environ):
        for rel in SECRET_DIRS + SECRET_FILES + PLATFORM_SECRET_DIRS:
            add(os.path.join(home, *rel.split("/")), "all")
        for rel, patterns in SECRET_NAMES:
            add(os.path.join(home, *rel.split("/")), "names", patterns)
        for rel, patterns in SECRET_UNLESS:
            add(os.path.join(home, *rel.split("/")), "unless", patterns)
        if _key(home):
            add(home, "hidden-names", SECRET_HIDDEN_PATTERNS)
    for var, rels in (("APPDATA", ("Mozilla", "Thunderbird", "Signal", "gcloud")),
                      ("LOCALAPPDATA", ("Google/Chrome/User Data", "Chromium/User Data",
                                        "BraveSoftware", "Microsoft/Edge/User Data"))):
        value = environ.get(var, "")
        if value and os.path.isabs(value):
            for rel in rels:
                add(_home_rel(value, rel), "all")
    for prefix, base in _xdg_bases(environ):
        for rel in SECRET_DIRS + SECRET_FILES:
            if rel.startswith(prefix + "/"):
                add(os.path.join(base, *rel[len(prefix) + 1:].split("/")), "all")
    # Where XDG moves them: the Bluetooth keys, the MCP HTTP token.
    data = environ.get("XDG_DATA_HOME", "")
    if data and os.path.isabs(data):
        add(os.path.join(data, "axross", "bluetooth-direct-keys.json"), "all")
    runtime = environ.get("XDG_RUNTIME_DIR", "")
    if runtime and os.path.isabs(runtime):
        add(os.path.join(runtime, "axross"), "names", ("*token*",))
    return rules


def _secret_name(name: str, patterns: tuple[str, ...]) -> bool:
    import fnmatch

    folded = name.casefold()
    return any(fnmatch.fnmatchcase(folded, p) for p in patterns)


def _secret_file_name(name: str) -> bool:
    """Whether a file below a hidden folder of the home is secret by its name."""
    return (_secret_name(name, SECRET_HIDDEN_PATTERNS)
            and not name.casefold().endswith(SECRET_CODE_SUFFIXES + (".pub",)))


def _secret_match(ck: tuple[str, ...], rule) -> bool:
    import fnmatch

    base, kind, patterns = rule
    if ck[:len(base)] != base:
        return False
    if kind == "all":
        return True
    if kind == "hidden-names":
        below = ck[len(base):]
        return (bool(below) and below[0].startswith(".")
                and (_secret_file_name(below[0]) or _secret_file_name(below[-1])))
    if len(ck) == len(base):
        return False  # the folder itself: its names may be listed
    name = ck[len(base)]
    matched = any(fnmatch.fnmatchcase(name, p.casefold() if _case_insensitive() else p)
                  for p in patterns)
    return matched if kind == "names" else not matched


def _secret_inodes(environ, rules) -> set[tuple[int, int]]:
    """``(device, inode)`` of the secret files that exist (the files and
    the files in the folders of the secret lists, a few levels deep, and the
    entries of a folder whose every entry but some is secret): a hard link
    elsewhere shares one. Bounded (4096 files)."""
    import stat as stat_module

    out: set[tuple[int, int]] = set()
    budget = [4096]
    real = _resolver()

    def add_file(path: str) -> None:
        try:
            st = os.stat(path)
        except OSError:
            return
        if stat_module.S_ISREG(st.st_mode):
            out.add((st.st_dev, st.st_ino))

    def walk(folder: str, depth: int) -> None:
        for name, is_link, is_dir in _scan_dir(folder):
            if budget[0] <= 0:
                return
            budget[0] -= 1
            path = os.path.join(folder, name)
            if is_dir:
                if depth > 0:
                    walk(path, depth - 1)
            elif not is_link:
                add_file(path)

    for home in homes(environ):
        for rel in SECRET_FILES:
            add_file(_home_rel(home, rel))
        for rel, patterns in SECRET_NAMES:
            folder = real(_home_rel(home, rel))
            for name, is_link, is_dir in _scan_dir(folder):
                if not is_dir and not is_link and _secret_name(name, patterns):
                    add_file(os.path.join(folder, name))
        for rel in tuple(rel for rel, _p in SECRET_UNLESS) + SECRET_DIRS:
            folder = real(_home_rel(home, rel))
            if os.path.isdir(folder):
                walk(folder, 3)
    for prefix, base in _xdg_bases(environ):
        for rel in SECRET_FILES:
            if rel.startswith(prefix + "/"):
                add_file(os.path.join(base, *rel[len(prefix) + 1:].split("/")))
    return out


def secret_checker(environ=os.environ, *, granted=()):
    """:func:`read_refusal` with the secret places resolved once - for the
    many paths of one tool call (grep, recursive_checksum); a new one per
    call, so a place re-pointed later is seen by the next call. *granted*:
    the folders the user gave the tools (the MCP root and extra folders):
    one inside a hidden entry of the home or a settings folder lifts
    default-deny for reads below it (:data:`READ_DENY_ALL_BELOW`); the
    secret places stay secret in it."""
    import stat as stat_module

    rules = _secret_rules(environ)
    areas = _deny_areas(environ)
    for home in homes(environ):
        for rel in READ_DENY_ALL_BELOW:
            for variant in (_home_rel(home, rel), os.path.realpath(_home_rel(home, rel))):
                item = (_key(variant), "all")
                if item[0] and item not in areas:
                    areas.append(item)
    grants = _granted_keys(granted)
    home_keys = [_key(h) for h in homes(environ)]
    # The targets of the symlinks among the secret places (~/.ssh/id_ed25519
    # -> ~/keys/id_ed25519) are secret where they are, too.
    for link, target in _area_links(environ):
        lk, tk = _key(link), _key(target)
        if tk and not _home_or_above(tk, home_keys) and any(_secret_match(lk, r) for r in rules):
            rule = (tk, "all", ())
            if rule not in rules:
                rules.append(rule)
    readlink = _memo_readlink()
    inodes: list[set[tuple[int, int]]] = []

    def check(path: str, *, entry: bool = False) -> str | None:
        # The contents are what the path resolves to; a symlink to a
        # secret, or a folder linked into ~/.ssh, resolves into the place -
        # and each name on the way counts (a link in ~/.ssh to a key elsewhere).
        absolute = os.path.abspath(path)
        chain = _link_chain(absolute, readlink)
        keys = list(dict.fromkeys(_key(c) for c in chain))
        for ck in keys:
            if TRASH_NAME in ck:
                return (f"{path}: the agent does not read axross's trash ({TRASH_NAME}): "
                        "what was deleted there may be a key or token")
        for rule in rules:
            for ck in keys:
                if _secret_match(ck, rule):
                    return (f"{path}: the agent does not read this secret file (a token or "
                            "private key: it would open the account or host it is for)")
                if entry and len(ck) <= len(rule[0]) and rule[0][:len(ck)] == ck:
                    return f"{path} holds secret files, which the agent does not read"
        for ck in keys:
            if _denied(ck, areas, grants):
                return (f"{path}: the agent does not read hidden entries of the home folder "
                        "or the settings, data and snap folders (~/.config, ~/.local, ~/snap, "
                        "~/Library, %APPDATA%) unless that folder is granted to it (the MCP "
                        "root or an extra folder there): many hold sessions, tokens and keys")
        # A hard link shares a secret file's contents under another name.
        try:
            st = os.stat(chain[-1])
        except OSError:
            st = None
        if st is not None and stat_module.S_ISREG(st.st_mode) and st.st_nlink > 1:
            if not inodes:
                inodes.append(_secret_inodes(environ, rules))
            if (st.st_dev, st.st_ino) in inodes[0]:
                return (f"{path}: the agent does not read this file: it is a hard link to a "
                        "secret file (a token or private key)")
        return None

    return check


def read_refusal(path: str, *, entry: bool = False, environ=os.environ,
                 granted=()) -> str | None:
    """Why the contents of *path* must not be handed to a tool, or None.
    *entry*: the path is copied or moved as a whole, so a folder that holds
    a secret is refused too (copying ~/.ssh takes its keys along). Compared
    like :func:`refusal` (components, case, each name on the way). Also
    default-deny for reads (:data:`READ_DENY_ALL_BELOW`) unless *granted*."""
    return secret_checker(environ, granted=granted)(path, entry=entry)


def _pattern_secrets(home: str, within) -> list[tuple[str, bool]]:
    """``(path, is_folder)`` of the existing entries below *home*'s hidden
    entries whose name matches :data:`SECRET_HIDDEN_PATTERNS` (a matching
    folder whole) - only below the folders in *within* (None: everywhere).
    A bounded walk per hidden entry (:data:`MAX_SECRET_WALK_ENTRY` entries,
    :data:`MAX_SECRET_WALK` in all, :data:`MAX_SECRET_DEPTH` deep, caches
    last and package stores skipped); a hidden entry whose walk does not end
    within that - or that holds more than :data:`MAX_SECRET_PATTERN_HIDES`
    matches - is listed whole. Symlinks are not followed."""
    import logging

    found: list[tuple[str, bool]] = []
    real_home = os.path.realpath(home)
    try:
        top = sorted(n for n in os.listdir(real_home) if n.startswith(".")
                     and n not in (".", ".."))
    except OSError:
        return found
    last = {n.casefold() for n in SECRET_WALK_LAST}
    top.sort(key=lambda n: (n.casefold() in last, n))
    skip_paths = {os.path.join(real_home, *rel.split("/")) for rel in SECRET_WALK_SKIP_PATHS}

    def wanted(path: str) -> bool:
        if within is None:
            return True
        return any(path == w or path.startswith(w.rstrip(os.sep) + os.sep)
                   or w.startswith(path.rstrip(os.sep) + os.sep) for w in within)

    containers = {os.path.join(real_home, *rel.split("/")) for rel in SECRET_WALK_CONTAINERS}
    units: list[str] = []

    def expand(path: str, depth: int) -> None:
        if not wanted(path):
            return
        try:
            if os.path.islink(path):
                return
            is_dir = os.path.isdir(path)
        except OSError:
            return
        name = os.path.basename(path)
        if depth == 0 and _secret_file_name(name):
            found.append((path, is_dir))
            return
        if not is_dir:
            if _secret_file_name(name):
                found.append((path, False))
            return
        if path in containers:
            try:
                names = sorted(os.listdir(path))[:MAX_HIDDEN_ENTRIES]
            except OSError:
                return
            for child in names:
                expand(os.path.join(path, child), depth + 1)
            return
        units.append(path)

    for name in top:
        expand(os.path.join(real_home, name), 0)
    total = MAX_SECRET_WALK
    for entry in units:
        budget = min(MAX_SECRET_WALK_ENTRY, total)
        room = MAX_SECRET_PATTERN_HIDES - len(found)
        mine: list[tuple[str, bool]] = []
        stack = [(entry, 0)]
        complete = True
        while stack:
            if budget <= 0 or len(mine) > room:
                complete = False
                break
            path, depth = stack.pop()
            budget -= 1
            total -= 1
            if path != entry and not wanted(path):
                continue
            try:
                is_link = os.path.islink(path)
                sub_dir = not is_link and os.path.isdir(path)
            except OSError:
                continue
            if is_link:
                continue
            base = os.path.basename(path)
            if path != entry and not sub_dir and _secret_file_name(base):
                mine.append((path, False))
                continue
            if (sub_dir and depth < MAX_SECRET_DEPTH and base not in SECRET_WALK_SKIP
                    and path not in skip_paths):
                try:
                    names = sorted(os.listdir(path))
                except OSError:
                    continue
                stack.extend((os.path.join(path, n), depth + 1) for n in reversed(names))
        if complete:
            found.extend(mine)
            continue
        logging.getLogger(__name__).warning(
            "secret files: %s holds more than the sandbox looks at (%d entries, %d found); "
            "it is covered whole in the agent sandbox", entry,
            MAX_SECRET_WALK_ENTRY if budget <= 0 else MAX_SECRET_WALK_ENTRY - budget, len(mine))
        found.append((entry, True))
    return found


def secret_hides(environ=os.environ, *, within=None) -> list[tuple[str, bool]]:
    """``(path, is_folder)`` of the existing secret places core.agent_sandbox
    covers in the sandbox (an empty read-only folder, an empty file): every
    secret folder and file, all of a folder whose private keys may have
    any name (``~/.ssh``), and each matching entry of a folder with secret
    names (axross's token files). Resolved, and never a symlink: a link
    leads to its target, which is listed instead."""
    import fnmatch

    out: list[tuple[str, bool]] = []

    def add(path: str) -> None:
        real = os.path.realpath(path)
        if not os.path.lexists(real) or os.path.islink(real):
            return
        item = (real, os.path.isdir(real))
        if item not in out:
            out.append(item)

    def add_names(folder: str, patterns: tuple[str, ...]) -> None:
        real = os.path.realpath(folder)
        try:
            names = sorted(os.listdir(real))[:4096]
        except OSError:
            return
        for name in names:
            key = name.casefold() if _case_insensitive() else name
            if any(fnmatch.fnmatchcase(key, p) for p in patterns):
                add(os.path.join(real, name))

    for home in homes(environ):
        for rel in SECRET_DIRS + SECRET_FILES + PLATFORM_SECRET_DIRS:
            add(_home_rel(home, rel))
        for rel, patterns in SECRET_NAMES:
            add_names(_home_rel(home, rel), patterns)
        for rel, _patterns in SECRET_UNLESS:
            add(_home_rel(home, rel))
    for prefix, base in _xdg_bases(environ):
        for rel in SECRET_DIRS + SECRET_FILES:
            if rel.startswith(prefix + "/"):
                add(os.path.join(base, *rel[len(prefix) + 1:].split("/")))
        if prefix == ".config":
            add_names(os.path.join(base, "axross"), ("*token*",))
    for var, rels in (("APPDATA", ("Mozilla", "Thunderbird", "Signal", "gcloud")),
                      ("LOCALAPPDATA", ("Google/Chrome/User Data", "Chromium/User Data",
                                        "BraveSoftware", "Microsoft/Edge/User Data"))):
        value = environ.get(var, "")
        if value and os.path.isabs(value):
            for rel in rels:
                add(_home_rel(value, rel))
    # The targets of symlinks among the secret places (~/.ssh/id_ed25519 ->
    # ~/keys/id_ed25519) hold the secret themselves.
    rules = _secret_rules(environ)
    home_keys = [_key(h) for h in homes(environ)]
    for link, target in _area_links(environ):
        tk = _key(target)
        if tk and not _home_or_above(tk, home_keys) and any(
                _secret_match(_key(link), rule) for rule in rules):
            add(target)
    covered = [path for path, _folder in out]
    seen_homes: set[str] = set()
    for home in homes(environ):
        real_home = os.path.realpath(home)
        if real_home in seen_homes or not _key(real_home):
            continue
        seen_homes.add(real_home)
        for path, _folder in _pattern_secrets(home, within):
            if not any(path == c or path.startswith(c.rstrip(os.sep) + os.sep) for c in covered):
                add(path)
    runtime = environ.get("XDG_RUNTIME_DIR", "")
    if runtime and os.path.isabs(runtime):
        add_names(os.path.join(runtime, "axross"), ("*token*",))
    return out
