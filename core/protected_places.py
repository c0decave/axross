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
DENY_ALL_BELOW = (".config", ".local/share", ".local/state")
#: The same for macOS (all of ~/Library) and Windows (%APPDATA%).
MACOS_DENY_ALL_BELOW = ("Library",)
WINDOWS_DENY_ALL_BELOW = ("AppData/Roaming",)
#: Hidden entries of the home folder that writes may change anyway
#: (reviewed: nothing runs code from them). Compared case-folded.
HIDDEN_WRITABLE: tuple[str, ...] = ()
#: Git runs code from these wherever a repository is (hooks, ``core.fsmonitor``,
#: ``core.pager`` and filters in the config, submodule URLs): refused anywhere.
#: Names below a ``.git`` folder; a ``.git`` entry itself (a folder or a
#: ``gitdir:`` file) is refused too, or a folder renamed to ``.git`` brings
#: a config along.
GIT_DIR = ".git"
GIT_CODE_NAMES = ("config", "config.worktree", "hooks", "info")
GIT_TREE_NAMES = (".gitmodules",)
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
#: (line by line, ``XDG_..._HOME=value``) for the same reason.
XDG_PROFILE_FILES = (".profile", ".bash_profile", ".bashrc", ".zshenv", ".zprofile", ".zshrc",
                     ".pam_environment", ".config/environment.d")
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


#: The XDG variables a profile line may set (``XDG_CONFIG_HOME=...``,
#: ``export XDG_DATA_HOME="$HOME/x"``, ``XDG_CONFIG_HOME DEFAULT=@{HOME}/x``).
_XDG_LINE = None
#: ``path -> ((mtime_ns, size), {variable: [values]})``: profile files read.
_PROFILE_CACHE: dict[str, tuple[tuple[int, int], dict[str, list[str]]]] = {}
_XDG_VARS = tuple(var for _prefix, var, _host in XDG_PLACES)


def _profile_values(path: str, home: str) -> dict[str, list[str]]:
    """The absolute XDG folders *path* (a shell or session file) sets."""
    global _XDG_LINE
    import re

    try:
        st = os.stat(path)
    except OSError:
        return {}
    stamp = (st.st_mtime_ns, st.st_size)
    cached = _PROFILE_CACHE.get(path)
    if cached is not None and cached[0] == stamp:
        return cached[1]
    if _XDG_LINE is None:
        _XDG_LINE = re.compile(r"^\s*(?:export\s+)?(XDG_(?:CONFIG|DATA|STATE|CACHE)_HOME)"
                               r"(?:\s+DEFAULT)?\s*=\s*(\S+?)\s*;?\s*$")
    found: dict[str, list[str]] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read(256 * 1024)
    except OSError:
        text = ""
    for line in text.splitlines():
        match = _XDG_LINE.match(line)
        if not match:
            continue
        value = match.group(2).strip("'\"")
        for token in ("${HOME}", "$HOME", "@{HOME}"):
            value = value.replace(token, home)
        if value.startswith("~/"):
            value = home + value[1:]
        if "$" in value or not os.path.isabs(value):
            continue  # another variable or a relative path (the XDG spec ignores those)
        found.setdefault(match.group(1), []).append(os.path.normpath(value))
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
            try:
                files += sorted(os.path.join(path, n) for n in os.listdir(path)
                                if n.endswith(".conf"))[:64]
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
    """Whether a *granted* folder lifts default-deny for *place* (it lies in
    one that is itself in a default-deny place: the user named it)."""
    areas = _deny_areas(environ)
    pk = _key(os.path.abspath(place))
    return any(pk[:len(g)] == g for g in _lifting_grants(granted, areas))


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


def _denied_entry(ck: tuple[str, ...], areas) -> tuple[str, ...] | None:
    """The key of the default-deny entry *ck* is (or lies in), or None."""
    for base, kind in areas:
        n = len(base)
        if len(ck) > n and ck[:n] == base and (kind == "all" or _hidden_name(ck[n])):
            return ck[:n + 1]
    return None


def _lifting_grants(granted, areas) -> list[tuple[str, ...]]:
    """The keys of the *granted* folders that lie in a default-deny area
    (or are an "all" area themselves): below them default-deny does not
    apply - the user named that folder. A granted home folder (or one
    above it) lifts nothing."""
    out: list[tuple[str, ...]] = []
    all_bases = {base for base, kind in areas if kind == "all"}
    for folder in granted or ():
        if not folder or not os.path.isabs(folder):
            continue
        for variant in (os.path.abspath(folder), os.path.realpath(folder)):
            gk = _key(variant)
            if (gk in all_bases or _denied_entry(gk, areas) is not None) and gk not in out:
                out.append(gk)
    return out


def _git_code(ck: tuple[str, ...]) -> bool:
    """Whether *ck* is a Git file that runs code (:data:`GIT_CODE_NAMES`
    below a ``.git`` folder, a ``.git`` entry itself, ``.gitmodules``)."""
    names = tuple(n.casefold() for n in GIT_CODE_NAMES)
    if ck and ck[-1] in {n.casefold() for n in GIT_TREE_NAMES}:
        return True
    for i, part in enumerate(ck):
        if part == GIT_DIR:
            if i == len(ck) - 1:
                return True
            if any(later.casefold() in names for later in ck[i + 1:]):
                return True
    return False


def write_checker(environ=os.environ, *, granted=()):
    """:func:`refusal` with the places resolved once - for the many paths of
    one tool call (an archive's members); a new one per call."""
    places = [(_key(place), place) for place in _all_places(environ)]
    areas = _deny_areas(environ)
    lifting = _lifting_grants(granted, areas)

    def check(path: str, *, entry: bool = False) -> str | None:
        absolute = os.path.abspath(path)
        candidates = {absolute, os.path.realpath(absolute),
                      os.path.join(os.path.realpath(os.path.dirname(absolute)),
                                   os.path.basename(absolute))}
        for candidate in candidates:
            if _start_name(os.path.basename(candidate)):
                return (f"{path}: the agent does not write Python start files "
                        f"({', '.join(START_NAMES)}): Python runs them at every start")
        keys = {_key(c) for c in candidates}
        for pk, place in places:
            for ck in keys:
                if ck[:len(pk)] == pk:
                    return (f"{path}: the agent does not change {place} (it could run code "
                            "or widen its own rights from there)")
                if entry and len(ck) < len(pk) and pk[:len(ck)] == ck:
                    return f"{path} holds {place}, which the agent does not change"
        for ck in keys:
            if _git_code(ck):
                return (f"{path}: the agent does not change Git's settings, hooks or "
                        "submodules (.git/config, .git/hooks, .git/info, .gitmodules, a "
                        ".git entry): Git runs code from them")
            if TRASH_NAME in ck:
                return (f"{path}: the agent does not change axross's trash ({TRASH_NAME}): "
                        "what is restored from it is put back with axross's rights")
            if (_denied_entry(ck, areas) is not None
                    and not any(ck[:len(g)] == g for g in lifting)):
                return (f"{path}: the agent does not change hidden entries of the home "
                        "folder or entries of the settings and data folders (~/.config, "
                        "~/.local/share, ~/.local/state, ~/Library, %APPDATA%) unless that "
                        "folder is granted to it: programs run code from many of them")
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
    folders) that is itself in such a place."""
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
               ".var/app/com.brave.Browser", ".snap/firefox", ".snap/chromium")
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
                ".local/share/fish/fish_history")
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
#: package caches: many files, no credentials).
SECRET_WALK_SKIP = ("site-packages", "dist-packages", "node_modules", "__pycache__", ".git")
#: Most entries the agent sandbox looks at for :data:`SECRET_HIDDEN_PATTERNS`
#: (:func:`secret_hides`), and how deep.
MAX_SECRET_WALK = 50_000
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


def secret_checker(environ=os.environ):
    """:func:`read_refusal` with the secret places resolved once - for the
    many paths of one tool call (grep, recursive_checksum); a new one per
    call, so a place re-pointed later is seen by the next call."""
    rules = _secret_rules(environ)

    def check(path: str, *, entry: bool = False) -> str | None:
        # The contents are what the path resolves to; a symlink to a
        # secret, or a folder linked into ~/.ssh, resolves into the place.
        absolute = os.path.abspath(path)
        keys = {_key(absolute), _key(os.path.realpath(absolute))}
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
        return None

    return check


def read_refusal(path: str, *, entry: bool = False, environ=os.environ) -> str | None:
    """Why the contents of *path* must not be handed to a tool, or None.
    *entry*: the path is copied or moved as a whole, so a folder that holds
    a secret is refused too (copying ~/.ssh takes its keys along). Compared
    like :func:`refusal` (components, case, resolved paths)."""
    return secret_checker(environ)(path, entry=entry)


def _pattern_secrets(home: str, within) -> list[tuple[str, bool]]:
    """``(path, is_folder)`` of the existing entries below *home*'s hidden
    entries whose name matches :data:`SECRET_HIDDEN_PATTERNS` (a matching
    folder whole) - only below the folders in *within* (None: everywhere).
    A bounded walk (:data:`MAX_SECRET_WALK` entries, :data:`MAX_SECRET_DEPTH`
    deep, :data:`MAX_SECRET_PATTERN_HIDES` found); symlinks are not followed."""
    import logging

    found: list[tuple[str, bool]] = []
    real_home = os.path.realpath(home)
    try:
        top = sorted(n for n in os.listdir(real_home) if n.startswith("."))
    except OSError:
        return found

    def wanted(path: str) -> bool:
        if within is None:
            return True
        return any(path == w or path.startswith(w.rstrip(os.sep) + os.sep)
                   or w.startswith(path.rstrip(os.sep) + os.sep) for w in within)

    budget = MAX_SECRET_WALK
    stack = [(os.path.join(real_home, name), 0) for name in reversed(top)]
    while stack and budget > 0 and len(found) < MAX_SECRET_PATTERN_HIDES:
        path, depth = stack.pop()
        budget -= 1
        if not wanted(path):
            continue
        try:
            is_link = os.path.islink(path)
            is_dir = not is_link and os.path.isdir(path)
        except OSError:
            continue
        if is_link:
            continue
        name = os.path.basename(path)
        if (depth == 0 or not is_dir) and _secret_file_name(name):
            found.append((path, is_dir))
            continue
        if is_dir and depth < MAX_SECRET_DEPTH and name not in SECRET_WALK_SKIP:
            try:
                names = sorted(os.listdir(path))
            except OSError:
                continue
            stack.extend((os.path.join(path, n), depth + 1) for n in reversed(names))
    if stack and (budget <= 0 or len(found) >= MAX_SECRET_PATTERN_HIDES):
        logging.getLogger(__name__).warning(
            "secret files: stopped looking below %s's hidden folders after %d entries "
            "(%d found); the rest is not covered in the agent sandbox",
            home, MAX_SECRET_WALK - budget, len(found))
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
