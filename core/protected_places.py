"""Places under the home folder the agent never writes, moves or deletes.

Changed, they run code or widen the agent's rights with no prompt: its own
settings and MCP servers, shell and session start files, autostart entries,
user services, commands on PATH, Python start hooks, Git and pip settings,
SSH and GnuPG keys. core.mcp_server refuses tool writes there whatever the
root, and core.agent_sandbox mounts them read-only - the missing ones too,
as empty read-only places (an agent would otherwise create them).

Places under ``~/.config``, ``~/.local/share`` and ``~/.local/state`` are
also protected where ``$XDG_CONFIG_HOME``, ``$XDG_DATA_HOME`` and
``$XDG_STATE_HOME`` move them (both locations count).

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
)
#: Files (relative to the home folder).
HOME_FILES = (
    ".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".bash_aliases", ".profile",
    ".zshrc", ".zprofile", ".zshenv", ".zlogin", ".zlogout", ".xprofile", ".xsession",
    ".xsessionrc", ".xinitrc", ".pam_environment", ".inputrc", ".gitconfig", ".pip/pip.conf",
    ".vimrc", ".npmrc", ".claude.json",
)
#: The host's home folder, set by core.agent_sandbox for the worker.
HOST_HOME_ENV = "AXROSS_AGENT_HOST_HOME"
#: ``(home-relative prefix, XDG variable, variable naming the host's value
#: in the agent sandbox)``: where XDG moves the places below the prefix.
XDG_PLACES = (
    (".config", "XDG_CONFIG_HOME", "AXROSS_AGENT_HOST_XDG_CONFIG_HOME"),
    (".local/share", "XDG_DATA_HOME", "AXROSS_AGENT_HOST_XDG_DATA_HOME"),
    (".local/state", "XDG_STATE_HOME", "AXROSS_AGENT_HOST_XDG_STATE_HOME"),
)

def _case_insensitive() -> bool:
    return sys.platform in ("win32", "darwin")


def _key(path: str) -> tuple[str, ...]:
    """*path* as comparable components (normcase, and casefolded where
    names are case-insensitive)."""
    text = os.path.normcase(os.path.abspath(path))
    if _case_insensitive():
        text = text.casefold()
    return tuple(part for part in text.replace("\\", "/").split("/") if part)


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


def _xdg_bases(environ) -> list[tuple[str, str]]:
    """``(home-relative prefix, folder)`` of every XDG location set to an
    absolute path - this process's and, in the agent sandbox, the host's."""
    out: list[tuple[str, str]] = []
    for prefix, var, host_var in XDG_PLACES:
        for value in (environ.get(var, ""), environ.get(host_var, "")):
            if value and os.path.isabs(value):
                base = (prefix, os.path.abspath(value))
                if base not in out:
                    out.append(base)
    return out


def protected_paths(environ=os.environ) -> list[tuple[str, bool]]:
    """``(path, is_folder)`` of every protected place as typed: below each
    home and where the XDG variables move them."""
    out: list[tuple[str, bool]] = []
    seen: set[str] = set()

    def add(path: str, folder: bool) -> None:
        if path not in seen:
            seen.add(path)
            out.append((path, folder))

    entries = [(rel, True) for rel in HOME_DIRS] + [(rel, False) for rel in HOME_FILES]
    for home in homes(environ):
        for rel, folder in entries:
            add(os.path.join(home, *rel.split("/")), folder)
    for prefix, base in _xdg_bases(environ):
        for rel, folder in entries:
            if rel.startswith(prefix + "/"):
                add(os.path.join(base, *rel[len(prefix) + 1:].split("/")), folder)
    return out


def _all_places(environ) -> list[str]:
    """Every protected place, as typed and as resolved."""
    out: list[str] = []
    for place, _folder in protected_paths(environ):
        for variant in (place, os.path.realpath(place)):
            if variant not in out:
                out.append(variant)
    return out


def existing_places(environ=os.environ) -> list[str]:
    """The protected places that exist now (as typed, not resolved)."""
    return [place for place, _folder in protected_paths(environ) if os.path.lexists(place)]


def refusal(path: str, *, entry: bool = False, environ=os.environ) -> str | None:
    """Why *path* must not be changed, or None. *entry*: the path's entry
    is created, removed or moved, so a folder that holds a protected place
    is refused too (deleting or replacing ~/.config takes ~/.config/autostart)."""
    absolute = os.path.abspath(path)
    candidates = {absolute, os.path.realpath(absolute),
                  os.path.join(os.path.realpath(os.path.dirname(absolute)),
                               os.path.basename(absolute))}
    keys = {_key(c) for c in candidates}
    for place in _all_places(environ):
        pk = _key(place)
        for ck in keys:
            if ck[:len(pk)] == pk:
                return (f"{path}: the agent does not change {place} (it could run code "
                        "or widen its own rights from there)")
            if entry and len(ck) < len(pk) and pk[:len(ck)] == ck:
                return f"{path} holds {place}, which the agent does not change"
    return None


# -- the read side: secrets --------------------------------------------------------------
#
# Read, these turn "read my files" into the user's accounts: axross's OAuth
# refresh tokens (Google Drive, OneDrive, Dropbox), its MCP HTTP token, its
# chat accounts' encryption keys and sync tokens, Bluetooth link keys, the
# ADB key it made, and the SSH and GnuPG private keys. core.mcp_server
# refuses to hand their contents to a tool (read_file, grep, checksum,
# preview, copies, the groups' readers) unless the operator opts in.

#: Folders whose every file is secret (relative to the home folder).
SECRET_DIRS = (".local/state/axross/chat", ".gnupg/private-keys-v1.d",
               ".gnupg/openpgp-revocs.d")
#: Secret files (relative to the home folder).
SECRET_FILES = (".gnupg/secring.gpg", ".android/adbkey",
                ".local/share/axross/bluetooth-direct-keys.json")
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

    def add(path: str, kind: str, patterns: tuple[str, ...] = ()) -> None:
        for variant in (path, os.path.realpath(path)):
            rule = (_key(variant), kind, patterns)
            if rule not in rules:
                rules.append(rule)

    for home in homes(environ):
        for rel in SECRET_DIRS + SECRET_FILES:
            add(os.path.join(home, *rel.split("/")), "all")
        for rel, patterns in SECRET_NAMES:
            add(os.path.join(home, *rel.split("/")), "names", patterns)
        for rel, patterns in SECRET_UNLESS:
            add(os.path.join(home, *rel.split("/")), "unless", patterns)
    # Where XDG moves them: the Bluetooth keys, the MCP HTTP token.
    data = environ.get("XDG_DATA_HOME", "")
    if data and os.path.isabs(data):
        add(os.path.join(data, "axross", "bluetooth-direct-keys.json"), "all")
    runtime = environ.get("XDG_RUNTIME_DIR", "")
    if runtime and os.path.isabs(runtime):
        add(os.path.join(runtime, "axross"), "names", ("*token*",))
    return rules


def _secret_match(ck: tuple[str, ...], rule) -> bool:
    import fnmatch

    base, kind, patterns = rule
    if ck[:len(base)] != base:
        return False
    if kind == "all":
        return True
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
