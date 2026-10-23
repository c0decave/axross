"""Open Terminal Here: which panes have a shell, and how to start one.

Two ways to get a terminal in the folder a pane shows:

* **Embedded** - the terminal dock (``ui.terminal_widget.TerminalDock``)
  opens a local shell in a local folder, or a shell on the pane's own SSH
  transport (SFTP / SCP sessions) followed by a ``cd`` line built by
  :func:`remote_cd_command`. Every other protocol has no shell.
* **External** - :func:`launch_external_terminal` starts the user's
  terminal emulator in a local folder: ``$TERMINAL`` first, then the
  common emulators in :data:`KNOWN_TERMINALS`. Argument list, no shell,
  ``cwd`` set, new session, stdio detached; a daemon thread reaps the
  child so it never lingers as a zombie.

No Qt here: the pane decides what to show, the main window routes the
request to the dock.
"""

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import threading
from collections.abc import Mapping

#: Tried in this order when ``$TERMINAL`` names nothing runnable.
KNOWN_TERMINALS: tuple[str, ...] = (
    "x-terminal-emulator",
    "gnome-terminal",
    "konsole",
    "xfce4-terminal",
    "alacritty",
    "kitty",
    "foot",
    "wezterm",
    "xterm",
)

LOCAL = "local"
SSH = "ssh"
NONE = ""


class TerminalLaunchError(OSError):
    """No terminal could be started; the message is meant for the user."""


# ---------------------------------------------------------------------------
# Which panes have a shell
# ---------------------------------------------------------------------------


def ssh_transport(backend):
    """The backend's live SSH transport, or None.

    SSHSession and the SCP session expose paramiko's ``Transport`` as
    ``transport``; a shell channel is opened on it with ``open_session``.
    """
    transport = getattr(backend, "transport", None)
    if transport is None or not callable(getattr(transport, "open_session", None)):
        return None
    try:
        return transport if transport.is_active() else None
    except Exception:  # noqa: BLE001 - a broken transport has no shell
        return None


#: Connection profiles whose session carries an SSH transport a shell can
#: be opened on (the terminal pane and terminal bookmarks use it).
SHELL_PROTOCOLS: tuple[str, ...] = ("sftp", "scp")


def profile_has_shell(profile) -> bool:
    """Whether a saved connection *profile* can open a terminal."""
    return getattr(profile, "protocol", "") in SHELL_PROTOCOLS


def shell_kind(backend) -> str:
    """:data:`LOCAL`, :data:`SSH` or :data:`NONE` for a pane's backend."""
    from core.local_fs import LocalFS

    if isinstance(backend, LocalFS):
        return LOCAL
    if ssh_transport(backend) is not None:
        return SSH
    return NONE


def no_shell_reason(backend) -> str:
    """Tooltip for a disabled *Open Terminal Here* entry."""
    if getattr(backend, "transport", None) is not None and ssh_transport(backend) is None:
        return "The SSH connection of this pane is not active; reconnect first."
    kind = type(backend).__name__
    return (
        f"{kind} has no shell: a terminal opens in local folders and on "
        "SSH connections (SFTP / SCP) only."
    )


# ---------------------------------------------------------------------------
# Remote cd line
# ---------------------------------------------------------------------------


def remote_cd_command(path: str) -> bytes:
    """The line that moves a fresh remote shell into *path*.

    ``shlex.quote`` keeps spaces, quotes and ``$``/``;`` literal, and ``--``
    keeps a leading dash from reading as an option. The leading space keeps
    it out of the history of shells that honour ``ignorespace``. Control
    characters are refused: they would reach the remote tty's line
    discipline (``^C``, ``^U``, a newline ending the line early) before any
    quoting applies.

    ``~`` and ``~/...`` (a terminal bookmark's folder is typed by hand) name
    the remote home folder: the tilde stays unquoted so the remote shell
    expands it, the rest is quoted. Every other path - all a pane sends are
    absolute - is quoted whole.
    """
    if not path:
        raise ValueError("remote folder is empty")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in path):
        raise ValueError(f"remote folder contains a control character: {path!r}")
    if path == "~" or path.startswith("~/"):
        rest = path[2:]
        return (f" cd -- ~/{shlex.quote(rest)}\n" if rest else " cd -- ~\n").encode()
    return f" cd -- {shlex.quote(path)}\n".encode()


# ---------------------------------------------------------------------------
# External terminal emulator
# ---------------------------------------------------------------------------


def find_terminal(environ: Mapping[str, str] | None = None) -> list[str] | None:
    """The terminal to start as an argv prefix, or None when none is found.

    ``$TERMINAL`` may carry arguments (split like a shell would, never run
    by one); its program must resolve on ``PATH``. Otherwise the first of
    :data:`KNOWN_TERMINALS` that exists wins.
    """
    env = os.environ if environ is None else environ
    wanted = (env.get("TERMINAL") or "").strip()
    if wanted:
        try:
            parts = shlex.split(wanted)
        except ValueError:
            parts = []
        if parts:
            program = shutil.which(parts[0])
            if program:
                return [program, *parts[1:]]
    for name in KNOWN_TERMINALS:
        program = shutil.which(name)
        if program:
            return [program]
    return None


# How each emulator is told its working directory. The process cwd is set
# as well, which is all that emulators without a flag (xterm, the Debian
# alternative) need; gnome-terminal hands the window to a server process,
# so it needs the flag.
_WORKDIR_ARGS: dict[str, tuple[str, ...]] = {
    "gnome-terminal": ("--working-directory={dir}",),
    "konsole": ("--workdir", "{dir}"),
    "xfce4-terminal": ("--working-directory={dir}",),
    "alacritty": ("--working-directory", "{dir}"),
    "kitty": ("--directory", "{dir}"),
    "foot": ("--working-directory={dir}",),
    "wezterm": ("start", "--cwd", "{dir}"),
}


def terminal_command(prefix: list[str], directory: str) -> list[str]:
    """*prefix* (from :func:`find_terminal`) plus the working-directory flag."""
    name = os.path.basename(prefix[0])
    extra = [arg.replace("{dir}", directory) for arg in _WORKDIR_ARGS.get(name, ())]
    return [*prefix, *extra]


def _reap(proc) -> None:
    try:
        proc.wait()
    except Exception:  # noqa: BLE001 - nothing to report to anyone
        pass


def launch_external_terminal(
    directory: str, *, environ: Mapping[str, str] | None = None
) -> list[str]:
    """Start a terminal emulator in local *directory*; returns the argv used.

    *environ* is where ``$TERMINAL`` is looked up (default ``os.environ``);
    the emulator itself always inherits the real environment. A file path
    opens its folder. Raises :class:`TerminalLaunchError` when the folder
    is gone (deleted, unmounted), when no emulator is installed or when it
    fails to start.
    """
    from core.subprocess_env import clean_child_env

    folder = os.path.abspath(directory)
    if os.path.isfile(folder):
        folder = os.path.dirname(folder)
    if not os.path.isdir(folder):
        raise TerminalLaunchError(f"{folder} is no longer a folder (deleted or unmounted?)")
    prefix = find_terminal(environ)
    if prefix is None:
        raise TerminalLaunchError(
            "No terminal emulator found. Set $TERMINAL or install one of: "
            + ", ".join(KNOWN_TERMINALS)
            + "."
        )
    argv = terminal_command(prefix, folder)
    try:
        proc = subprocess.Popen(
            argv,
            cwd=folder,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
            # The real environment (DISPLAY, WAYLAND_DISPLAY, ...), minus a
            # frozen bundle's loader paths; *environ* only picks the program.
            env=clean_child_env(),
        )
    except OSError as exc:
        raise TerminalLaunchError(f"{argv[0]} could not be started: {exc}") from exc
    threading.Thread(target=_reap, args=(proc,), name="terminal-reaper", daemon=True).start()
    return argv


__all__ = [
    "KNOWN_TERMINALS",
    "LOCAL",
    "NONE",
    "SSH",
    "TerminalLaunchError",
    "find_terminal",
    "launch_external_terminal",
    "no_shell_reason",
    "remote_cd_command",
    "shell_kind",
    "ssh_transport",
    "terminal_command",
]
