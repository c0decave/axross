"""Hand a file or a web page to the desktop - also from a frozen build.

``QDesktopServices.openUrl`` and Python's ``webbrowser`` start a host
program (xdg-open, a browser, ``/bin/sh``) with this process's environment
and accept no other. In a PyInstaller one-file build that environment
points LD_LIBRARY_PATH at the extraction folder. Reproduced with
dist/axross-full 0.13.22 and a stub xdg-open first on PATH: openUrl (xcb)
returned True, webbrowser.open returned False, and both children died with
"/bin/sh: symbol lookup error: /bin/sh: undefined symbol:
rl_trim_arg_from_keyseq" - nothing opened.

So a frozen build on a freedesktop platform starts ``xdg-open`` itself,
with :func:`core.subprocess_env.clean_child_env`; xdg-open asks the desktop
(or ``$BROWSER``) which program to use, as Qt and webbrowser would. From
the source tree, on macOS (LaunchServices, no child) and on Windows
(ShellExecute) everything goes the way it always went.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import threading
import webbrowser

from core.subprocess_env import clean_child_env

log = logging.getLogger(__name__)

#: The name the clean browser is registered under in ``webbrowser``.
BROWSER_NAME = "axross-xdg-open"

_install_lock = threading.Lock()
_installed = False


def needs_clean_opener(frozen: bool | None = None) -> bool:
    """True where Qt and webbrowser would start the opener with this
    process's loader path: a frozen build on Linux or a BSD."""
    if frozen is None:
        frozen = bool(getattr(sys, "frozen", False))
    return frozen and os.name == "posix" and sys.platform != "darwin"


def spawn_opener(target: str) -> bool:
    """Start ``xdg-open target`` with a clean environment, detached from
    this process's session. False when there is no xdg-open, it cannot be
    started, or *target* would read as an option (``--version``)."""
    if not target or target.startswith("-"):
        log.warning("desktop open: refusing a target that reads as an option: %r", target)
        return False
    opener = shutil.which("xdg-open")
    if opener is None:
        return False
    try:
        proc = subprocess.Popen(
            [opener, target],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
            env=clean_child_env(),
        )
    except OSError as exc:
        log.warning("desktop open: %s could not be started: %s", opener, exc)
        return False
    # xdg-open hands over and ends; reap it so no zombie stays behind.
    threading.Thread(target=proc.wait, name="xdg-open-reaper", daemon=True).start()
    return True


def open_url(url) -> bool:
    """Open *url* - a ``QUrl``, a URL string or a local path - in the
    desktop's handler, like ``QDesktopServices.openUrl``, which it falls
    back to wherever the clean opener is not needed or not available."""
    from PyQt6.QtCore import QUrl
    from PyQt6.QtGui import QDesktopServices

    if isinstance(url, QUrl):
        qurl = url
    elif os.path.isabs(str(url)):
        qurl = QUrl.fromLocalFile(str(url))
    else:
        qurl = QUrl(str(url))
    if needs_clean_opener():
        if qurl.isLocalFile():
            target = qurl.toLocalFile()
        else:
            target = qurl.toString(QUrl.ComponentFormattingOption.FullyEncoded)
        if spawn_opener(target):
            return True
        log.warning("desktop open: no clean xdg-open - falling back to Qt for %s", target)
    return QDesktopServices.openUrl(qurl)


def open_in_browser(url: str) -> bool:
    """Open a web page without Qt (the headless paths, e.g. a Dropbox
    login from an MCP server): the clean opener where it is needed, else
    ``webbrowser.open``."""
    if needs_clean_opener() and spawn_opener(url):
        return True
    return webbrowser.open(url)


class CleanEnvBrowser(webbrowser.BaseBrowser):
    """A ``webbrowser`` browser that opens through :func:`spawn_opener`."""

    def open(self, url, new=0, autoraise=True):  # noqa: A003 - webbrowser's API
        sys.audit("webbrowser.open", url)
        return spawn_opener(url)


def install_clean_webbrowser(*, frozen: bool | None = None) -> bool:
    """Put :class:`CleanEnvBrowser` first in ``webbrowser``'s order, where
    it is needed, so the browser logins inside google-auth-oauthlib (Google
    Drive) and msal (OneDrive) start a clean xdg-open; they call
    ``webbrowser`` themselves. Called right before such a login. Also ahead
    of ``$BROWSER``, which webbrowser would start with the inherited
    environment; xdg-open honours it in turn. Registers once per process.
    True when the clean browser is in place."""
    global _installed
    if not needs_clean_opener(frozen) or shutil.which("xdg-open") is None:
        return False
    with _install_lock:
        if not _installed:
            webbrowser.register(BROWSER_NAME, None, CleanEnvBrowser(BROWSER_NAME),
                                preferred=True)
            _installed = True
    return True


__all__ = [
    "BROWSER_NAME",
    "CleanEnvBrowser",
    "install_clean_webbrowser",
    "needs_clean_opener",
    "open_in_browser",
    "open_url",
    "spawn_opener",
]
