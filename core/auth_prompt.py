"""Ask the user for the code a sign-in shows in the browser.

Some sign-ins end with a code on a web page that the user copies back (the
Dropbox flow without a redirect). Backends connect on a worker thread and
must not read stdin: started from the desktop, axross has no terminal, and
started from one, the question would sit unseen in it. The window installs
a handler (ui.auth_prompt) that shows a dialog and waits for it; without
one, :func:`ask_code` answers None and the backend says what to do.
"""

from __future__ import annotations

import logging
from typing import Callable

log = logging.getLogger(__name__)

#: ``handler(service, url) -> code or None``; callable from any thread.
_HANDLER: Callable[[str, str], str | None] | None = None


def set_handler(handler: Callable[[str, str], str | None] | None) -> None:
    global _HANDLER
    _HANDLER = handler


def has_handler() -> bool:
    return _HANDLER is not None


def ask_code(service: str, url: str) -> str | None:
    """The code the user pasted for *service* after visiting *url*, trimmed;
    None when nobody can be asked, the user cancelled or left it empty."""
    handler = _HANDLER
    if handler is None:
        return None
    try:
        answer = handler(service, url)
    except Exception:  # noqa: BLE001 - a broken dialog is no answer, never a crash
        log.exception("asking for the %s sign-in code failed", service)
        return None
    answer = (answer or "").strip()
    return answer or None


__all__ = ["ask_code", "has_handler", "set_handler"]
