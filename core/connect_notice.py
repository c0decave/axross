"""Notes a backend gives while it connects, for whoever started the connect.

A connect may wait for something only the user can do elsewhere: the
phone asks "Allow USB debugging?" (core.adb_client) and nothing happens
until it is answered. The code that started the connect - Test
Connection in the connection dialog, the main window's connect worker -
listens with :func:`receiving` around ``ConnectionManager.connect`` and
shows each note (a status line, the status bar); the backend calls
:func:`notify` with a translated sentence. Without a listener in the
connecting thread a note goes nowhere.

The listener is per thread (a ContextVar): two connects at once each hear
only their own backend.
"""

from __future__ import annotations

import contextlib
import contextvars
import logging
from collections.abc import Callable, Iterator

log = logging.getLogger(__name__)

_LISTENER: contextvars.ContextVar[Callable[[str], object] | None] = contextvars.ContextVar(
    "axross_connect_notice", default=None
)


@contextlib.contextmanager
def receiving(listener: Callable[[str], object] | None) -> Iterator[None]:
    """*listener(text)* hears the notes of connects made in the body."""
    token = _LISTENER.set(listener)
    try:
        yield
    finally:
        _LISTENER.reset(token)


def notify(text: str) -> None:
    """Hand *text* to the listener of this thread, if there is one. A
    listener that fails is logged: the connect goes on."""
    listener = _LISTENER.get()
    if listener is None:
        return
    try:
        listener(text)
    except Exception as exc:  # noqa: BLE001 - a status line must not stop a connect
        log.debug("connect notice listener failed: %s", exc)


__all__ = ["notify", "receiving"]
