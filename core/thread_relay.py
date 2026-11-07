"""Calls from worker threads into the GUI thread, without the crash.

Emitting a signal of a QObject from a worker thread is safe only while that
object lives. A window closed (``deleteLater``) or garbage-collected while
its worker is about to report deletes the object in the GUI thread while the
worker thread is inside ``emit()``: a use-after-free, a segfault in the GUI
thread. tests/test_media_viewer_ui.py reproduces it for the media viewer's
workers within seconds.

:class:`GuiCall` is the safe way. A worker calls it like a function, from any
thread; ``receiver.method(*args)`` then runs in the GUI thread, unless the
receiver has been deleted by then, in which case the call is dropped.
Workers emit only on one relay object that lives as long as the process;
receivers are looked up and called in the GUI thread, the thread that also
deletes them.

Nothing here runs when a receiver is destroyed - no slot on ``destroyed``, no
lock taken. A garbage collection can delete a receiver at any allocation, on
any thread, in the middle of other code: a Python slot on ``destroyed`` of an
object collected as part of a reference cycle crashed PyQt there, and a lock
held by the interrupted code was taken again. Entries of deleted receivers
are dropped when a call for them arrives and swept now and then instead.
"""

from __future__ import annotations

import itertools
import threading
import weakref
from collections.abc import Callable
from typing import Any

from PyQt6 import sip
from PyQt6.QtCore import QCoreApplication, QObject, pyqtSignal

#: A sweep of the entries of deleted receivers after this many new ones.
SWEEP_EVERY = 256


class _Relay(QObject):
    """The one object worker threads emit on. Never deleted."""

    post = pyqtSignal(object, object)  # key, args

    def __init__(self) -> None:
        super().__init__()
        self.post.connect(self._dispatch)  # queued when emitted from a worker

    def _dispatch(self, key, args: tuple) -> None:
        entry = _TARGETS.get(key)
        if entry is None:
            return
        ref, func = entry
        receiver = ref()
        if receiver is None or sip.isdeleted(receiver):
            _TARGETS.pop(key, None)
            return
        func(receiver, *args)


#: key -> (weak reference to the receiver, the method's function). Single
#: dict operations are atomic, so no lock (see the module docstring).
_TARGETS: dict[int, tuple[weakref.ref, Callable[..., Any]]] = {}
_KEYS = itertools.count(1)
_RELAY: _Relay | None = None
_RELAY_LOCK = threading.Lock()


def _relay() -> _Relay:
    global _RELAY
    if _RELAY is None or sip.isdeleted(_RELAY):
        with _RELAY_LOCK:
            # Deleted anyway (sip.delete by hand): a new one for new calls;
            # GuiCalls made before keep the old, dead signal.
            if _RELAY is None or sip.isdeleted(_RELAY):
                relay = _Relay()
                app = QCoreApplication.instance()
                if app is not None and relay.thread() is not app.thread():
                    relay.moveToThread(app.thread())
                # Owned by C++ from now on: the exit clean-up
                # (core/qt_exit.py) deletes every Python-owned QObject while
                # daemon workers may still be calling into this one.
                sip.transferto(relay, None)
                _RELAY = relay
    return _RELAY


def _alive(ref: weakref.ref) -> bool:
    obj = ref()
    return obj is not None and not sip.isdeleted(obj)


def _sweep() -> None:
    for key, (ref, _func) in list(_TARGETS.items()):
        if not _alive(ref):
            _TARGETS.pop(key, None)


class GuiCall:
    """``GuiCall(receiver.method)(*args)``, from any thread, runs
    ``receiver.method(*args)`` in the GUI thread while *receiver* - a
    QObject - lives; after its deletion the call is dropped.

    Only a method of a QObject: the GuiCall keeps a weak reference to the
    object and the method's function, so it never keeps the object alive.
    """

    __slots__ = ("_key", "_post")

    def __init__(self, method: Callable[..., Any]) -> None:
        receiver = getattr(method, "__self__", None)
        if not isinstance(receiver, QObject):
            raise TypeError("GuiCall takes a method of a QObject")
        relay = _relay()
        key = next(_KEYS)
        _TARGETS[key] = (weakref.ref(receiver), method.__func__)
        if key % SWEEP_EVERY == 0:
            _sweep()
        self._key = key
        self._post = relay.post

    def __call__(self, *args: Any) -> None:
        self._post.emit(self._key, args)


__all__ = ["GuiCall"]
