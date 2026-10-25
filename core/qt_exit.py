"""Delete the Qt objects Python still owns before PyQt's exit clean-up does.

When the interpreter exits, PyQt6 runs ``cleanup_on_exit``, an atexit
handler that ``import PyQt6.QtCore`` registers. It walks sip's map of
wrapped C++ objects (``sip_api_visit_wrappers``) and deletes every QObject
Python still owns from inside that walk, with the GIL released. A
destructor that calls back into Python there - a ``destroyed`` slot, a
Python event filter that gets the Destroy event of a child - registers new
wrappers; when that makes sip grow its map, the walk goes on in the freed
table and the process dies with SIGSEGV after all its work was done
(pyqt6_sip 13.11.1 sip_core.c sip_api_visit_wrappers; reproduced with
PyQt6 6.10/Python 3.12 and PyQt6 6.11/Python 3.14 by a script that uses
no axross code).

The handler installed here runs before PyQt's (atexit runs its handlers
last in, first out, and installing imports PyQt6.QtCore first) and deletes
the same objects PyQt would - Python-owned QObjects except the application
object and running threads - one by one with ``sip.delete``, outside any
walk. PyQt's walk then has nothing left to delete, so no Python code runs
inside it.

What it costs: the destructors run a little earlier, before the atexit
handlers registered between ``import PyQt6.QtCore`` and the install. And
``sip.delete`` hands an object that lives in another thread to
``deleteLater`` (PyQt's release function for QObject does that), so the
object is deleted in its own thread when that thread still runs an event
loop and not at all when the thread has finished; PyQt's walk deleted it
from the main thread instead. The process ends either way.
"""

from __future__ import annotations

import atexit
import gc
import logging
import sys

log = logging.getLogger(__name__)

#: A destructor may build new objects Python owns; each round deletes what
#: the previous one left. Bounded: a slot that builds a new object on every
#: deletion must not keep the exit going.
MAX_ROUNDS = 5

_installed = False


def _qt():
    """(sip, QCoreApplication, QObject, QThread), or None without PyQt6."""
    try:
        from PyQt6 import sip
        from PyQt6.QtCore import QCoreApplication, QObject, QThread
    except ImportError:
        return None
    return sip, QCoreApplication, QObject, QThread


def _python_owned(qt) -> list:
    """The QObjects PyQt's exit walk would delete, top-level ones first."""
    sip, QCoreApplication, QObject, QThread = qt
    app = QCoreApplication.instance()
    found = []
    for obj in gc.get_objects():
        # type(), not isinstance(): a proxy's __class__ can raise.
        if not issubclass(type(obj), QObject) or obj is app:
            continue
        try:
            if sip.isdeleted(obj) or not sip.ispyowned(obj):
                continue
            if isinstance(obj, QThread) and obj.isRunning():
                continue
            found.append((obj.parent() is not None, obj))
        except RuntimeError:
            continue
    # A parent deletes its children with it; those are skipped below.
    found.sort(key=lambda pair: pair[0])
    return [obj for _, obj in found]


def delete_python_owned_qobjects() -> int:
    """Delete every QObject Python owns, except the application object and
    running threads; return how many were handed to ``sip.delete`` (one
    living in another thread goes to its ``deleteLater``).

    Only for the end of the process: it deletes windows, models and
    workers that are still referenced.
    """
    qt = _qt()
    if qt is None:
        return 0
    sip = qt[0]
    deleted = 0
    for _ in range(MAX_ROUNDS):
        pending = _python_owned(qt)
        if not pending:
            break
        for obj in pending:
            try:
                if sip.isdeleted(obj) or not sip.ispyowned(obj):
                    continue  # went with its parent, or a destructor took it
                sip.delete(obj)
                deleted += 1
            except RuntimeError as exc:
                log.debug("Exit clean-up skipped a %s: %s", type(obj).__name__, exc)
        del pending
    return deleted


def _at_exit() -> None:
    try:
        count = delete_python_owned_qobjects()
    except Exception:  # an exit handler must not hide the process's status
        log.debug("Exit clean-up of Qt objects failed", exc_info=True)
        return
    if count:
        log.debug("Exit clean-up deleted %d Qt objects before PyQt's", count)


def install_orderly_qt_exit(*, only_if_loaded: bool = False) -> bool:
    """Register the exit handler once; True when it is registered.

    False without PyQt6, and with ``only_if_loaded`` when nothing has
    imported PyQt6.QtCore yet (a headless run needs no handler and does not
    pay for the import).
    """
    global _installed
    if _installed:
        return True
    if only_if_loaded and "PyQt6.QtCore" not in sys.modules:
        return False
    # Imported first, so PyQt's handler is registered before this one and
    # runs after it.
    if _qt() is None:
        return False
    atexit.register(_at_exit)
    _installed = True
    return True
