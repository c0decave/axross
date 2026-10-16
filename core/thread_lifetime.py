"""Letting a worker QThread outlive the object that started it.

A QThread parented to a dialog dies with it, and destroying a QThread
that still runs aborts the whole process ("QThread: Destroyed while thread
is still running"). The main window keeps its dialogs as children until it
is destroyed itself, so quitting the app during a slow network attempt
started from a dialog took the app down. A blocking network call cannot be
interrupted, and waiting for it would freeze the window, so a closing
dialog hands the thread over instead: its signals are cut from the dialog
and it deletes itself once its run() returns. The same goes for the main
window's connect and scheduler threads when the window closes, and for a
connect task dropped while its attempt still runs.
"""

from __future__ import annotations

import logging

from PyQt6.QtCore import QThread, pyqtBoundSignal

log = logging.getLogger(__name__)

#: Threads handed over by a closed owner and still running, with the
#: objects that must live as long as they do (a worker moved onto one).
_DETACHED: dict[QThread, tuple] = {}


def detach_running_thread(
    thread: QThread | None, *signals: pyqtBoundSignal, keep: tuple = ()
) -> bool:
    """Hand a still-running *thread* over so it may outlive its owner.

    Every slot on *signals* (the thread's result signals) is disconnected,
    so a late result reaches nobody. *keep* holds objects the running code
    still uses, such as a worker QObject whose slot is executing. Returns
    False when there was nothing to detach (no thread, or it finished).
    """
    # Not isRunning(): inside Qt's finish phase it is already False while
    # the thread still has to delete its worker, which needs the GIL. A
    # QThread destroyed then waits for it with the GIL held - a deadlock.
    # wait(0) is True only once the thread is really done.
    if thread is None or thread.wait(0):
        return False
    for signal in signals:
        try:
            signal.disconnect()
        except TypeError:  # nothing connected
            pass
    thread.setParent(None)
    _DETACHED[thread] = keep
    if thread.isRunning():
        thread.finished.connect(thread.deleteLater)
    else:
        # finished() is being emitted right now, a new connection may miss
        # it. The event loop deletes the thread, and its destructor's wait
        # runs there without the GIL.
        thread.deleteLater()
    thread.destroyed.connect(lambda _obj=None, t=thread: _DETACHED.pop(t, None))
    log.debug("left a running worker thread to finish on its own")
    return True

