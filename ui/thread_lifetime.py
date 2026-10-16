"""Moved to :mod:`core.thread_lifetime`; the connect worker needs it too.

Re-exported here so the dialogs and their tests keep one registry.
"""

from __future__ import annotations

from core.thread_lifetime import _DETACHED, detach_running_thread  # noqa: F401

__all__ = ["detach_running_thread"]
