"""Production tarpit — a 3-second countdown wrapper around mutating
operations against profiles flagged as production.

Anti-typo discipline. The classic story is "I meant to ``rm -rf`` on
my dev box but I had the prod tab focused". axross already has a
preview / dry-run layer for the explicit ``preview_*`` verbs; this
module is the *implicit* layer — when a profile is flagged
``production = True`` and the operator triggers a destructive op
without a preview, axross interposes a short countdown with a clear
"this is prod, hit Esc to bail" banner.

Design constraints (intentional):

* The tarpit fires **once per pane-session**, not per operation. The
  point is to shake the operator out of muscle memory, not to
  drown them in confirmations.
* The Esc-to-cancel behaviour is implemented by the GUI layer; this
  module just exposes the gate (``arm_for_session`` + ``should_arm``)
  and the per-call wrapper. Headless / REPL contexts get a stdin
  prompt instead.
* The flag lives on the connection profile, not on the path. Path-level
  rules (e.g. "/etc is sacred") are out of scope here — they belong in
  ``core/path_policy.py``.
* Read-only profiles (`read_only` flag, separate addon) are a different
  feature; the tarpit only addresses *intentional* writes against
  *intentional* prod profiles.

The wrapper is a context manager:

    >>> from core.safety_tarpit import production_gate
    >>> with production_gate(profile, "remove file /var/log/foo.log"):
    ...     backend.remove("/var/log/foo.log")

Inside the ``with``, the gate has either fired its countdown (default
3 s) or been suppressed because the gate was already armed earlier in
this session. ``KeyboardInterrupt`` raised during the countdown
propagates out of the context manager so the caller's destructive
op never runs.
"""

from __future__ import annotations

import logging
import os
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field

log = logging.getLogger(__name__)


DEFAULT_COUNTDOWN_S = 3.0
ENV_DISABLE = "AXROSS_TARPIT_DISABLE"  # "1" disables the gate (CI / scripts)


# ---------------------------------------------------------------------------
# Per-session state
# ---------------------------------------------------------------------------


@dataclass
class _SessionState:
    """Per-(session-id) memory of which profiles have already paid
    the tarpit toll."""

    fired: set[str] = field(default_factory=set)


_STATE: dict[str, _SessionState] = {}
_LOCK = threading.Lock()


def _state_for(session_id: str) -> _SessionState:
    with _LOCK:
        s = _STATE.get(session_id)
        if s is None:
            s = _SessionState()
            _STATE[session_id] = s
        return s


def reset_session(session_id: str) -> None:
    """Forget that the gate already fired in this session — the next
    op against a prod profile will tarpit again. Called by the GUI on
    pane-close."""
    with _LOCK:
        _STATE.pop(session_id, None)


def reset_all() -> None:
    """Clear every session's fired-state. Tests / REPL convenience."""
    with _LOCK:
        _STATE.clear()


# ---------------------------------------------------------------------------
# Disable
# ---------------------------------------------------------------------------


def _is_disabled() -> bool:
    return (os.environ.get(ENV_DISABLE, "") or "").strip() == "1"


# ---------------------------------------------------------------------------
# Profile flag accessor
# ---------------------------------------------------------------------------


def is_production(profile) -> bool:
    """``True`` if a profile carries a truthy ``production`` flag.

    The flag is a small profile addition — see ``core/profiles.py``.
    Defaults to False; existing profiles need an explicit opt-in.
    Accepts loose attribute lookup so callers can pass a duck type.
    """
    return bool(getattr(profile, "production", False))


def profile_label(profile) -> str:
    """Best-effort human label for a profile — used in tarpit text."""
    name = getattr(profile, "name", "") or ""
    proto = getattr(profile, "protocol", "")
    host = getattr(profile, "host", "")
    if name and host:
        return f"{name} ({proto}://{host})"
    if host:
        return f"{proto}://{host}"
    return name or "<unnamed profile>"


# ---------------------------------------------------------------------------
# Countdown — headless / REPL renderer
# ---------------------------------------------------------------------------


def _stdout_countdown(seconds: float, *, label: str, op_desc: str) -> bool:
    """Print a one-second-ticking countdown to stderr. Returns True
    if the operator let it run out, False on interrupt.

    ``KeyboardInterrupt`` is captured here so callers can decide
    whether to abort. We re-raise so the caller's ``with`` block
    short-circuits.
    """
    fh = sys.stderr
    try:
        fh.write("\n  ⚠ axross production tarpit\n")
        fh.write(f"    target: {label}\n")
        fh.write(f"    op:     {op_desc}\n")
        fh.write(f"    Hit Ctrl-C in the next {seconds:.0f} s to abort.\n")
        fh.flush()
        deadline = time.monotonic() + seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            fh.write(f"    {remaining:>4.1f}s …\r")
            fh.flush()
            time.sleep(min(0.1, max(0.0, remaining)))
        fh.write("    proceeding.        \n")
        fh.flush()
        return True
    except KeyboardInterrupt:
        fh.write("\n    aborted by operator.\n")
        fh.flush()
        raise


# A pluggable callable so the GUI can replace the countdown with a
# coloured QDialog without this module importing Qt.
_COUNTDOWN_RENDERER = _stdout_countdown


def set_countdown_renderer(renderer) -> None:
    """Install a custom countdown renderer.

    Signature: ``renderer(seconds: float, *, label: str, op_desc: str) -> bool``.
    Return True on "proceed", raise KeyboardInterrupt or return False on
    abort. The default renderer prints to stderr.
    """
    global _COUNTDOWN_RENDERER  # noqa: PLW0603
    _COUNTDOWN_RENDERER = renderer


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def should_arm(profile, session_id: str) -> bool:
    """Decide whether a destructive op against ``profile`` should
    fire the tarpit. Returns False when the gate has already fired
    in this session (one-toll-per-pane), when the env-disable is on,
    or when the profile isn't flagged production."""
    if _is_disabled():
        return False
    if not is_production(profile):
        return False
    key = profile_label(profile)
    state = _state_for(session_id)
    return key not in state.fired


def arm_fired(profile, session_id: str) -> None:
    """Record that we already paid the tarpit toll for this profile
    in this session. Called from the GUI when its dialog finishes."""
    key = profile_label(profile)
    _state_for(session_id).fired.add(key)


@contextmanager
def production_gate(
    profile,
    op_desc: str,
    *,
    session_id: str = "global",
    countdown_s: float = DEFAULT_COUNTDOWN_S,
) -> Iterator[None]:
    """Context manager — fires the tarpit on the first destructive op
    per session against a production profile.

    If the operator interrupts during the countdown, ``KeyboardInterrupt``
    propagates out of the ``with`` and the wrapped op does not run.
    The gate is a no-op when:

    * ``profile.production`` is False (or the attribute is missing).
    * ``AXROSS_TARPIT_DISABLE=1`` is set.
    * The gate has already fired in this session (per ``session_id``).

    Args:
        profile: any object with a ``production`` attribute (typically
            :class:`core.profiles.ConnectionProfile`).
        op_desc: human-readable description of the operation, e.g.
            ``"remove tree /var/lib/postgres"``. Echoed back to the
            operator during the countdown.
        session_id: opaque identifier for the calling pane / shell.
            The default ``"global"`` is intentionally simple — pass
            a real ID from the GUI to get per-pane behaviour.
        countdown_s: how long to stall. Default 3 s.
    """
    if not should_arm(profile, session_id):
        yield
        return
    label = profile_label(profile)
    log.warning(
        "production_gate ARMED target=%s op=%r (countdown=%.1fs)",
        label,
        op_desc,
        countdown_s,
    )
    proceed = _COUNTDOWN_RENDERER(
        countdown_s,
        label=label,
        op_desc=op_desc,
    )
    if not proceed:
        raise KeyboardInterrupt(f"production_gate aborted before {op_desc!r}")
    arm_fired(profile, session_id)
    yield


__all__ = [
    "DEFAULT_COUNTDOWN_S",
    "ENV_DISABLE",
    "arm_fired",
    "is_production",
    "production_gate",
    "profile_label",
    "reset_all",
    "reset_session",
    "set_countdown_renderer",
    "should_arm",
]
