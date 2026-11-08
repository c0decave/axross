"""Whether the start offers the Getting Started tour.

``offer_tour_at_start`` in settings.json (a bool, default true): at the
next start the window shows a small notice in its status bar - "Take the
Getting Started tour" - never a dialog (tests and the startup watchdog
start the window offscreen; nothing may wait for an answer there). Once
the notice is shown it is not offered again: showing it stores false.
Edit > Settings… > General switches it on again (the notice comes back at
the next start) or off before it ever appears. Anything but a bool in the
hand-editable file reads as the default.
"""

from __future__ import annotations

from core import open_limits as OL

SETTING = "offer_tour_at_start"
DEFAULT = True


def offer_at_start() -> bool:
    value = OL.read_setting(SETTING, DEFAULT)
    return value if isinstance(value, bool) else DEFAULT


def set_offer_at_start(enabled: bool) -> None:
    if not isinstance(enabled, bool):
        raise TypeError(f"{SETTING} must be true or false, not {enabled!r}")
    OL.write_setting(SETTING, enabled)


def mark_offered() -> None:
    """The notice was shown: not again (until the setting says so)."""
    set_offer_at_start(False)


__all__ = ["DEFAULT", "SETTING", "mark_offered", "offer_at_start", "set_offer_at_start"]
