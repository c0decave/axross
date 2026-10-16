"""When a file pane becomes the active pane: on click, or after hovering.

Stored as ``pane_activation`` in settings.json: ``"click"``, or the hover
delay in whole seconds, 1 to 3. Anything else - the file is hand-editable -
reads as the default, one second.
"""

from __future__ import annotations

from core import open_limits as OL

SETTING = "pane_activation"
CLICK = "click"
HOVER_SECONDS = (1, 2, 3)
DEFAULT = 1


def _valid(value) -> bool:
    if value == CLICK:
        return True
    return type(value) is int and value in HOVER_SECONDS


def activation():
    """``"click"`` or the hover delay in seconds."""
    value = OL.read_setting(SETTING, DEFAULT)
    return value if _valid(value) else DEFAULT


def activation_delay_ms() -> int | None:
    """Hover delay in milliseconds, or None when only a click activates."""
    value = activation()
    return None if value == CLICK else value * 1000


def set_activation(value) -> None:
    if not _valid(value):
        raise ValueError(
            f"pane activation must be {CLICK!r} or one of {HOVER_SECONDS}, not {value!r}"
        )
    OL.write_setting(SETTING, value)
