"""Typed reads of fields in a server's JSON answer.

A cloud API answer is JSON the server controls. Code that does
``entry.get("size", 0)`` and then ``int()`` / ``.replace()`` / ``.get()``
on the result turns a field of the wrong type into an AttributeError,
TypeError or ValueError deep in a caller that only handles OSError.
These helpers read one field with the type the code expects, or that
type's empty value.
"""

from __future__ import annotations

from datetime import datetime, timezone

# Above any real file size (2**64 has 20 digits) and far below Python's
# int-from-str digit limit.
_MAX_SIZE_DIGITS = 20


def as_dict(value) -> dict:
    return value if isinstance(value, dict) else {}


def as_list(value) -> list:
    return value if isinstance(value, list) else []


def as_str(value) -> str:
    return value if isinstance(value, str) else ""


def as_size(value, *, digit_strings: bool = False) -> int:
    """A non-negative integer field, else 0.

    ``digit_strings`` also accepts a decimal string (or bytes) of ASCII
    digits (the Google APIs send int64 values as JSON strings, a RESP
    server may answer with a bulk string).
    """
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value if value >= 0 else 0
    if digit_strings and isinstance(value, (bytes, bytearray)):
        value = bytes(value).decode("ascii", "replace")
    if (
        digit_strings
        and isinstance(value, str)
        and 0 < len(value) <= _MAX_SIZE_DIGITS
        and value.isascii()
        and value.isdigit()
    ):
        return int(value)
    return 0


def as_utc_datetime(value, default: datetime | None = None) -> datetime:
    """An RFC 3339 timestamp field as an aware datetime.

    A naive result is taken as UTC. Anything else - not a string, not a
    timestamp - gives *default* (the epoch, in UTC, when omitted). Always
    aware, so results can be compared and sorted with each other.
    """
    fallback = default if default is not None else datetime.fromtimestamp(0, timezone.utc)
    if not isinstance(value, str) or not value:
        return fallback
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return fallback
    return parsed if parsed.tzinfo is not None else parsed.replace(tzinfo=timezone.utc)
