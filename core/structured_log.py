"""Small structured logging helper with redaction."""

from __future__ import annotations

import logging
from typing import Any

from core.redaction import redact


def log_event(
    logger: logging.Logger,
    level: int,
    event: str,
    /,
    **fields: Any,
) -> None:
    """Emit one stable key=value log line.

    This intentionally stays stdlib-only. Downstream users can grep for
    ``event=...`` / ``operation_id=...`` while the human log dock remains
    readable.
    """
    clean = redact(fields)
    parts = [f"event={event}"]
    for key in sorted(clean):
        value = clean[key]
        parts.append(f"{key}={value!r}")
    logger.log(level, " ".join(parts))


__all__ = ["log_event"]
