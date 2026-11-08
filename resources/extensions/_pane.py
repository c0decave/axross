"""What the bundled extensions share about the file pane they acted on.

Not an extension itself: a name starting with "_" is skipped by the
extension loader (core.extensions._candidates)."""

from __future__ import annotations


def refresh_pane(pane) -> None:
    """Show *pane*'s folder again without blocking - unless the pane was
    closed while the job ran. Its refresh then raised RuntimeError
    ("wrapped C/C++ object has been deleted") in on_done, and the host
    marked the extension failed for work that had been done."""
    if pane is None:
        return
    try:
        from PyQt6 import sip

        if sip.isdeleted(pane):
            return
    except TypeError:  # no Qt object (a test's stand-in)
        pass
    refresh = getattr(pane, "refresh_after_change", None) or pane.refresh
    refresh()
