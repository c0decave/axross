"""Put the process-wide temp directory back after a test moved it.

``tempfile.tempdir`` is global. main() routes it to tmpfs
(core.tmpfs_detect.apply_tempdir_preference); a test that runs main() in
the test process without stubbing that step moves every later test's temp
files, and the failure shows up far from the cause.
"""

from __future__ import annotations

import tempfile


def restore_tempdir(saved: str | None) -> str | None:
    """Reset ``tempfile.tempdir`` to *saved*; return the value it had when
    it differed, else ``None``."""
    current = tempfile.tempdir
    if current == saved:
        return None
    tempfile.tempdir = saved
    return current
