"""Put back the environment variables that keep a test run isolated.

tests/conftest.py gives the run a private HOME, XDG directories and the
null keyring backend. A test that changes one of them without restoring it
sends every later test's files (or secrets) somewhere else.
"""

from __future__ import annotations

import os

ISOLATION_VARS = (
    "HOME",
    "XDG_CONFIG_HOME",
    "XDG_DATA_HOME",
    "XDG_CACHE_HOME",
    "XDG_STATE_HOME",
    "PYTHON_KEYRING_BACKEND",
)


def snapshot_isolation_env() -> dict[str, str | None]:
    return {name: os.environ.get(name) for name in ISOLATION_VARS}


def restore_isolation_env(saved: dict[str, str | None]) -> dict[str, str | None]:
    """Reset every isolation variable to *saved*; return the ones that had
    changed, with the value they had (``None`` when it was removed)."""
    changed: dict[str, str | None] = {}
    for name, value in saved.items():
        current = os.environ.get(name)
        if current == value:
            continue
        changed[name] = current
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
    return changed
