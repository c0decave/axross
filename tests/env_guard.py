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


#: What axross sets for itself while it runs (core.multimedia_env: the
#: audio backend the probe found, no GPU probing; core.tls_env: the CA
#: bundle). A test that runs that code leaves them in os.environ, and an
#: app a later test starts takes them as the user's own choice (measured:
#: a leaked QT_AUDIO_BACKEND made the probe try one backend instead of two).
RUNTIME_VARS = (
    "QT_AUDIO_BACKEND",
    "QT_FFMPEG_DECODING_HW_DEVICE_TYPES",
    "QT_FFMPEG_ENCODING_HW_DEVICE_TYPES",
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
)


def snapshot_runtime_env() -> dict[str, str | None]:
    return {name: os.environ.get(name) for name in RUNTIME_VARS}


def restore_runtime_env(saved: dict[str, str | None]) -> None:
    """Reset every runtime variable to *saved*, quietly (setting them is
    the code under test's job), and let axross's registries of what it
    set forget the ones taken back."""
    for name, value in saved.items():
        if os.environ.get(name) == value:
            continue
        if value is None:
            os.environ.pop(name, None)
        else:
            os.environ[name] = value
    import sys

    for module_name in ("core.multimedia_env", "core.tls_env"):
        registry = getattr(sys.modules.get(module_name), "_SET_BY_AXROSS", None)
        if registry is not None:
            registry.difference_update({n for n in registry if n not in os.environ})
