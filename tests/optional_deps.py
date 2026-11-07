"""Skip - not fail - what needs a library this machine does not have.

numpy comes with the voice packages (Piper, faster-whisper) and Qt
Multimedia needs the system's PulseAudio client library (libpulse.so.0).
A machine without them cannot run a test that synthesizes a tone or opens
a QMediaPlayer; that is no failure of axross. Each helper skips only the
test (or module) that really needs the library: the tests around it that
do not still run.
"""

from __future__ import annotations

import pytest


def need_numpy():
    """numpy, or skip: ``np = need_numpy()``."""
    return pytest.importorskip("numpy", reason="numpy is not installed")


def qt_multimedia_error() -> str | None:
    """Why PyQt6.QtMultimedia does not load here (a missing libpulse.so.0,
    no QtMultimedia in this PyQt6), or None when it loads."""
    try:
        import PyQt6.QtMultimedia  # noqa: F401
    except ImportError as exc:
        return f"Qt Multimedia does not load here: {exc}"
    return None


def need_qt_multimedia() -> None:
    """Skip the test - or, at import time, the whole module - when Qt
    Multimedia does not load."""
    why = qt_multimedia_error()
    if why is not None:
        pytest.skip(why, allow_module_level=True)


#: For ``@needs_qt_multimedia`` on a test or ``pytestmark``.
needs_qt_multimedia = pytest.mark.skipif(qt_multimedia_error() is not None,
                                         reason=qt_multimedia_error() or "")
