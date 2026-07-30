#!/usr/bin/env python3
"""The git backend must not leak dulwich's exception types.

Reported from real use: writing a file produced

    Error -3 while decompressing data: incorrect header check

An opaque zlib code with no path, no object id and no dialog around it.
Two separate things are wrong there, and only one of them is about
whatever corrupted the repository:

``zlib.error`` is not an ``OSError``. Its MRO is ``error → Exception``,
so it escapes the documented backend contract
(docs/SCRIPTING_REFERENCE.md:18, "OSError for connection failure") that
every other backend keeps. Concretely: ``ui/text_editor._save_file``
wraps the save in ``except OSError``, so a zlib failure is not caught at
all — the user gets a raw traceback instead of the "Save Error" dialog
that exists for exactly this.

Loose git objects ARE zlib streams, so this is the one backend in the
tree where a decompression failure is reachable at all. Whether the
object was corrupt on disk, half-written, or clipped by a packfile
problem is not settled here — that part is NOT reproduced. What is
settled is that however it fails, it has to fail like every other
backend: an OSError naming the path.
"""

from __future__ import annotations

import sys
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_zlib_error_is_not_an_oserror():
    """The premise, pinned so the fix cannot be argued away later."""
    assert not issubclass(zlib.error, OSError)


def test_the_editor_only_catches_oserror():
    """Pins the other half of the chain: the save path's except clause
    is what decides whether the user sees a dialog or a traceback."""
    source = (Path(__file__).resolve().parent.parent / "ui/text_editor.py").read_text()
    body = source[source.index("def _save_file"):source.index("def _save_atomic")]
    assert "except OSError" in body
    assert "except zlib" not in body, (
        "the editor must not need to know about zlib — the backend normalises"
    )


# --------------------------------------------------------------------------
# The normalisation helper
# --------------------------------------------------------------------------


def test_happy_a_successful_call_passes_its_value_through():
    from core.git_fs_client import _as_oserror

    with _as_oserror("read", "/repo/x"):
        result = 42
    assert result == 42


def test_sad_a_zlib_failure_becomes_an_oserror_naming_the_path():
    from core.git_fs_client import _as_oserror

    with pytest.raises(OSError) as excinfo:
        with _as_oserror("write", "/repo/.xinitrc"):
            raise zlib.error("Error -3 while decompressing data: incorrect header check")

    message = str(excinfo.value)
    assert "/repo/.xinitrc" in message, message
    assert "corrupt" in message.lower(), message
    # The original stays reachable for a bug report.
    assert isinstance(excinfo.value.__cause__, zlib.error)


def test_sad_an_oserror_is_left_exactly_as_it_was():
    """Re-wrapping would bury errno and the original message."""
    from core.git_fs_client import _as_oserror

    original = PermissionError("permission denied")
    with pytest.raises(PermissionError) as excinfo:
        with _as_oserror("read", "/repo/x"):
            raise original
    assert excinfo.value is original


def test_edge_a_dulwich_object_error_is_normalised_too():
    """dulwich raises its own types for a malformed object; they are no
    more an OSError than zlib's."""
    from core.git_fs_client import _as_oserror

    class _ObjectFormatException(Exception):
        pass

    with pytest.raises(OSError) as excinfo:
        with _as_oserror("read", "/repo/y"):
            raise _ObjectFormatException("invalid object header")
    assert "/repo/y" in str(excinfo.value)


def test_edge_keyboard_interrupt_is_not_swallowed():
    """A user pressing Ctrl+C must not be reported as a corrupt repo."""
    from core.git_fs_client import _as_oserror

    with pytest.raises(KeyboardInterrupt):
        with _as_oserror("read", "/repo/x"):
            raise KeyboardInterrupt


def test_edge_the_operation_name_appears_in_the_message():
    """"could not write" and "could not read" send a reader to very
    different places."""
    from core.git_fs_client import _as_oserror

    with pytest.raises(OSError) as excinfo:
        with _as_oserror("write", "/repo/z"):
            raise zlib.error("boom")
    assert "write" in str(excinfo.value)
