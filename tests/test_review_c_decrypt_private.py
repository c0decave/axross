"""Review C, round 1: the plain text of a decrypted file is the user's alone.

The file pane's Decrypt wrote a new plain-text file with a new file's
default mode (0644 under the usual umask): the clear text of a 0600
``.axenc`` was readable by every account of the machine - the MCP decrypt
tool writes 0600. Now atomic_write takes the mode of a new file
(``new_mode``) and Decrypt gives 0600; an existing file it is asked to
overwrite keeps its own mode.
"""

from __future__ import annotations

import inspect
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.operation_journal as OJ  # noqa: E402
from core.atomic_io import atomic_write  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


@pytest.fixture(autouse=True)
def _quiet(monkeypatch):
    monkeypatch.setattr(OJ, "start_operation", lambda *a, **k: "")
    old = os.umask(0o022)
    yield
    os.umask(old)


def _mode(path) -> int:
    return stat.S_IMODE(os.stat(path).st_mode)


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_sad_a_new_file_gets_the_mode_asked_for(tmp_path):
    dst = tmp_path / "secret.txt"
    atomic_write(LocalFS(), str(dst), b"top secret", new_mode=0o600)
    assert dst.read_bytes() == b"top secret" and _mode(dst) == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_happy_an_existing_file_keeps_its_mode(tmp_path):
    dst = tmp_path / "notes.txt"
    dst.write_text("old")
    os.chmod(dst, 0o640)
    atomic_write(LocalFS(), str(dst), b"new", new_mode=0o600)
    assert dst.read_bytes() == b"new" and _mode(dst) == 0o640


@pytest.mark.skipif(os.name == "nt", reason="POSIX modes")
def test_happy_without_new_mode_a_new_file_gets_the_default(tmp_path):
    dst = tmp_path / "plain.txt"
    atomic_write(LocalFS(), str(dst), b"x")
    assert _mode(dst) == 0o644


def test_sad_the_file_panes_decrypt_writes_its_plain_text_private():
    from ui import file_pane

    source = inspect.getsource(file_pane.FilePaneWidget._decrypt_selected_file)
    assert "new_mode=0o600" in source
