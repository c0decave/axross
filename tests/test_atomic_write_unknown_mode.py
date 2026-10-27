"""atomic_write never reads a failed stat as "the file is new".

core/atomic_io._resolve_destination asked ``stat()`` for the mode of the
file a save replaces and took ANY OSError as "new file": the temp file
got the default mode and was renamed over the old one. Measured: a 0600
secret saved while that stat timed out came back 0644 - readable by every
local user - and a symlink at the path would have been replaced by a
regular file. Only "not found" means new now (FileNotFoundError, or
exists() answering False for a backend such as RamFS whose stat raises a
plain OSError); any other failure stops the save before a byte is written.
"""

from __future__ import annotations

import os
import stat as stat_module

import pytest

from core.atomic_io import atomic_write
from core.local_fs import LocalFS
from core.ram_fs import RamFsSession


class _StatFailsOnce:
    error: OSError = TimeoutError("stat timed out")

    def arm(self, error=None):
        self.armed = error or self.error
        return self

    def stat(self, path):
        err = getattr(self, "armed", None)
        if err is not None:
            self.armed = None
            raise err
        return super().stat(path)


class _FlakyLocal(_StatFailsOnce, LocalFS):
    pass


class _FlakyRam(_StatFailsOnce, RamFsSession):
    pass


def _mode(path):
    return stat_module.S_IMODE(os.stat(path).st_mode)


def test_happy_a_save_keeps_the_mode_of_the_file_it_replaces(tmp_path):
    p = tmp_path / "secret.env"
    p.write_text("A=1\n")
    os.chmod(p, 0o600)
    atomic_write(LocalFS(), str(p), b"A=2\n")
    assert p.read_text() == "A=2\n" and _mode(p) == 0o600


def test_happy_a_new_file_on_ramfs_still_saves(tmp_path):
    """RamFS stat raises a plain OSError for a missing path."""
    ram = RamFsSession()
    atomic_write(ram, "/new.txt", b"hello")
    with ram.open_read("/new.txt") as fh:
        assert fh.read() == b"hello"


def test_sad_a_stat_that_times_out_stops_the_save(tmp_path):
    p = tmp_path / "secret.env"
    p.write_text("A=1\n")
    os.chmod(p, 0o600)
    with pytest.raises(OSError):
        atomic_write(_FlakyLocal().arm(), str(p), b"A=2\n")
    assert p.read_text() == "A=1\n" and _mode(p) == 0o600
    assert os.listdir(tmp_path) == ["secret.env"]


def test_sad_a_refused_stat_stops_the_save_on_a_remote():
    ram = _FlakyRam()
    with ram.open_write("/s.env") as fh:
        fh.write(b"A=1\n")
    ram.chmod("/s.env", 0o600)
    with pytest.raises(OSError):
        atomic_write(ram.arm(PermissionError("refused")), "/s.env", b"A=2\n")
    with ram.open_read("/s.env") as fh:
        assert fh.read() == b"A=1\n"


def test_edge_file_not_found_from_stat_is_a_new_file(tmp_path):
    p = tmp_path / "fresh.txt"
    atomic_write(_FlakyLocal().arm(FileNotFoundError("gone")), str(p), b"x")
    assert p.read_bytes() == b"x"


def test_e2e_editor_document_save_keeps_a_secret_private(tmp_path):
    """TextDocument.save_as (the editor's Save As) goes through atomic_write."""
    from core.text_document import TextDocument

    p = tmp_path / "secret.env"
    p.write_text("A=1\n")
    os.chmod(p, 0o600)
    doc = TextDocument.untitled()
    with pytest.raises(OSError):
        doc.save_as(_FlakyLocal().arm(), str(p), ["A=2", ""])
    assert p.read_text() == "A=1\n" and _mode(p) == 0o600
