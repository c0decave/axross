"""Overwriting a RamFS file keeps its permission bits.

Measured before: every commit of a writer built a fresh entry with mode
0o644. An executable script saved in a RAM workspace came back 0o644, and
``atomic_write`` -- which pre-creates its temp file with the target's mode
precisely so the mode survives -- lost it too, because the data write
replaced the pre-created entry.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.atomic_io import atomic_write  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402


def _write(ram, path, data, append=False):
    with ram.open_write(path, append=append) as fh:
        fh.write(data)


def test_happy_a_new_file_gets_the_default_mode():
    ram = RamFsSession()
    _write(ram, "/a.txt", b"x")
    assert ram.stat("/a.txt").permissions == 0o644


def test_sad_an_overwrite_keeps_an_executable_bit():
    ram = RamFsSession()
    _write(ram, "/run.sh", b"#!/bin/sh\n")
    ram.chmod("/run.sh", 0o755)
    _write(ram, "/run.sh", b"#!/bin/sh\necho hi\n")
    assert ram.stat("/run.sh").permissions == 0o755


def test_sad_atomic_write_keeps_a_private_mode():
    ram = RamFsSession()
    _write(ram, "/secret", b"old")
    ram.chmod("/secret", 0o600)
    atomic_write(ram, "/secret", b"new")
    assert ram.stat("/secret").permissions == 0o600
    with ram.open_read("/secret") as fh:
        assert fh.read() == b"new"


def test_edge_an_append_keeps_the_mode():
    ram = RamFsSession()
    _write(ram, "/log", b"a")
    ram.chmod("/log", 0o640)
    _write(ram, "/log", b"b", append=True)
    assert ram.stat("/log").permissions == 0o640


def test_edge_a_removed_and_recreated_file_starts_over():
    ram = RamFsSession()
    _write(ram, "/x", b"a")
    ram.chmod("/x", 0o700)
    ram.remove("/x")
    _write(ram, "/x", b"b")
    assert ram.stat("/x").permissions == 0o644


def test_sad_writing_over_a_directory_still_fails():
    ram = RamFsSession()
    ram.mkdir("/d")
    with pytest.raises(OSError):
        _write(ram, "/d", b"x")
