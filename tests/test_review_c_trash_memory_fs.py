"""Review C, round 1: Move to Trash out of a RAM disk.

A file in ``/run/user/$UID`` or ``/dev/shm`` (a tmpfs: in memory, gone at
the next boot - where axross's RAM temp files go, "nothing lands on
disk") was copied by Move to Trash into ``~/.axross-trash`` on the home's
disk, in clear text, where it stayed until the trash was emptied. Now a
local trash that would take a file from a memory file system onto a disk
refuses: the file stays, and the message says to delete it permanently.
"""

from __future__ import annotations

import os
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import tmpfs_detect as TD  # noqa: E402
from core import trash as T  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

SHM = "/dev/shm"


@pytest.fixture
def in_memory(tmp_path):
    if not os.path.isdir(SHM) or os.stat(SHM).st_dev == os.stat(tmp_path).st_dev:
        pytest.skip("needs /dev/shm on a file system of its own")
    path = Path(SHM) / f"axross-test-{uuid.uuid4().hex}.txt"
    path.write_text("kept in memory only\n")
    yield path
    path.unlink(missing_ok=True)


def test_sad_a_file_of_a_memory_file_system_does_not_go_to_a_trash_on_disk(
        in_memory, tmp_path, monkeypatch):
    monkeypatch.setattr(TD, "memory_fs", lambda path: str(path).startswith(SHM))
    with pytest.raises(OSError, match="(?i)memory"):
        T.trash(LocalFS(), str(in_memory), root=str(tmp_path / "home" / ".axross-trash"),
                journal=False)
    assert in_memory.read_text() == "kept in memory only\n"
    trash = tmp_path / "home" / ".axross-trash"
    assert not trash.exists() or not any(p.suffix != ".json" for p in trash.iterdir())


def test_happy_a_trash_in_memory_too_takes_it(in_memory, tmp_path, monkeypatch):
    monkeypatch.setattr(TD, "memory_fs", lambda path: True)
    trash_id = T.trash(LocalFS(), str(in_memory), root=str(tmp_path / ".axross-trash"),
                       journal=False)
    assert trash_id and not in_memory.exists()


def test_happy_a_file_on_the_trashs_own_disk_still_goes(tmp_path, monkeypatch):
    monkeypatch.setattr(TD, "memory_fs", lambda path: True)
    source = tmp_path / "a.txt"
    source.write_text("x")
    assert T.trash(LocalFS(), str(source), root=str(tmp_path / ".axross-trash"), journal=False)
    assert not source.exists()


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="mountinfo is Linux's")
def test_edge_memory_fs_reads_the_mount_that_holds_a_path():
    shm_tmpfs = any(line.split()[4] == SHM and " - tmpfs " in line
                    for line in open("/proc/self/mountinfo", encoding="utf-8"))
    if not shm_tmpfs:
        pytest.skip("no tmpfs at /dev/shm")
    assert TD.memory_fs(os.path.join(SHM, "no-such-file", "below"))
    assert TD.memory_fs(SHM)
    assert not TD.memory_fs("/proc/self")
