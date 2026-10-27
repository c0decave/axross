"""Rsync rename() never lands inside or merges into an existing folder.

core/rsync_client.py renamed by download + upload + remove. With the
destination an existing folder, measured on the lab's rsync daemon
(tests/docker/Dockerfile.rsync):

* ``rename("/t/report.txt", "/t/Archive")`` uploaded the file INTO
  Archive under the temp name ``payload``, deleted report.txt and
  returned - the file's name was gone and the caller was told "renamed".
* ``rename("/t/proj", "/t/Archive")`` merged proj into Archive, replacing
  Archive/p.txt with proj/p.txt, and deleted proj.

The shell backends refuse both (rename_command, 0.11.79). Rsync now asks
first: a folder destination is IsADirectoryError, a folder over a file is
FileExistsError, and nothing is copied or removed. A file over a file is
replaced, as rename does everywhere else.
"""

from __future__ import annotations

import socket
import uuid

import pytest

from core.rsync_client import RsyncSession

LAB = ("10.99.0.34", 873)


def _lab_up() -> bool:
    try:
        with socket.create_connection(LAB, timeout=0.5):
            return True
    except OSError:
        return False


class _Recording(RsyncSession):
    """No daemon: a fixed tree; every rsync run and remove is recorded."""

    def __init__(self, tree: dict[str, bool]):  # noqa: D107 - path -> is_dir
        self.tree = dict(tree)
        self.runs: list[list[str]] = []
        self.removed: list[str] = []
        self._preserve_metadata = False

    def stat(self, path):
        from models.file_item import FileItem

        if path not in self.tree:
            raise FileNotFoundError(path)
        return FileItem(name=path.rsplit("/", 1)[-1], is_dir=self.tree[path])

    def _build_url(self, path):
        return "rsync://host/mod" + path

    def _run_rsync(self, args, timeout=None):
        self.runs.append(list(args))
        return ""

    def remove(self, path, recursive=False):
        self.removed.append(path)


TREE = {"/t": True, "/t/Archive": True, "/t/report.txt": False, "/t/old.txt": False,
        "/t/proj": True}


# ------------------------------------------------------------------ offline

def test_happy_rename_onto_a_free_name_copies_then_removes():
    s = _Recording(TREE)
    s.rename("/t/report.txt", "/t/new.txt")
    assert len(s.runs) == 2 and s.runs[-1][-1].endswith("/t/new.txt")
    assert s.removed == ["/t/report.txt"]


@pytest.mark.parametrize("src", ["/t/report.txt", "/t/proj"])
def test_sad_rename_onto_a_folder_does_nothing(src):
    s = _Recording(TREE)
    with pytest.raises(IsADirectoryError):
        s.rename(src, "/t/Archive")
    assert s.runs == [] and s.removed == []


def test_sad_a_folder_over_a_file_does_nothing():
    s = _Recording(TREE)
    with pytest.raises(FileExistsError):
        s.rename("/t/proj", "/t/old.txt")
    assert s.runs == [] and s.removed == []


def test_edge_a_failed_destination_check_does_nothing():
    s = _Recording(TREE)

    def broken(path):
        raise TimeoutError("listing timed out")

    s.stat = broken
    with pytest.raises(OSError):
        s.rename("/t/report.txt", "/t/Archive")
    assert s.runs == [] and s.removed == []


def test_edge_a_file_over_a_file_is_replaced():
    s = _Recording(TREE)
    s.rename("/t/report.txt", "/t/old.txt")
    assert s.removed == ["/t/report.txt"] and len(s.runs) == 2


# ------------------------------------------------------------------ live (lab)

@pytest.fixture
def lab():
    if not _lab_up():
        pytest.skip("lab rsync daemon (10.99.0.34) not reachable")
    s = RsyncSession(host=LAB[0], port=LAB[1], module="testmod",
                     username="rsyncuser", password="rsync123")
    base = "/audit-" + uuid.uuid4().hex[:8]
    s.mkdir(base)
    s.mkdir(base + "/Archive")
    s.mkdir(base + "/proj")
    for name, data in (("Archive/one.txt", b"keep"), ("Archive/p.txt", b"archived p"),
                       ("proj/p.txt", b"p"), ("report.txt", b"report")):
        with s.open_write(f"{base}/{name}") as fh:
            fh.write(data)
    try:
        yield s, base
    finally:
        s.remove(base, recursive=True)


def _read(s, path):
    with s.open_read(path) as fh:
        return fh.read()


def test_e2e_lab_rename_onto_a_folder_keeps_everything(lab):
    s, base = lab
    with pytest.raises(IsADirectoryError):
        s.rename(base + "/report.txt", base + "/Archive")
    with pytest.raises(IsADirectoryError):
        s.rename(base + "/proj", base + "/Archive")
    assert sorted(i.name for i in s.list_dir(base + "/Archive")) == ["one.txt", "p.txt"]
    assert _read(s, base + "/Archive/p.txt") == b"archived p"
    assert _read(s, base + "/report.txt") == b"report"
    assert _read(s, base + "/proj/p.txt") == b"p"


def test_e2e_lab_rename_onto_a_free_name_still_works(lab):
    s, base = lab
    s.rename(base + "/report.txt", base + "/renamed.txt")
    assert _read(s, base + "/renamed.txt") == b"report"
    assert not s.exists(base + "/report.txt")
