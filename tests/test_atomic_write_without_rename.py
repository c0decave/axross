"""atomic_write on a backend that can write but not rename.

TFTP stores files but has no rename (core/tftp_client.py ``rename``
raises; the registry says ``can_rename=False``). atomic_write still took
the temp-file route for it - write a sibling ``.tmp`` file, then rename
it over the target - so every save failed at the rename: the MCP
``write_file`` tool, the text and hex editors and scripting's
``write_bytes`` could not write to TFTP at all (measured against the lab
TFTP server through ``remote_open`` + ``write_file``). The transfer
engine already asked the capabilities first (core/transfer_manager.py)
and writes such backends directly; atomic_write now does the same.
"""

from __future__ import annotations

import io

import pytest

from core import atomic_io
from core.ram_fs import RamFsSession


class TftpSession(RamFsSession):
    """Named like the real class, so the registry's TFTP capabilities
    apply: writes work, rename never does."""

    def __init__(self):
        super().__init__(label="tftp-like")
        self.renames = 0

    def rename(self, src, dst):
        self.renames += 1
        raise OSError("TFTP does not support rename.")


class _Spy(RamFsSession):
    def __init__(self):
        super().__init__(label="spy")
        self.renamed = []

    def rename(self, src, dst):
        self.renamed.append((src, dst))
        return super().rename(src, dst)


_Spy.__name__ = "RamFsSession"


def _read(backend, path):
    with backend.open_read(path) as fh:
        return fh.read()


# --- happy ------------------------------------------------------------------


def test_happy_a_backend_without_rename_is_written_directly():
    b = TftpSession()
    atomic_io.atomic_write(b, "/config.txt", b"hostname lab\n")
    assert _read(b, "/config.txt") == b"hostname lab\n"
    assert b.renames == 0 and [e.name for e in b.list_dir("/")] == ["config.txt"]


def test_happy_the_stream_variant_too():
    b = TftpSession()
    n = atomic_io.atomic_write_stream(b, "/big.bin", io.BytesIO(b"x" * 5000), chunk_size=1024)
    assert n == 5000 and _read(b, "/big.bin") == b"x" * 5000 and b.renames == 0


# --- sad --------------------------------------------------------------------


def test_sad_a_failing_direct_write_still_raises(monkeypatch):
    b = TftpSession()

    def refuse(path, append=False):
        raise OSError("TFTP error 2: access violation")

    monkeypatch.setattr(b, "open_write", refuse)
    with pytest.raises(OSError, match="access violation"):
        atomic_io.atomic_write(b, "/x.txt", b"data")


# --- edge -------------------------------------------------------------------


def test_edge_a_rename_capable_backend_keeps_the_temp_file_route():
    b = _Spy()
    atomic_io.atomic_write(b, "/a.txt", b"one")
    assert len(b.renamed) == 1 and b.renamed[0][1] == "/a.txt"
    assert _read(b, "/a.txt") == b"one"
