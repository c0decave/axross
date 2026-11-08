"""A compressed tar's declared member sizes are counted while its headers are
read, and Cancel stops the read (review 2 of 0.15.176).

Before: ``_tar_members_capped`` (listing, extract, a selection's extract)
read every header before any byte cap was checked. In a compressed tar the
next header lies behind the member's data, so a 2.4 KB ``.tar.bz2``
declaring one 10 TB member of zeros made tarfile decompress all of it -
hours of a core for the archive preview or MCP archive_list - and Cancel
could not stop it. A GNU long-name header of the same kind was read in one
call, into memory.

The tests use a virtual decompressed stream that counts the bytes a real
decompressor would have produced, so nothing large is ever inflated.
"""

from __future__ import annotations

import contextlib
import gzip
import os
import sys
import tarfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import archive as AR  # noqa: E402

pytestmark = pytest.mark.timeout(60)


class _Inflating:
    """The decompressed side of a compressed tar: *head*, then zeros
    without end. ``work`` counts the bytes a decompressor would have had to
    produce (seeking forward is decompressing; seeking back starts over)."""

    def __init__(self, head: bytes) -> None:
        self.head, self.pos, self.work, self.biggest_read = head, 0, 0, 0

    def tell(self) -> int:
        return self.pos

    def seek(self, pos: int, whence: int = 0) -> int:
        if whence == os.SEEK_CUR:
            pos += self.pos
        elif whence != os.SEEK_SET:
            raise OSError("no end to seek from")
        self.work += pos - self.pos if pos >= self.pos else pos
        self.pos = pos
        return pos

    def read(self, n: int = -1) -> bytes:
        assert n is not None and n >= 0
        self.biggest_read = max(self.biggest_read, n)
        data = self.head[self.pos:self.pos + n]
        data += b"\0" * (n - len(data))
        self.pos += n
        self.work += n
        return data

    def close(self) -> None:
        pass


def _header(name: str, size: int, kind=tarfile.REGTYPE, fmt=tarfile.GNU_FORMAT) -> bytes:
    ti = tarfile.TarInfo(name)
    ti.size, ti.type = size, kind
    return ti.tobuf(format=fmt)


@pytest.fixture
def virtual(monkeypatch, tmp_path):
    """``(path, stream)``: core.archive opens *path* as a TarFile over the
    virtual stream."""
    state: dict = {}

    @contextlib.contextmanager
    def fake_open(_path, _budget=None):
        with tarfile.TarFile(fileobj=state["stream"], mode="r") as tf:
            yield tf

    monkeypatch.setattr(AR, "_open_tar", fake_open)

    def make(head: bytes):
        state["stream"] = _Inflating(head)
        path = tmp_path / "bomb.tar.bz2"
        path.write_bytes(b"BZh9")  # extract() wants a file; the stream is virtual
        return str(path), state["stream"]

    return make


def test_sad_listing_stops_at_a_declared_size_above_the_budget(virtual):
    path, stream = virtual(_header("zeros.bin", 10 * 2**40))  # 10 TB
    with pytest.raises(AR.UnsafeArchive, match="declares more than"):
        AR.list_archive(path)
    assert stream.work < 1 << 20, stream.work  # nothing behind the header inflated


def test_sad_extract_stops_before_reading_past_the_first_big_member(virtual, tmp_path):
    path, stream = virtual(_header("a.bin", 2 * AR.MAX_EXTRACT_TOTAL_BYTES))
    with pytest.raises(AR.UnsafeArchive):
        AR.extract(path, str(tmp_path / "out"))
    assert stream.work < 1 << 20, stream.work
    assert not (tmp_path / "out").exists()


def test_sad_a_huge_long_name_header_is_not_read_whole(tmp_path, monkeypatch):
    """The first header, read while tarfile builds the TarFile: a GNU long
    name of 64 MiB (zeros, 64 KiB as gzip) was read in one call."""
    reads: list[int] = []
    real_read = gzip.GzipFile.read

    def spy(self, size=-1):
        reads.append(size)
        return real_read(self, size)

    monkeypatch.setattr(gzip.GzipFile, "read", spy)
    path = tmp_path / "longname.tar.gz"
    head = _header("././@LongLink", 64 * 2**20, kind=tarfile.GNUTYPE_LONGNAME)
    path.write_bytes(gzip.compress(head + b"\0" * (64 * 2**20), 1))
    with pytest.raises(AR.UnsafeArchive):
        AR.list_archive(str(path))
    assert max(reads) <= AR.MAX_TAR_READ


def test_edge_cancel_stops_the_skip_over_one_big_member(virtual):
    path, stream = virtual(_header("zeros.bin", AR.MAX_LIST_TAR_BYTES - 1))
    polls: list[int] = []

    def cancel() -> bool:
        polls.append(stream.pos)
        return len(polls) > 3

    with pytest.raises(AR.ExtractCancelled):
        AR.list_archive(path, cancel=cancel)
    assert stream.work < 512 << 20, stream.work  # stopped in steps, not after 8 GiB


def test_edge_a_real_tar_gz_declaring_too_much_is_refused_at_once(tmp_path):
    """A real gzip stream: the header declares 9 GiB, no data follows."""
    path = tmp_path / "x.tar.gz"
    path.write_bytes(gzip.compress(_header("big.bin", AR.MAX_LIST_TAR_BYTES + 1)))
    with pytest.raises(AR.UnsafeArchive, match="declares more than"):
        AR.list_archive(str(path))
    # The same member in a plain .tar costs nothing to seek past: listed
    # (a sparse file - nothing is written but the header).
    plain = tmp_path / "x.tar"
    size = AR.MAX_LIST_TAR_BYTES + 1
    with open(plain, "wb") as fh:
        fh.write(_header("big.bin", size))
        fh.truncate(512 + (size + 511) // 512 * 512 + 1024)
    [entry] = AR.list_archive(str(plain))
    assert entry.size == size
