"""``axross.move`` between two backends keeps a source that changed while
it was being copied (the MCP ``move`` tool runs through it as well).

Reported: the cross-backend move streamed the source to the destination and
then removed the source - without looking at it again. A log that was
still being appended to lost every line written after the copy had read
its end: those lines were in neither place, and the move returned success.

Now the source's size is compared before and after the copy; when it
differs, the copy is taken back (as on a failed source removal) and the
move raises, so the source stays exactly as it is.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import core.scripting as axross  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

LATE = b"LATE LOG LINE\n"


class _WrittenAtEof(LocalFS):
    """A writer appends to the source right after the copy read its end."""

    def open_read(self, path):
        handle = super().open_read(path)
        real_read = handle.read
        state = {"done": False}

        def read(n=-1):
            data = real_read(n)
            if not data and not state["done"]:
                state["done"] = True
                with open(path, "ab") as writer:
                    writer.write(LATE)
            return data

        handle.read = read
        return handle


class _NoStat(LocalFS):
    def stat(self, path):
        raise OSError(95, "Operation not supported")


def test_happy_an_unchanged_file_is_moved(tmp_path):
    src, dst = tmp_path / "app.log", tmp_path / "out" / "app.log"
    dst.parent.mkdir()
    src.write_bytes(b"line\n" * 100)
    assert axross.move(LocalFS(), str(src), LocalFS(), str(dst)) == 500
    assert not src.exists()
    assert dst.read_bytes() == b"line\n" * 100


def test_sad_a_file_appended_during_the_copy_is_kept_and_the_copy_taken_back(tmp_path):
    src, dst = tmp_path / "app.log", tmp_path / "out" / "app.log"
    dst.parent.mkdir()
    src.write_bytes(b"line\n" * 100)
    with pytest.raises(OSError, match="changed while it was copied"):
        axross.move(_WrittenAtEof(), str(src), LocalFS(), str(dst))
    assert src.read_bytes() == b"line\n" * 100 + LATE
    assert not dst.exists()
    assert os.listdir(dst.parent) == []


def test_edge_a_source_without_stat_moves_as_before(tmp_path):
    src, dst = tmp_path / "f.bin", tmp_path / "out" / "f.bin"
    dst.parent.mkdir()
    src.write_bytes(b"x" * 64)
    axross.move(_NoStat(), str(src), LocalFS(), str(dst))
    assert not src.exists()
    assert dst.read_bytes() == b"x" * 64


class _ShortRead(LocalFS):
    """open_read ends after half the file, without an error."""

    def open_read(self, path):
        import io

        with open(path, "rb") as fh:
            data = fh.read()
        return io.BytesIO(data[: len(data) // 2])


def test_sad_a_short_copy_keeps_the_source_and_takes_the_copy_back(tmp_path):
    # The audit of 2026-10-22: a stream that ends early must not cost the source.
    src, dst = tmp_path / "f.bin", tmp_path / "out" / "f.bin"
    dst.parent.mkdir()
    src.write_bytes(b"y" * 4096)
    with pytest.raises(OSError, match="only 2048 of 4096 bytes"):
        axross.move(_ShortRead(), str(src), LocalFS(), str(dst))
    assert src.read_bytes() == b"y" * 4096
    assert not dst.exists()
