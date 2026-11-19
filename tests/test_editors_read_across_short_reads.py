"""The text and hex editors read a file to its end across short reads.

Both read a file with one ``read(cap + 1)``. A network backend's reader may
hand out less per call (a socket's worth): the editor then showed only the
first part as the whole file - and a save wrote that part back over it.
"""

from __future__ import annotations

import io
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import text_document as TD  # noqa: E402


class _Trickle(io.RawIOBase):
    """A reader that gives at most 1000 bytes per read, as a socket may."""

    def __init__(self, data: bytes) -> None:
        self._data, self._pos = data, 0

    def readable(self) -> bool:
        return True

    def read(self, n=-1):
        if n is None or n < 0:
            n = len(self._data)
        chunk = self._data[self._pos:self._pos + min(n, 1000)]
        self._pos += len(chunk)
        return chunk


DATA = bytes(range(256)) * 40  # 10240 bytes


def test_sad_the_text_editor_reads_past_a_short_read():
    assert TD._read_capped(_Trickle(DATA), 1 << 20) == DATA


def test_sad_the_hex_editor_reads_past_a_short_read():
    from ui import hex_editor as HE

    assert HE._read_capped(_Trickle(DATA), 1 << 20) == DATA


def test_edge_the_cap_still_holds_across_short_reads():
    import pytest

    from ui import hex_editor as HE

    with pytest.raises(TD.EditorReadLimitError):
        TD._read_capped(_Trickle(DATA), 5000)
    with pytest.raises(HE.HexEditorReadLimitError):
        HE._read_capped(_Trickle(DATA), 5000)
    assert TD._read_capped(_Trickle(DATA), len(DATA)) == DATA
