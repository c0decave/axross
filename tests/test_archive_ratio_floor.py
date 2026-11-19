"""The ZIP ratio guard applies from 64 MiB (core.archive.RATIO_CHECK_FLOOR).

Measured before: axross refused to extract its own ZIP of 1 MB of zeros
(a disk image, a preallocated file) - "compression ratio 1015.2:1 exceeds
100:1 cap" - while the same data as tar or 7z extracted. A member under
64 MiB is not ratio-checked now; the total (1 GiB), member-count and
nesting caps still bound the archive, and a member of 64 MiB or more over
100:1 is still refused.
"""

from __future__ import annotations

import hashlib
import os
import sys
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import archive as AR  # noqa: E402
from core import packer as PK  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


@pytest.mark.parametrize("fmt", ["zip", "tar.gz", "7z"])
def test_happy_axross_extracts_its_own_archive_of_a_megabyte_of_zeros(tmp_path, fmt):
    if fmt == "7z":
        pytest.importorskip("py7zr")
    src = tmp_path / "src"
    src.mkdir()
    data = b"\0" * 1_000_000
    (src / "disk.img").write_bytes(data)
    (src / "notes.txt").write_text("hello")
    result = PK.pack(LocalFS(), str(src), ["disk.img", "notes.txt"], "img",
                     PK.PackOptions(fmt=fmt))
    out = tmp_path / "out"
    AR.extract(result.path, str(out))
    assert hashlib.sha256((out / "disk.img").read_bytes()).digest() == \
        hashlib.sha256(data).digest()
    assert (out / "notes.txt").read_text() == "hello"


def test_happy_selected_members_of_zeros_extract_too(tmp_path):
    archive = tmp_path / "a.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("zeros.bin", b"\0" * (8 * 1024 * 1024))
    out = tmp_path / "out"
    AR.extract_members(str(archive), str(out), ["zeros.bin"])
    assert os.path.getsize(out / "zeros.bin") == 8 * 1024 * 1024


def test_sad_a_member_of_64_mib_or_more_over_100_to_1_is_still_refused(tmp_path):
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.bin", b"\0" * AR.RATIO_CHECK_FLOOR)
    out = tmp_path / "out"
    with pytest.raises(AR.UnsafeArchive, match="ratio"):
        AR.extract(str(archive), str(out))
    assert not out.exists()
    with pytest.raises(AR.UnsafeArchive, match="ratio"):
        AR.extract_members(str(archive), str(tmp_path / "out2"), ["bomb.bin"])


def test_edge_the_floor_is_where_the_ratio_starts_to_count():
    under = AR.RATIO_CHECK_FLOOR - 1
    AR.check_bomb_ratio(under, 1, "under")  # not checked
    compressed = AR.RATIO_CHECK_FLOOR // 100 + 1
    AR.check_bomb_ratio(100 * compressed, compressed, "exactly 100:1")
    with pytest.raises(AR.UnsafeArchive):
        AR.check_bomb_ratio(100 * compressed + 1, compressed, "just over")
    # A non-empty member that claims 0 compressed bytes is malformed at any size.
    with pytest.raises(AR.UnsafeArchive):
        AR.check_bomb_ratio(10, 0, "empty-compressed")
