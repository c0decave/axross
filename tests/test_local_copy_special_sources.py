"""LocalFS.copy (the MCP server's copy, NFS/iSCSI server-side copies)
refuses a source that is no regular file - a character device was read
for ever - and a copy never keeps setuid, setgid or sticky (copystat
kept them; every transfer strips them)."""
from __future__ import annotations

import os
import stat

import pytest

from core.local_fs import LocalFS

pytestmark = pytest.mark.skipif(os.name != "posix", reason="POSIX files")


def test_sad_a_device_is_refused(tmp_path):
    # /dev/null: a character device that ends at once (/dev/zero, a tty
    # never end - the copy read them for ever).
    with pytest.raises(OSError, match="not a regular file"):
        LocalFS().copy("/dev/null", str(tmp_path / "null"))
    assert not (tmp_path / "null").exists()


def test_sad_setuid_is_not_kept(tmp_path):
    src = tmp_path / "tool"
    src.write_text("#!/bin/sh\n")
    os.chmod(src, 0o4755)
    LocalFS().copy(str(src), str(tmp_path / "copy"))
    assert stat.S_IMODE(os.stat(tmp_path / "copy").st_mode) == 0o755
