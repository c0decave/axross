"""Checksum Manifest's Replace and Update write over an existing SHA256SUMS
also where a rename does not replace a file (SMB, Windows).

Review: the new manifest went to a temporary file renamed onto
SHA256SUMS; SMB (and os.rename on Windows) refuses a rename onto an
existing file, so Replace and Update failed with FileExistsError and the
old manifest stayed. The temp file now takes its place through
core.server_ops' replace-with-backup step.
"""

from __future__ import annotations

import errno
import importlib.util
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import extensions as EX  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _load():
    path = EX.bundled_dir() / "checksum_manifest.py"
    spec = importlib.util.spec_from_file_location("checksum_manifest_replace_ext", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _WindowsLikeFS(LocalFS):
    """os.rename on Windows - and SmbSession.rename - refuse an existing
    target with FileExistsError. (The impacket SMB test server renames
    nothing at all, so SMB itself is not driven here.)"""

    def rename(self, src, dst):
        if os.path.exists(dst):
            raise FileExistsError(errno.EEXIST, "Cannot create a file when that file already exists", dst)
        return super().rename(src, dst)


def test_happy_replace_writes_over_an_existing_manifest_where_rename_does_not_replace(tmp_path):
    cm = _load()
    (tmp_path / "a.txt").write_bytes(b"one")
    (tmp_path / "SHA256SUMS").write_text("0" * 64 + "  a.txt\n")
    fs = _WindowsLikeFS()
    text = cm.manifest_text(fs, str(tmp_path), ["a.txt"])
    cm._write(fs, str(tmp_path / "SHA256SUMS"), text)
    assert (tmp_path / "SHA256SUMS").read_text() == text
    assert sorted(os.listdir(tmp_path)) == ["SHA256SUMS", "a.txt"]  # no temp, no backup left
