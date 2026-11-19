"""A move does not delete a local source written to, or replaced, while it
was copied - also at the same size (a database or disk image rewritten in
place, a file saved anew). The size check did not see it and no checksum
checks the copy where the destination has none (WebDAV, S3, FTP): the
change was in neither place."""
from __future__ import annotations

import io
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class _NoChecksumFS(LocalFS):
    def checksum(self, path, algorithm="sha256"):
        return ""


class _RewrittenWhileRead(_NoChecksumFS):
    """Its file is rewritten at the same size once the copy has read it."""

    def open_read(self, path):
        with open(path, "rb") as fh:
            old = fh.read()
        with open(path, "r+b") as fh:  # in place, same size
            fh.write(b"N" * len(old))
        st = os.stat(path)
        os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 5_000_000_000))
        return io.BytesIO(old)


def _move(tmp_path, source) -> tuple[TW.TransferJob, Path, Path]:
    src, dst = tmp_path / "db.sqlite", tmp_path / "out" / "db.sqlite"
    dst.parent.mkdir()
    src.write_bytes(b"O" * 4096)
    job = TW.TransferJob(source_path=str(src), dest_path=str(dst), filename="db.sqlite",
                         total_bytes=4096, source_backend=source,
                         dest_backend=_NoChecksumFS(), use_temp_file=True, move=True)
    TW.TransferWorker()._process_job(job)
    return job, src, dst


def test_sad_a_source_rewritten_at_the_same_size_is_kept(tmp_path):
    job, src, dst = _move(tmp_path, _RewrittenWhileRead())
    assert job.status == TW.TransferStatus.ERROR
    assert "changed while it was copied" in job.error_message
    assert src.read_bytes() == b"N" * 4096  # the change is still there


def test_happy_an_unchanged_source_is_moved(tmp_path):
    job, src, dst = _move(tmp_path, _NoChecksumFS())
    assert job.status == TW.TransferStatus.DONE, job.error_message
    assert not src.exists() and dst.read_bytes() == b"O" * 4096
