"""A partial that no resume can adopt is not left behind.

Measured before (review round 6): a cancelled copy from a source that
reports no modification time (rsh, a shell listing without one) kept its
hidden ``.name.part-<job>`` for a resume - but a partial is adopted only by
the source fingerprint in its name, and such a source has none: the hidden
file stayed for good. Now it is removed; a fingerprinted one is kept.
"""

from __future__ import annotations

import dataclasses
import io
import os
import sys
from datetime import datetime
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker  # noqa: E402

DATA = b"x" * (3 * 1024 * 1024)


class _Source(RamFsSession):
    def __init__(self, box, *, timed):
        super().__init__()
        self._box, self._timed = box, timed
        with super().open_write("/f.bin") as fh:
            fh.write(DATA)

    def stat(self, path):
        item = super().stat(path)
        if not self._timed:
            item = dataclasses.replace(item, modified=datetime.fromtimestamp(0))  # no time
        return item

    def open_read(self, path, mode="rb"):
        box = self._box

        class _Cancelling(io.BytesIO):
            def read(inner, n=-1):
                chunk = super().read(n)
                if inner.tell() > 0:
                    box[0].cancel_event.set()
                return chunk

        return _Cancelling(DATA)


def _cancelled_copy(tmp_path, *, timed):
    box = [None]
    job = TransferJob(source_path="/f.bin", dest_path=str(tmp_path / "f.bin"),
                      filename="f.bin", total_bytes=len(DATA),
                      source_backend=_Source(box, timed=timed), dest_backend=LocalFS(),
                      use_temp_file=True)
    box[0] = job
    TransferWorker()._process_job(job)
    assert job.status is TransferStatus.CANCELLED, job.error_message
    return [p.name for p in tmp_path.iterdir()]


def test_sad_a_partial_without_source_fingerprint_is_removed(tmp_path):
    assert _cancelled_copy(tmp_path, timed=False) == []


def test_happy_a_fingerprinted_partial_is_kept_for_a_resume(tmp_path):
    left = _cancelled_copy(tmp_path, timed=True)
    assert len(left) == 1 and left[0].startswith(".f.bin.part-")
