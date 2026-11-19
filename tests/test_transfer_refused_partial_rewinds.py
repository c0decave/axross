"""A local partial that matches the source but may not be continued (it
has another name - a hard link -, another owner, it is a link) restarts
the copy from byte 0. The comparison had left the source at the
partial's end: the restart copied only the tail into a new file, which
failed as a short copy - or, with the source's size unknown, was
committed as "the file"."""
from __future__ import annotations

import os
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import pytest  # noqa: E402

from core import transfer_worker as TW  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class _NoChecksumFS(LocalFS):
    def checksum(self, path, algorithm="sha256"):
        return ""


@pytest.mark.parametrize("known_size", [True, False])
def test_sad_a_refused_partial_restarts_from_the_start(tmp_path, known_size):
    data = random.Random(3).randbytes(300_000)
    src = tmp_path / "src.bin"
    src.write_bytes(data)
    fp = TW.source_fingerprint(LocalFS().stat(str(src)))
    partial = tmp_path / TW.partial_name("dst.bin", "1a2b3c4d", fp)
    partial.write_bytes(data[:100_000])
    other = tmp_path / "other-name"
    os.link(partial, other)  # a partial with two names is not appended to
    fs = _NoChecksumFS()
    job = TW.TransferJob(source_path=str(src), dest_path=str(tmp_path / "dst.bin"),
                         filename="src.bin", source_backend=fs, dest_backend=fs,
                         resume=True, temp_path=str(partial),
                         total_bytes=len(data) if known_size else 0)
    TW.TransferWorker()._process_job(job)
    assert job.status == TW.TransferStatus.DONE, job.error_message
    assert (tmp_path / "dst.bin").read_bytes() == data
    assert other.read_bytes() == data[:100_000]  # the other name was left alone
