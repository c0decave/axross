"""The integrity check after a transfer does not hash a local file whose
hash cannot be compared.

LocalFS has no native checksum: ``checksum`` reads the whole file. The
check asked both sides first and compared after, so an upload to SMB,
FTP, WebDAV, S3 or RamFS (no checksum, or MD5 / an ETag against the local
SHA-256) and a download from them re-read the whole local file for a
comparison that could not happen - for a 10 GiB file 10 GiB of disk reads
per transfer. Now the other side is asked first, and the local file is
hashed only when its SHA-256 can be compared. What is compared, and every
verdict, is unchanged.
"""

from __future__ import annotations

import hashlib
import io
from pathlib import Path
from types import SimpleNamespace

import pytest

from core.local_fs import LocalFS
from core.transfer_worker import TransferJob, TransferWorker, _ChecksumMismatch

DATA = bytes(range(256)) * 64


class _Remote:
    """A non-local backend with a fixed native checksum and content."""

    def __init__(self, checksum, data: bytes = DATA):
        self._checksum = checksum
        self._data = data
        self.checksum_calls = 0

    def checksum(self, path, algorithm="sha256"):
        self.checksum_calls += 1
        if isinstance(self._checksum, Exception):
            raise self._checksum
        return self._checksum

    def open_read(self, path):
        return io.BytesIO(self._data)


class _CountingLocal(LocalFS):
    """LocalFS whose (inherited, whole-file) checksum calls are counted."""

    def __init__(self) -> None:
        super().__init__()
        self.checksum_calls = 0

        def counted(path, algorithm="sha256", _orig=self.checksum):
            self.checksum_calls += 1
            return _orig(path, algorithm)

        self.checksum = counted  # instance attribute: the class method stays LocalFS's


@pytest.fixture
def local_file(tmp_path: Path) -> str:
    path = tmp_path / "a.bin"
    path.write_bytes(DATA)
    return str(path)


def _verify(src, src_path, dst, dst_path, *, forced=False):
    job = TransferJob(filename="a.bin", source_backend=src, dest_backend=dst,
                      source_path=src_path, dest_path=dst_path, verify_checksum=forced)
    worker = SimpleNamespace(_stream_sha256=TransferWorker._stream_sha256)
    TransferWorker._verify_integrity(worker, job)


SHA = "sha256:" + hashlib.sha256(DATA).hexdigest()
UNUSABLE = ["", None, "md5:" + hashlib.md5(DATA).hexdigest(), "s3-etag:abc-2", "etag:xyz",
            OSError("no such command")]


# -- happy: nothing comparable, no local hash -----------------------------------


@pytest.mark.parametrize("remote_value", UNUSABLE, ids=repr)
def test_happy_upload_to_a_backend_without_a_comparable_hash_reads_no_local_file(
        local_file, remote_value):
    local, remote = _CountingLocal(), _Remote(remote_value)
    _verify(local, local_file, remote, "/a.bin")
    assert local.checksum_calls == 0
    assert remote.checksum_calls == 1


@pytest.mark.parametrize("remote_value", UNUSABLE, ids=repr)
def test_happy_download_from_a_backend_without_a_comparable_hash_reads_no_local_file(
        local_file, remote_value):
    local, remote = _CountingLocal(), _Remote(remote_value)
    _verify(remote, "/a.bin", local, local_file)
    assert local.checksum_calls == 0
    assert remote.checksum_calls == 1


def test_happy_a_comparable_remote_sha256_is_still_compared_and_passes(local_file):
    local, remote = _CountingLocal(), _Remote(SHA)
    _verify(local, local_file, remote, "/a.bin")
    _verify(remote, "/a.bin", local, local_file)
    assert local.checksum_calls == 2


def test_happy_local_to_local_still_hashes_both(local_file, tmp_path):
    copy = tmp_path / "b.bin"
    copy.write_bytes(DATA)
    src, dst = _CountingLocal(), _CountingLocal()
    _verify(src, local_file, dst, str(copy))
    assert (src.checksum_calls, dst.checksum_calls) == (1, 1)


@pytest.mark.parametrize("src_value", ["", None, "s3-etag:abc-2", "etag:xyz"], ids=repr)
def test_happy_between_two_remotes_a_source_without_a_comparable_value_skips_the_other(
        src_value):
    src, dst = _Remote(src_value), _Remote(SHA)
    _verify(src, "/a", dst, "/b")
    assert dst.checksum_calls == 0


def test_happy_between_two_remotes_matching_values_are_compared():
    src, dst = _Remote("md5:ab"), _Remote("md5:ab")
    _verify(src, "/a", dst, "/b")
    assert (src.checksum_calls, dst.checksum_calls) == (1, 1)


# -- sad: every mismatch is still caught -------------------------------------------


def test_sad_a_differing_remote_sha256_is_still_a_mismatch_either_way(local_file):
    wrong = _Remote("sha256:" + "0" * 64)
    with pytest.raises(_ChecksumMismatch):
        _verify(_CountingLocal(), local_file, wrong, "/a.bin")
    with pytest.raises(_ChecksumMismatch):
        _verify(wrong, "/a.bin", _CountingLocal(), local_file)


def test_sad_forced_verification_without_a_native_hash_still_streams_and_catches(local_file):
    corrupt = _Remote("", data=DATA[:-1] + b"X")
    local = _CountingLocal()
    with pytest.raises(_ChecksumMismatch):
        _verify(local, local_file, corrupt, "/a.bin", forced=True)
    with pytest.raises(_ChecksumMismatch):
        _verify(corrupt, "/a.bin", local, local_file, forced=True)
    assert local.checksum_calls == 0  # streamed, not hashed twice


def test_sad_two_remote_backends_with_differing_hashes_still_mismatch():
    with pytest.raises(_ChecksumMismatch):
        _verify(_Remote("sha256:aa"), "/a", _Remote("sha256:bb"), "/b")


# -- edge ---------------------------------------------------------------------------


def test_edge_forced_verification_of_identical_bytes_passes(local_file):
    local = _CountingLocal()
    _verify(local, local_file, _Remote("md5:whatever"), "/a.bin", forced=True)
    _verify(_Remote(""), "/a.bin", local, local_file, forced=True)
    assert local.checksum_calls == 0


def test_edge_a_local_subclass_with_its_own_checksum_is_asked_as_before(local_file):
    class NativeLocal(LocalFS):
        calls = 0

        def checksum(self, path, algorithm="sha256"):
            NativeLocal.calls += 1
            return "md5:" + hashlib.md5(DATA).hexdigest()

    remote = _Remote("md5:" + hashlib.md5(DATA).hexdigest())
    _verify(NativeLocal(), local_file, remote, "/a.bin")
    assert NativeLocal.calls == 1


def test_edge_e2e_upload_to_ramfs_through_the_worker_reads_the_source_once(tmp_path):
    """The real worker, LocalFS -> RamFS (no checksum): the source is read
    by the copy and by nothing else."""
    from core.ram_fs import RamFsSession
    from core.transfer_worker import TransferDirection

    src = tmp_path / "big.bin"
    payload = DATA * 50
    src.write_bytes(payload)
    local, ram = _CountingLocal(), RamFsSession()
    job = TransferJob(source_path=str(src), dest_path="/big.bin", filename="big.bin",
                      direction=TransferDirection.UPLOAD, total_bytes=len(payload))
    job.source_backend, job.dest_backend = local, ram
    worker = TransferWorker()
    errors = []
    worker.job_error.connect(lambda _id, msg: errors.append(msg))
    worker._process_job(job)
    assert errors == []
    assert job.status.name == "DONE"
    with ram.open_read("/big.bin") as fh:
        assert fh.read() == payload
    assert local.checksum_calls == 0
