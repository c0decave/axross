"""The post-transfer integrity check compares content hashes only.

S3's ETag is the content MD5 only for a single-part upload without
SSE-KMS / SSE-C; a multipart ETag is an MD5 of part MD5s plus "-N", so
the SAME bytes uploaded with other part sizes carry another ETag. A
WebDAV getetag is server/inode based. The verifier compared any two
values with the same prefix, so an S3 -> S3 (or WebDAV -> WebDAV) copy
of identical bytes failed with "Integrity FAIL". Such fingerprints are
now not compared (forced verification streams both sides instead), and
S3 labels a KMS / SSE-C ETag as ``s3-etag`` rather than ``md5``.
"""

from __future__ import annotations

import hashlib
import io
from types import SimpleNamespace

import pytest

from core.s3_client import S3Session
from core.transfer_worker import TransferJob, TransferWorker, _ChecksumMismatch

DATA = bytes(range(256)) * 4096  # 1 MiB


def _multipart_etag(blob: bytes, part: int) -> str:
    parts = [hashlib.md5(blob[i : i + part]).digest() for i in range(0, len(blob), part)]
    return f'"{hashlib.md5(b"".join(parts)).hexdigest()}-{len(parts)}"'


class _Head:
    def __init__(self, **resp):
        self.resp = resp

    def head_object(self, Bucket, Key):
        return dict(self.resp)


def _s3(**resp) -> S3Session:
    s = object.__new__(S3Session)
    s._s3 = _Head(**resp)
    s._bucket = "b"
    return s


class _Backend:
    """A backend with a fixed native checksum and some content."""

    def __init__(self, checksum: str, data: bytes = DATA):
        self._checksum = checksum
        self._data = data

    def checksum(self, path, algorithm="sha256"):
        return self._checksum

    def open_read(self, path):
        return io.BytesIO(self._data)


def _verify(src, dst, *, forced=False):
    job = TransferJob(
        filename="a",
        source_backend=src,
        dest_backend=dst,
        source_path="/a",
        dest_path="/a",
        verify_checksum=forced,
    )
    worker = SimpleNamespace(_stream_sha256=TransferWorker._stream_sha256)
    TransferWorker._verify_integrity(worker, job)


# -- happy -------------------------------------------------------------------


def test_happy_identical_bytes_with_other_multipart_sizes_pass():
    src = _s3(ETag=_multipart_etag(DATA, 512 * 1024))
    dst = _s3(ETag=_multipart_etag(DATA, 256 * 1024))
    assert src.checksum("/a") != dst.checksum("/a")
    _verify(src, dst)


def test_happy_webdav_etags_of_two_copies_are_not_compared():
    _verify(_Backend('etag:"inode-1"'), _Backend('etag:"inode-2"'))


def test_happy_equal_single_part_md5_etags_pass():
    md5 = hashlib.md5(DATA).hexdigest()
    _verify(_s3(ETag=f'"{md5}"'), _s3(ETag=f'"{md5}"', ServerSideEncryption="AES256"))


# -- sad ---------------------------------------------------------------------


def test_sad_a_real_md5_mismatch_still_fails():
    with pytest.raises(_ChecksumMismatch):
        _verify(_s3(ETag='"' + "a" * 32 + '"'), _s3(ETag='"' + "b" * 32 + '"'))


def test_sad_forced_verification_streams_fingerprints_and_catches_a_difference():
    src = _Backend("s3-etag:x-2", DATA)
    dst = _Backend("s3-etag:x-2", DATA[:-1] + b"!")
    with pytest.raises(_ChecksumMismatch, match="sha256"):
        _verify(src, dst, forced=True)


def test_sad_s3_kms_and_sse_c_etags_are_not_labelled_md5():
    etag = '"' + "c" * 32 + '"'
    assert _s3(ETag=etag, ServerSideEncryption="aws:kms").checksum("/a").startswith("s3-etag:")
    assert _s3(ETag=etag, ServerSideEncryption="aws:kms:dsse").checksum("/a").startswith(
        "s3-etag:"
    )
    assert _s3(ETag=etag, SSECustomerAlgorithm="AES256").checksum("/a").startswith("s3-etag:")


# -- edge --------------------------------------------------------------------


def test_edge_forced_verification_of_equal_content_passes():
    _verify(_Backend("s3-etag:x-2"), _Backend("s3-etag:y-4"), forced=True)


def test_edge_plain_and_sse_s3_etags_stay_md5():
    md5 = hashlib.md5(DATA).hexdigest()
    assert _s3(ETag=f'"{md5}"').checksum("/a") == f"md5:{md5}"
    assert _s3(ETag=f'"{md5}"', ServerSideEncryption="AES256").checksum("/a") == f"md5:{md5}"


def test_edge_an_etag_that_is_not_32_hex_is_a_fingerprint():
    assert _s3(ETag='"not-a-hash"').checksum("/a").startswith("s3-etag:")
    assert _s3(ETag='"abc"').checksum("/a") == "s3-etag:abc"
    assert _s3(ETag="").checksum("/a") == ""
