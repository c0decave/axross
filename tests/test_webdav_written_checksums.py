"""WebDAV: the checksum PROPFIND after an upload is skipped once the server
proved it keeps no SHA-256 of uploads.

Measured before (lab, 20 ms relay, 500 x 4 KiB upload): one PROPFIND per
file for ``checksum()``, which on a server without ``oc:checksums`` (Apache
mod_dav, nginx, rclone, axross's own server) can only answer the ETag - a
storage fingerprint the transfer engine never compares
(core.transfer_worker._STORAGE_FINGERPRINTS). 22 s of 70 s.

``checksum_kinds(path, written=True)`` says so after the first written file
came back without one; every RECHECK_WRITTEN_EVERY-th is still asked, and
one that comes back WITH a SHA-256 makes every later one asked again. A
file this session did not write is always asked (a Nextcloud file can carry
the hash its uploader sent).
"""

from __future__ import annotations

import hashlib
import io

import pytest

pytest.importorskip("defusedxml")
pytest.importorskip("requests")

from core.webdav_client import WebDavSession  # noqa: E402


class FakeClient:
    """_WebDavClient stand-in: PUT keeps the bytes; PROPFIND answers the
    etag, plus a SHA256 entry when *hashes* is on."""

    def __init__(self, hashes: bool = False) -> None:
        self.files: dict[str, bytes] = {}
        self.hashes = hashes
        self.propfinds = 0

    def upload_from(self, fileobj, path):
        self.files[path] = fileobj.read()

    def info(self, path):
        self.propfinds += 1
        data = self.files[path]
        sums = [f"SHA256:{hashlib.sha256(data).hexdigest()}"] if self.hashes else []
        return {"path": path, "name": path.rsplit("/", 1)[-1], "size": len(data),
                "isdir": False, "etag": f"e{len(data)}", "oc_checksums": sums}


def _session(client: FakeClient) -> WebDavSession:
    s = WebDavSession.__new__(WebDavSession)
    s._client = client
    return s


def _upload(s: WebDavSession, path: str, data: bytes = b"data") -> None:
    w = s.open_write(path)
    w.write(data)
    w.close()


def test_happy_after_one_upload_without_a_hash_the_next_are_not_asked():
    s = _session(FakeClient())
    assert s.checksum_kinds("/a", written=True) is None  # nothing known yet
    _upload(s, "/a")
    assert s.checksum("/a").startswith("etag:")
    assert s.checksum_kinds("/b", written=True) == frozenset({"etag"})


def test_happy_a_server_that_hashes_uploads_is_always_asked():
    s = _session(FakeClient(hashes=True))
    _upload(s, "/a")
    assert s.checksum("/a").startswith("sha256:")
    for _ in range(5):
        assert s.checksum_kinds("/b", written=True) is None


def test_sad_a_file_not_written_here_is_always_asked():
    client = FakeClient()
    s = _session(client)
    _upload(s, "/a")
    s.checksum("/a")
    assert s.checksum_kinds("/other", written=False) is None
    client.files["/other"] = b"x"
    s.checksum("/other")  # not one of ours: teaches nothing about uploads
    assert s._written_hash == {"sha256": False}


def test_sad_one_hashed_upload_later_turns_the_skipping_off_for_good():
    client = FakeClient()
    s = _session(client)
    _upload(s, "/a")
    s.checksum("/a")
    client.hashes = True
    _upload(s, "/b")
    assert s.checksum("/b").startswith("sha256:")
    _upload(s, "/c")
    client.hashes = False
    s.checksum("/c")
    assert s.checksum_kinds("/d", written=True) is None


def test_edge_every_nth_written_file_is_asked_again():
    s = _session(FakeClient())
    _upload(s, "/a")
    s.checksum("/a")
    answers = [s.checksum_kinds("/x", written=True) for _ in range(2 * s.RECHECK_WRITTEN_EVERY)]
    assert answers.count(None) == 2
    assert answers[s.RECHECK_WRITTEN_EVERY - 1] is None


def test_edge_a_discarded_writer_is_no_upload():
    s = _session(FakeClient())
    w = s.open_write("/a")
    w.write(b"x")
    w.discard()
    assert not s._written_paths


def test_happy_the_transfer_skips_the_propfind_but_still_verifies_when_forced(tmp_path):
    """Through the worker: the second upload sends no PROPFIND for the
    check; with verify_checksum it reads the file back instead."""
    from core.local_fs import LocalFS
    from core.transfer_worker import TransferJob, TransferStatus, TransferWorker

    client = FakeClient()
    s = _session(client)
    s.open_read = lambda path: io.BytesIO(client.files[path])
    for i, forced in enumerate([False, False, True]):
        src = tmp_path / f"f{i}"
        src.write_bytes(b"payload %d" % i)
        job = TransferJob(source_path=str(src), dest_path=f"/f{i}", filename=f"f{i}",
                          total_bytes=src.stat().st_size, use_temp_file=False,
                          verify_checksum=forced)
        job.source_backend, job.dest_backend = LocalFS(), s
        s.exists = lambda path: path in client.files
        before = client.propfinds
        TransferWorker()._process_job(job)
        assert job.status == TransferStatus.DONE, job.error_message
        assert client.propfinds - before == (1 if i == 0 else 0)
