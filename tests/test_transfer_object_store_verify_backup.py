"""An overwrite of an S3 or Azure Blob object that fails its integrity check
puts the original object back.

Round 1 verified a direct write while its rollback snapshot was still held,
so a mismatch could restore the old destination. S3 and Azure Blob take no
snapshot: their writers commit the whole object at close, so a failed
upload leaves the old object alone. But the check runs after that commit.
A corrupt upload over an existing object replaced it, the job reported
"Integrity FAIL", and the original was gone. With ``verify_checksum`` on,
the old object is now copied server-side next to it first (S3 CopyObject,
Azure Copy Blob). The copy is put back on a mismatch and removed once the
check passes.

The sessions are the real classes; only their service clients are fakes,
as in tests/test_s3_head_errors.py and
tests/test_azure_copy_waits_for_the_server.py.
"""

from __future__ import annotations

import hashlib
import io
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

pytest.importorskip("botocore")
pytest.importorskip("azure.storage.blob")

from azure.core.exceptions import ResourceNotFoundError  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

from core import s3_client as S3  # noqa: E402
from core.azure_client import AzureBlobSession  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker  # noqa: E402

ORIGINAL = b"ORIGINAL PRECIOUS OBJECT"
NEW = b"NEW CONTENT FROM THE LOCAL DISK"
WHEN = datetime(2026, 1, 1, tzinfo=timezone.utc)


class Store:
    """The bucket / container: key -> bytes, and what was asked of it."""

    def __init__(self, *, corrupt=(), refuse_copies=0, refuse_copies_after=None):
        self.objects: dict[str, bytes] = {"dst.txt": ORIGINAL}
        self.corrupt = set(corrupt)  # keys whose next upload arrives damaged
        self.copies: list[tuple[str, str]] = []
        self.uploads: list[str] = []
        self.refuse_copies = refuse_copies
        self.refuse_copies_after = refuse_copies_after
        self.seen_while_checking: dict[str, bytes] | None = None

    def put(self, key: str, data: bytes) -> None:
        self.uploads.append(key)
        if key in self.corrupt:
            self.corrupt.discard(key)
            data = bytes([data[0] ^ 0xFF]) + data[1:]
        self.objects[key] = data

    def copy(self, src: str, dst: str) -> None:
        if self.refuse_copies_after is not None and len(self.copies) >= self.refuse_copies_after:
            raise OSError("copy refused (throttled)")
        if self.refuse_copies:
            self.refuse_copies -= 1
            raise OSError("copy refused (AccessDenied)")
        self.copies.append((src, dst))
        self.objects[dst] = self.objects[src]

    def md5(self, key: str) -> str:
        if self.seen_while_checking is None and key == "dst.txt" and self.uploads:
            self.seen_while_checking = dict(self.objects)
        return hashlib.md5(self.objects[key]).hexdigest()


# -- S3: a boto3 client in memory --------------------------------------------------------


class FakeS3:
    def __init__(self, store: Store) -> None:
        self.store = store

    @staticmethod
    def _missing(op):
        return ClientError({"Error": {"Code": "404", "Message": "Not Found"}}, op)

    def head_object(self, Bucket, Key):
        if Key not in self.store.objects:
            raise self._missing("HeadObject")
        return {"ContentLength": len(self.store.objects[Key]), "LastModified": WHEN,
                "ETag": f'"{self.store.md5(Key)}"'}

    def list_objects_v2(self, Bucket, Prefix="", MaxKeys=1000, **_kw):
        keys = sorted(k for k in self.store.objects if k.startswith(Prefix))[:MaxKeys]
        return {"KeyCount": len(keys), "Contents": [{"Key": k} for k in keys]}

    def get_object(self, Bucket, Key, **_kw):
        if Key not in self.store.objects:
            raise ClientError({"Error": {"Code": "NoSuchKey"}}, "GetObject")
        return {"Body": io.BytesIO(self.store.objects[Key])}

    def upload_fileobj(self, fileobj, Bucket, Key, **_kw):
        self.store.put(Key, fileobj.read())

    def copy_object(self, Bucket, Key, CopySource, **_kw):
        self.store.copy(CopySource["Key"], Key)

    def delete_object(self, Bucket, Key):
        self.store.objects.pop(Key, None)


def s3_session(store: Store) -> S3.S3Session:
    s = S3.S3Session.__new__(S3.S3Session)
    s._bucket = "b"
    s._anonymous = False
    s._s3 = FakeS3(store)
    return s


# -- Azure Blob: a container client in memory -------------------------------------------


class FakeBlob:
    def __init__(self, store: Store, name: str) -> None:
        self.store, self.name = store, name
        self.url = f"https://acct.blob.core.windows.net/c/{name}"

    def get_blob_properties(self):
        if self.name not in self.store.objects:
            raise ResourceNotFoundError("BlobNotFound")
        return SimpleNamespace(
            size=len(self.store.objects[self.name]), last_modified=WHEN, metadata={},
            content_settings=SimpleNamespace(
                content_md5=bytearray(bytes.fromhex(self.store.md5(self.name)))),
            copy=SimpleNamespace(status="success", status_description=""),
        )

    def upload_blob(self, data, overwrite=False, **_kw):
        self.store.put(self.name, data.read() if hasattr(data, "read") else bytes(data))

    def download_blob(self, **_kw):
        if self.name not in self.store.objects:
            raise ResourceNotFoundError("BlobNotFound")
        data = self.store.objects[self.name]
        return SimpleNamespace(size=len(data), chunks=lambda: iter([data]))

    def start_copy_from_url(self, url, **_kw):
        self.store.copy(url.rsplit("/c/", 1)[1], self.name)

    def delete_blob(self, **_kw):
        if self.store.objects.pop(self.name, None) is None:
            raise ResourceNotFoundError("BlobNotFound")


class _Pages(list):
    continuation_token = None

    def by_page(self):
        return iter([self]) if self else iter([])


class FakeContainer:
    def __init__(self, store: Store) -> None:
        self.store = store

    def get_blob_client(self, name):
        return FakeBlob(self.store, name)

    def list_blobs(self, name_starts_with="", **_kw):
        return _Pages(SimpleNamespace(name=k) for k in sorted(self.store.objects)
                      if k.startswith(name_starts_with))


def azure_session(store: Store) -> AzureBlobSession:
    s = object.__new__(AzureBlobSession)
    s._container = FakeContainer(store)
    return s


SESSIONS = {"s3": s3_session, "azure-blob": azure_session}


def run(tmp_path, store: Store, kind: str, *, move: bool = False) -> TransferJob:
    src = tmp_path / "src.txt"
    src.write_bytes(NEW)
    job = TransferJob(source_path=str(src), dest_path="/dst.txt", filename="src.txt",
                      total_bytes=len(NEW), use_temp_file=False, verify_checksum=True,
                      move=move)
    job.source_backend = LocalFS()
    job.dest_backend = SESSIONS[kind](store)
    TransferWorker()._process_job(job)
    return job


@pytest.mark.parametrize("kind", SESSIONS)
def test_sad_a_failed_check_puts_the_original_object_back(tmp_path, kind):
    store = Store(corrupt={"dst.txt"})
    job = run(tmp_path, store, kind)
    assert job.status == TransferStatus.ERROR
    assert "Integrity FAIL" in job.error_message
    assert store.objects == {"dst.txt": ORIGINAL}  # the original, and no copy left


@pytest.mark.parametrize("kind", SESSIONS)
def test_happy_the_original_is_kept_until_the_check_passes(tmp_path, kind):
    """While the upload is checked a server-side copy of the original sits
    next to it; once the check passes only the new object is left."""
    store = Store()
    job = run(tmp_path, store, kind)
    assert job.status == TransferStatus.DONE, job.error_message
    kept = {k: v for k, v in store.seen_while_checking.items() if k != "dst.txt"}
    assert list(kept.values()) == [ORIGINAL]
    assert next(iter(kept)).startswith(".dst.txt.previous-")
    assert store.objects == {"dst.txt": NEW}


@pytest.mark.parametrize("kind", SESSIONS)
def test_sad_no_copy_of_the_original_means_no_upload(tmp_path, kind):
    """The copy cannot be made (refused, throttled, over 5 GB for one
    CopyObject): the transfer is refused before anything is uploaded."""
    store = Store(refuse_copies=1)
    job = run(tmp_path, store, kind)
    assert job.status == TransferStatus.ERROR
    assert "cannot keep a copy" in job.error_message
    assert store.uploads == []
    assert store.objects == {"dst.txt": ORIGINAL}


@pytest.mark.parametrize("kind", SESSIONS)
def test_sad_a_move_that_fails_its_check_keeps_source_and_original(tmp_path, kind):
    store = Store(corrupt={"dst.txt"})
    job = run(tmp_path, store, kind, move=True)
    assert job.status == TransferStatus.ERROR
    assert (tmp_path / "src.txt").read_bytes() == NEW
    assert store.objects == {"dst.txt": ORIGINAL}


@pytest.mark.parametrize("kind", SESSIONS)
def test_edge_an_original_that_cannot_be_put_back_is_kept_and_named(tmp_path, kind):
    """The copy back fails as well: the copy of the original stays, and the
    error names it."""
    store = Store(corrupt={"dst.txt"}, refuse_copies_after=1)
    job = run(tmp_path, store, kind)
    assert job.status == TransferStatus.ERROR
    kept = [k for k in store.objects if k != "dst.txt"]
    assert len(kept) == 1 and store.objects[kept[0]] == ORIGINAL
    assert "kept as /" + kept[0] in job.error_message
