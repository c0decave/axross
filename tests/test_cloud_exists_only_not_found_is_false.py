"""exists() and is_dir() say False only for "not found".

S3, Azure Blob, Azure Files, Google Drive and OneDrive answered False
when the server did not answer at all - a 503 SlowDown, a 403, a timeout,
a dropped connection. server_side_copy(overwrite=False) takes False from
exists() as its no-clobber go-ahead, so a throttled HEAD let it overwrite
the file it was told to keep. Any failure other than "not found" is now
an OSError.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace as NS
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

botocore_exceptions = pytest.importorskip("botocore.exceptions")
azure_exceptions = pytest.importorskip("azure.core.exceptions")
pytest.importorskip("googleapiclient")
requests = pytest.importorskip("requests")

import httplib2  # noqa: E402
from googleapiclient.discovery import build  # noqa: E402
from requests_fuzz_adapter import mount  # noqa: E402

from core.azure_client import AzureBlobSession, AzureFilesSession  # noqa: E402
from core.gdrive_client import GDriveSession  # noqa: E402
from core.onedrive_client import OneDriveSession  # noqa: E402
from core.s3_client import S3Session  # noqa: E402
from core.server_ops import server_side_copy  # noqa: E402

ClientError = botocore_exceptions.ClientError


# -- S3 ----------------------------------------------------------------------


def _client_error(code: str, status: int, op: str) -> Exception:
    return ClientError(
        {"Error": {"Code": code, "Message": code}, "ResponseMetadata": {"HTTPStatusCode": status}},
        op,
    )


class _S3:
    def __init__(self, objects, *, fail: Exception | None = None):
        self.objects = dict(objects)
        self.fail = fail

    def head_object(self, Bucket, Key):
        if self.fail is not None:
            raise self.fail
        if Key in self.objects:
            return {"ContentLength": len(self.objects[Key])}
        raise _client_error("404", 404, "HeadObject")

    def list_objects_v2(self, Bucket, Prefix="", MaxKeys=1000, **kw):
        if self.fail is not None:
            raise self.fail
        keys = sorted(k for k in self.objects if k.startswith(Prefix))[:MaxKeys]
        return {"KeyCount": len(keys), "Contents": [{"Key": k} for k in keys]}

    def copy_object(self, Bucket, Key, CopySource):
        self.objects[Key] = self.objects[CopySource["Key"]]


def _s3(objects, **kw) -> S3Session:
    s = S3Session.__new__(S3Session)
    s._bucket = "b"
    s._anonymous = False
    s._s3 = _S3(objects, **kw)
    return s


S3_FAILURES = [
    _client_error("SlowDown", 503, "HeadObject"),
    _client_error("403", 403, "HeadObject"),
    _client_error("InternalError", 500, "HeadObject"),
]


def test_happy_s3_present_and_absent_keys():
    s = _s3({"a.txt": b"x", "dir/b.txt": b"y"})
    assert s.exists("/a.txt") is True
    assert s.exists("/dir") is True
    assert s.is_dir("/dir") is True
    assert s.exists("/missing.txt") is False
    assert s.is_dir("/missing") is False


@pytest.mark.parametrize("fail", S3_FAILURES, ids=["503-slowdown", "403", "500"])
def test_sad_s3_a_failed_answer_is_an_oserror(fail):
    s = _s3({"a.txt": b"x"}, fail=fail)
    with pytest.raises(OSError, match="a.txt"):
        s.exists("/a.txt")
    with pytest.raises(OSError, match="dir"):
        s.is_dir("/dir")


def test_sad_s3_no_clobber_copy_keeps_the_target_when_head_is_throttled():
    s = _s3({"a.txt": b"new", "b.txt": b"PRECIOUS"})
    s._s3.fail = _client_error("SlowDown", 503, "HeadObject")
    with pytest.raises(OSError):
        server_side_copy(s, "/a.txt", "/b.txt", overwrite=False)
    assert s._s3.objects["b.txt"] == b"PRECIOUS"


def test_edge_s3_a_listing_failure_after_a_404_head_is_an_oserror():
    s = _s3({})

    def list_fails(**kw):
        raise _client_error("SlowDown", 503, "ListObjectsV2")

    s._s3.list_objects_v2 = list_fails
    with pytest.raises(OSError):
        s.exists("/a.txt")


# -- Azure Blob --------------------------------------------------------------


class _Pages:
    def __init__(self, items):
        self._it = iter([items])
        self.continuation_token = None

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._it)


class _Paged(list):
    def by_page(self):
        return _Pages(list(self))


class _Container:
    def __init__(self, blobs, *, fail: Exception | None = None):
        self.blobs = dict(blobs)
        self.fail = fail

    def get_blob_client(self, name):
        def props():
            if self.fail is not None:
                raise self.fail
            if name not in self.blobs:
                raise azure_exceptions.ResourceNotFoundError("BlobNotFound")
            return NS(metadata=self.blobs[name])

        return NS(get_blob_properties=props)

    def list_blobs(self, name_starts_with="", **kw):
        if self.fail is not None:
            raise self.fail
        return _Paged(NS(name=n) for n in sorted(self.blobs) if n.startswith(name_starts_with))


def _blob(blobs, **kw) -> AzureBlobSession:
    s = AzureBlobSession.__new__(AzureBlobSession)
    s._container = _Container(blobs, **kw)
    return s


AZURE_FAILURES = [
    ConnectionResetError("reset"),
    azure_exceptions.HttpResponseError("503 ServerBusy"),
    azure_exceptions.ClientAuthenticationError("403 AuthenticationFailed"),
]


def test_happy_azure_blob_present_and_absent():
    s = _blob({"a.txt": {}, "dir/b.txt": {}, "lake": {"hdi_isfolder": "true"}})
    assert s.exists("/a.txt") is True
    assert s.is_dir("/dir") is True
    assert s.is_dir("/lake") is True
    assert s.exists("/missing") is False
    assert s.is_dir("/missing") is False
    assert s.is_dir("/a.txt") is False


@pytest.mark.parametrize("fail", AZURE_FAILURES, ids=["reset", "503", "auth"])
def test_sad_azure_blob_a_failed_answer_is_an_oserror(fail):
    s = _blob({"a.txt": {}}, fail=fail)
    with pytest.raises(OSError):
        s.exists("/a.txt")
    with pytest.raises(OSError):
        s.is_dir("/dir")


def test_edge_azure_blob_placeholder_probe_failure_is_an_oserror():
    s = _blob({})

    def props_fail(name):
        def props():
            raise azure_exceptions.HttpResponseError("503 ServerBusy")

        return NS(get_blob_properties=props)

    s._container.get_blob_client = props_fail
    with pytest.raises(OSError):
        s.is_dir("/lake")


# -- Azure Files -------------------------------------------------------------


class _Share:
    def __init__(self, dirs, files, *, fail: Exception | None = None):
        self.dirs, self.files, self.fail = set(dirs), set(files), fail

    def get_directory_client(self, rel):
        share = self

        def dir_props():
            if share.fail is not None:
                raise share.fail
            if rel in share.dirs:
                return {}
            if rel in share.files:
                # Azure Files answers a directory probe of a file name with
                # 404 (or ResourceTypeMismatch); both mean "no directory".
                raise azure_exceptions.ResourceNotFoundError("ResourceNotFound")
            raise azure_exceptions.ResourceNotFoundError("ResourceNotFound")

        def file_client(name):
            full = f"{rel}/{name}" if rel else name

            def file_props():
                if share.fail is not None:
                    raise share.fail
                if full in share.files:
                    return {"size": 1}
                raise azure_exceptions.ResourceNotFoundError("ResourceNotFound")

            return NS(get_file_properties=file_props)

        return NS(get_directory_properties=dir_props, get_file_client=file_client)


def _files(dirs, files, **kw) -> AzureFilesSession:
    s = AzureFilesSession.__new__(AzureFilesSession)
    s._share = _Share(dirs, files, **kw)
    return s


def test_happy_azure_files_present_and_absent():
    s = _files({"dir"}, {"dir/a.txt"})
    assert s.exists("/dir") is True
    assert s.exists("/dir/a.txt") is True
    assert s.is_dir("/dir") is True
    assert s.is_dir("/dir/a.txt") is False
    assert s.exists("/dir/missing") is False
    assert s.is_dir("/missing") is False


@pytest.mark.parametrize("fail", AZURE_FAILURES, ids=["reset", "503", "auth"])
def test_sad_azure_files_a_failed_answer_is_an_oserror(fail):
    s = _files({"dir"}, {"dir/a.txt"}, fail=fail)
    with pytest.raises(OSError):
        s.exists("/dir/a.txt")
    with pytest.raises(OSError):
        s.is_dir("/dir")


def test_edge_azure_files_type_mismatch_means_no_directory():
    s = _files(set(), {"a.txt"})
    mismatch = azure_exceptions.ResourceExistsError("ResourceTypeMismatch")
    mismatch.error_code = "ResourceTypeMismatch"

    original = s._share.get_directory_client

    def get_dir(rel):
        client = original(rel)
        if rel == "a.txt":

            def dir_props():
                raise mismatch

            client.get_directory_properties = dir_props
        return client

    s._share.get_directory_client = get_dir
    assert s.is_dir("/a.txt") is False
    assert s.exists("/a.txt") is True


# -- Google Drive ------------------------------------------------------------


class _GHttp:
    def __init__(self, answer):
        self.answer = answer

    def request(self, uri, method="GET", body=None, headers=None, **_kwargs):
        status, payload = self.answer(uri)
        if isinstance(payload, BaseException):
            raise payload
        resp = httplib2.Response({"status": str(status), "content-type": "application/json"})
        return resp, json.dumps(payload).encode()


def _gdrive(answer) -> GDriveSession:
    s = GDriveSession.__new__(GDriveSession)
    s._service = build("drive", "v3", http=_GHttp(answer), static_discovery=True)
    s._path_cache = {"/": "root"}
    return s


def _gdrive_store(uri):
    if "/files?" in uri:
        if "name+%3D+%27a.txt%27" in uri or "name%20%3D%20%27a.txt%27" in uri:
            return 200, {"files": [{"id": "F1", "name": "a.txt", "mimeType": "text/plain"}]}
        return 200, {"files": []}
    if "/files/F1" in uri:
        return 200, {"id": "F1", "name": "a.txt", "mimeType": "text/plain"}
    return 404, {"error": {"code": 404, "message": "File not found"}}


def test_happy_gdrive_present_and_absent():
    s = _gdrive(_gdrive_store)
    assert s.exists("/a.txt") is True
    assert s.is_dir("/a.txt") is False
    assert s.exists("/missing") is False
    assert s.is_dir("/missing") is False


@pytest.mark.parametrize(
    "answer",
    [
        lambda uri: (0, TimeoutError("read timed out")),
        lambda uri: (503, {"error": {"code": 503, "message": "backendError"}}),
        lambda uri: (403, {"error": {"code": 403, "message": "rateLimitExceeded"}}),
    ],
    ids=["timeout", "503", "403-rate"],
)
def test_sad_gdrive_a_failed_answer_is_an_oserror(answer):
    s = _gdrive(answer)
    with pytest.raises(OSError):
        s.exists("/a.txt")
    with pytest.raises(OSError):
        s.is_dir("/a.txt")


def test_edge_gdrive_a_cached_id_gone_on_the_server_is_not_a_folder():
    s = _gdrive(lambda uri: (404, {"error": {"code": 404, "message": "File not found"}}))
    s._path_cache["/gone"] = "GONE"
    assert s.is_dir("/gone") is False


# -- OneDrive ----------------------------------------------------------------


def _onedrive(responder) -> OneDriveSession:
    s = OneDriveSession.__new__(OneDriveSession)
    s._http = requests.Session()
    mount(s._http, responder)
    s._access_token = "t"
    s._app = mock.Mock()
    s._app.get_accounts.return_value = [{"username": "u"}]
    s._app.acquire_token_silent.return_value = {"access_token": "t"}
    s._cache = mock.Mock(has_state_changed=False)
    s._drive_type = "personal"
    s._site_id = None
    s._scopes = []
    return s


def _graph_store(request):
    if request.url.endswith("root:/a.txt"):
        return 200, {}, json.dumps({"id": "1", "name": "a.txt", "file": {}}).encode()
    if request.url.endswith("root:/dir"):
        return 200, {}, json.dumps({"id": "2", "name": "dir", "folder": {}}).encode()
    return 404, {}, b'{"error":{"code":"itemNotFound"}}'


def test_happy_onedrive_present_and_absent():
    s = _onedrive(_graph_store)
    assert s.exists("/a.txt") is True
    assert s.is_dir("/dir") is True
    assert s.is_dir("/a.txt") is False
    assert s.exists("/missing") is False
    assert s.is_dir("/missing") is False


@pytest.mark.parametrize("status", [429, 500, 503, 403])
def test_sad_onedrive_a_failed_answer_is_an_oserror(status):
    s = _onedrive(lambda r: (status, {}, b'{"error":{"code":"serviceNotAvailable"}}'))
    with pytest.raises(OSError):
        s.exists("/a.txt")
    with pytest.raises(OSError):
        s.is_dir("/a.txt")


def test_edge_onedrive_a_dropped_connection_is_an_oserror():
    def drop(request):
        raise requests.ConnectionError("connection reset")

    s = _onedrive(drop)
    with pytest.raises(OSError):
        s.exists("/a.txt")


def test_edge_onedrive_not_found_is_file_not_found_for_stat():
    s = _onedrive(_graph_store)
    with pytest.raises(FileNotFoundError):
        s.stat("/missing")
