"""Cloud backends (Google Drive, OneDrive, Dropbox, Azure Blob / Files):
typed errors, bounded retries, every page of a name lookup, no file at a
path ending in "/".

Found by the final protocol review (repros in pt-rev4-proto/cloud):

* Google Drive's name lookup read only the first page of files.list
  (pageSize=2, no nextPageToken). Drive documents empty pages while more
  follow: "not found" made open_write / mkdir create a SECOND report.txt /
  photos, and every later lookup of the name failed as ambiguous.
* No retry on 429 / 5xx: OneDrive ignored Retry-After and one bad chunk
  threw away a whole upload session; Drive ran with num_retries=0.
* The write handles' close() let the SDK's own exception out (HttpError,
  ApiError, HttpResponseError - no OSError): the editor's "Cannot save
  file" dialog was skipped for the "Unexpected Error" one. Errors without
  an errno reached a FUSE mount as ENOENT.
* Azure open_read of a missing path was a plain OSError.
* Dropbox conflicts were untyped: server_side_copy(overwrite=True) onto an
  existing file always failed.
* A path ending in "/" was written as a FILE.

The services are the in-memory fakes tests/fake_gdrive.py,
fake_onedrive.py, fake_dropbox.py and fake_azure_files.py (the SDKs' own
error types); Drive's retry also runs over the real googleapiclient.
"""

from __future__ import annotations

import errno
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import cloud_http  # noqa: E402
from core.atomic_io import atomic_write  # noqa: E402


@pytest.fixture
def pauses(monkeypatch):
    """The pauses cloud_http makes before retries (no real waiting)."""
    seen: list[float] = []
    monkeypatch.setattr(cloud_http, "_sleep", seen.append)
    return seen


def _write(backend, path, data):
    with backend.open_write(path) as fh:
        fh.write(data)


def _read(backend, path):
    with backend.open_read(path) as fh:
        return fh.read()


# -- fakes -----------------------------------------------------------------------------


@pytest.fixture
def gdrive():
    pytest.importorskip("googleapiclient")
    import fake_gdrive

    drive = fake_gdrive.FakeDrive()
    return drive, fake_gdrive.make_session(drive)


@pytest.fixture
def onedrive():
    pytest.importorskip("requests")
    import fake_onedrive

    graph = fake_onedrive.FakeGraph()
    return graph, fake_onedrive.make_session(graph)


@pytest.fixture
def dropbox_fake():
    pytest.importorskip("dropbox")
    import fake_dropbox

    fx = fake_dropbox.FakeDropbox()
    return fx, fake_dropbox.make_session(fx)


@pytest.fixture
def azure_files():
    pytest.importorskip("azure.storage.fileshare")
    import fake_azure_files

    share = fake_azure_files.FakeShare()
    return share, fake_azure_files.make_session(share)


@pytest.fixture
def azure_blob():
    pytest.importorskip("azure.storage.blob")
    import test_backend_conformance as C

    from core.azure_client import AzureBlobSession

    s = object.__new__(AzureBlobSession)
    s._container = C._AzureStore()
    return s._container, s


def _fresh(gd):
    gd._path_cache = {"/": "root"}


# -- 1. Google Drive: every page of a name lookup ---------------------------------------


def test_happy_gdrive_lookup_follows_an_empty_first_page(gdrive):
    drive, s = gdrive
    _write(s, "/report.txt", b"v1")
    s.mkdir("/photos")

    _fresh(s)
    drive.empty_first_page = 1
    assert s.exists("/report.txt") is True

    _fresh(s)
    drive.empty_first_page = 1
    _write(s, "/report.txt", b"v2")  # an update of the one file, not a second
    same = [v for v in drive.items.values() if v["name"] == "report.txt"]
    assert [v["data"] for v in same] == [b"v2"]

    _fresh(s)
    drive.empty_first_page = 1
    with pytest.raises(FileExistsError):
        s.mkdir("/photos")
    assert len([v for v in drive.items.values() if v["name"] == "photos"]) == 1
    _fresh(s)
    assert _read(s, "/report.txt") == b"v2"


def test_sad_gdrive_a_name_two_items_hold_is_ambiguous_even_across_pages(gdrive):
    drive, s = gdrive
    _write(s, "/a.txt", b"1")
    # A second item of the name, as the web UI or another client makes it.
    root_child = next(v for v in drive.items.values() if v["name"] == "a.txt")
    drive.items["DUP"] = dict(root_child, id="DUP", data=b"2")
    _fresh(s)
    drive.empty_first_page = 1
    with pytest.raises(OSError) as info:
        s.stat("/a.txt")
    assert info.value.errno == getattr(errno, "ENOTUNIQ", errno.EIO)
    assert not isinstance(info.value, FileNotFoundError)


def test_edge_gdrive_a_case_insensitive_match_is_another_name(gdrive):
    drive, s = gdrive
    drive.name_ci = True
    _write(s, "/Report.txt", b"upper")
    _fresh(s)
    assert s.exists("/report.txt") is False
    _write(s, "/report.txt", b"lower")
    names = sorted(v["name"] for v in drive.items.values() if v["name"].lower() == "report.txt")
    assert names == ["Report.txt", "report.txt"]


def test_edge_gdrive_a_repeated_page_token_fails(gdrive, monkeypatch):
    drive, s = gdrive
    _write(s, "/a.txt", b"1")
    monkeypatch.setattr(drive, "_list", lambda q, size, tok: {"files": [], "nextPageToken": "T"})
    _fresh(s)
    with pytest.raises(OSError) as info:
        s.exists("/a.txt")
    assert info.value.errno == errno.EPROTO


# -- 2. retries on 429 / 5xx ------------------------------------------------------------


def test_happy_onedrive_retries_a_throttled_request_after_retry_after(onedrive, pauses,
                                                                      monkeypatch):
    import fake_onedrive

    graph, s = onedrive
    s.mkdir("/docs")
    real_err = graph._err

    def throttled(status, code, msg):
        resp = real_err(status, code, msg)
        if status == 429:
            resp.headers = {"Retry-After": "3"}
        return resp

    monkeypatch.setattr(graph, "_err", throttled)
    graph.throttle = 1
    assert s.list_dir("/docs") == []
    assert pauses == [3.0]
    assert isinstance(graph, fake_onedrive.FakeGraph)


def test_happy_onedrive_upload_session_resumes_after_a_failed_chunk(onedrive, pauses,
                                                                    monkeypatch):
    import fake_onedrive

    graph, s = onedrive
    s.mkdir("/docs")
    monkeypatch.setattr("core.onedrive_client._SIMPLE_UPLOAD_MAX", 1024)
    monkeypatch.setattr("core.onedrive_client._UPLOAD_CHUNK", 1024)
    real_put = graph.put
    chunks = {"n": 0}

    def flaky(url, headers=None, data=None, timeout=None, **kw):
        if url.startswith("https://upload.fake/"):
            chunks["n"] += 1
            if chunks["n"] == 3:
                return fake_onedrive.Resp(503, {"error": {"code": "serviceNotAvailable"}},
                                          {"Retry-After": "1"})
        return real_put(url, headers=headers, data=data, timeout=timeout, **kw)

    monkeypatch.setattr(graph, "put", flaky)
    data = bytes(range(256)) * 20  # 5 chunks
    _write(s, "/docs/big.bin", data)
    assert graph.nodes["docs/big.bin"]["data"] == data
    assert pauses == [1.0]


def test_sad_onedrive_gives_up_after_the_bounded_attempts_with_eagain(onedrive, pauses):
    graph, s = onedrive
    graph.throttle = 100
    with pytest.raises(OSError) as info:
        s.stat("/x")
    assert info.value.errno == errno.EAGAIN
    assert not isinstance(info.value, FileNotFoundError)  # a FUSE mount said ENOENT
    assert len(pauses) == cloud_http.ATTEMPTS - 1
    assert graph.throttle == 100 - cloud_http.ATTEMPTS


def test_edge_onedrive_a_post_is_retried_on_429_but_not_on_5xx(onedrive, pauses, monkeypatch):
    import fake_onedrive

    graph, s = onedrive
    posts = []

    def failing_post(url, headers=None, json=None, timeout=None, **kw):
        posts.append(url)
        return fake_onedrive.Resp(500, {"error": {"code": "generalException"}})

    monkeypatch.setattr(graph, "post", failing_post)
    with pytest.raises(OSError) as info:
        s.mkdir("/new")  # sent twice, a lost answer would make it twice
    assert info.value.errno == errno.EIO
    assert len(posts) == 1 and pauses == []


def test_happy_gdrive_retries_a_5xx_over_the_real_client(pauses):
    pytest.importorskip("googleapiclient")
    import httplib2
    from googleapiclient.discovery import build

    from core.gdrive_client import GDriveSession

    class FlakyHttp:
        def __init__(self):
            self.n = 0

        def request(self, uri, method="GET", body=None, headers=None, **kw):
            self.n += 1
            if self.n == 1:
                return (httplib2.Response({"status": "503", "retry-after": "2"}),
                        b'{"error":{"code":503,"message":"backendError"}}')
            return (httplib2.Response({"status": "200", "content-type": "application/json"}),
                    json.dumps({"files": []}).encode())

    http = FlakyHttp()
    s = GDriveSession.__new__(GDriveSession)
    s._service = build("drive", "v3", http=http, static_discovery=True)
    s._path_cache = {"/": "root"}
    assert s.list_dir("/") == []
    assert http.n == 2 and pauses == [2.0]


def test_sad_gdrive_a_create_is_not_retried_on_5xx(gdrive, pauses, monkeypatch):
    import fake_gdrive

    drive, s = gdrive
    calls = []

    def broken(body, media):
        calls.append(body["name"])
        raise fake_gdrive._http_error(500, "backendError")

    monkeypatch.setattr(drive, "_create", broken)
    with pytest.raises(OSError) as info:
        s.mkdir("/x")
    assert info.value.errno == errno.EIO
    assert calls == ["x"] and pauses == []


def test_edge_retry_after_is_capped_and_garbage_ignored():
    assert cloud_http.retry_after_seconds("5") == 5.0
    assert cloud_http.retry_after_seconds("86400") == cloud_http.RETRY_AFTER_CAP
    assert cloud_http.retry_after_seconds("-3") == 0.0
    assert cloud_http.retry_after_seconds("soon") is None
    assert cloud_http.retry_after_seconds("nan") is None
    assert cloud_http.retry_after_seconds(None) is None
    assert cloud_http.retry_after_seconds("Wed, 21 Oct 2015 07:28:00 GMT") == 0.0
    for attempt in range(1, 10):
        assert 0 < cloud_http.delay(attempt) <= cloud_http.MAX_DELAY


# -- 3. typed errors, close() included ---------------------------------------------------


def test_happy_gdrive_full_storage_on_save_is_an_enospc_oserror(gdrive, monkeypatch):
    import fake_gdrive

    drive, s = gdrive

    def quota(*a, **k):
        raise fake_gdrive._http_error(403, "storageQuotaExceeded")

    monkeypatch.setattr(drive, "_create", quota)
    with pytest.raises(OSError) as info:
        atomic_write(s, "/notes.txt", b"edited")
    assert info.value.errno == errno.ENOSPC


def test_sad_dropbox_insufficient_space_on_save_is_an_enospc_oserror(dropbox_fake, monkeypatch):
    import dropbox.files as F
    import fake_dropbox

    fx, s = dropbox_fake

    def full(f, path, mode=None, **kw):
        raise fake_dropbox._err(F.UploadError.path(F.UploadWriteFailed(
            reason=F.WriteError.insufficient_space, upload_session_id="s")))

    monkeypatch.setattr(fx, "files_upload", full)
    with pytest.raises(OSError) as info:
        atomic_write(s, "/notes.txt", b"edited")
    assert info.value.errno == errno.ENOSPC


def test_sad_azure_writers_close_with_an_oserror(azure_blob, azure_files, monkeypatch):
    from azure.core.exceptions import HttpResponseError

    import fake_azure_files
    import test_backend_conformance as C

    _store, blob = azure_blob

    def refused(self, *a, **k):
        exc = HttpResponseError(message="This request is not authorized to perform this operation.")
        exc.status_code = 403
        raise exc

    monkeypatch.setattr(C._AzureBlob, "upload_blob", refused)
    with pytest.raises(PermissionError):
        atomic_write(blob, "/notes.txt", b"x")

    _share, files = azure_files

    def full(self, *a, **k):
        raise HttpResponseError(message="The specified share is full. ErrorCode:ShareSizeLimitReached")

    monkeypatch.setattr(fake_azure_files._File, "upload_file", full)
    with pytest.raises(OSError) as info:
        atomic_write(files, "/notes.txt", b"x")
    assert info.value.errno == errno.ENOSPC


def test_edge_dropbox_a_5xx_is_eio_not_enoent(dropbox_fake, monkeypatch):
    from dropbox.exceptions import InternalServerError

    fx, s = dropbox_fake
    _write(s, "/log.txt", b"data")

    def flaky(path, **kw):
        raise InternalServerError("req", 500, "Internal Server Error")

    monkeypatch.setattr(fx, "files_get_metadata", flaky)
    with pytest.raises(OSError) as info:
        s.stat("/log.txt")
    assert info.value.errno == errno.EIO
    with pytest.raises(OSError):
        s.exists("/log.txt")  # never False for a failed request


# -- 4. Azure open_read of a missing path -----------------------------------------------


def test_happy_azure_open_read_of_a_missing_path_is_file_not_found(azure_blob, azure_files):
    for _store, backend in (azure_blob, azure_files):
        with pytest.raises(FileNotFoundError):
            backend.open_read("/nope.txt")


def test_sad_azure_files_mkdir_of_an_existing_folder_and_remove_of_a_missing_file(azure_files):
    _share, s = azure_files
    s.mkdir("/d")
    with pytest.raises(FileExistsError):
        s.mkdir("/d")
    with pytest.raises(FileNotFoundError):
        s.remove("/nope")


# -- 5. Dropbox conflicts ---------------------------------------------------------------


def test_happy_dropbox_copy_with_overwrite_replaces_the_file(dropbox_fake):
    from core.server_ops import server_side_copy

    fx, s = dropbox_fake
    _write(s, "/a.txt", b"new")
    _write(s, "/b.txt", b"old")
    server_side_copy(s, "/a.txt", "/b.txt", overwrite=True)
    assert _read(s, "/b.txt") == b"new"
    assert sorted(i.name for i in s.list_dir("/")) == ["a.txt", "b.txt"]


def test_sad_dropbox_copy_and_rename_onto_a_taken_name_are_file_exists(dropbox_fake):
    from core.server_ops import server_side_copy

    fx, s = dropbox_fake
    _write(s, "/a.txt", b"new")
    _write(s, "/b.txt", b"old")
    with pytest.raises(FileExistsError):
        s.copy("/a.txt", "/b.txt")
    with pytest.raises(FileExistsError):
        s.rename("/a.txt", "/b.txt")
    with pytest.raises(FileExistsError):
        server_side_copy(s, "/a.txt", "/b.txt", overwrite=False)
    assert _read(s, "/b.txt") == b"old"


def test_edge_dropbox_absence_and_folder_answers_are_typed(dropbox_fake):
    fx, s = dropbox_fake
    _write(s, "/f", b"x")
    s.mkdir("/d")
    with pytest.raises(FileNotFoundError):
        s.stat("/nope")
    with pytest.raises(FileNotFoundError):
        s.remove("/nope")
    with pytest.raises(FileExistsError):
        s.mkdir("/d")
    with pytest.raises(NotADirectoryError):
        s.list_dir("/f")
    with pytest.raises(IsADirectoryError):
        _write(s, "/d", b"over a folder")
    assert s.exists("/f/below") is False


# -- 6. a path ending in "/" is no file -------------------------------------------------


@pytest.mark.parametrize("which", ["gdrive", "onedrive", "dropbox_fake", "azure_files",
                                   "azure_blob"])
def test_happy_a_write_to_a_path_ending_in_a_slash_is_refused(which, request):
    _svc, s = request.getfixturevalue(which)
    with pytest.raises(IsADirectoryError):
        _write(s, "/t/", b"data")
    assert "t" not in {i.name for i in s.list_dir("/")}


@pytest.mark.parametrize("which", ["gdrive", "onedrive", "dropbox_fake", "azure_files"])
def test_sad_a_file_renamed_or_copied_to_a_path_ending_in_a_slash_is_refused(which, request):
    _svc, s = request.getfixturevalue(which)
    _write(s, "/g", b"other")
    with pytest.raises(IsADirectoryError):
        s.rename("/g", "/h/")
    with pytest.raises(IsADirectoryError):
        s.copy("/g", "/h/")
    assert _read(s, "/g") == b"other"
    assert {i.name for i in s.list_dir("/")} == {"g"}


@pytest.mark.parametrize("which", ["gdrive", "onedrive", "dropbox_fake", "azure_files"])
def test_edge_stat_of_a_file_with_a_trailing_slash_is_not_a_directory(which, request):
    _svc, s = request.getfixturevalue(which)
    _write(s, "/g", b"other")
    s.mkdir("/d")
    with pytest.raises(NotADirectoryError):
        s.stat("/g/")
    assert s.stat("/d/").is_dir is True
