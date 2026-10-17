"""Azure Blob / Azure Files stat(): only "not found" moves on to the
folder check.

stat() probed the path as a blob (Azure Files: as a file) and swallowed
EVERY exception from that probe before it tried the folder check. A 503,
a refused request or a dropped connection on the file probe so became
"it is a folder" when a folder of the same name exists (Blob: blobs under
"x/" beside the blob "x"), and "Not found" otherwise. Now only the SDK's
not-found answer (Files: also ResourceTypeMismatch) falls through; every
other failure is an OSError, and a path that is really absent is
FileNotFoundError.
"""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace as NS

import pytest

azure_exceptions = pytest.importorskip("azure.core.exceptions")

from core.azure_client import AzureBlobSession, AzureFilesSession  # noqa: E402

WHEN = datetime(2026, 1, 1, tzinfo=timezone.utc)
FAILURES = [
    ConnectionResetError("reset"),
    azure_exceptions.HttpResponseError("503 ServerBusy"),
    azure_exceptions.ClientAuthenticationError("403 AuthenticationFailed"),
]
FAILURE_IDS = ["reset", "503", "auth"]


def _not_a_miss(exc: BaseException) -> bool:
    """An OSError that neither is nor reads as "not found"."""
    return (
        isinstance(exc, OSError)
        and not isinstance(exc, FileNotFoundError)
        and "not found" not in str(exc).lower()
    )


# -- Azure Blob --------------------------------------------------------------


class _Paged:
    def __init__(self, items):
        self.items = items

    def by_page(self):
        return iter([self.items])


class _Container:
    def __init__(self, blobs: dict, *, head_fail: dict | None = None):
        self.blobs = blobs  # name -> metadata
        self.head_fail = head_fail or {}

    def get_blob_client(self, name):
        def props():
            if name in self.head_fail:
                raise self.head_fail[name]
            if name not in self.blobs:
                raise azure_exceptions.ResourceNotFoundError("BlobNotFound")
            return NS(size=7, last_modified=WHEN, metadata=self.blobs[name])

        return NS(get_blob_properties=props)

    def list_blobs(self, name_starts_with="", **kw):
        return _Paged([NS(name=n) for n in sorted(self.blobs) if n.startswith(name_starts_with)])


def _blob(blobs, **kw) -> AzureBlobSession:
    s = object.__new__(AzureBlobSession)
    s._container = _Container(blobs, **kw)
    return s


def test_happy_blob_file_folder_placeholder_and_missing():
    s = _blob({"a.txt": {}, "dir/x": {}, "lake": {"hdi_isfolder": "true"}})
    item = s.stat("/a.txt")
    assert not item.is_dir and item.size == 7
    assert s.stat("/dir").is_dir
    assert s.stat("/lake").is_dir
    with pytest.raises(FileNotFoundError):
        s.stat("/missing")


@pytest.mark.parametrize("fail", FAILURES, ids=FAILURE_IDS)
def test_sad_blob_a_failed_probe_of_a_file_beside_a_folder_is_not_the_folder(fail):
    s = _blob({"logs": {}, "logs/a.txt": {}}, head_fail={"logs": fail})
    with pytest.raises(OSError) as info:
        s.stat("/logs")
    assert _not_a_miss(info.value)


@pytest.mark.parametrize("fail", FAILURES, ids=FAILURE_IDS)
def test_sad_blob_a_failed_probe_of_a_file_is_not_absent(fail):
    s = _blob({"a.txt": {}}, head_fail={"a.txt": fail})
    with pytest.raises(OSError) as info:
        s.stat("/a.txt")
    assert _not_a_miss(info.value)


def test_edge_blob_a_folder_listing_that_fails_after_a_404_is_an_oserror():
    s = _blob({})

    def list_fails(**kw):
        raise azure_exceptions.HttpResponseError("503 ServerBusy")

    s._container.list_blobs = list_fails
    with pytest.raises(OSError) as info:
        s.stat("/a.txt")
    assert _not_a_miss(info.value)


def test_edge_blob_a_prefix_path_needs_no_probe():
    s = _blob({}, head_fail={"x/": azure_exceptions.HttpResponseError("503")})
    assert s.stat("/x/").is_dir


# -- Azure Files -------------------------------------------------------------


def _mismatch() -> Exception:
    exc = azure_exceptions.ResourceExistsError("ResourceTypeMismatch")
    exc.error_code = "ResourceTypeMismatch"
    return exc


class _Share:
    """dirs / files: sets of share-relative paths. ``file_fail`` /
    ``dir_fail``: path -> exception the matching probe raises."""

    def __init__(self, dirs, files, *, file_fail=None, dir_fail=None, file_probe_of_dir=None):
        self.dirs, self.files = set(dirs), set(files)
        self.file_fail, self.dir_fail = file_fail or {}, dir_fail or {}
        # What a file probe of a directory raises (404 or type mismatch).
        self.file_probe_of_dir = file_probe_of_dir

    def get_directory_client(self, rel):
        share = self

        def dir_props():
            if rel in share.dir_fail:
                raise share.dir_fail[rel]
            if rel in share.dirs:
                return {"last_modified": WHEN}
            raise azure_exceptions.ResourceNotFoundError("ResourceNotFound")

        def file_client(name):
            full = f"{rel}/{name}" if rel else name

            def file_props():
                if full in share.file_fail:
                    raise share.file_fail[full]
                if full in share.files:
                    return {"size": 5, "last_modified": WHEN}
                if full in share.dirs and share.file_probe_of_dir is not None:
                    raise share.file_probe_of_dir
                raise azure_exceptions.ResourceNotFoundError("ResourceNotFound")

            return NS(get_file_properties=file_props)

        return NS(get_directory_properties=dir_props, get_file_client=file_client)


def _files(dirs, files, **kw) -> AzureFilesSession:
    s = AzureFilesSession.__new__(AzureFilesSession)
    s._share = _Share(dirs, files, **kw)
    return s


def test_happy_files_file_directory_and_missing():
    s = _files({"dir"}, {"dir/a.txt"})
    item = s.stat("/dir/a.txt")
    assert not item.is_dir and item.size == 5
    assert s.stat("/dir").is_dir
    with pytest.raises(FileNotFoundError):
        s.stat("/dir/missing")


@pytest.mark.parametrize("fail", FAILURES, ids=FAILURE_IDS)
def test_sad_files_a_failed_file_probe_is_not_a_directory_or_absent(fail):
    # "dir/a" is a file and a directory probe would say "no directory":
    # the failed file probe must not end in "Not found".
    s = _files({"dir"}, {"dir/a"}, file_fail={"dir/a": fail})
    with pytest.raises(OSError) as info:
        s.stat("/dir/a")
    assert _not_a_miss(info.value)


@pytest.mark.parametrize("fail", FAILURES, ids=FAILURE_IDS)
def test_sad_files_a_failed_directory_probe_is_not_absent(fail):
    s = _files({"dir"}, set(), dir_fail={"dir": fail})
    with pytest.raises(OSError) as info:
        s.stat("/dir")
    assert _not_a_miss(info.value)


@pytest.mark.parametrize("answer", ["404", "mismatch"])
def test_edge_files_a_file_probe_of_a_directory_falls_through(answer):
    probe = (
        azure_exceptions.ResourceNotFoundError("ResourceNotFound")
        if answer == "404"
        else _mismatch()
    )
    s = _files({"dir"}, set(), file_probe_of_dir=probe)
    assert s.stat("/dir").is_dir


def test_edge_files_a_directory_probe_type_mismatch_after_a_404_is_absent():
    s = _files(set(), set(), dir_fail={"ghost": _mismatch()})
    with pytest.raises(FileNotFoundError):
        s.stat("/ghost")
