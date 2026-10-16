"""Azure Blob / Files: hostile or broken answers fail as OSError, not silently.

Found by tests/test_fuzz_azure.py:

* the SDK fetches a blob in ranges and stitches whatever each range
  answer carried without checking its length: short range answers gave
  a complete-looking, wrong file (30 bytes for a "20 MB" blob);
* a NextMarker the server repeats kept list_dir paging forever;
* the virtual-directory probe in AzureBlobSession.stat, snapshots_list
  and the recursive delete of AzureFilesSession let the SDK's
  HttpResponseError / DecodeError / UnicodeDecodeError through;
* a negative Content-Length became a negative FileItem size, and an
  Azure Files entry without a name a FileItem named None.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("azure.storage.blob")
from azure.core.pipeline.transport import RequestsTransport  # noqa: E402
from azure.storage.blob import BlobServiceClient  # noqa: E402
from requests_fuzz_adapter import mount  # noqa: E402
from test_fuzz_azure import (  # noqa: E402
    PROPS,
    _Storage,
    blob,
    files_listing,
    listing,
    share_file,
)

from core.azure_client import AzureBlobSession  # noqa: E402


def _blob_session(storage) -> AzureBlobSession:
    sess = requests.Session()
    mount(sess, storage)
    service = BlobServiceClient(
        account_url="https://acct.blob.core.windows.net",
        credential=None,
        transport=RequestsTransport(session=sess, session_owner=False),
        retry_total=0,
    )
    s = AzureBlobSession.__new__(AzureBlobSession)
    s._service = service
    s._container = service.get_container_client("c")
    s._container_name = "c"
    s._account_key = ""
    return s


def _files_session(storage):
    pytest.importorskip("azure.storage.fileshare")
    from azure.storage.fileshare import ShareServiceClient

    from core.azure_client import AzureFilesSession

    sess = requests.Session()
    mount(sess, storage)
    service = ShareServiceClient(
        account_url="https://acct.file.core.windows.net",
        credential="sv=2024-01-01&sig=x",
        transport=RequestsTransport(session=sess, session_owner=False),
        retry_total=0,
    )
    s = AzureFilesSession.__new__(AzureFilesSession)
    s._service = service
    s._share = service.get_share_client("s")
    s._share_name = "s"
    return s


def test_happy_download_of_the_announced_size():
    assert _blob_session(_Storage()).open_read("/a.txt").read() == b"hello"


@pytest.mark.parametrize(
    "content_range", ["bytes 0-4/20000000", "bytes 0-4/100"], ids=["large-lie", "small-lie"]
)
def test_sad_short_range_answers_are_an_oserror(content_range):
    storage = _Storage()
    storage.content_headers = {"Content-Range": content_range, "Content-Length": "5"}
    with pytest.raises(OSError, match="announced"):
        _blob_session(storage).open_read("/a.txt")


def test_sad_files_short_download_is_an_oserror():
    storage = _Storage()
    storage.props = {**PROPS, "x-ms-type": "File"}
    storage.content_headers = {"Content-Range": "bytes 0-4/100", "Content-Length": "5"}
    with pytest.raises(OSError, match="announced"):
        _files_session(storage).open_read("/a.txt")


def test_edge_repeating_next_marker_fails_instead_of_paging_forever():
    storage = _Storage()
    storage.listing = listing(blob(b"a.txt"), marker=b"again")
    with pytest.raises(OSError, match="paging marker"):
        _blob_session(storage).list_dir("/")


def test_edge_files_repeating_next_marker():
    storage = _Storage()
    storage.listing = files_listing(share_file(b"a.txt"), marker=b"again")
    with pytest.raises(OSError, match="paging marker"):
        _files_session(storage).list_dir("/")


def test_sad_directory_probe_failure_is_an_oserror():
    storage = _Storage()
    storage.status = 503
    s = _blob_session(storage)
    with pytest.raises(OSError):
        s.stat("/a.txt")
    with pytest.raises(OSError):
        s.snapshots_list("/a.txt")


def test_sad_files_recursive_delete_failure_is_an_oserror():
    storage = _Storage()
    storage.props = {**PROPS, "x-ms-type": "File"}
    storage.listing = b"\xff not xml"
    s = _files_session(storage)
    s.is_dir = lambda path: True  # the tree walk is what is under test
    with pytest.raises(OSError, match="Cannot remove /sub"):
        s.remove("/sub", recursive=True)


def test_edge_negative_size_reads_as_zero():
    storage = _Storage()
    storage.listing = listing(blob(b"a.txt", size=b"-1"))
    items = _blob_session(storage).list_dir("/")
    assert [(i.name, i.size) for i in items] == [("a.txt", 0)]


def test_edge_files_entry_without_a_name_is_skipped():
    storage = _Storage()
    storage.listing = files_listing(share_file(b"") + share_file(b"ok.txt"))
    items = _files_session(storage).list_dir("/")
    assert [i.name for i in items] == ["ok.txt"]
