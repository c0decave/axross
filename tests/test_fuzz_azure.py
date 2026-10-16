"""Fuzz: the Azure Blob backend against a hostile storage endpoint.

The real ``azure-storage-blob`` SDK runs on azure-core's RequestsTransport
over a ``requests`` session whose transport is a scripted adapter: mutated
List Blobs XML (entities, bad encodings, truncation, absurd sizes and
dates, traversal names), lying property headers, short and over-long
downloads, error statuses with garbage bodies, a NextMarker that loops.
Every call returns sane data or raises OSError.
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
from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402
from requests_fuzz_adapter import mount  # noqa: E402

from core.azure_client import AzureBlobSession  # noqa: E402

DATE = "Tue, 02 Jan 2024 03:04:05 GMT"


def listing(blobs: bytes = b"", marker: bytes = b"") -> bytes:
    return (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<EnumerationResults ServiceEndpoint="https://acct.blob.core.windows.net/" '
        b'ContainerName="c"><Prefix></Prefix><Delimiter>/</Delimiter><Blobs>'
        + blobs
        + b"</Blobs><NextMarker>"
        + marker
        + b"</NextMarker></EnumerationResults>"
    )


def blob(name: bytes, size: bytes = b"5", date: bytes = DATE.encode()) -> bytes:
    return (
        b"<Blob><Name>" + name + b"</Name><Properties><Last-Modified>" + date + b"</Last-Modified>"
        b"<Etag>0x1</Etag><Content-Length>" + size + b"</Content-Length>"
        b"<Content-Type>text/plain</Content-Type><BlobType>BlockBlob</BlobType>"
        b"</Properties></Blob>"
    )


LISTING = listing(blob(b"a.txt") + b"<BlobPrefix><Name>sub/</Name></BlobPrefix>")
PROPS = {
    "Content-Length": "5",
    "Last-Modified": DATE,
    "ETag": '"0x1"',
    "x-ms-blob-type": "BlockBlob",
    "Content-Type": "text/plain",
}


class _Storage:
    def __init__(self) -> None:
        self.listing = LISTING
        self.props = dict(PROPS)
        self.content = b"hello"
        self.content_headers: dict | None = None
        self.status = 200
        self.raise_exc: Exception | None = None

    def __call__(self, request):
        if self.raise_exc is not None:
            raise self.raise_exc
        url, method = request.url, request.method
        if self.status != 200:
            return self.status, {"Content-Type": "application/xml"}, b"\xff<Error><Code>X"
        if "comp=list" in url or "restype=container" in url and method == "GET":
            return 200, {"Content-Type": "application/xml"}, self.listing
        if method == "HEAD" or "restype=container" in url or "restype=directory" in url:
            return 200, dict(self.props), b""
        if method == "GET":
            body = self.content
            headers = self.content_headers or {
                **self.props,
                "Content-Length": str(len(body)),
                "Content-Range": f"bytes 0-{max(len(body) - 1, 0)}/{len(body)}",
            }
            return 206, headers, body
        return 201, {"ETag": '"0x2"', "Last-Modified": DATE}, b""


@pytest.fixture
def azure():
    storage = _Storage()
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
    yield storage, s


def _ops(s):
    return {
        "list_dir": lambda: s.list_dir("/"),
        "stat": lambda: s.stat("/a.txt"),
        "stat_dir": lambda: s.stat("/sub"),
        "is_dir": lambda: s.is_dir("/sub"),
        "exists": lambda: s.exists("/a.txt"),
        "open_read": lambda: s.open_read("/a.txt").read(),
        "list_versions": lambda: s.list_versions("/a.txt"),
        "checksum": lambda: s.checksum("/a.txt"),
        "snapshots_list": lambda: s.snapshots_list("/a.txt"),
    }


def _all_ops(s, ctx):
    for name, op in _ops(s).items():
        result = check_contract(op, (OSError,), timeout=15.0, context=f"{ctx} {name}")
        if name in ("list_dir", "stat"):
            for item in result if isinstance(result, list) else [result]:
                if hasattr(item, "name"):
                    assert isinstance(item.name, str) and item.name
                    assert isinstance(item.size, int) and item.size >= 0


def test_happy_listing(azure):
    _storage, s = azure
    assert sorted((i.name, i.is_dir, i.size) for i in s.list_dir("/")) == [
        ("a.txt", False, 5),
        ("sub", True, 0),
    ]
    assert s.stat("/a.txt").size == 5
    assert s.open_read("/a.txt").read() == b"hello"


HOSTILE_LISTINGS = {
    "entity": b'<!DOCTYPE x [<!ENTITY a "b">]><EnumerationResults>&a;</EnumerationResults>',
    "external": b'<!DOCTYPE x [<!ENTITY a SYSTEM "file:///etc/passwd">]><E>&a;</E>',
    "bad-encoding": LISTING.replace(b'encoding="utf-8"', b'encoding="bogus"'),
    "negative-size": listing(blob(b"a.txt", size=b"-1")),
    "junk-size": listing(blob(b"a.txt", size=b"abc")),
    "huge-size": listing(blob(b"a.txt", size=b"9" * 5000)),
    "junk-date": listing(blob(b"a.txt", date=b"yesterday")),
    "traversal": listing(blob(b"../../etc/passwd") + blob(b"a/../../b")),
    "empty-name": listing(blob(b"")),
    "invalid-utf8": listing(blob(b"caf\xe9")),
    "deep": b"<a>" * 50000 + b"</a>" * 50000,
    "not-xml": b"{json: 1}",
    "empty": b"",
}


@pytest.mark.parametrize("body", list(HOSTILE_LISTINGS.values()), ids=list(HOSTILE_LISTINGS))
def test_sad_hostile_listings(azure, body):
    storage, s = azure
    storage.listing = body
    _all_ops(s, repr(body)[:60])


def test_sad_mutated_listings(azure):
    storage, s = azure
    for n, body in enumerate(mutants([LISTING], seed=0x415A, per_entry=iterations(150))):
        storage.listing = body
        _all_ops(s, f"mutant {n}")


@pytest.mark.parametrize(
    "props",
    [
        {**PROPS, "Content-Length": "-1"},
        {**PROPS, "Content-Length": "abc"},
        {**PROPS, "Last-Modified": "yesterday"},
        {**PROPS, "Content-MD5": "!!!not-base64"},
        {**PROPS, "x-ms-blob-type": "Nope"},
        {},
    ],
    ids=["neg-length", "junk-length", "junk-date", "junk-md5", "junk-type", "no-headers"],
)
def test_sad_lying_property_headers(azure, props):
    storage, s = azure
    storage.props = props
    _all_ops(s, repr(props)[:60])


@pytest.mark.parametrize(
    "headers",
    [
        {"Content-Range": "bytes 0-4/40000000", "Content-Length": "5"},
        {"Content-Range": "bytes x-y/z", "Content-Length": "5"},
        {"Content-Range": "bytes 0-4/5", "Content-Length": "500"},
        {},
    ],
    ids=["range-lies-large", "range-junk", "length-lies", "no-headers"],
)
def test_sad_lying_download(azure, headers):
    storage, s = azure
    storage.content_headers = headers
    check_contract(lambda: s.open_read("/a.txt").read(), (OSError,), timeout=15.0)


@pytest.mark.parametrize("status", [400, 403, 404, 409, 500, 503])
def test_sad_error_statuses(azure, status):
    storage, s = azure
    storage.status = status
    _all_ops(s, f"status {status}")


@pytest.mark.parametrize(
    "exc",
    [requests.ConnectionError("reset"), requests.ReadTimeout("slow")],
    ids=["reset", "timeout"],
)
def test_sad_transport_failures(azure, exc):
    storage, s = azure
    storage.raise_exc = exc
    _all_ops(s, type(exc).__name__)


def test_edge_next_marker_that_loops(azure):
    storage, s = azure
    storage.listing = listing(blob(b"a.txt"), marker=b"again")
    result = check_contract(lambda: s.list_dir("/"), (OSError,), timeout=15.0)
    assert isinstance(result, OSError)


# -- Azure Files ---------------------------------------------------------------


def files_listing(entries: bytes = b"", marker: bytes = b"") -> bytes:
    return (
        b'<?xml version="1.0" encoding="utf-8"?>'
        b'<EnumerationResults ServiceEndpoint="https://acct.file.core.windows.net/" '
        b'ShareName="s" DirectoryPath=""><Entries>'
        + entries
        + b"</Entries><NextMarker>"
        + marker
        + b"</NextMarker></EnumerationResults>"
    )


def share_file(name: bytes, size: bytes = b"5") -> bytes:
    return (
        b"<File><Name>"
        + name
        + b"</Name><Properties><Content-Length>"
        + size
        + b"</Content-Length>"
        b"</Properties></File>"
    )


FILES_LISTING = files_listing(
    share_file(b"a.txt") + b"<Directory><Name>sub</Name><Properties /></Directory>"
)


@pytest.fixture
def azure_files():
    pytest.importorskip("azure.storage.fileshare")
    from azure.storage.fileshare import ShareServiceClient

    from core.azure_client import AzureFilesSession

    storage = _Storage()
    storage.listing = FILES_LISTING
    storage.props = {**PROPS, "x-ms-type": "File"}
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
    yield storage, s


def _files_ops(s):
    return {
        "list_dir": lambda: s.list_dir("/"),
        "stat": lambda: s.stat("/a.txt"),
        "is_dir": lambda: s.is_dir("/sub"),
        "exists": lambda: s.exists("/a.txt"),
        "open_read": lambda: s.open_read("/a.txt").read(),
        "remove_tree": lambda: s.remove("/sub", recursive=True),
        "checksum": lambda: s.checksum("/a.txt"),
    }


def _all_files_ops(s, ctx):
    for name, op in _files_ops(s).items():
        result = check_contract(op, (OSError,), timeout=15.0, context=f"{ctx} {name}")
        if name in ("list_dir", "stat"):
            for item in result if isinstance(result, list) else [result]:
                if hasattr(item, "name"):
                    assert isinstance(item.name, str) and item.name
                    assert isinstance(item.size, int) and item.size >= 0


def test_happy_files_listing(azure_files):
    _storage, s = azure_files
    assert sorted((i.name, i.is_dir, i.size) for i in s.list_dir("/")) == [
        ("a.txt", False, 5),
        ("sub", True, 0),
    ]
    assert s.open_read("/a.txt").read() == b"hello"


HOSTILE_FILES_LISTINGS = {
    "entity": HOSTILE_LISTINGS["entity"],
    "negative-size": files_listing(share_file(b"a.txt", size=b"-1")),
    "junk-size": files_listing(share_file(b"a.txt", size=b"abc")),
    "traversal": files_listing(share_file(b"../../x") + share_file(b"a/b")),
    "empty-name": files_listing(share_file(b"")),
    "invalid-utf8": files_listing(share_file(b"caf\xe9")),
    "not-xml": b"{json: 1}",
    "marker-loop": files_listing(share_file(b"a.txt"), marker=b"again"),
}


@pytest.mark.parametrize(
    "body", list(HOSTILE_FILES_LISTINGS.values()), ids=list(HOSTILE_FILES_LISTINGS)
)
def test_sad_files_hostile_listings(azure_files, body):
    storage, s = azure_files
    storage.listing = body
    _all_files_ops(s, repr(body)[:60])


def test_sad_files_mutated_listings(azure_files):
    storage, s = azure_files
    for n, body in enumerate(mutants([FILES_LISTING], seed=0x4146, per_entry=iterations(100))):
        storage.listing = body
        _all_files_ops(s, f"mutant {n}")


@pytest.mark.parametrize("status", [400, 403, 404, 500, 503])
def test_sad_files_error_statuses(azure_files, status):
    storage, s = azure_files
    storage.status = status
    _all_files_ops(s, f"status {status}")


def test_sad_files_short_download(azure_files):
    storage, s = azure_files
    storage.content_headers = {"Content-Range": "bytes 0-4/40000000", "Content-Length": "5"}
    result = check_contract(lambda: s.open_read("/a.txt").read(), (OSError,), timeout=15.0)
    assert isinstance(result, OSError)
