"""open_read of FTP, S3, Azure Blob/Files, WebDAV, Dropbox, OneDrive and
Google Drive keeps at most a few MiB of a download in RAM.

Each of them collected the whole file in an io.BytesIO before returning
(FTP retrbinary into BytesIO, S3 ``Body.read()``, Azure ``readall()``,
WebDAV ``download_to(BytesIO)``): a 4 GiB ISO needed 4 GiB of RAM. They
now spool into a SpooledTemporaryFile (core.read_spool) like SCP does:
small files stay in memory, larger ones go to a temp file. Size checks
(Azure's announced size, botocore's Content-Length check) still apply.

Dropbox (``response.content``), OneDrive (a non-streamed ``requests``
GET) and Google Drive (MediaIoBaseDownload into a BytesIO, 100 MiB per
request) did the same; they spool too, and Drive asks for the file in
``gdrive_client._DOWNLOAD_CHUNK`` ranges.

The SDKs are stubs that hand out the body in chunks; everything else is
the backends' own code.
"""

from __future__ import annotations

import hashlib
import io
import tracemalloc
from ftplib import error_perm
from types import SimpleNamespace

import pytest

from core import gdrive_client, read_spool
from core.azure_client import AzureBlobSession, AzureFilesSession
from core.dropbox_client import DropboxSession
from core.ftp_client import FtpSession
from core.onedrive_client import OneDriveSession
from core.s3_client import S3Session
from core.webdav_client import WebDavSession

httplib2 = pytest.importorskip("httplib2")
requests = pytest.importorskip("requests")
from googleapiclient.discovery import build  # noqa: E402
from requests.adapters import BaseAdapter  # noqa: E402
from requests.structures import CaseInsensitiveDict  # noqa: E402
from urllib3.response import HTTPResponse  # noqa: E402

CHUNK = 64 * 1024
BIG = 32 * 1024 * 1024
#: The spool's own memory part plus a read chunk and slack.
PEAK_LIMIT = read_spool.READ_SPOOL_MAX + 4 * 1024 * 1024
#: Drive answers a whole range request at once: the spool plus a chunk
#: (and the fake body's copy of it) and slack.
GDRIVE_PEAK_LIMIT = read_spool.READ_SPOOL_MAX + 2 * gdrive_client._DOWNLOAD_CHUNK + 2 * 1024 * 1024


def _peak_limit(maker: str) -> int:
    return GDRIVE_PEAK_LIMIT if maker == "gdrive" else PEAK_LIMIT


def _block(i: int) -> bytes:
    return bytes([i % 251]) * CHUNK


def _payload(total: int) -> bytes:
    return b"".join(_block(i) for i in range(total // CHUNK)) + b"t" * (total % CHUNK)


class _Body:
    """botocore StreamingBody / azure StorageStreamDownloader shape."""

    def __init__(self, total: int, *, announced: int | None = None, fail_at: int | None = None):
        self.total = total
        self.size = total if announced is None else announced
        self.sent = 0
        self.fail_at = fail_at
        self.closed = False

    def _next(self, n: int) -> bytes:
        if self.fail_at is not None and self.sent >= self.fail_at:
            raise ConnectionError("connection reset mid-body")
        n = min(n, self.total - self.sent)
        start = self.sent
        self.sent += n
        out = bytearray()
        pos = start
        while pos < start + n:
            i = pos // CHUNK
            in_block = min(CHUNK - pos % CHUNK, start + n - pos)
            fill = bytes([i % 251]) if i < self.total // CHUNK else b"t"
            out += fill * in_block
            pos += in_block
        return bytes(out)

    def read(self, n=-1):
        if n is None or n < 0:
            n = self.total - self.sent
        return self._next(n)

    def readall(self):
        return self.read(-1)

    def chunks(self):
        while self.sent < self.total:
            yield self._next(CHUNK)

    def close(self):
        self.closed = True


class _S3:
    def __init__(self, body):
        self.body = body

    def get_object(self, Bucket, Key, **kw):
        return {"Body": self.body, "ContentLength": self.body.size}


class _Blob:
    def __init__(self, body):
        self.body = body

    def download_blob(self, *a, **kw):
        return self.body

    def download_file(self, *a, **kw):
        return self.body


class _Container:
    def __init__(self, body):
        self.body = body

    def get_blob_client(self, key):
        return _Blob(self.body)


class _Share:
    def __init__(self, body):
        self.body = body

    def get_directory_client(self, d):
        return self

    def get_file_client(self, n):
        return _Blob(self.body)


class _Dav:
    def __init__(self, body):
        self.body = body

    def download_to(self, fh, path):
        for c in self.body.chunks():
            fh.write(c)


class _Ftp:
    def __init__(self, body, *, perm_error: bool = False):
        self.body = body
        self.perm_error = perm_error

    def retrbinary(self, cmd, callback, blocksize=8192, rest=None):
        if self.perm_error:
            raise error_perm("550 No such file")
        for c in self.body.chunks():
            callback(c)
        return "226 done"


def _ftp(body, **kw):
    s = object.__new__(FtpSession)
    ftp = _Ftp(body, **kw)
    s._ensure_connected = lambda: ftp
    return s


def _s3(body):
    s = object.__new__(S3Session)
    s._s3, s._bucket, s._to_key = _S3(body), "b", lambda p: p.lstrip("/")
    return s


def _blob(body):
    s = object.__new__(AzureBlobSession)
    s._container, s._to_key = _Container(body), lambda p: p.lstrip("/")
    return s


def _files(body):
    s = object.__new__(AzureFilesSession)
    s._share, s._to_path = _Share(body), lambda p: p.lstrip("/")
    return s


def _dav(body):
    s = object.__new__(WebDavSession)
    s._client, s._norm = _Dav(body), lambda p: p
    return s


class _DbxResponse:
    """requests.Response shape the Dropbox SDK hands out (stream=True)."""

    def __init__(self, body):
        self.body = body
        self.closed = False

    def iter_content(self, chunk_size=1, decode_unicode=False):
        return read_spool.read_chunks(self.body, chunk_size)

    @property
    def content(self):
        return self.body.read(-1)

    def close(self):
        self.closed = True


class _Dbx:
    def __init__(self, body):
        self.body = body

    def files_download(self, path, rev=None):
        self.response = _DbxResponse(self.body)
        return SimpleNamespace(), self.response


def _dropbox(body):
    s = object.__new__(DropboxSession)
    dbx = _Dbx(body)
    s._ensure_connected = lambda: dbx
    return s


class _BodyRaw(io.RawIOBase):
    def __init__(self, body):
        self.body = body

    def readable(self):
        return True

    def read(self, n=-1):
        # Straight from the body: RawIOBase.read would add two copies of
        # every chunk that the real socket does not make.
        return self.body.read(n)

    def readinto(self, buf):
        data = self.body.read(len(buf))
        buf[: len(data)] = data
        return len(data)


class _StreamingGraph(BaseAdapter):
    """Answers every request with the body, streamed like the network."""

    def __init__(self, body):
        super().__init__()
        self.body = body

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        headers = {"Content-Length": str(self.body.total)}
        resp = requests.Response()
        resp.status_code = 200
        resp.headers = CaseInsensitiveDict(headers)
        resp.raw = HTTPResponse(
            body=_BodyRaw(self.body),
            headers=headers,
            status=200,
            preload_content=False,
            decode_content=False,
            request_method=request.method,
        )
        resp.url, resp.request = request.url, request
        if not stream:
            resp.content  # noqa: B018 - load the body like the real adapter
        return resp

    def close(self):
        pass


def _onedrive(body):
    s = object.__new__(OneDriveSession)
    s._http = requests.Session()
    s._http.mount("https://", _StreamingGraph(body))
    s._access_token = "t"
    s._ensure_token = lambda: None
    s._drive_type, s._site_id = "personal", None
    return s


class _MediaHttp:
    """httplib2.Http shape: answers MediaIoBaseDownload's Range requests."""

    def __init__(self, body):
        self.body = body

    def request(self, uri, method="GET", body=None, headers=None, **kw):
        total = self.body.total
        if total == 0:
            return httplib2.Response({"status": "200", "content-length": "0"}), b""
        start, end = (int(x) for x in headers["range"].split("=")[1].split("-"))
        data = self.body.read(min(end, total - 1) - start + 1)
        last = start + len(data) - 1
        return httplib2.Response(
            {"status": "206", "content-range": f"bytes {start}-{last}/{total}"}
        ), data


def _gdrive(body):
    s = object.__new__(gdrive_client.GDriveSession)
    s._service = build("drive", "v3", http=_MediaHttp(body), static_discovery=True)
    s._path_cache = {"/": "root", "/big.bin": "F1"}
    return s


MAKERS = {
    "ftp": _ftp,
    "s3": _s3,
    "azure_blob": _blob,
    "azure_files": _files,
    "webdav": _dav,
    "dropbox": _dropbox,
    "onedrive": _onedrive,
    "gdrive": _gdrive,
}


def _open(maker, body, *, version: bool = False):
    sess = MAKERS[maker](body)
    if version:
        return sess.open_version_read("/big.bin", "v1")
    return sess.open_read("/big.bin")


# -- happy -------------------------------------------------------------------


@pytest.mark.parametrize("maker", MAKERS)
def test_happy_a_large_download_is_not_held_in_ram(maker):
    tracemalloc.start()
    try:
        fh = _open(maker, _Body(BIG))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    try:
        assert peak < _peak_limit(maker), f"{peak / 2**20:.1f} MiB held for a {BIG >> 20} MiB file"
        digest = hashlib.sha256()
        while chunk := fh.read(1 << 20):
            digest.update(chunk)
        assert digest.hexdigest() == hashlib.sha256(_payload(BIG)).hexdigest()
    finally:
        fh.close()


@pytest.mark.parametrize("maker", ["s3", "azure_blob", "dropbox", "onedrive", "gdrive"])
def test_happy_a_version_download_is_not_held_in_ram(maker):
    tracemalloc.start()
    try:
        fh = _open(maker, _Body(BIG), version=True)
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    try:
        assert peak < _peak_limit(maker), f"{peak / 2**20:.1f} MiB held"
        fh.seek(0, 2)
        assert fh.tell() == BIG
    finally:
        fh.close()


@pytest.mark.parametrize("maker", MAKERS)
def test_happy_a_small_file_reads_back_and_seeks(maker):
    fh = _open(maker, _Body(5000))
    try:
        assert fh.read() == _payload(5000)
        fh.seek(0)
        assert fh.read(10) == _payload(5000)[:10]
    finally:
        fh.close()


# -- sad ---------------------------------------------------------------------


@pytest.mark.parametrize("maker", ["azure_blob", "azure_files"])
def test_sad_azure_short_download_is_still_an_oserror(maker):
    with pytest.raises(OSError, match="announced"):
        _open(maker, _Body(5000, announced=20000))


@pytest.mark.parametrize("maker", MAKERS)
def test_sad_a_connection_reset_mid_body_is_an_oserror(maker):
    with pytest.raises(OSError):
        _open(maker, _Body(BIG, fail_at=4 * CHUNK))


def test_sad_ftp_permission_error_is_an_oserror():
    with pytest.raises(OSError, match="Cannot read"):
        _ftp(_Body(10), perm_error=True).open_read("/nope")


def test_sad_spool_chunks_refuses_a_size_mismatch_and_closes():
    closed = []

    class Watched:
        def __iter__(self):
            yield b"abc"

    real = read_spool.tempfile.SpooledTemporaryFile

    def tracking(*a, **kw):
        f = real(*a, **kw)
        orig = f.close
        f.close = lambda: (closed.append(True), orig())[1]
        return f

    read_spool.tempfile.SpooledTemporaryFile = tracking
    try:
        with pytest.raises(OSError, match="received 3 bytes, the server announced 5"):
            read_spool.spool_chunks(Watched(), expected_size=5, what="Cannot read /x")
    finally:
        read_spool.tempfile.SpooledTemporaryFile = real
    assert closed == [True]


# -- edge --------------------------------------------------------------------


@pytest.mark.parametrize("maker", MAKERS)
def test_edge_an_empty_file_reads_as_empty(maker):
    fh = _open(maker, _Body(0))
    try:
        assert fh.read() == b""
    finally:
        fh.close()


@pytest.mark.parametrize("fail_at", [None, 2 * CHUNK], ids=["read", "reset"])
def test_edge_dropbox_closes_the_streamed_response(fail_at):
    # The SDK streams a download; whoever does not read it to the end
    # must close it (dropbox base.py files_download docstring).
    sess = _dropbox(_Body(5 * CHUNK, fail_at=fail_at))
    try:
        sess.open_read("/big.bin").close()
    except OSError:
        assert fail_at is not None
    assert sess._ensure_connected().response.closed


def test_edge_read_chunks_stops_at_the_end_and_skips_nothing():
    body = _Body(3 * CHUNK + 7)
    data = b"".join(read_spool.read_chunks(body, size=CHUNK))
    assert data == _payload(3 * CHUNK + 7)


def test_edge_a_file_at_the_spool_limit_stays_in_memory():
    fh = read_spool.spool_chunks([b"x" * read_spool.READ_SPOOL_MAX])
    try:
        assert not fh._rolled
        assert len(fh.read()) == read_spool.READ_SPOOL_MAX
    finally:
        fh.close()
