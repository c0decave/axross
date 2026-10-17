"""Dropbox / OneDrive upload a large file in chunks, not in one request.

Both writers sent the whole file in a single request on close():
Dropbox ``files/upload`` takes at most 150 MiB per request and the
Graph simple upload (``PUT .../content``) is meant for small files
(documented limit 4 MB for many drives, 250 MB at most), so a large
save failed after the whole file was spooled. Above the threshold the
writers now use an upload session (Dropbox upload_session start /
append_v2 / finish; Graph createUploadSession + Content-Range chunks).
The thresholds are lowered for the test; scripted transports, no network.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

import pytest
import requests

sys.path.insert(0, str(Path(__file__).resolve().parent))

from requests_fuzz_adapter import mount  # noqa: E402

_DATA = bytes(range(256)) * 41  # 10_496 bytes


# ---------------------------------------------------------------------------
# Dropbox
# ---------------------------------------------------------------------------


@pytest.fixture
def dbx(monkeypatch):
    dropbox = pytest.importorskip("dropbox")
    from core import dropbox_client as D

    monkeypatch.setattr(D, "_SINGLE_UPLOAD_MAX", 4096, raising=False)
    monkeypatch.setattr(D, "_UPLOAD_CHUNK", 4096, raising=False)
    calls: list[tuple[str, dict, bytes]] = []

    def responder(request):
        endpoint = request.url.split("/2/", 1)[1]
        arg = json.loads(request.headers.get("Dropbox-API-Arg", "{}"))
        body = request.body or b""
        calls.append((endpoint, arg, bytes(body)))
        if endpoint == "files/upload_session/start":
            out = {"session_id": "S1"}
        elif endpoint == "files/upload_session/append_v2":
            out = None
        else:  # files/upload, files/upload_session/finish
            out = {
                ".tag": "file", "name": "big.bin", "id": "id:b", "rev": "0123456789abcdef",
                "client_modified": "2024-01-02T03:04:05Z",
                "server_modified": "2024-01-02T03:04:05Z", "size": 1,
            }
        return 200, {"Content-Type": "application/json"}, json.dumps(out).encode()

    sess = requests.Session()
    mount(sess, responder)
    s = D.DropboxSession.__new__(D.DropboxSession)
    s._dbx = dropbox.Dropbox(
        oauth2_access_token="t", session=sess, max_retries_on_error=0, max_retries_on_rate_limit=0
    )
    s._proxies = {}
    return s, calls


def test_happy_dropbox_large_file_goes_through_an_upload_session(dbx):
    s, calls = dbx
    with s.open_write("/big.bin") as fh:
        fh.write(_DATA)
    endpoints = [c[0] for c in calls]
    assert endpoints[0] == "files/upload_session/start"
    assert endpoints[-1] == "files/upload_session/finish"
    assert "files/upload" not in endpoints
    assert b"".join(c[2] for c in calls) == _DATA
    offset = len(calls[0][2])
    for endpoint, arg, body in calls[1:]:
        assert arg["cursor"] == {"session_id": "S1", "offset": offset}
        offset += len(body)
    assert calls[-1][1]["commit"]["path"] == "/big.bin"
    assert calls[-1][1]["commit"]["mode"] == {".tag": "overwrite"}


def test_sad_dropbox_small_file_keeps_the_single_request(dbx):
    s, calls = dbx
    with s.open_write("/small.bin") as fh:
        fh.write(b"x" * 4096)
    assert [c[0] for c in calls] == ["files/upload"]


def test_edge_dropbox_exact_chunk_multiple_ends_with_finish(dbx):
    s, calls = dbx
    with s.open_write("/b.bin") as fh:
        fh.write(b"y" * 8192)  # two full chunks: start + finish
    assert [c[0] for c in calls] == ["files/upload_session/start", "files/upload_session/finish"]
    assert sum(len(c[2]) for c in calls) == 8192


# ---------------------------------------------------------------------------
# OneDrive
# ---------------------------------------------------------------------------


@pytest.fixture
def od(monkeypatch):
    from core import onedrive_client as O

    monkeypatch.setattr(O, "_SIMPLE_UPLOAD_MAX", 4096, raising=False)
    monkeypatch.setattr(O, "_UPLOAD_CHUNK", 4096, raising=False)
    calls: list[tuple[str, str, dict, bytes]] = []
    upload_url = "https://upload.example.test/session/1"

    def responder(request):
        body = request.body or b""
        if isinstance(body, str):
            body = body.encode()
        calls.append((request.method, request.url, dict(request.headers), bytes(body)))
        if request.url.endswith(":/createUploadSession"):
            return 200, {}, json.dumps({"uploadUrl": upload_url}).encode()
        if request.url == upload_url:
            start, end_total = request.headers["Content-Range"].split(" ")[1].split("-")
            end, total = (int(x) for x in end_total.split("/"))
            status = 201 if end + 1 == total else 202
            return status, {}, json.dumps({"id": "F"}).encode()
        return 200, {}, json.dumps({"id": "F"}).encode()

    s = O.OneDriveSession.__new__(O.OneDriveSession)
    s._http = requests.Session()
    mount(s._http, responder)
    s._access_token = "t"
    s._app = mock.Mock()
    s._app.get_accounts.return_value = [{"username": "u"}]
    s._app.acquire_token_silent.return_value = {"access_token": "t"}
    s._cache = mock.Mock(has_state_changed=False)
    s._drive_type = "personal"
    s._site_id = None
    s._site_url = ""
    s._tenant_id = "common"
    s._scopes = []
    s._proxies = {}
    return s, calls, upload_url


def test_happy_onedrive_large_file_goes_through_an_upload_session(od):
    s, calls, upload_url = od
    with s.open_write("/dir/big.bin") as fh:
        fh.write(_DATA)
    assert calls[0][0] == "POST" and calls[0][1].endswith("/root:/dir/big.bin:/createUploadSession")
    chunks = [c for c in calls if c[1] == upload_url]
    assert b"".join(c[3] for c in chunks) == _DATA
    start = 0
    for _m, _u, headers, body in chunks:
        assert headers["Content-Range"] == f"bytes {start}-{start + len(body) - 1}/{len(_DATA)}"
        # The upload URL is pre-authenticated: no bearer token goes to it.
        assert "Authorization" not in headers
        start += len(body)
    assert not any(c[1].endswith(":/content") for c in calls)


def test_sad_onedrive_small_file_keeps_the_simple_upload(od):
    s, calls, _upload_url = od
    with s.open_write("/small.bin") as fh:
        fh.write(b"x" * 4096)
    assert [(c[0], c[1].rsplit(":", 1)[-1]) for c in calls] == [("PUT", "/content")]


def test_edge_onedrive_upload_url_must_be_https(od, monkeypatch):
    s, calls, _upload_url = od
    real = s._graph_post
    monkeypatch.setattr(
        s, "_graph_post", lambda url, data: {**real(url, data), "uploadUrl": "http://evil.test/x"}
    )
    with pytest.raises(OSError, match="upload URL"):
        with s.open_write("/big.bin") as fh:
            fh.write(_DATA)
    assert not any("evil.test" in c[1] for c in calls)
