"""WebDAV retries a request the server turned away with 429 or 503.

Nextcloud answers 429 when its rate or brute-force limits trip and 503 in
maintenance mode; a busy reverse proxy answers 503. Those say "not
processed, try again later" (often with Retry-After), and the cloud
backends retry them (core.cloud_http) - WebDAV failed the listing or the
transfer at once. Now a request that may be sent twice is sent again, at
most cloud_http.ATTEMPTS times, after cloud_http's pause or the server's
Retry-After (capped). MOVE / COPY retry only on 429: under "Overwrite: F"
a second MOVE after an unseen success answers 412 / 404.
"""

from __future__ import annotations

import io
from types import SimpleNamespace

import pytest

W = pytest.importorskip("core.webdav_client")
from core import cloud_http  # noqa: E402


class _Resp:
    def __init__(self, status: int, method: str, url: str, headers=None) -> None:
        self.status_code = status
        self.headers = headers or {}
        self.request = SimpleNamespace(method=method, url=url)
        self.closed = False
        self.content = b""

    def close(self) -> None:
        self.closed = True

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
        return False

    def iter_content(self, chunk_size=1):
        return iter(())


class _Session:
    def __init__(self, answers) -> None:
        self.answers = list(answers)  # (status, headers) per send
        self.sent: list = []

    def request(self, method, url, **kw):
        data = kw.get("data")
        body = data.read() if hasattr(data, "read") else data
        self.sent.append((method, body))
        status, headers = self.answers.pop(0) if len(self.answers) > 1 else self.answers[0]
        return _Resp(status, method, url, headers)


class _Client(W._WebDavClient):
    def __init__(self, answers) -> None:  # no network, no requests.Session
        self._base, self._url_path = "http://h/dav", "/dav"
        self._auth, self._timeout = None, 5.0
        self.fake = _Session(answers)

    @property
    def session(self):
        return self.fake


@pytest.fixture
def pauses(monkeypatch):
    waited: list[float] = []
    monkeypatch.setattr(cloud_http, "_sleep", waited.append)
    return waited


# -- happy -------------------------------------------------------------------


def test_happy_a_listing_answered_503_is_asked_again(pauses):
    c = _Client([(503, {"Retry-After": "2"}), (207, {})])
    with c._request("PROPFIND", "/d", data=b"<x/>", headers={"Depth": "1"}) as resp:
        assert resp.status_code == 207
    assert [m for m, _ in c.fake.sent] == ["PROPFIND", "PROPFIND"]
    assert pauses == [2.0]


def test_happy_an_upload_answered_429_is_sent_again_from_its_start(pauses):
    c = _Client([(429, {}), (201, {})])
    body = io.BytesIO(b"x" * 1000)
    body.seek(0)
    c.upload_from(body, "/f")
    assert [b for _, b in c.fake.sent] == [b"x" * 1000, b"x" * 1000]
    assert len(pauses) == 1


def test_happy_delete_and_mkcol_are_retried(pauses):
    c = _Client([(503, {}), (204, {})])
    c.delete("/f")
    c = _Client([(503, {}), (201, {})])
    c.mkdir("/d")
    assert len(pauses) == 2


# -- sad ---------------------------------------------------------------------


def test_sad_the_retries_are_bounded(pauses):
    c = _Client([(503, {})])
    with pytest.raises(W.WebDavRequestError) as info:
        c.delete("/f")
    assert info.value.status == 503
    assert len(c.fake.sent) == cloud_http.ATTEMPTS
    assert len(pauses) == cloud_http.ATTEMPTS - 1


def test_sad_move_and_copy_retry_only_a_rate_limit(pauses):
    c = _Client([(503, {}), (201, {})])
    with pytest.raises(W.WebDavRequestError):
        c.move("/a", "/b")
    assert len(c.fake.sent) == 1
    c = _Client([(429, {}), (201, {})])
    c.copy("/a", "/b")
    assert len(c.fake.sent) == 2


def test_sad_a_body_that_cannot_rewind_is_not_sent_twice(pauses):
    class _Stream:
        def __init__(self):
            self._data = io.BytesIO(b"abc")

        def read(self, n=-1):
            return self._data.read(n)

    c = _Client([(503, {}), (201, {})])
    with pytest.raises(W.WebDavRequestError):
        c.upload_from(_Stream(), "/f")
    assert len(c.fake.sent) == 1
    assert pauses == []


# -- edge --------------------------------------------------------------------


@pytest.mark.parametrize("method", ["LOCK", "UNLOCK", "PROPPATCH", "POST"])
def test_edge_other_methods_are_not_retried(pauses, method):
    c = _Client([(503, {}), (200, {})])
    assert c._request(method, "/f").status_code == 503
    assert len(c.fake.sent) == 1


def test_edge_a_hostile_retry_after_is_capped(pauses):
    c = _Client([(429, {"Retry-After": "86400"}), (207, {})])
    c._request("PROPFIND", "/d")
    assert pauses == [cloud_http.RETRY_AFTER_CAP]


def test_edge_other_errors_are_not_retried(pauses):
    for status in (500, 502, 404, 507):
        c = _Client([(status, {}), (204, {})])
        assert c._request("GET", "/f").status_code == status
        assert len(c.fake.sent) == 1
    assert pauses == []
