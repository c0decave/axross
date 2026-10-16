"""A PROPFIND answer that is not usable XML is an OSError.

``defusedxml.ElementTree.fromstring`` raises ``ParseError`` (a SyntaxError)
for malformed XML, ``EntitiesForbidden`` / ``DTDForbidden`` (ValueError) for
XXE and billion-laughs, and ``LookupError`` for an unknown encoding. None
of them is an OSError, so list_dir, stat and checksum crashed every caller
(found by tests/test_fuzz_webdav.py).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import webdav_client as W  # noqa: E402

GOOD = (
    b"<d:multistatus xmlns:d='DAV:'><d:response><d:href>/dav/f</d:href><d:propstat>"
    b"<d:prop><d:getcontentlength>3</d:getcontentlength></d:prop>"
    b"<d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response></d:multistatus>"
)

BAD = {
    "empty": b"",
    "truncated": b"<d:multistatus xmlns:d='DAV:'><d:response>",
    "garbage": b"\xff\xfe<\x00",
    "xxe": b'<?xml version="1.0"?><!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
    b"<d:multistatus xmlns:d='DAV:'>&x;</d:multistatus>",
    "laughs": b'<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "aa"><!ENTITY b "&a;&a;">]>'
    b"<d:multistatus xmlns:d='DAV:'>&b;</d:multistatus>",
    "bad-encoding": b'<?xml version="1.0" encoding="bogus-enc"?><a/>',
}


def _client() -> W._WebDavClient:
    return W._WebDavClient("http://127.0.0.1:1/dav", "", "")


def test_happy_wellformed_multistatus_parses():
    [entry] = _client()._parse_propfind(GOOD)
    assert entry["path"] == "/f" and entry["size"] == 3


@pytest.mark.parametrize("payload", list(BAD.values()), ids=list(BAD))
def test_sad_unusable_propfind_xml_is_a_webdav_request_error(payload):
    with pytest.raises(W.WebDavRequestError, match="PROPFIND"):
        _client()._parse_propfind(payload)


@pytest.mark.parametrize("payload", list(BAD.values()), ids=list(BAD))
def test_sad_backend_calls_report_oserror(monkeypatch, payload):
    s = W.WebDavSession.__new__(W.WebDavSession)
    s._client = _client()
    monkeypatch.setattr(s._client, "_propfind", lambda *a, **k: s._client._parse_propfind(payload))
    for op in (lambda: s.list_dir("/"), lambda: s.stat("/f"), lambda: s.checksum("/f")):
        with pytest.raises(OSError):
            op()
    assert s.exists("/f") is False


def test_edge_quota_with_unusable_xml_is_zero(monkeypatch):
    client = _client()

    class _Resp:
        status_code = 207
        content = BAD["xxe"]

    monkeypatch.setattr(client, "_request", lambda *a, **k: _Resp())
    assert client.quota("/") == (0, 0, 0)
