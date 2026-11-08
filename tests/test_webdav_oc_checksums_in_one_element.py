"""Nextcloud / ownCloud send every checksum of a file in ONE
<oc:checksum> element, separated by blanks: "SHA1:.. MD5:.. ADLER32:..".

WebDavSession.checksum split each element at the first ":" only, so
"sha1" answered "sha1:<sha1> md5:<md5> adler32:<adler>" (never equal to
another backend's SHA-1: every compare said "different") and "md5" /
"adler32" fell back to the ETag. Each blank-separated token is one
checksum now.
"""

from __future__ import annotations

from unittest import mock

import pytest

pytest.importorskip("defusedxml")

from core.webdav_client import WebDavSession, _WebDavClient  # noqa: E402

SHA1 = "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
MD5 = "5d41402abc4b2a76b9719d911017c592"


def _session(checksums: str) -> WebDavSession:
    body = f"""<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:oc="http://owncloud.org/ns">
 <d:response><d:href>/remote.php/dav/files/alice/a.txt</d:href>
  <d:propstat><d:prop>
   <d:getcontentlength>5</d:getcontentlength>
   <d:getlastmodified>Sun, 08 Nov 2026 10:00:00 GMT</d:getlastmodified>
   <d:resourcetype/><d:getetag>"abc"</d:getetag>
   <oc:checksums>{checksums}</oc:checksums>
  </d:prop><d:status>HTTP/1.1 200 OK</d:status></d:propstat></d:response>
</d:multistatus>""".encode()
    c = _WebDavClient.__new__(_WebDavClient)
    c._url_path = "/remote.php/dav/files/alice"
    info = c._parse_propfind(body)[0]
    s = WebDavSession.__new__(WebDavSession)
    s._client = mock.Mock(info=lambda p: info)
    s._norm = lambda p: p
    return s


def test_sad_nextcloud_puts_all_checksums_in_one_element():
    s = _session(f"<oc:checksum>SHA1:{SHA1} MD5:{MD5} ADLER32:062c0215</oc:checksum>")
    assert s.checksum("/a.txt", "sha1") == f"sha1:{SHA1}"
    assert s.checksum("/a.txt", "md5") == f"md5:{MD5}"
    assert s.checksum("/a.txt", "adler32") == "adler32:062c0215"


def test_happy_one_checksum_per_element_still_works():
    s = _session(f"<oc:checksum>SHA1:{SHA1}</oc:checksum><oc:checksum>MD5:{MD5}</oc:checksum>")
    assert s.checksum("/a.txt", "sha1") == f"sha1:{SHA1}"
    assert s.checksum("/a.txt", "md5") == f"md5:{MD5}"


def test_edge_an_unknown_or_empty_token_falls_back_to_the_etag():
    s = _session("<oc:checksum>  SHA1: garbage MD5 </oc:checksum>")
    assert s.checksum("/a.txt", "sha256") == "etag:abc"
    assert s.checksum("/a.txt", "md5") == "etag:abc"
