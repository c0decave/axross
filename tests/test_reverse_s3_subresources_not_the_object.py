"""Reverse-S3: a subresource or a CopyObject is refused, never done to the object.

``core/reverse_serve.py`` routed S3 requests by the path alone: the query
string and the ``x-amz-copy-source`` header were never looked at. Every
PUT stored its body as the object, every DELETE removed it, every GET
returned it, whatever the call really was:

* ``aws s3 mv s3://b/a s3://b/c`` (CopyObject, then DeleteObject) wrote
  an empty ``c`` - the empty CopyObject body - and then deleted ``a``;
* ``put-object-tagging`` (``PUT ?tagging``) replaced the object with the
  tagging XML; ``delete-object-tagging`` (``DELETE ?tagging``) deleted it;
* ``GET ?acl`` / ``GET ?tagging`` returned the object as the ACL.

Now every PUT / DELETE / GET / HEAD that names a subresource
(``tagging``, ``acl``, ``uploads``, ``uploadId``, ``partNumber``,
``versionId``, ``retention``, ``legal-hold``, ...) and every PUT with
``x-amz-copy-source`` is answered 501 NotImplemented with an S3 error
body, and nothing on the backend changes. The parameters of the calls
served (ListObjects paging, presign parameters, the SDKs' ``x-id``) still
work, and ``If-None-Match: *`` (create only) is honoured instead of
ignored.
"""

from __future__ import annotations

import http.client
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import reverse_serve as RS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

PRECIOUS = b"precious data"


@pytest.fixture
def root(tmp_path):
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "a").write_bytes(PRECIOUS)
    return tmp_path


@pytest.fixture
def srv(root):
    server = RS.serve_s3(LocalFS(), bind="127.0.0.1", port=0, root_path=str(root))
    yield server
    server.shutdown()


def _req(srv, method, path, body=b"", headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
    h = {"Authorization": "Bearer " + srv.auth_token, "Content-Length": str(len(body))}
    h.update(headers or {})
    try:
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


def _code(body: bytes) -> str:
    return ET.fromstring(body).findtext("Code")


# -- happy ---------------------------------------------------------------------------------


def test_happy_the_sdk_x_id_label_is_served_but_a_subresource_beside_it_is_not(srv, root):
    assert _req(srv, "PUT", "/b/n?x-id=PutObject", b"new")[0] == 200
    assert _req(srv, "GET", "/b/n?x-id=GetObject")[1] == b"new"
    assert _req(srv, "PUT", "/b/n?tagging&x-id=PutObjectTagging", b"<Tagging/>")[0] == 501
    assert _req(srv, "DELETE", "/b/n?tagging&x-id=DeleteObjectTagging")[0] == 501
    assert (root / "b" / "n").read_bytes() == b"new"
    assert _req(srv, "DELETE", "/b/n?x-id=DeleteObject")[0] == 204
    assert not (root / "b" / "n").exists()


def test_happy_listing_parameters_and_get_overrides_are_served_but_not_subresources(srv):
    status, body = _req(srv, "GET", "/b?list-type=2&prefix=&max-keys=10&encoding-type=url")
    assert status == 200 and b"<Key>a</Key>" in body
    status, body = _req(srv, "GET", "/b/a?response-content-type=text%2Fplain")
    assert (status, body) == (200, PRECIOUS)
    assert _req(srv, "GET", "/b?list-type=2&versions")[0] == 501
    assert _req(srv, "GET", "/b/a?response-content-type=text%2Fplain&acl")[0] == 501


def test_happy_bucket_location_is_answered_not_listed(srv):
    status, body = _req(srv, "GET", "/b?location")
    assert status == 200
    assert ET.fromstring(body).tag.endswith("LocationConstraint")


def test_happy_if_none_match_star_creates_a_key_once(srv, root):
    assert _req(srv, "PUT", "/b/lock", b"x", {"If-None-Match": "*"})[0] == 200
    assert _req(srv, "PUT", "/b/lock", b"y", {"If-None-Match": "*"})[0] == 412
    assert (root / "b" / "lock").read_bytes() == b"x"


# -- sad -----------------------------------------------------------------------------------


def test_sad_copy_object_neither_writes_an_empty_copy_nor_loses_the_source(srv, root):
    status, body = _req(srv, "PUT", "/b/c", b"", {"x-amz-copy-source": "/b/a"})
    assert status == 501 and _code(body) == "NotImplemented"
    assert not (root / "b" / "c").exists()
    assert (root / "b" / "a").read_bytes() == PRECIOUS


def test_sad_copy_object_over_an_existing_key_keeps_it(srv, root):
    (root / "b" / "c").write_bytes(b"keep me")
    status, _ = _req(srv, "PUT", "/b/c", b"", {"x-amz-copy-source": "b/a"})
    assert status == 501
    assert (root / "b" / "c").read_bytes() == b"keep me"


def test_sad_put_object_tagging_does_not_replace_the_object(srv, root):
    tagging = b"<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag></TagSet></Tagging>"
    status, body = _req(srv, "PUT", "/b/a?tagging", tagging)
    assert status == 501 and _code(body) == "NotImplemented"
    assert (root / "b" / "a").read_bytes() == PRECIOUS


def test_sad_delete_object_tagging_does_not_delete_the_object(srv, root):
    status, body = _req(srv, "DELETE", "/b/a?tagging")
    assert status == 501 and _code(body) == "NotImplemented"
    assert (root / "b" / "a").read_bytes() == PRECIOUS


@pytest.mark.parametrize(
    "query",
    [
        "acl",
        "tagging",
        "uploads",
        "uploadId=u1&partNumber=1",
        "partNumber=1",
        "versionId=v1",
        "retention",
        "legal-hold",
        "x-amz-copy-source=%2Fb%2Fa",
    ],
)
def test_sad_put_with_a_subresource_keeps_the_object(srv, root, query):
    status, body = _req(srv, "PUT", f"/b/a?{query}", b"not the object")
    assert status == 501 and _code(body) == "NotImplemented"
    assert (root / "b" / "a").read_bytes() == PRECIOUS


@pytest.mark.parametrize("query", ["versionId=v1", "uploadId=u1", "acl", "retention"])
def test_sad_delete_with_a_subresource_keeps_the_object(srv, root, query):
    assert _req(srv, "DELETE", f"/b/a?{query}")[0] == 501
    assert (root / "b" / "a").read_bytes() == PRECIOUS


@pytest.mark.parametrize("query", ["acl", "tagging", "torrent", "partNumber=1", "versionId=v1"])
def test_sad_get_with_a_subresource_is_not_answered_with_the_object(srv, query):
    status, body = _req(srv, "GET", f"/b/a?{query}")
    assert status == 501 and _code(body) == "NotImplemented"
    assert PRECIOUS not in body


@pytest.mark.parametrize("query", ["acl", "versioning", "uploads", "versions", "policy"])
def test_sad_bucket_subresource_get_is_not_answered_with_a_listing(srv, query):
    status, body = _req(srv, "GET", f"/b?{query}")
    assert status == 501 and b"ListBucketResult" not in body


def test_sad_if_none_match_star_keeps_an_existing_key(srv, root):
    status, body = _req(srv, "PUT", "/b/a", b"overwrite", {"If-None-Match": "*"})
    assert status == 412 and _code(body) == "PreconditionFailed"
    assert (root / "b" / "a").read_bytes() == PRECIOUS


def test_sad_a_condition_on_an_etag_is_not_ignored(srv, root):
    assert _req(srv, "PUT", "/b/a", b"x", {"If-Match": '"abc"'})[0] == 501
    assert _req(srv, "DELETE", "/b/a", headers={"If-Match": '"abc"'})[0] == 501
    assert (root / "b" / "a").read_bytes() == PRECIOUS


# -- edge ----------------------------------------------------------------------------------


def test_edge_read_only_refuses_a_copy_with_403_and_a_get_subresource_with_501(root):
    server = RS.serve_s3(
        LocalFS(), bind="127.0.0.1", port=0, root_path=str(root), read_only=True
    )
    try:
        copy_status, _ = _req(server, "PUT", "/b/c", b"", {"x-amz-copy-source": "/b/a"})
        acl_status, acl_body = _req(server, "GET", "/b/a?acl")
    finally:
        server.shutdown()
    assert copy_status == 403
    assert not (root / "b" / "c").exists()
    assert acl_status == 501 and PRECIOUS not in acl_body


def test_edge_a_folder_marker_put_with_a_subresource_is_refused(srv, root):
    assert _req(srv, "PUT", "/b/dir/?acl")[0] == 501
    assert not (root / "b" / "dir").exists()


def test_edge_presign_parameters_are_not_taken_for_subresources(srv):
    query = (
        "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=k%2F20260101%2Fus-east-1%2Fs3"
        "&X-Amz-Date=20260101T000000Z&X-Amz-Expires=60&X-Amz-SignedHeaders=host"
        "&X-Amz-Signature=00"
    )
    assert _req(srv, "GET", f"/b/a?{query}") == (200, PRECIOUS)
    assert _req(srv, "GET", f"/b/a?{query}&tagging")[0] == 501
