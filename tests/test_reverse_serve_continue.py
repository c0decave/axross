"""Reverse-serve: ``Expect: 100-continue``, keep-alive and S3 multipart upload.

``core/reverse_serve.py`` spoke HTTP/1.0 and never answered
``Expect: 100-continue``: boto3 and aws-cli send it with every PUT and
wait a second for it, so each 4 KiB PUT took 1,003-1,012 ms. And
CreateMultipartUpload was 501, so every upload above boto3's / aws-cli's
8 MiB multipart threshold failed.

Now the server speaks HTTP/1.1: ``100 Continue`` goes out only when the
handler starts reading the body - after the token, the path, the
read-only switch and the size checks passed; a refused request gets its
final answer and never an invitation to send the body. A connection
carries further requests only when the body was read to its end (else
it closes, with ``Connection: close``), waits KEEPALIVE_IDLE_S for the
next request, and the server's stop closes it. Multipart upload works
with the PUT's limits: parts in a private local folder, at most
MULTIPART_MAX_UPLOADS uploads, MULTIPART_MAX_PARTS parts and
MULTIPART_MAX_BYTES, removed on complete, abort, expiry and stop.
"""

from __future__ import annotations

import hashlib
import http.client
import io
import os
import shutil
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import reverse_serve as RS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

OLD = b"precious old content"
NS = "{http://s3.amazonaws.com/doc/2006-03-01/}"


@pytest.fixture
def cache(tmp_path, monkeypatch):
    """The multipart parts' folder, private to the test."""
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path / "cache"))
    return tmp_path / "cache" / "axross" / "s3-multipart"


@pytest.fixture
def root(tmp_path):
    (tmp_path / "srv" / "b").mkdir(parents=True)
    (tmp_path / "srv" / "b" / "f").write_bytes(OLD)
    return tmp_path / "srv"


def _serve(kind, root, **kw):
    serve = RS.serve_s3 if kind == "s3" else RS.serve_webdav
    return serve(LocalFS(), bind="127.0.0.1", port=0, root_path=str(root), **kw)


@pytest.fixture
def s3(root, cache):
    server = _serve("s3", root)
    yield server
    server.shutdown()


def _recv_head(sock: socket.socket, timeout: float = 10.0) -> bytes:
    """Bytes up to the end of one response head (or EOF)."""
    sock.settimeout(timeout)
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            break
        data += chunk
    return data


def _recv_all(sock: socket.socket, timeout: float = 10.0) -> bytes:
    sock.settimeout(timeout)
    data = b""
    while chunk := sock.recv(65536):
        data += chunk
    return data


def _expect_put(srv, path: bytes, length: int, token: str | None = None, extra: bytes = b""):
    """Send a PUT's head with ``Expect: 100-continue`` (no body yet) and
    return the socket and the first response head the server sends."""
    sock = socket.create_connection(("127.0.0.1", srv.port), timeout=10)
    token = srv.auth_token if token is None else token
    sock.sendall(
        b"PUT " + path + b" HTTP/1.1\r\nHost: 127.0.0.1\r\n"
        b"Authorization: Bearer " + token.encode() + b"\r\n"
        b"Expect: 100-continue\r\n" + extra
        + b"Content-Length: " + str(length).encode() + b"\r\n\r\n"
    )
    return sock, _recv_head(sock)


def _req(srv, method, path, body=b"", headers=None, conn=None):
    own = conn is None
    conn = conn or http.client.HTTPConnection("127.0.0.1", srv.port, timeout=30)
    h = {"Authorization": "Bearer " + srv.auth_token, "Content-Length": str(len(body))}
    h.update(headers or {})
    try:
        conn.request(method, path, body=body, headers=h)
        resp = conn.getresponse()
        return resp.status, resp.read(), resp
    finally:
        if own:
            conn.close()


def _code(body: bytes) -> str:
    return ET.fromstring(body.strip()).findtext("Code")


def _create(srv, key="b/big") -> str:
    status, body, _ = _req(srv, "POST", f"/{key}?uploads")
    assert status == 200, body
    return ET.fromstring(body).findtext(f"{NS}UploadId")


def _part(srv, upload_id, number, data, key="b/big"):
    status, body, resp = _req(srv, "PUT", f"/{key}?partNumber={number}&uploadId={upload_id}", data)
    return status, body, resp.getheader("ETag")


def _complete_xml(parts) -> bytes:
    rows = "".join(f"<Part><PartNumber>{n}</PartNumber><ETag>{e}</ETag></Part>" for n, e in parts)
    return (f'<CompleteMultipartUpload xmlns="http://s3.amazonaws.com/doc/2006-03-01/">{rows}'
            "</CompleteMultipartUpload>").encode()


def _boto3_client(srv, verify=None):
    boto3 = pytest.importorskip("boto3")
    from botocore.config import Config

    return boto3.client(
        "s3", endpoint_url=srv.base_url, aws_access_key_id=srv.auth_token,
        aws_secret_access_key="unused", region_name="us-east-1", verify=verify,
        config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}),
    )


# -- happy ---------------------------------------------------------------------------------


@pytest.mark.parametrize("kind", ["s3", "webdav"])
def test_happy_100_continue_comes_once_the_put_is_accepted(kind, root, cache):
    srv = _serve(kind, root)
    try:
        sock, head = _expect_put(srv, b"/b/f", 3)
        with sock:
            assert head == b"HTTP/1.1 100 Continue\r\n\r\n"
            sock.sendall(b"new")
            final = _recv_head(sock)
        assert final.split(b" ", 2)[1] in (b"200", b"201"), final
        assert (root / "b" / "f").read_bytes() == b"new"
    finally:
        srv.shutdown()


def test_happy_boto3_gets_its_100_continue_and_reuses_the_connection(s3, root, monkeypatch):
    """Counted, not timed: botocore's wait for the 100 (1 s, here widened
    to 30 s so a loaded machine cannot fake a pass) must see it on every
    PUT, and five PUTs travel over one connection."""
    import botocore.awsrequest as AR

    client = _boto3_client(s3)
    seen = []
    original = AR.urllib3.util.wait_for_read

    def wait_for_read(sock, timeout=None):
        got = original(sock, 30)
        seen.append(got)
        return got

    monkeypatch.setattr(AR.urllib3.util, "wait_for_read", wait_for_read)
    connections = []
    setup = RS._BaseHandler.setup

    def counting_setup(self):
        connections.append(self.client_address)
        setup(self)

    monkeypatch.setattr(RS._BaseHandler, "setup", counting_setup)
    for i in range(5):
        client.put_object(Bucket="b", Key=f"k{i}", Body=b"x" * 4096 + bytes([i]))
    assert seen == [True] * 5
    assert len(connections) == 1
    assert (root / "b" / "k3").read_bytes() == b"x" * 4096 + b"\x03"


def test_happy_boto3_uploads_above_the_multipart_threshold(s3, root, cache):
    from boto3.s3.transfer import TransferConfig

    client = _boto3_client(s3)
    data = os.urandom(5 * 1024 * 1024 * 2 + 12345)  # three parts of 5 MiB
    config = TransferConfig(multipart_threshold=5 * 1024 * 1024, multipart_chunksize=5 * 1024 * 1024)
    client.upload_fileobj(io.BytesIO(data), "b", "big", Config=config)
    assert (root / "b" / "big").read_bytes() == data
    assert client.head_object(Bucket="b", Key="big")["ContentLength"] == len(data)
    # Nothing of the parts is left behind.
    assert [p for p in cache.rglob("*") if p.is_file()] == []


def test_happy_a_raw_multipart_upload_replaces_a_part_and_keeps_the_old_object_until_complete(
        s3, root, cache):
    (root / "b" / "big").write_bytes(OLD)
    upload_id = _create(s3)
    assert _part(s3, upload_id, 1, b"first-wrong")[0] == 200
    status, _, etag1 = _part(s3, upload_id, 1, b"first|")  # the same number again: replaced
    assert status == 200 and etag1 == f'"{hashlib.md5(b"first|").hexdigest()}"'
    _, _, etag2 = _part(s3, upload_id, 2, b"second")
    assert (root / "b" / "big").read_bytes() == OLD  # not yet
    status, body, _ = _req(s3, "POST", f"/b/big?uploadId={upload_id}",
                           _complete_xml([(1, etag1), (2, etag2)]))
    assert status == 200
    result = ET.fromstring(body.strip())
    assert result.tag == f"{NS}CompleteMultipartUploadResult"
    assert result.findtext(f"{NS}ETag").endswith('-2"')
    assert (root / "b" / "big").read_bytes() == b"first|second"
    # Done: the upload is gone.
    assert _part(s3, upload_id, 3, b"late")[0] == 404
    assert [p for p in cache.rglob("*") if p.is_file()] == []


def test_happy_abort_removes_the_parts(s3, root, cache):
    upload_id = _create(s3)
    _part(s3, upload_id, 1, b"abc")
    assert [p for p in cache.rglob("part-*")]
    status, _, _ = _req(s3, "DELETE", f"/b/big?uploadId={upload_id}")
    assert status == 204
    assert list(cache.rglob("part-*")) == []
    assert not (root / "b" / "big").exists()
    status, body, _ = _req(s3, "POST", f"/b/big?uploadId={upload_id}", _complete_xml([(1, "0" * 32)]))
    assert status == 404 and _code(body) == "NoSuchUpload"


def _aws_chunked(data: bytes, step: int = 4, signed: bool = False) -> bytes:
    """*data* in aws-chunked frames, with a checksum trailer (what boto3
    sends over HTTPS) or chunk signatures."""
    ext = b";chunk-signature=" + b"0" * 64 if signed else b""
    out = b"".join(b"%x%s\r\n%s\r\n" % (len(data[i:i + step]), ext, data[i:i + step])
                   for i in range(0, len(data), step))
    return out + b"0" + ext + b"\r\n" + (b"" if signed else b"x-amz-checksum-crc32:AAAAAA==\r\n") + b"\r\n"


def _http_chunked(data: bytes) -> bytes:
    return b"%x\r\n%s\r\n0\r\n\r\n" % (len(data), data)


def _raw_put(srv, path: bytes, head: bytes, body: bytes) -> bytes:
    with socket.create_connection(("127.0.0.1", srv.port), timeout=10) as sock:
        sock.sendall(b"PUT " + path + b" HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n"
                     b"Authorization: Bearer " + srv.auth_token.encode() + b"\r\n" + head + b"\r\n" + body)
        return _recv_all(sock)


@pytest.mark.parametrize("outer", ["chunked", "length"])
@pytest.mark.parametrize("signed", [False, True])
def test_happy_an_aws_chunked_put_stores_the_data_not_the_frames(s3, root, outer, signed):
    data = b"the real object bytes"
    inner = _aws_chunked(data, signed=signed)
    head = (b"Content-Encoding: aws-chunked\r\nX-Amz-Decoded-Content-Length: %d\r\n" % len(data))
    if outer == "chunked":
        reply = _raw_put(s3, b"/b/f", head + b"Transfer-Encoding: chunked\r\n", _http_chunked(inner))
    else:
        reply = _raw_put(s3, b"/b/f", head + b"Content-Length: %d\r\n" % len(inner), inner)
    assert reply.startswith(b"HTTP/1.1 200"), reply[:200]
    assert (root / "b" / "f").read_bytes() == data


def test_happy_boto3_over_https_puts_and_uploads_multipart(root, cache, tmp_path):
    """Over HTTPS botocore sends aws-chunked bodies with a trailing
    checksum (plain HTTP: not): the object is the data, also in parts."""
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl not available")
    key, crt = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run([openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
                    "-out", str(crt), "-days", "1", "-subj", "/CN=localhost",
                    "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
                   check=True, capture_output=True)
    pytest.importorskip("boto3")
    from boto3.s3.transfer import TransferConfig

    srv = _serve("s3", root, cert_file=str(crt), key_file=str(key))
    try:
        client = _boto3_client(srv, verify=str(crt))
        client.put_object(Bucket="b", Key="small", Body=b"tls bytes")
        assert (root / "b" / "small").read_bytes() == b"tls bytes"
        data = os.urandom(6 * 1024 * 1024 + 7)
        config = TransferConfig(multipart_threshold=5 * 1024 * 1024,
                                multipart_chunksize=5 * 1024 * 1024)
        client.upload_fileobj(io.BytesIO(data), "b", "big", Config=config)
        assert (root / "b" / "big").read_bytes() == data
    finally:
        srv.shutdown()


def test_happy_a_slow_complete_keeps_the_client_waiting_with_spaces(s3, root, cache, monkeypatch):
    """The 200 goes out before the assembly and a space now and then
    keeps the client's read timeout away; botocore parses the result."""
    client = _boto3_client(s3)
    monkeypatch.setattr(RS, "MULTIPART_COMPLETE_TICK_S", 0.01)
    store = RS._BaseHandler._store_body

    def slow_store(self, path, body):
        time.sleep(0.2)
        store(self, path, body)

    monkeypatch.setattr(RS._BaseHandler, "_store_body", slow_store)
    upload_id = client.create_multipart_upload(Bucket="b", Key="big")["UploadId"]
    etag = client.upload_part(Bucket="b", Key="big", UploadId=upload_id, PartNumber=1,
                              Body=b"slow")["ETag"]
    seen = []
    original_assemble = RS._S3Handler._assemble

    def assemble(self, bucket, key, files):
        class Spy:
            def __init__(self, inner):
                self.inner = inner

            def write(self, data):
                seen.append(data)
                return self.inner.write(data)

            def flush(self):
                return self.inner.flush()

        self.wfile = Spy(self.wfile)
        return original_assemble(self, bucket, key, files)

    monkeypatch.setattr(RS._S3Handler, "_assemble", assemble)
    answer = client.complete_multipart_upload(
        Bucket="b", Key="big", UploadId=upload_id,
        MultipartUpload={"Parts": [{"PartNumber": 1, "ETag": etag}]})
    assert answer["ETag"].endswith('-1"')
    assert b" " in seen
    assert (root / "b" / "big").read_bytes() == b"slow"


def test_sad_a_failed_assembly_is_an_error_in_the_200_and_the_upload_stays(s3, root, cache, monkeypatch):
    from botocore.exceptions import ClientError

    client = _boto3_client(s3)
    upload_id = client.create_multipart_upload(Bucket="b", Key="big")["UploadId"]
    etag = client.upload_part(Bucket="b", Key="big", UploadId=upload_id, PartNumber=1,
                              Body=b"data")["ETag"]
    store = RS._BaseHandler._store_body

    def failing_store(self, path, body):
        raise OSError("disk on fire")

    monkeypatch.setattr(RS._BaseHandler, "_store_body", failing_store)
    parts = {"Parts": [{"PartNumber": 1, "ETag": etag}]}
    with pytest.raises(ClientError) as caught:
        client.complete_multipart_upload(Bucket="b", Key="big", UploadId=upload_id,
                                         MultipartUpload=parts)
    assert caught.value.response["Error"]["Code"] == "InternalError"
    assert not (root / "b" / "big").exists()
    monkeypatch.setattr(RS._BaseHandler, "_store_body", store)
    client.complete_multipart_upload(Bucket="b", Key="big", UploadId=upload_id, MultipartUpload=parts)
    assert (root / "b" / "big").read_bytes() == b"data"


# -- sad -----------------------------------------------------------------------------------


@pytest.mark.parametrize("case", ["short", "long", "missing", "after"])
def test_sad_an_aws_chunked_body_that_does_not_match_keeps_the_old_object(s3, root, case):
    data = b"0123456789"
    inner = _aws_chunked(data)
    declared = {"short": len(data) - 1, "long": len(data) + 1}.get(case, len(data))
    head = b"Content-Encoding: aws-chunked\r\n"
    if case != "missing":
        head += b"X-Amz-Decoded-Content-Length: %d\r\n" % declared
    if case == "after":
        inner += b"trailing junk"
    reply = _raw_put(s3, b"/b/f", head + b"Content-Length: %d\r\n" % len(inner), inner)
    assert reply.startswith(b"HTTP/1.1 4"), reply[:200]
    assert (root / "b" / "f").read_bytes() == OLD


@pytest.mark.parametrize("kind", ["s3", "webdav"])
def test_sad_a_bad_token_gets_its_refusal_and_no_invitation(kind, root, cache):
    srv = _serve(kind, root)
    try:
        sock, head = _expect_put(srv, b"/b/f", 5, token="wrong-token-wrong-token")
        with sock:
            status = head.split(b" ", 2)[1]
            assert head.startswith(b"HTTP/1.1 ") and status in (b"401", b"403"), head
            assert b"100 Continue" not in head
            assert b"Connection: close" in head  # the unread body ends the connection
        assert (root / "b" / "f").read_bytes() == OLD
    finally:
        srv.shutdown()


@pytest.mark.parametrize("kind", ["s3", "webdav"])
@pytest.mark.parametrize("case", ["traversal", "read_only", "too_large"])
def test_sad_a_refused_path_or_size_gets_no_invitation(kind, case, root, cache):
    srv = _serve(kind, root, read_only=case == "read_only")
    try:
        path = b"/b/../../etc/x" if case == "traversal" else b"/b/f"
        length = RS.MAX_BODY_BYTES + 1 if case == "too_large" else 5
        sock, head = _expect_put(srv, path, length)
        with sock:
            assert head.startswith(b"HTTP/1.1 4"), head
            assert b"100 Continue" not in head
        assert (root / "b" / "f").read_bytes() == OLD
    finally:
        srv.shutdown()


def test_sad_a_part_of_an_unknown_upload_or_beyond_the_cap_gets_no_invitation(
        s3, root, cache, monkeypatch):
    sock, head = _expect_put(s3, b"/b/big?partNumber=1&uploadId=" + b"A" * 32, 5)
    with sock:
        assert head.startswith(b"HTTP/1.1 404") and b"100 Continue" not in head
    monkeypatch.setattr(RS, "MULTIPART_MAX_BYTES", 10)
    upload_id = _create(s3)
    assert _part(s3, upload_id, 1, b"123456")[0] == 200
    sock, head = _expect_put(s3, f"/b/big?partNumber=2&uploadId={upload_id}".encode(), 5)
    with sock:
        assert head.startswith(b"HTTP/1.1 400") and b"100 Continue" not in head
        assert b"EntityTooLarge" in head + _recv_all(sock)
    for number in ("0", "10001", "x"):
        status, body, _ = _part(s3, upload_id, number, b"1")
        assert status == 400, number


def test_sad_complete_refuses_a_wrong_etag_a_missing_part_and_a_dtd(s3, root, cache):
    upload_id = _create(s3)
    _, _, etag = _part(s3, upload_id, 1, b"data")
    for body, code in (
        (_complete_xml([(1, '"' + "0" * 32 + '"')]), "InvalidPart"),
        (_complete_xml([(1, etag), (2, etag)]), "InvalidPart"),
        (_complete_xml([(2, etag), (1, etag)]), "MalformedXML"),
        (b'<?xml version="1.0"?><!DOCTYPE x [<!ENTITY a "aaaa">]>'
         b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>&a;</ETag></Part>"
         b"</CompleteMultipartUpload>", "MalformedXML"),
        (b"<CompleteMultipartUpload/>", "MalformedXML"),
    ):
        status, answer, _ = _req(s3, "POST", f"/b/big?uploadId={upload_id}", body)
        assert status == 400 and _code(answer) == code, (body, answer)
    assert not (root / "b" / "big").exists()
    # The upload survived the refusals.
    status, _, _ = _req(s3, "POST", f"/b/big?uploadId={upload_id}", _complete_xml([(1, etag)]))
    assert status == 200 and (root / "b" / "big").read_bytes() == b"data"


def test_sad_an_upload_is_bound_to_its_key(s3, root, cache):
    upload_id = _create(s3, "b/one")
    status, body, _ = _part(s3, upload_id, 1, b"x", key="b/two")
    assert status == 404 and _code(body) == "NoSuchUpload"
    status, _, _ = _req(s3, "DELETE", f"/b/two?uploadId={upload_id}")
    assert status == 404
    assert _part(s3, upload_id, 1, b"x", key="b/one")[0] == 200


def test_sad_read_only_and_no_token_refuse_create(root, cache):
    srv = _serve("s3", root, read_only=True)
    try:
        status, body, _ = _req(srv, "POST", "/b/big?uploads")
        assert status == 403 and _code(body) == "AccessDenied"
        status, body, _ = _req(srv, "POST", "/b/big?uploads", headers={"Authorization": "Bearer nope"})
        assert status == 403
    finally:
        srv.shutdown()
    assert not cache.exists() or list(cache.rglob("up-*")) == []


def test_sad_too_many_open_uploads_are_refused(s3, cache, monkeypatch):
    monkeypatch.setattr(RS, "MULTIPART_MAX_UPLOADS", 2)
    _create(s3, "b/x1")
    _create(s3, "b/x2")
    status, body, _ = _req(s3, "POST", "/b/x3?uploads")
    assert status == 400 and _code(body) == "InvalidRequest"


def test_sad_other_posts_stay_501(s3, root):
    status, body, _ = _req(s3, "POST", "/b?delete", b"<Delete/>")
    assert status == 501 and _code(body) == "NotImplemented"
    status, body, _ = _req(s3, "POST", "/b/f", b"form")
    assert status == 501
    assert (root / "b" / "f").read_bytes() == OLD


def test_sad_a_symlinked_parts_folder_is_refused(s3, root, cache, tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    cache.parent.mkdir(parents=True)
    cache.symlink_to(elsewhere)
    status, body, _ = _req(s3, "POST", "/b/big?uploads")
    assert status in (403, 500)
    assert list(elsewhere.iterdir()) == []


def test_sad_a_body_left_unread_is_never_taken_for_the_next_request(s3, root):
    """A GET with a body, the body being a DELETE: with keep-alive the
    unread body would be parsed as the next request (smuggling)."""
    smuggled = (b"DELETE /b/f HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer "
                + s3.auth_token.encode() + b"\r\nContent-Length: 0\r\n\r\n")
    with socket.create_connection(("127.0.0.1", s3.port), timeout=10) as sock:
        sock.sendall(b"GET /b/f HTTP/1.1\r\nHost: 127.0.0.1\r\nAuthorization: Bearer "
                     + s3.auth_token.encode() + b"\r\nContent-Length: " + str(len(smuggled)).encode()
                     + b"\r\n\r\n" + smuggled)
        reply = _recv_all(sock)
    assert reply.startswith(b"HTTP/1.1 200") and b"Connection: close" in reply
    assert reply.count(b"HTTP/1.1 ") == 1
    assert (root / "b" / "f").read_bytes() == OLD


# -- edge ----------------------------------------------------------------------------------


def test_edge_a_kept_alive_connection_serves_again_then_idles_out(s3, root, monkeypatch):
    monkeypatch.setattr(RS, "KEEPALIVE_IDLE_S", 0.3)
    conn = http.client.HTTPConnection("127.0.0.1", s3.port, timeout=10)
    try:
        assert _req(s3, "PUT", "/b/f", b"one", conn=conn)[0] == 200
        status, body, resp = _req(s3, "GET", "/b/f", conn=conn)
        assert (status, body) == (200, b"one")
        assert resp.getheader("Connection") != "close"
        sock = conn.sock
        sock.settimeout(10)
        assert sock.recv(1) == b""  # the server closed the idle connection
    finally:
        conn.close()


def test_edge_stop_closes_an_idle_kept_alive_connection_at_once(root, cache):
    srv = _serve("s3", root)
    conn = http.client.HTTPConnection("127.0.0.1", srv.port, timeout=10)
    try:
        assert _req(srv, "GET", "/b/f", conn=conn)[1] == OLD
        started = time.monotonic()
        srv.shutdown()
        conn.sock.settimeout(RS.KEEPALIVE_IDLE_S * 4)
        assert conn.sock.recv(1) == b""
        # Before the idle timeout: the stop closed it, not the wait.
        assert time.monotonic() - started < RS.KEEPALIVE_IDLE_S * 4
    finally:
        conn.close()


def test_edge_an_idle_upload_expires_and_stop_removes_everything(s3, root, cache, monkeypatch):
    first = _create(s3, "b/one")
    _part(s3, first, 1, b"abc")
    monkeypatch.setattr(RS, "MULTIPART_IDLE_S", 0.0)
    time.sleep(0.01)
    _create(s3, "b/two")  # expires the first
    assert len(list(cache.rglob("up-*"))) == 1
    assert _part(s3, first, 2, b"x")[0] == 404
    s3.shutdown()
    assert list(cache.iterdir()) == []


def test_edge_a_folder_marker_key_is_no_multipart_target(s3):
    status, body, _ = _req(s3, "POST", "/b/dir/?uploads")
    assert status == 400 and _code(body) == "InvalidArgument"


def test_edge_without_expect_a_put_still_works(s3, root):
    assert _req(s3, "PUT", "/b/f", b"plain")[0] == 200
    assert (root / "b" / "f").read_bytes() == b"plain"
