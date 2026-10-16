"""Fuzz: S3Session against a hostile S3-compatible endpoint.

botocore parses the XML; axross turns what it raises into OSError. A lying
ListObjects answer, garbage HEAD headers, a server that hangs up or stalls
must end in sane items or an OSError - never a BotoCoreError /
ResponseParserError that callers do not catch, and never a hang.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402
from http_fuzz_server import STALL, FakeHttpServer, response  # noqa: E402

pytest.importorskip("boto3")

from core import s3_client as S3  # noqa: E402

LIST = b"""<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
 <Name>fuzzbucket</Name><Prefix>dir/</Prefix><KeyCount>3</KeyCount><MaxKeys>1000</MaxKeys>
 <Delimiter>/</Delimiter><IsTruncated>false</IsTruncated>
 <Contents><Key>dir/a.txt</Key><LastModified>2026-01-01T10:00:00.000Z</LastModified>
  <ETag>"abc"</ETag><Size>1234</Size><StorageClass>STANDARD</StorageClass></Contents>
 <Contents><Key>dir/b.bin</Key><LastModified>2026-01-02T10:00:00.000Z</LastModified>
  <ETag>"def-2"</ETag><Size>0</Size></Contents>
 <CommonPrefixes><Prefix>dir/sub/</Prefix></CommonPrefixes>
</ListBucketResult>"""

VERSIONS = b"""<?xml version="1.0" encoding="UTF-8"?>
<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
 <Name>fuzzbucket</Name><Prefix>dir/a.txt</Prefix><IsTruncated>false</IsTruncated>
 <Version><Key>dir/a.txt</Key><VersionId>v1</VersionId><IsLatest>true</IsLatest>
  <LastModified>2026-01-01T10:00:00.000Z</LastModified><Size>3</Size></Version>
</ListVersionsResult>"""

HEAD = (
    b'HTTP/1.1 200 OK\r\nContent-Length: 1234\r\nETag: "abc"\r\n'
    b"Last-Modified: Thu, 01 Jan 2026 10:00:00 GMT\r\nContent-Type: text/plain\r\n\r\n"
)


class S3Server:
    def __init__(self) -> None:
        self.list = LIST
        self.versions = VERSIONS
        self.head = HEAD
        self.get = response(200, b"content")
        self.raw = None
        self.http = FakeHttpServer(self._respond)

    def _respond(self, method, path, headers, body):
        if self.raw is not None:
            return self.raw
        if method == "HEAD":
            return self.head
        if "versions" in path:
            return response(200, self.versions, {"Content-Type": "application/xml"})
        if "list-type=2" in path or path.rstrip("/").endswith("fuzzbucket"):
            return response(200, self.list, {"Content-Type": "application/xml"})
        if method == "GET":
            return self.get
        return response(200)

    def close(self) -> None:
        self.http.close()


@pytest.fixture
def s3srv():
    srv = S3Server()
    yield srv
    srv.close()


def _session(srv: S3Server) -> S3.S3Session:
    import boto3
    from botocore import UNSIGNED
    from botocore.config import Config

    s = S3.S3Session("fuzzbucket", region="us-east-1", endpoint=srv.http.url)
    # Same client, without retries and with short timeouts: a stalled
    # server must fail the same way, only sooner.
    s._s3 = boto3.client(
        "s3",
        region_name="us-east-1",
        endpoint_url=srv.http.url,
        config=Config(
            signature_version=UNSIGNED,
            retries={"max_attempts": 1, "mode": "standard"},
            connect_timeout=0.2,
            read_timeout=0.2,
        ),
    )
    return s


def _ops(s):
    return {
        "list_dir": lambda: s.list_dir("/dir"),
        "stat": lambda: s.stat("/dir/a.txt"),
        "stat_dir": lambda: s.stat("/dir/sub"),
        "is_dir": lambda: s.is_dir("/dir/sub"),
        "exists": lambda: s.exists("/dir/a.txt"),
        "checksum": lambda: s.checksum("/dir/a.txt"),
        "open_read": lambda: s.open_read("/dir/a.txt"),
        "list_versions": lambda: s.list_versions("/dir/a.txt"),
    }


def _all_ops(s, ctx, only=None):
    for name, op in _ops(s).items():
        if only and name not in only:
            continue
        result = check_contract(op, (OSError,), timeout=20.0, context=f"{ctx} {name}")
        if name == "list_dir" and not isinstance(result, OSError):
            for item in result:
                assert isinstance(item.name, str) and isinstance(item.size, int)


def test_happy_listing(s3srv):
    items = _session(s3srv).list_dir("/dir")
    assert sorted(i.name for i in items) == ["a.txt", "b.bin", "sub"]


@pytest.mark.parametrize(
    "raw",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n<a/",
        b"HTTP/1.1 500 Internal\r\nContent-Length: 9\r\n\r\nnot xml!!",
        b"HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n<ListBucketResult>",
        b"HTTP/1.1 503 Slow Down\r\nContent-Length: 0\r\n\r\n",
        b"garbage\r\n\r\n",
        STALL,
        None,
    ],
    ids=["truncated-xml", "500-text", "short-body", "503", "garbage", "stall", "hangup"],
)
def test_sad_hostile_http(s3srv, raw):
    s = _session(s3srv)
    s3srv.raw = raw
    # A stall costs a read timeout per call: two calls show it times out.
    # One call per request kind; the rest repeat the same parse path.
    only = (
        ("list_dir", "stat") if raw is STALL else ("list_dir", "stat", "open_read", "list_versions")
    )
    _all_ops(s, repr(raw)[:60], only=only)


@pytest.mark.parametrize(
    "head",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: -5\r\nLast-Modified: garbage\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nContent-Length: abc\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nLast-Modified: Thu, 01 Jan 99999 10:00:00 GMT\r\n\r\n",
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nETag: \xff\xfe\r\n\r\n",
    ],
)
def test_sad_hostile_head_headers(s3srv, head):
    s = _session(s3srv)
    s3srv.head = head
    _all_ops(s, repr(head)[:60], only=("stat", "exists", "checksum"))


def test_edge_lying_keys_outside_the_prefix(s3srv):
    from core.path_policy import drop_unsafe_names

    s3srv.list = (
        b"<ListBucketResult xmlns='http://s3.amazonaws.com/doc/2006-03-01/'>"
        b"<IsTruncated>false</IsTruncated>"
        b"<Contents><Key>elsewhere/../../etc/passwd</Key><Size>1</Size></Contents>"
        b"<Contents><Key>dir/a/b/c</Key><Size>1</Size></Contents>"
        b"<Contents><Key>dir/ok.txt</Key><Size>-7</Size></Contents>"
        b"<CommonPrefixes><Prefix>x/../</Prefix></CommonPrefixes>"
        b"</ListBucketResult>"
    )
    items = check_contract(lambda: _session(s3srv).list_dir("/dir"), (OSError,), context="lying")
    if not isinstance(items, OSError):
        assert all(i.name in ("ok.txt",) for i in drop_unsafe_names(items))


def test_fuzz_list_objects_mutants(s3srv):
    s = _session(s3srv)
    for n, payload in enumerate(mutants([LIST], seed=0x53, per_entry=iterations(8))):
        s3srv.list = payload
        _all_ops(s, f"ListObjects mutant #{n}: {payload[:100]!r}", only=("list_dir", "is_dir"))


def test_fuzz_list_versions_mutants(s3srv):
    s = _session(s3srv)
    for n, payload in enumerate(mutants([VERSIONS], seed=0x54, per_entry=iterations(6))):
        s3srv.versions = payload
        _all_ops(s, f"ListVersions mutant #{n}: {payload[:100]!r}", only=("list_versions",))


def test_fuzz_head_mutants(s3srv):
    s = _session(s3srv)
    for n, payload in enumerate(mutants([HEAD], seed=0x55, per_entry=iterations(6))):
        s3srv.head = payload
        _all_ops(s, f"HEAD mutant #{n}: {payload[:100]!r}", only=("stat", "exists", "checksum"))
