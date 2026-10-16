"""stat() and exists() report a broken HEAD answer as OSError.

botocore raises ValueError when it cannot parse a HEAD response's
Content-Length or Last-Modified ("Invalid timestamp", "invalid literal for
int()"), and BotoCoreError subclasses such as ConnectionClosedError when the
endpoint hangs up or answers garbage. stat() and exists() caught only
ClientError, so both escaped every OSError handler (found by
tests/test_fuzz_s3.py).
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("boto3")

from botocore.exceptions import ClientError, ConnectionClosedError  # noqa: E402

from core import s3_client as S3  # noqa: E402


class _FakeS3:
    def __init__(self, head):
        self._head = head
        self.listed = 0

    def head_object(self, **kw):
        if isinstance(self._head, BaseException):
            raise self._head
        return self._head

    def list_objects_v2(self, **kw):
        self.listed += 1
        return {"KeyCount": 0}


def _session(head) -> S3.S3Session:
    s = S3.S3Session.__new__(S3.S3Session)
    s._bucket = "b"
    s._s3 = _FakeS3(head)
    return s


def test_happy_head_answer_is_an_item():
    when = datetime(2026, 1, 1, tzinfo=timezone.utc)
    s = _session({"ContentLength": 5, "LastModified": when})
    item = s.stat("/a.txt")
    assert (item.name, item.size) == ("a.txt", 5)
    assert s.exists("/a.txt") is True


BROKEN = [
    ValueError('Invalid timestamp "garbage": Unknown string format: garbage'),
    ValueError("invalid literal for int() with base 10: 'abc'"),
    ConnectionClosedError(endpoint_url="http://127.0.0.1:1/b/a.txt"),
]


@pytest.mark.parametrize("exc", BROKEN, ids=["bad-date", "bad-length", "hangup"])
def test_sad_unparsable_or_dropped_head_is_an_oserror(exc):
    s = _session(exc)
    with pytest.raises(OSError, match="a.txt"):
        s.stat("/a.txt")
    with pytest.raises(OSError, match="a.txt"):
        s.exists("/a.txt")


def test_edge_head_404_still_falls_back_to_the_prefix_probe():
    err = ClientError({"Error": {"Code": "404"}}, "HeadObject")
    s = _session(err)
    assert s.exists("/a.txt") is False
    with pytest.raises(OSError, match="Not found"):
        s.stat("/a.txt")
    assert s._s3.listed == 2
