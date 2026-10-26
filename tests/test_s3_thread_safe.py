"""S3: the boto3 client comes from a boto3 Session of the S3Session's own.

boto3 documents low-level clients as thread safe, but ``boto3.client()``
builds the client from the shared default session, and "invoking
boto3.client() inside of a concurrent context may result in response
ordering issues or interpreter failures from underlying SSL modules"
(boto3 guide, clients.html). S3Session used ``boto3.client()`` - two
profiles connecting at the same time, or a session connecting while a
transfer worker builds another, went through the shared default session.
Now every S3Session builds its client from ``boto3.session.Session()``
and leaves the default session alone, so several transfer jobs can share
one S3Session (core.transfer_pool._PARALLEL_SAFE).
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

boto3 = pytest.importorskip("boto3")

from botocore.exceptions import ClientError  # noqa: E402

from core import s3_client as S3  # noqa: E402


@pytest.fixture
def no_default_session(monkeypatch):
    """boto3.client() must not be called, nor the default session made."""
    monkeypatch.setattr(boto3, "DEFAULT_SESSION", None)

    def refuse(*args, **kwargs):
        raise AssertionError("boto3.client() uses the shared default session")

    monkeypatch.setattr(boto3, "client", refuse)
    yield
    assert boto3.DEFAULT_SESSION is None


def _session(monkeypatch, **kwargs) -> S3.S3Session:
    # No server: the connection test is answered here.
    monkeypatch.setattr(S3.S3Session, "_test_bucket", lambda self, bucket: None)
    return S3.S3Session(
        bucket="testbucket",
        region="eu-central-1",
        access_key="AKIDEXAMPLE",
        secret_key="secret",
        endpoint="http://127.0.0.1:9",
        **kwargs,
    )


# ---------------------------------------------------------------- happy path


def test_happy_the_client_comes_from_a_boto3_session_of_its_own(monkeypatch, no_default_session):
    s = _session(monkeypatch)
    assert isinstance(s._boto_session, boto3.session.Session)
    assert s._boto_session is not boto3.DEFAULT_SESSION
    assert s._s3.meta.region_name == "eu-central-1"
    assert s._s3.meta.endpoint_url == "http://127.0.0.1:9"


def test_happy_sessions_built_at_the_same_time_each_have_their_own(
    monkeypatch, no_default_session
):
    monkeypatch.setattr(S3.S3Session, "_test_bucket", lambda self, bucket: None)
    built: list = []
    errors: list = []

    def build():
        try:
            built.append(
                S3.S3Session(
                    bucket="testbucket",
                    region="us-east-1",
                    access_key="AKIDEXAMPLE",
                    secret_key="secret",
                    endpoint="http://127.0.0.1:9",
                )
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=build) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(60)
    assert errors == []
    assert len({id(s._boto_session) for s in built}) == 8


# ------------------------------------------------------------------ sad path


def test_sad_a_region_redirect_builds_its_client_from_the_same_session(
    monkeypatch, no_default_session
):
    calls = []

    def test_bucket(self, bucket):
        calls.append(self._s3.meta.region_name)
        if len(calls) == 1:
            raise ClientError(
                {
                    "Error": {"Code": "PermanentRedirect", "Message": "moved"},
                    "ResponseMetadata": {"HTTPHeaders": {"x-amz-bucket-region": "ap-south-1"}},
                },
                "HeadBucket",
            )

    monkeypatch.setattr(S3.S3Session, "_test_bucket", test_bucket)
    s = S3.S3Session(
        bucket="testbucket", region="us-east-1", access_key="AKIDEXAMPLE", secret_key="secret"
    )
    assert calls == ["us-east-1", "ap-south-1"]
    assert s._region == "ap-south-1"
    assert s._s3.meta.region_name == "ap-south-1"


def test_sad_the_profile_proxy_reaches_the_client(monkeypatch, no_default_session):
    monkeypatch.setenv("AXROSS_ALLOW_PRIVATE_PROXY", "1")
    s = _session(
        monkeypatch,
        proxy_type="http",
        proxy_host="proxy.example",
        proxy_port=8080,
        proxy_username="u",
        proxy_password="p",
    )
    assert s._s3.meta.config.proxies["http"] == "http://u:p@proxy.example:8080"


# ---------------------------------------------------------------- edge cases


def test_edge_every_open_write_spools_on_its_own_and_uploads_its_own_bytes():
    uploads = {}
    lock = threading.Lock()

    class _Client:
        def upload_fileobj(self, fileobj, bucket, key):
            data = fileobj.read()
            with lock:
                uploads[key] = data

    s = object.__new__(S3.S3Session)
    s._s3 = _Client()
    s._bucket = "b"
    s._anonymous = False
    start = threading.Barrier(8)

    def write(i):
        with s.open_write(f"/k{i}") as fh:
            start.wait(10)  # all eight writers open at once
            for _ in range(50):
                fh.write(bytes([i]) * 100)

    threads = [threading.Thread(target=write, args=(i,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(30)
    assert uploads == {f"k{i}": bytes([i]) * 5000 for i in range(8)}


def test_edge_the_client_is_not_replaced_after_connecting(monkeypatch):
    """No call after the constructor swaps the client: a transfer worker
    holding it never races a reconnect."""
    src = Path(S3.__file__).read_text(encoding="utf-8")
    body = src[src.index("class S3Session") :]
    init_end = body.index("    @property\n    def name")
    assert "self._s3 =" not in body[init_end:]
