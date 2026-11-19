"""Connecting to S3: a wrong key, a key that may not use the bucket, a
missing bucket, a closed port and an unknown host each say what to check.

Measured with boto3 against core.reverse_serve's S3 server (the real wire
protocol) and a loopback server that answers as AWS does for a wrong key:

* a wrong key / a refused key: "Permission denied for the item. Your
  account has no rights to it there; choose another place ..." (the
  backend's "Check credentials" text was dropped for its errno);
* a missing bucket: "the item was not found. It may have been moved or
  deleted; refresh the folder ...";
* a closed port and a host name that does not resolve: "The connection was
  closed by the other side" (botocore's EndpointConnectionError mapped to
  ECONNRESET).

A HEAD answer has no body, so HeadBucket's bare 403 cannot tell a wrong key
from a key without the right to list; the listing's answer can.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("boto3")

from core import reverse_serve  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402
from core.s3_client import S3Session  # noqa: E402
from core.user_errors import describe  # noqa: E402


@pytest.fixture(autouse=True)
def _no_proxy_env(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY",
                 "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")


@pytest.fixture
def s3():
    ram = RamFsSession()
    ram.mkdir("/bkt")
    server = reverse_serve.serve_s3(ram, bind="127.0.0.1", port=0,
                                    auth_token="token-of-the-test-0123456789")
    yield server
    server.shutdown()


class _AwsRefusesTheKey(BaseHTTPRequestHandler):
    """HEAD: 403 without a body; GET (ListObjectsV2): 403 with AWS's XML."""

    protocol_version = "HTTP/1.1"
    code = "InvalidAccessKeyId"

    def log_message(self, *_args) -> None:
        pass

    def do_HEAD(self) -> None:  # noqa: N802
        self.send_response(403)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        body = (f'<?xml version="1.0" encoding="UTF-8"?><Error><Code>{self.code}</Code>'
                "<Message>The AWS Access Key Id you provided does not exist in our records."
                "</Message></Error>").encode()
        self.send_response(403)
        self.send_header("Content-Type", "application/xml")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def aws_refusing():
    def start(code: str):
        handler = type("Handler", (_AwsRefusesTheKey,), {"code": code})
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        httpd.daemon_threads = True
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        servers.append(httpd)
        return f"http://127.0.0.1:{httpd.server_address[1]}"

    servers: list = []
    yield start
    for httpd in servers:
        httpd.shutdown()
        httpd.server_close()


def test_happy_the_right_key_connects(s3):
    session = S3Session(bucket="bkt", access_key="token-of-the-test-0123456789",
                        secret_key="x", endpoint=s3.base_url)
    assert session.list_dir("/") == [] and session.connected


@pytest.mark.parametrize("code", ["InvalidAccessKeyId", "SignatureDoesNotMatch"])
def test_sad_a_wrong_key_says_to_check_the_key(aws_refusing, code):
    with pytest.raises(PermissionError) as info:
        S3Session(bucket="bkt", access_key="AKIAWRONG", secret_key="x",
                  endpoint=aws_refusing(code))
    text = describe(info.value)
    assert "access key" in text and "secret key" in text
    assert "the item" not in text


def test_sad_a_key_without_rights_says_so(s3):
    with pytest.raises(PermissionError) as info:
        S3Session(bucket="bkt", access_key="another-key", secret_key="x", endpoint=s3.base_url)
    text = describe(info.value)
    assert "bkt" in text and "denied" in text and "the item" not in text


def test_sad_a_missing_bucket_is_named(s3):
    with pytest.raises(FileNotFoundError) as info:
        S3Session(bucket="photos", access_key="token-of-the-test-0123456789",
                  secret_key="x", endpoint=s3.base_url)
    text = describe(info.value)
    assert "photos" in text and "does not exist" in text and "refresh the folder" not in text


def test_sad_a_closed_port_is_a_refused_connection():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    with pytest.raises(ConnectionRefusedError) as info:
        S3Session(bucket="bkt", access_key="a", secret_key="b",
                  endpoint=f"http://127.0.0.1:{port}")
    assert "refused the connection" in describe(info.value)


def test_sad_an_unknown_host_is_a_name_that_does_not_resolve(monkeypatch):
    def no_such_host(*_args, **_kwargs):
        raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")

    monkeypatch.setattr(socket, "getaddrinfo", no_such_host)
    with pytest.raises(OSError) as info:
        S3Session(bucket="bkt", access_key="a", secret_key="b",
                  endpoint="http://s3.example.invalid")
    text = describe(info.value)
    assert "could not be resolved" in text and "closed by the other side" not in text


def test_sad_a_dropped_server_is_not_connected_any_more(s3):
    session = S3Session(bucket="bkt", access_key="token-of-the-test-0123456789",
                        secret_key="x", endpoint=s3.base_url)
    s3.shutdown()
    assert not session.connected
    assert os.environ.get("AWS_EC2_METADATA_DISABLED") == "true"
