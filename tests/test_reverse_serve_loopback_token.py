"""Reverse-serve: a token on loopback too, unless the caller opts out.

A loopback reverse-server ran without any auth: every local user of the
host could reach the exposed backend - with the credentials of whoever
opened it - through 127.0.0.1:<port>. Operator decision 2026-10-17: a
token by default, as ``mcp_http`` already does (core/mcp_http.py, no TLS
-> generated token); ``auth_token=None`` is the explicit opt-out for
clients that cannot send one (aws-cli), and only on loopback.

WebDAV clients (davfs2, Finder, gnome-files, cadaver) speak Basic auth,
not Bearer: the token is accepted as the Basic password, and a refusal
carries ``WWW-Authenticate`` so they ask for it.
"""

from __future__ import annotations

import base64
import logging
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import reverse_serve as RS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


@pytest.fixture
def root(tmp_path):
    (tmp_path / "bucket").mkdir()
    (tmp_path / "bucket" / "a.txt").write_bytes(b"secret")
    return tmp_path


@pytest.fixture
def servers():
    started = []
    yield started
    for srv in started:
        srv.shutdown()


def _get(url: str, headers: dict | None = None) -> tuple[int, bytes, dict]:
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, resp.read(), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), dict(exc.headers)


def _basic(user: str, password: str) -> dict:
    raw = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {raw}"}


def _dav(root, servers, **kw):
    srv = RS.serve_webdav(LocalFS(), bind="127.0.0.1", port=0, root_path=str(root), **kw)
    servers.append(srv)
    return srv


def _s3(root, servers, **kw):
    srv = RS.serve_s3(LocalFS(), bind="127.0.0.1", port=0, root_path=str(root), **kw)
    servers.append(srv)
    return srv


# -- happy ---------------------------------------------------------------------------------


def test_happy_a_loopback_webdav_server_gets_a_token_and_asks_for_it(root, servers):
    srv = _dav(root, servers)
    assert len(srv.auth_token) >= 32
    code, _, headers = _get(f"{srv.base_url}/bucket/a.txt")
    assert code == 401
    assert headers.get("WWW-Authenticate", "").startswith("Basic ")
    bearer = {"Authorization": f"Bearer {srv.auth_token}"}
    assert _get(f"{srv.base_url}/bucket/a.txt", bearer)[:2] == (200, b"secret")
    assert _get(f"{srv.base_url}/bucket/a.txt", _basic("any", srv.auth_token))[:2] == (
        200,
        b"secret",
    )


def test_happy_a_loopback_s3_server_gets_a_token(root, servers):
    srv = _s3(root, servers)
    assert len(srv.auth_token) >= 32
    assert _get(f"{srv.base_url}/bucket/a.txt")[0] == 403
    bearer = {"Authorization": f"Bearer {srv.auth_token}"}
    assert _get(f"{srv.base_url}/bucket/a.txt", bearer)[:2] == (200, b"secret")


# -- sad -----------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "headers",
    [
        {"Authorization": "Bearer wrong-token-wrong-token-wrong"},
        _basic("any", "wrong"),
        {"Authorization": "Basic %%%not-base64%%%"},
        {"Authorization": "Basic " + base64.b64encode(b"no-colon").decode()},
        {"Authorization": "Digest username=x"},
    ],
)
def test_sad_a_wrong_or_malformed_credential_is_refused(root, servers, headers):
    srv = _dav(root, servers)
    assert _get(f"{srv.base_url}/bucket/a.txt", headers)[0] == 401


def test_sad_no_token_is_refused_off_loopback():
    with pytest.raises(PermissionError, match="only on a loopback"):
        RS.serve_webdav(LocalFS(), bind="0.0.0.0", port=0, auth_token=None)
    with pytest.raises(PermissionError, match="without auth_token"):
        RS.serve_s3(LocalFS(), bind="0.0.0.0", port=0)


# -- edge ----------------------------------------------------------------------------------


def test_edge_auth_token_none_is_the_explicit_loopback_opt_out(root, servers, caplog):
    with caplog.at_level(logging.WARNING, logger="core.reverse_serve"):
        srv = _s3(root, servers, auth_token=None)
    assert srv.auth_token == ""
    assert _get(f"{srv.base_url}/bucket/a.txt")[:2] == (200, b"secret")
    assert any("without a token" in r.getMessage() for r in caplog.records)


def test_edge_a_given_token_is_kept(root, servers):
    token = "t" * 40
    srv = _dav(root, servers, auth_token=token)
    assert srv.auth_token == token
    assert _get(f"{srv.base_url}/bucket/a.txt", _basic("", token))[0] == 200


def test_edge_tokens_differ_and_never_reach_the_log_or_repr(root, servers, caplog):
    with caplog.at_level(logging.DEBUG, logger="core.reverse_serve"):
        first = _dav(root, servers)
        second = _s3(root, servers)
    assert first.auth_token != second.auth_token
    for srv in (first, second):
        assert srv.auth_token not in repr(srv)
        assert all(srv.auth_token not in r.getMessage() for r in caplog.records)


# -- S3 SDK clients: the token as the access key id ----------------------------------------
# aws-cli and restic sign every request (SigV4) and own the Authorization
# header, so they cannot send a Bearer token; their access key id travels
# in that header in clear, as a Bearer token does.


def test_happy_boto3_signs_with_the_token_as_access_key(root, servers):
    boto3 = pytest.importorskip("boto3")
    from botocore.config import Config

    srv = _s3(root, servers)

    def client(key):
        return boto3.client(
            "s3",
            endpoint_url=srv.base_url,
            aws_access_key_id=key,
            aws_secret_access_key="ignored",
            region_name="us-east-1",
            config=Config(s3={"addressing_style": "path"}, retries={"max_attempts": 1}),
        )

    body = client(srv.auth_token).get_object(Bucket="bucket", Key="a.txt")["Body"].read()
    assert body == b"secret"
    from botocore.exceptions import ClientError

    with pytest.raises(ClientError):
        client("not-the-token").get_object(Bucket="bucket", Key="a.txt")


@pytest.mark.parametrize(
    "header",
    [
        "AWS4-HMAC-SHA256 Credential=wrong/20261017/us-east-1/s3/aws4_request, Signature=x",
        "AWS4-HMAC-SHA256 SignedHeaders=host, Signature=x",
        "AWS wrong:signature",
    ],
)
def test_sad_a_signature_with_another_access_key_is_refused(root, servers, header):
    srv = _s3(root, servers)
    assert _get(f"{srv.base_url}/bucket/a.txt", {"Authorization": header})[0] == 403


def test_edge_the_v2_form_carries_the_token_too(root, servers):
    srv = _s3(root, servers)
    header = {"Authorization": f"AWS {srv.auth_token}:signature"}
    assert _get(f"{srv.base_url}/bucket/a.txt", header)[:2] == (200, b"secret")
