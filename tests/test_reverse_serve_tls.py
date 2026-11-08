"""Reverse-serve: HTTPS off loopback, or an explicit opt-in to plain HTTP.

``core/reverse_serve.py`` served only plain HTTP (a bare
``ThreadingHTTPServer``, ``base_url`` always ``http://``) and had no TLS
option, yet a LAN bind (``bind="0.0.0.0"``) needed nothing but a token.
The token - a Bearer header, the Basic password or the AWS access key id
- and every file then crossed the network in clear: anyone sniffing the
LAN took the token and had the exposed backend. core/mcp_http.py refuses
exactly this setup.

Now ``cert_file`` + ``key_file`` serve HTTPS (TLS 1.2+, ``https://`` in
``base_url``), on loopback or not, and a non-loopback bind without them
is refused unless ``allow_insecure_http=True`` opts in, which logs a
warning. The scripting API (``axross.serve_s3`` / ``serve_webdav``)
passes the options through.
"""

from __future__ import annotations

import http.client
import logging
import shutil
import socket
import ssl
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import reverse_serve as RS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

TOKEN = "t" * 32


@pytest.fixture(scope="module")
def pem(tmp_path_factory):
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl not available")
    tmp = tmp_path_factory.mktemp("pem")
    key, crt = tmp / "key.pem", tmp / "cert.pem"
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(crt), "-days", "1", "-subj", "/CN=localhost",
         "-addext", "subjectAltName=IP:127.0.0.1,DNS:localhost"],
        check=True,
        capture_output=True,
    )
    return str(crt), str(key)


@pytest.fixture
def root(tmp_path):
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "a.txt").write_bytes(b"secret bytes")
    return tmp_path


@pytest.fixture
def servers():
    started = []
    yield started
    for srv in started:
        srv.shutdown()


def _https_get(srv, crt: str, path: str) -> tuple[int, bytes]:
    ctx = ssl.create_default_context(cafile=crt)
    conn = http.client.HTTPSConnection("127.0.0.1", srv.port, context=ctx, timeout=10)
    try:
        conn.request("GET", path, headers={"Authorization": "Bearer " + srv.auth_token})
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


# -- happy ---------------------------------------------------------------------------------


@pytest.mark.parametrize("flavour", ["webdav", "s3"])
def test_happy_cert_and_key_serve_https_off_loopback(root, servers, pem, flavour):
    crt, key = pem
    serve = RS.serve_webdav if flavour == "webdav" else RS.serve_s3
    srv = serve(
        LocalFS(), bind="0.0.0.0", port=0, root_path=str(root), auth_token=TOKEN,
        cert_file=crt, key_file=key,
    )
    servers.append(srv)
    assert srv.tls and srv.base_url.startswith("https://")
    assert _https_get(srv, crt, "/b/a.txt") == (200, b"secret bytes")


def test_happy_tls_on_loopback_too(root, servers, pem):
    crt, key = pem
    srv = RS.serve_webdav(
        LocalFS(), bind="127.0.0.1", port=0, root_path=str(root), cert_file=crt, key_file=key
    )
    servers.append(srv)
    assert srv.base_url == f"https://127.0.0.1:{srv.port}"
    assert _https_get(srv, crt, "/b/a.txt") == (200, b"secret bytes")


def test_happy_the_scripting_api_passes_tls_through(root, servers, pem):
    from core import scripting as axross

    crt, key = pem
    srv = axross.serve_s3(
        LocalFS(), bind="0.0.0.0", port=0, root_path=str(root), auth_token=TOKEN,
        cert_file=crt, key_file=key,
    )
    servers.append(srv)
    assert srv.tls
    assert _https_get(srv, crt, "/b/a.txt") == (200, b"secret bytes")


# -- sad -----------------------------------------------------------------------------------


def _refused(serve, servers, **kw):
    try:
        srv = serve(LocalFS(), port=0, **kw)
    except PermissionError as exc:
        return str(exc)
    servers.append(srv)
    return None


@pytest.mark.parametrize("flavour", ["webdav", "s3"])
def test_sad_a_lan_bind_over_plain_http_is_refused(servers, flavour):
    serve = RS.serve_webdav if flavour == "webdav" else RS.serve_s3
    message = _refused(serve, servers, bind="0.0.0.0", auth_token=TOKEN)
    assert message is not None and "plain HTTP" in message


def test_sad_the_scripting_api_refuses_plain_http_off_loopback(servers):
    from core import scripting as axross

    message = _refused(axross.serve_webdav, servers, bind="0.0.0.0", auth_token=TOKEN)
    assert message is not None and "cert_file" in message


def test_sad_a_cert_without_its_key_is_refused(pem):
    crt, _key = pem
    with pytest.raises(ValueError, match="together"):
        RS.serve_webdav(LocalFS(), bind="0.0.0.0", port=0, auth_token=TOKEN, cert_file=crt)


def test_sad_a_plain_http_client_gets_nothing_from_a_tls_server(root, servers, pem):
    crt, key = pem
    srv = RS.serve_webdav(
        LocalFS(), bind="127.0.0.1", port=0, root_path=str(root), cert_file=crt, key_file=key
    )
    servers.append(srv)
    with socket.create_connection(("127.0.0.1", srv.port), timeout=10) as s:
        s.sendall(b"GET /b/a.txt HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
        try:
            reply = s.recv(4096)
        except ConnectionError:
            reply = b""
    assert b"secret bytes" not in reply
    # ... and the server still serves the next (TLS) client.
    assert _https_get(srv, crt, "/b/a.txt")[0] == 200


# -- edge ----------------------------------------------------------------------------------


def test_edge_explicit_opt_in_serves_plain_http_with_a_warning(root, servers, caplog):
    with caplog.at_level(logging.WARNING, logger="core.reverse_serve"):
        srv = RS.serve_s3(
            LocalFS(), bind="0.0.0.0", port=0, root_path=str(root), auth_token=TOKEN,
            allow_insecure_http=True,
        )
    servers.append(srv)
    assert not srv.tls and srv.base_url.startswith("http://")
    assert any("plain HTTP" in r.getMessage() for r in caplog.records)
    assert TOKEN not in caplog.text


def test_edge_loopback_plain_http_needs_no_opt_in(root, servers):
    srv = RS.serve_webdav(LocalFS(), bind="127.0.0.1", port=0, root_path=str(root))
    servers.append(srv)
    assert not srv.tls and srv.base_url.startswith("http://")


def test_edge_an_unreadable_certificate_fails_the_start(tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_text("not a certificate")
    with pytest.raises((ssl.SSLError, OSError)):
        RS.serve_webdav(
            LocalFS(), bind="0.0.0.0", port=0, auth_token=TOKEN,
            cert_file=str(bad), key_file=str(bad),
        )
