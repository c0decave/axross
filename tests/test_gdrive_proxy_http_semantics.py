"""GDrive through a proxy keeps googleapiclient's build_http() semantics.

With a proxy configured, _build_service handed googleapiclient a bare
``httplib2.Http(proxy_info=...)``: no socket timeout (build_http sets
60 s, so a stalled proxy hung the call forever) and 308 still followed
as a redirect - Drive answers 308 "Resume Incomplete" to every non-final
chunk of the resumable upload the writer uses. Without a proxy
``build()`` creates its Http through build_http() itself.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("googleapiclient")
pytest.importorskip("google_auth_httplib2")

import googleapiclient.http as gh  # noqa: E402
import httplib2  # noqa: E402

from core import gdrive_client  # noqa: E402


def _built_http(ptype: str, host: str = "203.0.113.7", port: int = 1080):
    captured: dict = {}
    s = gdrive_client.GDriveSession.__new__(gdrive_client.GDriveSession)
    s._proxy_type, s._proxy_host, s._proxy_port = ptype, host, port
    s._proxy_username = s._proxy_password = ""

    def fake_build(*args, **kwargs):
        captured.update(kwargs)
        return object()

    with mock.patch.object(gdrive_client, "build", fake_build):
        s._build_service(creds=None)
    return captured


@pytest.mark.parametrize("ptype", ["socks5", "socks4", "http"])
def test_happy_proxied_http_has_the_build_http_timeout_and_proxy(ptype):
    http = _built_http(ptype)["http"].http
    assert http.timeout == gh.DEFAULT_HTTP_TIMEOUT_SEC
    assert isinstance(http.proxy_info, httplib2.ProxyInfo)
    assert (http.proxy_info.proxy_host, http.proxy_info.proxy_port) == ("203.0.113.7", 1080)


def test_sad_resume_incomplete_308_is_not_followed_as_a_redirect():
    http = _built_http("socks5")["http"].http
    assert 308 not in http.redirect_codes
    assert 301 in http.redirect_codes


def test_edge_without_a_proxy_build_gets_no_http_of_ours():
    captured = _built_http("none", host="")
    assert "http" not in captured
