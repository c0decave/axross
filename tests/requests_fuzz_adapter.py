"""A ``requests`` transport adapter that answers from a script.

Mounted on a ``requests.Session`` (``session.mount("https://", adapter)``)
it stands in for the network under clients and SDKs built on requests -
https URLs included, so no TLS fake server is needed. ``responder(request)``
returns ``(status, headers, body)`` or raises an exception the way the real
adapter would (``requests.ConnectionError``, ``requests.ReadTimeout``).
"""

from __future__ import annotations

import io
from collections.abc import Callable

import requests
from requests.adapters import BaseAdapter
from requests.structures import CaseInsensitiveDict
from urllib3.response import HTTPResponse

Responder = Callable[[requests.PreparedRequest], tuple[int, dict, bytes]]


class ScriptedAdapter(BaseAdapter):
    def __init__(self, responder: Responder) -> None:
        super().__init__()
        self.responder = responder
        self.requests: list[requests.PreparedRequest] = []

    def send(self, request, stream=False, timeout=None, verify=True, cert=None, proxies=None):
        self.requests.append(request)
        status, headers, body = self.responder(request)
        raw = HTTPResponse(
            body=io.BytesIO(body),
            headers=headers,
            status=status,
            preload_content=False,
            decode_content=False,
            request_method=request.method,  # a HEAD answer has no body
        )
        resp = requests.Response()
        resp.status_code = status
        resp.headers = CaseInsensitiveDict(headers)
        resp.raw = raw
        resp.reason = "X"
        resp.url = request.url
        resp.request = request
        resp.encoding = requests.utils.get_encoding_from_headers(resp.headers)
        if not stream:
            resp.content  # noqa: B018 - load the body like the real adapter
        return resp

    def close(self) -> None:
        pass


def mount(session: requests.Session, responder: Responder) -> ScriptedAdapter:
    adapter = ScriptedAdapter(responder)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return adapter
