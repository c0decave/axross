"""A loopback Azure Storage endpoint that speaks just enough of the Blob and
File REST APIs to connect: Get Container / Share Properties and the first
page of List Blobs / List Directories and Files.

The azure-storage SDKs talk to it as to Azure (a connection string with
``BlobEndpoint=`` / ``FileEndpoint=`` pointing here), so a test sees what
the SDK makes of a real answer - status, ``x-ms-error-code`` header and
XML error body - instead of a stand-in object. ``answers`` decides per
operation: ``{"container_props": (403, "AuthorizationPermissionMismatch")}``
makes Get Container Properties fail the way Azure answers a
container-scoped SAS. ``requests`` records (method, path, query) of every
call.

Operations (the query decides): ``container_props`` (restype=container),
``container_list`` (restype=container&comp=list), ``share_props``
(restype=share), ``dir_list`` (restype=directory&comp=list).
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

ACCOUNT = "devstoreaccount1"
#: Azurite's well-known development key (public, not a secret).
KEY = "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/K1SZFPTOtr/KBHBeksoGMGw=="
SAS = "sv=2021-06-08&ss=b&srt=co&sp=rl&se=2099-01-01T00:00:00Z&sig=Zm9v"

_MESSAGES = {
    "AuthorizationPermissionMismatch": "This request is not authorized to perform this "
                                       "operation using this permission.",
    "AuthorizationResourceTypeMismatch": "This request is not authorized to perform this "
                                         "operation using this resource type.",
    "AuthenticationFailed": "Server failed to authenticate the request. Make sure the value "
                            "of Authorization header is formed correctly including the signature.",
    "AuthorizationFailure": "This request is not authorized to perform this operation.",
    "ContainerNotFound": "The specified container does not exist.",
    "ShareNotFound": "The specified share does not exist.",
}


def _operation(query: dict) -> str:
    restype = query.get("restype", [""])[0]
    comp = query.get("comp", [""])[0]
    if restype == "container":
        return "container_list" if comp == "list" else "container_props"
    if restype == "share":
        return "share_props"
    if restype == "directory" and comp == "list":
        return "dir_list"
    return "other"


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *_args) -> None:  # quiet
        pass

    def _send(self, status: int, body: bytes = b"", headers: dict | None = None) -> None:
        self.send_response(status)
        for name, value in (headers or {}).items():
            self.send_header(name, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("x-ms-request-id", "00000000-0000-0000-0000-000000000000")
        self.send_header("x-ms-version", "2021-06-08")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def setup(self) -> None:
        super().setup()
        self.server.owner.connections.add(self.connection)  # type: ignore[attr-defined]

    def _answer(self) -> None:
        parts = urlsplit(self.path)
        query = parse_qs(parts.query)
        op = _operation(query)
        server: FakeAzureStorage = self.server.owner  # type: ignore[attr-defined]
        server.requests.append((self.command, parts.path, op))
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        status, code = server.answers.get(op, (200, ""))
        if status >= 400:
            message = _MESSAGES.get(code, code)
            body = (f'<?xml version="1.0" encoding="utf-8"?><Error><Code>{code}</Code>'
                    f"<Message>{message}</Message></Error>").encode()
            self._send(status, body, {"Content-Type": "application/xml", "x-ms-error-code": code})
            return
        segments = [s for s in parts.path.split("/") if s]
        name = segments[1] if len(segments) > 1 else ""
        endpoint = f"http://127.0.0.1:{server.port}/{ACCOUNT}/"
        common = {"ETag": '"0x8D0000000000000"', "Last-Modified": "Mon, 02 Jan 2024 00:00:00 GMT"}
        if op in ("container_props", "share_props"):
            self._send(200, b"", common)
        elif op == "container_list":
            body = (f'<?xml version="1.0" encoding="utf-8"?><EnumerationResults '
                    f'ServiceEndpoint="{endpoint}" ContainerName="{name}"><Blobs></Blobs>'
                    f"<NextMarker /></EnumerationResults>").encode()
            self._send(200, body, {"Content-Type": "application/xml"})
        elif op == "dir_list":
            body = (f'<?xml version="1.0" encoding="utf-8"?><EnumerationResults '
                    f'ServiceEndpoint="{endpoint}" ShareName="{name}" DirectoryPath="">'
                    f"<Entries></Entries><NextMarker /></EnumerationResults>").encode()
            self._send(200, body, {"Content-Type": "application/xml"})
        else:
            self._send(400, b"", {"x-ms-error-code": "UnsupportedHttpVerb"})

    do_GET = do_HEAD = do_PUT = do_DELETE = _answer


class FakeAzureStorage:
    """Blob + File endpoints of one account on 127.0.0.1 (one port)."""

    def __init__(self, answers: dict | None = None) -> None:
        self.answers: dict[str, tuple[int, str]] = dict(answers or {})
        self.requests: list[tuple[str, str, str]] = []
        self.connections: set = set()
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._httpd.owner = self  # type: ignore[attr-defined]
        self._httpd.daemon_threads = True
        self.port = self._httpd.server_address[1]
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    @property
    def endpoint(self) -> str:
        return f"http://127.0.0.1:{self.port}/{ACCOUNT}"

    def key_connection_string(self, service: str = "Blob") -> str:
        return (f"DefaultEndpointsProtocol=http;AccountName={ACCOUNT};AccountKey={KEY};"
                f"{service}Endpoint={self.endpoint};")

    def sas_connection_string(self, service: str = "Blob") -> str:
        return f"{service}Endpoint={self.endpoint};SharedAccessSignature={SAS}"

    def close(self) -> None:
        """Stop listening and cut the open (keep-alive) connections: a
        server that went away, not one that stopped taking new clients."""
        import socket

        self._httpd.shutdown()
        self._httpd.server_close()
        for connection in list(self.connections):
            try:
                connection.shutdown(socket.SHUT_RDWR)
                connection.close()
            except OSError:
                pass
