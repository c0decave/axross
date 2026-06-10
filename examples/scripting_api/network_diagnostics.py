"""Network diagnostic helper examples.

The ``run()`` smoke starts a local HTTP server so it does not depend
on the internet. Docker-only diagnostics live in
``docker_protocol_smoke.py``.
"""

from __future__ import annotations

import contextlib
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

COVERS = (
    "dns_resolve",
    "dns_records",
    "dns_reverse",
    "port_open",
    "port_scan",
    "subnet_hosts",
    "ping",
    "PingResult",
    "mac_lookup",
    "OuiInfo",
    "whois",
    "WhoisInfo",
    "time_skew",
    "TimeSkew",
    "tcp_banner",
    "tls_cert",
    "TlsCert",
    "ssh_hostkey",
    "SshHostKey",
    "http_probe",
    "HttpProbe",
    "snmp_get",
    "snmp_walk",
    "snmp_set",
    "SnmpVar",
)


class _Handler(BaseHTTPRequestHandler):
    server_version = "AxrossExample/1"

    def do_HEAD(self) -> None:  # noqa: N802 - stdlib callback name
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802 - stdlib callback name
        body = b"hello from axross example\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _fmt: str, *_args) -> None:
        return


@contextlib.contextmanager
def _http_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[0], int(server.server_address[1])
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)


def tls_certificate_example(host: str = "example.com", port: int = 443):
    """Inspect a TLS certificate when the caller permits network IO."""
    import axross

    return axross.tls_cert(host, port, verify=False)


def ssh_hostkey_example(host: str = "10.99.0.10", port: int = 22):
    """Inspect an SSH host key. The default target is the Docker lab."""
    import axross

    return axross.ssh_hostkey(host, port)


def run() -> dict:
    """Run diagnostics that are safe on a developer laptop."""
    import axross

    optional: dict[str, str] = {}
    with _http_server() as (host, port):
        assert axross.port_open(host, port, timeout=1.0)
        scan = axross.port_scan(host, [port, port + 1], timeout=0.2)
        pings = axross.ping(host, port=port, timeout=1.0, count=2)
        banner = axross.tcp_banner(
            host,
            port,
            send=b"HEAD / HTTP/1.0\r\nHost: localhost\r\n\r\n",
            timeout=1.0,
        )
        probe = axross.http_probe(f"http://{host}:{port}/", timeout=2.0)
        skew = axross.time_skew(host, source="http", port=port, timeout=2.0)

        assert port in scan
        assert all(p.reachable for p in pings)
        assert banner.startswith(b"HTTP/")
        assert probe.status == 200
        assert skew.source == "http"

    assert "127.0.0.1" in axross.subnet_hosts("127.0.0.0/30")
    assert axross.dns_resolve("localhost")

    try:
        optional["dns_records"] = ",".join(axross.dns_records("localhost", "A"))
    except OSError as exc:
        optional["dns_records"] = f"skipped: {exc}"

    try:
        optional["dns_reverse"] = ",".join(axross.dns_reverse("127.0.0.1"))
    except OSError as exc:
        optional["dns_reverse"] = f"skipped: {exc}"

    try:
        oui = axross.mac_lookup("00:00:5E:00:53:01")
        optional["mac_lookup"] = oui.oui
    except OSError as exc:
        optional["mac_lookup"] = f"skipped: {exc}"

    try:
        info = axross.whois("127.0.0.1", timeout=2.0)
        optional["whois"] = info.kind
    except (OSError, NotImplementedError) as exc:
        optional["whois"] = f"skipped: {exc}"

    return {
        "http_status": probe.status,
        "ping_samples": len(pings),
        "banner_prefix": banner[:12].decode("ascii", errors="replace"),
        "optional": optional,
    }


if __name__ == "__main__":
    print(run())
