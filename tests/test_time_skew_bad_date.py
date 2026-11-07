"""The HTTP clock check says OSError for a Date header it cannot read.

Found in review (2026-11-02, the same kind of bug as the NNTP date fix of
0.14.197): core.net_helpers.time_skew parsed the server's Date header
without a guard - a garbled date raised ValueError, one past a C int
OverflowError, though the function documents OSError for every answer
it cannot use.
"""

from __future__ import annotations

import http.server
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
pytest.importorskip("requests", reason="requests not installed")


def _server(date: str):
    class Handler(http.server.BaseHTTPRequestHandler):
        def date_time_string(self, timestamp=None):  # noqa: ARG002 - the header sent
            return date

        def do_HEAD(self):  # noqa: N802 - http.server's name
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server


@pytest.mark.parametrize("date", ["not a date at all", "Thu, 1 Jan 2026 4294967296:00:00 GMT",
                                  "Thu, 1 Jan 99999999999 10:00:00 GMT"])
def test_sad_an_unreadable_date_header_is_an_oserror(date):
    from core.net_helpers import time_skew

    server = _server(date)
    try:
        with pytest.raises(OSError, match="unreadable Date"):
            time_skew("127.0.0.1", source="http", port=server.server_address[1], timeout=5.0)
    finally:
        server.shutdown()


def test_happy_a_good_date_gives_the_skew():
    from email.utils import formatdate

    from core.net_helpers import time_skew

    server = _server(formatdate(usegmt=True))
    try:
        skew = time_skew("127.0.0.1", source="http", port=server.server_address[1], timeout=5.0)
        assert skew.source == "http" and abs(skew.offset_seconds) < 5
    finally:
        server.shutdown()
