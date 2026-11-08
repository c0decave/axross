"""``axross --mcp-http HOST:PORT`` alone starts the HTTP server (review 1
of 0.15.176).

Before: SPEC.md lists ``axross --mcp-http HOST:PORT`` as an operating
mode, but main.py entered the MCP path only on ``--mcp-list-tools``,
``--mcp-server`` or ``AXROSS_MCP=1``. ``--mcp-http`` was parsed and then
ignored: the GUI came up, no server, no warning, exit 0 - and from a
terminal the start even detached into the background like a GUI start.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import main as axross_main  # noqa: E402


def _main(*argv):
    from tests.test_mcp_write_root import _main_in_process

    # Reaching the GUI path is the bug: it must fail loudly, not open a window.
    with mock.patch.object(axross_main, "_gui_smoke_ms",
                           side_effect=AssertionError("the GUI path was taken")):
        return _main_in_process(*argv)


def test_happy_mcp_http_alone_serves_http():
    code, err, serve, serve_http = _main("--mcp-http", "127.0.0.1:7331", "--foreground")
    assert code == 0, err
    serve.assert_not_called()
    config = serve_http.call_args.args[0]
    assert (config.host, config.port) == ("127.0.0.1", 7331)
    assert config.allow_write is False


def test_sad_mcp_http_alone_keeps_its_refusals():
    code, err, _serve, serve_http = _main("--mcp-http", "0.0.0.0:7331")
    assert code == 2 and "non-loopback" in err
    serve_http.assert_not_called()


def test_edge_mcp_http_does_not_detach_from_the_terminal():
    args = argparse.Namespace(foreground=False, debug=False, verbose=False, script=None,
                              mcp_server=False, mcp_list_tools=False,
                              mcp_http="127.0.0.1:7331")

    class Tty:
        def isatty(self):
            return True

    assert axross_main.should_detach(args, {"DISPLAY": ":0"}, (Tty(), Tty()),
                                     platform="posix", system="linux") is False
