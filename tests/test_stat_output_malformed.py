"""Malformed ``stat --format`` output is an OSError for Telnet and SCP.

``_parse_stat_gnu`` (telnet_client, shared with scp_client) raised
ValueError for output it could not split or convert ("garbage", a size
"x", an mtime out of datetime's range), and TelnetSession.stat /
ScpSession.stat passed it through to callers that handle OSError (found
by tests/test_fuzz_telnet.py).
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import telnet_client as T  # noqa: E402


def test_happy_gnu_stat_output_parses():
    item = T._parse_stat_gnu("/a.txt|5|1767268800|81a4|u|g|regular file")
    assert (item.name, item.size, item.permissions, item.owner) == ("a.txt", 5, 0o644, "u")


BAD = [
    "garbage",
    "/a|x|1|81a4|u|g|file",
    "/a|5|y|81a4|u|g|file",
    "/a|5|1|zz|u|g|file",
    "/a|5|-99999999999|81a4|u|g|file",
    "/a|5|99999999999999999999|81a4|u|g|file",
    "/a|5|1e9|81a4|u|g|file",
]


@pytest.mark.parametrize("output", BAD)
def test_sad_malformed_output_is_an_oserror(output):
    with pytest.raises(OSError, match="stat output"):
        T._parse_stat_gnu(output)


@pytest.mark.parametrize("backend", ["telnet", "scp"])
def test_edge_backend_stat_reports_oserror(backend):
    if backend == "telnet":
        s = T.TelnetSession.__new__(T.TelnetSession)
        s._caps = T._Capabilities(has_stat_gnu=True)
    else:
        from core import scp_client as SC

        s = SC.SCPSession.__new__(SC.SCPSession)
        s._caps = SC._Capabilities(has_stat_gnu=True)
    s._exec = lambda cmd, timeout=None: "/a|x|y|z|u|g|f"
    with pytest.raises(OSError):
        s.stat("/a")
