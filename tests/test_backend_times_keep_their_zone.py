"""Timestamps that broke FileItem's rule "a naive datetime is local time".

* Telnet listings handed out the server's ``ls`` wall clock as a naive
  time: for a server in another zone every mtime was off by the
  difference. ls runs under ``TZ=UTC0`` now and the parser returns aware
  UTC times.
* WMI dropped the DMTF offset (``...+060`` is UTC+1).
* NNTP: a ``-0000`` date came back naive although it is UTC.
* WMI raised ValueError for a path it cannot take; callers of a backend
  handle OSError (the error is both now).
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))


@pytest.fixture
def berlin_client():
    old = os.environ.get("TZ")
    os.environ["TZ"] = "Europe/Berlin"
    time.tzset()
    yield
    if old is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = old
    time.tzset()


def test_sad_telnet_listing_time_is_not_the_servers_wall_clock(tmp_path, berlin_client) -> None:
    """Client in Berlin, server shell in New York."""
    from core.telnet_client import TelnetSession, _Capabilities

    f = tmp_path / "f.txt"
    f.write_text("x")
    stamp = time.time() - 86400
    os.utime(f, (stamp, stamp))

    class NewYorkShell:
        def execute(self, cmd, timeout=30):
            env = {**os.environ, "TZ": "America/New_York", "LC_ALL": "C"}
            p = subprocess.run(["sh", "-c", cmd + " 2>&1"], capture_output=True, text=True, env=env)
            return p.stdout, p.returncode

        def execute_checked(self, cmd, timeout=30):
            out, code = self.execute(cmd, timeout)
            assert code == 0, out
            return out

    s = object.__new__(TelnetSession)
    s._shell = NewYorkShell()
    s._caps = _Capabilities()
    s._connected = True
    s._ensure_connected = lambda: s._shell
    item = next(i for i in s.list_dir(str(tmp_path)) if i.name == "f.txt")
    expected = datetime.fromtimestamp(stamp).replace(second=0, microsecond=0)
    assert item.modified == expected


def test_edge_ls_date_parser_in_utc_mode() -> None:
    from core.telnet_client import _parse_ls_date

    assert _parse_ls_date("Mar 16  2025", utc=True) == datetime(2025, 3, 16, tzinfo=timezone.utc)
    recent = _parse_ls_date("Jan  1 10:00", utc=True)
    assert recent.tzinfo is timezone.utc and recent <= datetime.now(timezone.utc)
    assert _parse_ls_date("junk", utc=True) == datetime.fromtimestamp(0, timezone.utc)


def test_sad_wmi_dmtf_offset_is_kept() -> None:
    from core.wmi_client import _parse_dmtf

    dt = _parse_dmtf("20240101120000.000000+060")
    assert dt == datetime(2024, 1, 1, 11, 0, tzinfo=timezone.utc)
    assert _parse_dmtf("20240101120000.250000-300") == datetime(
        2024, 1, 1, 17, 0, 0, 250000, tzinfo=timezone.utc
    )
    assert _parse_dmtf("20240101120000.000000+000").utcoffset() == timedelta(0)
    assert _parse_dmtf("garbage") == datetime.fromtimestamp(0)


def test_sad_nntp_minus_zero_date_is_utc() -> None:
    from core.nntp_lib import parse_overview_date

    dt = parse_overview_date("Thu, 1 Jan 2026 10:00:00 -0000")
    assert dt.tzinfo is not None
    assert dt == datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc)


def test_sad_wmi_unusable_path_is_an_oserror() -> None:
    from core import wmi_client as W

    s = object.__new__(W.WMISession)
    s._connect = lambda: object()
    s._exec_query = lambda wbem, q, strict=False: []
    for call in (
        lambda: s.exists(""),
        lambda: s.is_dir("\\\\srv\\share"),
        lambda: s.exists("C:\\a\x01b"),
        lambda: s.stat("relative\\x"),
    ):
        with pytest.raises(OSError):
            call()
    with pytest.raises(ValueError):  # still a ValueError for old callers
        W._split_wmi("")
