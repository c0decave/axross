"""SMB: smbprotocol failures beyond SMBOSError, and edge FILETIMEs, are OSError.

SmbSession caught ``(OSError, SMBOSError)`` only. smbprotocol raises
SMBException (not an OSError) for a message whose signature does not
verify and for a closed connection, and its message worker stores any
exception from parsing a server message - KeyError for an unknown message
id, struct.error / ValueError for a short or malformed one - and raises
it in the caller (smbprotocol/connection.py _process_message_thread,
_check_worker_running). And a file written "9999-12-31 23:59:59 UTC"
listed east of UTC raised ValueError from datetime.fromtimestamp
(SmbSession._modified): local time is in year 10000.
"""

from __future__ import annotations

import os
import struct
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("smbprotocol")
from smb_fake_client import (  # noqa: E402
    DirEntry,
    FakeSmbClient,
    StatResult,
    make_session,
    smb_info,
)
from smbprotocol.exceptions import SMBConnectionClosed, SMBException  # noqa: E402

from core import smb_client  # noqa: E402


@pytest.fixture
def smb(monkeypatch):
    fake = FakeSmbClient()
    monkeypatch.setattr(smb_client, "smbclient", fake)
    return fake, make_session(fake)


@pytest.fixture
def east_of_utc():
    old = os.environ.get("TZ")
    os.environ["TZ"] = "Europe/Berlin"
    time.tzset()
    try:
        yield
    finally:
        if old is None:
            os.environ.pop("TZ", None)
        else:
            os.environ["TZ"] = old
        time.tzset()


def test_happy_listing(smb):
    _fake, s = smb
    assert sorted((i.name, i.is_dir) for i in s.list_dir("/")) == [("a.txt", False), ("sub", True)]


@pytest.mark.parametrize(
    "exc",
    [
        SMBException("Server message signature could not be verified"),
        SMBConnectionClosed("SMB socket was closed"),
        KeyError(17),
        struct.error("unpack requires a buffer of 4 bytes"),
        ValueError("bad length"),
    ],
    ids=["signature", "closed", "unknown-message-id", "short-message", "bad-value"],
)
@pytest.mark.parametrize("op", ["list_dir", "stat", "mkdir", "remove", "rename", "open_read"])
def test_sad_library_failure_is_an_oserror(smb, exc, op):
    fake, s = smb
    fake.fail = exc
    call = {
        "list_dir": lambda: s.list_dir("/"),
        "stat": lambda: s.stat("/a.txt"),
        "mkdir": lambda: s.mkdir("/new"),
        "remove": lambda: s.remove("/a.txt"),
        "rename": lambda: s.rename("/a.txt", "/b.txt"),
        "open_read": lambda: s.open_read("/a.txt"),
    }[op]
    with pytest.raises(OSError):
        call()


def test_edge_is_dir_and_exists_report_a_library_failure(smb):
    """A closed connection says nothing about the path: "no" would be
    the no-clobber check's go-ahead to write (see
    tests/test_smb_exists_only_not_found_is_false.py)."""
    fake, s = smb
    fake.fail = SMBException("closed")
    with pytest.raises(OSError):
        s.is_dir("/sub")
    with pytest.raises(OSError):
        s.exists("/a.txt")


@pytest.mark.parametrize(
    "written",
    [
        datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc),
        datetime(1601, 1, 1, tzinfo=timezone.utc),
    ],
    ids=["year-9999", "year-1601"],
)
def test_edge_filetime_at_the_range_edges_lists(smb, east_of_utc, written):
    fake, s = smb
    fake.entries = [DirEntry("edge.txt", smb_info(written=written))]
    [item] = s.list_dir("/")
    assert item.name == "edge.txt"
    assert isinstance(item.modified, datetime)


def test_edge_stat_with_an_out_of_range_mtime(smb, east_of_utc):
    fake, s = smb
    end_of_time = datetime(9999, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
    fake.stat_value = StatResult(0o100644, 5, int(end_of_time.timestamp()) * 1_000_000_000)
    assert s.stat("/a.txt").size == 5
