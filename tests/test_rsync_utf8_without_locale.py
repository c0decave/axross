"""rsync lists UTF-8 names also when axross runs without a locale.

Proof run (environment cleared with env -i, as a service, a container
or an MCP server started by a client may run): the lab write matrix
listed "Grüße ü 名前 space.txt" as "Gr\\#303\\#274\\#303\\#237e ..." and
stat() could not find it. The rsync client escapes every high-bit byte
that the current locale cannot print, and the child environment carried
no locale (only LANG and LC_ALL are forwarded, and neither was set).
rsync now runs with --8-bit-output and its output is read as UTF-8,
whatever the caller's locale. Against a real ``rsync --daemon``.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests.test_rsync_remove_folder import rsyncd  # noqa: E402,F401 - the daemon fixture

pytestmark = pytest.mark.skipif(not shutil.which("rsync"), reason="rsync binary not installed")

NAME = "Grüße ü 名前 space.txt"


@pytest.fixture
def no_locale(monkeypatch):
    for var in ("LANG", "LC_ALL", "LC_CTYPE", "LANGUAGE"):
        monkeypatch.delenv(var, raising=False)


# --- happy ----------------------------------------------------------------


def test_happy_a_utf8_name_lists_as_it_is(rsyncd, no_locale):  # noqa: F811
    session, data = rsyncd
    (data / NAME).write_bytes(b"hello")
    assert NAME in [i.name for i in session.list_dir("/")]


def test_happy_stat_and_read_find_it(rsyncd, no_locale):  # noqa: F811
    session, data = rsyncd
    (data / NAME).write_bytes(b"hello")
    assert session.stat("/" + NAME).size == 5
    with session.open_read("/" + NAME) as fh:
        assert fh.read() == b"hello"


# --- sad ------------------------------------------------------------------


def test_sad_a_missing_utf8_name_is_still_missing(rsyncd, no_locale):  # noqa: F811
    session, _ = rsyncd
    with pytest.raises(OSError):
        session.stat("/Nicht da ü.txt")


# --- edge -----------------------------------------------------------------


def test_edge_an_ascii_name_with_a_backslash_hash_stays_literal(rsyncd, no_locale):  # noqa: F811
    session, data = rsyncd
    (data / "a#b c.txt").write_text("x")
    assert "a#b c.txt" in [i.name for i in session.list_dir("/")]


def test_edge_a_utf8_locale_lists_the_same(rsyncd, monkeypatch):  # noqa: F811
    monkeypatch.setenv("LANG", "C.UTF-8")
    session, data = rsyncd
    (data / NAME).write_bytes(b"hello")
    assert NAME in [i.name for i in session.list_dir("/")]
