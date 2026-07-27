#!/usr/bin/env python3
"""``SqliteFsSession`` must honour SQLite's ``:memory:`` magic name.

``sqlite3.connect(":memory:")`` opens a private in-memory database.
``sqlite3.connect("/some/cwd/:memory:")`` opens a FILE literally named
``:memory:``. ``core/sqlite_fs_client.py`` ran every path through
``os.path.abspath`` before connecting, so it always produced the second
form:

* callers who asked for a throwaway in-memory vault silently got a
  persistent on-disk database — the data they expected to evaporate
  stayed on the filesystem, which matters for a tool whose own docs
  pitch this backend for "encrypted-overlay" and credential-adjacent
  storage;
* every run littered the working directory with a file named
  ``:memory:``. The repo carries one (tracked as an artefact in
  ``.gitignore``, which calls the behaviour out as a filed follow-up).

These tests pin the intended contract in both directions: the magic
name stays magic, and every real path is still resolved to an absolute
one.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.sqlite_fs_client import SqliteFsSession  # noqa: E402


@pytest.fixture()
def in_tmp_cwd(tmp_path, monkeypatch):
    """Run with cwd inside tmp_path so a stray ``:memory:`` file is
    both detectable and harmless."""
    monkeypatch.chdir(tmp_path)
    return tmp_path


# --------------------------------------------------------------------------
# Happy path — real paths keep working exactly as before
# --------------------------------------------------------------------------


def test_happy_relative_path_is_resolved_to_absolute(in_tmp_cwd):
    session = SqliteFsSession("vault.sqlite")
    try:
        assert os.path.isabs(session._db_path)
        assert Path(session._db_path) == in_tmp_cwd / "vault.sqlite"
        assert (in_tmp_cwd / "vault.sqlite").exists()
    finally:
        session.close()


def test_happy_absolute_path_round_trips(in_tmp_cwd):
    target = in_tmp_cwd / "sub" / "vault.sqlite"
    target.parent.mkdir()
    session = SqliteFsSession(str(target))
    try:
        assert Path(session._db_path) == target
    finally:
        session.close()


# --------------------------------------------------------------------------
# The regression — ``:memory:`` must not become a file
# --------------------------------------------------------------------------


def test_memory_name_creates_no_file_on_disk(in_tmp_cwd):
    session = SqliteFsSession(":memory:")
    try:
        assert session._db_path == ":memory:"
        assert not (in_tmp_cwd / ":memory:").exists(), (
            "':memory:' was materialised as a real file — abspath() ate "
            "SQLite's magic name"
        )
        # Nothing else may be created either.
        assert list(in_tmp_cwd.iterdir()) == []
    finally:
        session.close()


def test_memory_backend_is_functional(in_tmp_cwd):
    """The in-memory database still has to behave like a backend —
    a fix that merely skips abspath but breaks the schema is no fix."""
    session = SqliteFsSession(":memory:")
    try:
        row = session._conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='axross_files'"
        ).fetchone()
        assert row is not None, "schema was not created on the in-memory db"
    finally:
        session.close()


@pytest.mark.parametrize("url", ["sqlite:///:memory:", "sqlite://:memory:"])
def test_memory_via_sqlite_url_forms(in_tmp_cwd, url):
    """Edge: the profile layer hands URLs, not bare paths. Both URL
    spellings strip down to the same magic name."""
    session = SqliteFsSession(url)
    try:
        assert session._db_path == ":memory:"
        assert not (in_tmp_cwd / ":memory:").exists()
    finally:
        session.close()


def test_memory_name_is_reported_verbatim(in_tmp_cwd):
    """The session label must not advertise a path that does not
    exist — users read this string in the connection UI."""
    session = SqliteFsSession(":memory:")
    try:
        assert session.name == "SQLite: :memory:"
    finally:
        session.close()


# --------------------------------------------------------------------------
# Sad path — an empty path is still rejected
# --------------------------------------------------------------------------


def test_sad_empty_path_still_raises(in_tmp_cwd):
    with pytest.raises(OSError):
        SqliteFsSession("")


def test_sad_empty_sqlite_url_still_raises(in_tmp_cwd):
    with pytest.raises(OSError):
        SqliteFsSession("sqlite:///")
