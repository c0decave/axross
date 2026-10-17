"""Opening a PostgreSQL vault: readers get in, errors are OSErrors.

Measured against PostgreSQL 18.4 in a disposable container: a role with
only SELECT on an existing ``axross_files`` table could not connect -
the constructor always ran ``CREATE TABLE IF NOT EXISTS``, and PostgreSQL
checks the schema's CREATE privilege before it looks for the table
("permission denied for schema public"). Against the public RNAcentral
database (no axross table, no CREATE) the same raw
``psycopg.errors.InsufficientPrivilege`` left the constructor, and a
wrong password a raw ``psycopg.OperationalError`` - not the OSError that
open_url documents. Now the schema is only created when the table is
missing, and driver errors at open time are OSErrors that say why.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

psycopg = pytest.importorskip("psycopg")

from core import postgres_fs_client as P  # noqa: E402


class _Cursor:
    def __init__(self, conn):
        self.conn = conn
        self._row = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.conn.sql.append(
            sql.strip().split()[0].upper() + (" regclass" if "to_regclass" in sql else "")
        )
        if "to_regclass" in sql:
            self._row = ("axross_files" if self.conn.table_exists else None,)
            return
        if sql.strip().upper().startswith("CREATE") and not self.conn.may_create:
            raise psycopg.errors.InsufficientPrivilege("permission denied for schema public")

    def fetchone(self):
        return self._row


class _Conn:
    def __init__(self, table_exists: bool, may_create: bool):
        self.table_exists = table_exists
        self.may_create = may_create
        self.sql: list[str] = []
        self.closed = False

    def cursor(self):
        return _Cursor(self)

    def close(self):
        self.closed = True


@pytest.fixture
def connect(monkeypatch):
    made = []

    def run(table_exists=True, may_create=True, fail=None):
        def fake_connect(dsn, autocommit=True):
            if fail is not None:
                raise fail
            made.append(_Conn(table_exists, may_create))
            return made[-1]

        monkeypatch.setattr(P.psycopg, "connect", fake_connect)
        return P.PostgresFsSession(url="postgres://reader:pw@db.lab:5432/vault"), made

    run.made = made
    return run


# --- happy ----------------------------------------------------------------


def test_happy_a_reader_opens_an_existing_vault(connect):
    session, made = connect(table_exists=True, may_create=False)
    assert "CREATE" not in made[0].sql
    assert session.name.startswith("PostgreSQL:")


def test_happy_a_new_vault_is_created_where_allowed(connect):
    _, made = connect(table_exists=False, may_create=True)
    assert "CREATE" in made[0].sql


# --- sad ------------------------------------------------------------------


def test_sad_no_table_and_no_create_right_is_a_permission_error(connect):
    with pytest.raises(PermissionError, match="axross_files"):
        connect(table_exists=False, may_create=False)


def test_sad_a_failed_login_is_an_oserror(connect):
    with pytest.raises(OSError, match="password authentication failed"):
        connect(fail=psycopg.OperationalError("FATAL:  password authentication failed for user"))


# --- edge -----------------------------------------------------------------


def test_edge_the_connection_is_closed_when_opening_fails(connect):
    with pytest.raises(PermissionError):
        connect(table_exists=False, may_create=False)
    assert connect.made and connect.made[0].closed


def test_edge_the_driver_error_is_kept_as_the_cause(connect):
    with pytest.raises(OSError) as info:
        connect(fail=psycopg.OperationalError("connection refused"))
    assert isinstance(info.value.__cause__, psycopg.Error)
