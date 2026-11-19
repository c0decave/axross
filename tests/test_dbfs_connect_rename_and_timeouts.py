"""SQLite, PostgreSQL, Redis and MongoDB as file systems: connecting,
a dropped connection, and renaming a folder.

Before:

* a folder rename was one autocommitted insert / delete after the other:
  a failure half way left the folder split between the old and the new
  name, and every renamed entry got "now" as its modification time;
* a remove (and a rename) loaded every child's file body only to see
  whether the folder was empty;
* SQLite: a path that is no database, or a folder that does not exist,
  raised sqlite3's own error without the path (no OSError) and leaked
  the connection; ``connected`` stayed True after close();
* PostgreSQL: no connect time-out - a server that takes the connection
  and never answers held the connect for ever; once the server dropped
  the connection ``connected`` still said True (psycopg does not
  reconnect), so the connection manager handed the dead session out;
* Redis: no time-outs at all (redis-py waits for ever); a refused
  connection was redis' own ConnectionError, no OSError;
* MongoDB: a refused server took 30 s and its error (no OSError) carried
  the whole topology description; a mode another client stored as text
  raised a bare ValueError on save.
"""

from __future__ import annotations

import errno
import socket
import sqlite3
import sys
import threading
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.sqlite_fs_client import SqliteFsSession  # noqa: E402
from core.user_errors import describe  # noqa: E402


def _put(s, path, data=b"x"):
    with s.open_write(path) as fh:
        fh.write(data)


# ------------------------------------------------------------ rename / remove


def test_sad_a_folder_rename_that_fails_half_way_changes_nothing(tmp_path):
    s = SqliteFsSession(str(tmp_path / "v.sqlite"))
    s.mkdir("/src")
    for n in range(5):
        _put(s, f"/src/f{n}")
    real = s._db_insert
    calls = [0]

    def flaky(row):
        calls[0] += 1
        if calls[0] == 4:
            raise sqlite3.OperationalError("disk I/O error (simulated)")
        return real(row)

    s._db_insert = flaky
    with pytest.raises(OSError):
        s.rename("/src", "/dst")
    s._db_insert = real
    assert sorted(i.name for i in s.list_dir("/src")) == [f"f{n}" for n in range(5)]
    assert not s.exists("/dst")
    # And the session goes on working.
    s.rename("/src", "/dst")
    assert sorted(i.name for i in s.list_dir("/dst")) == [f"f{n}" for n in range(5)]


def test_happy_a_rename_keeps_the_modification_time(tmp_path):
    s = SqliteFsSession(str(tmp_path / "v.sqlite"))
    s.mkdir("/m")
    _put(s, "/m/a.txt")
    before = s.stat("/m/a.txt").modified
    time.sleep(1.1)
    s.rename("/m", "/n")
    assert s.stat("/n/a.txt").modified == before


def test_edge_a_remove_reads_no_file_bodies(tmp_path):
    s = SqliteFsSession(str(tmp_path / "v.sqlite"))
    s.mkdir("/big")
    _put(s, "/big/f", b"\0" * 1024)
    with mock.patch.object(type(s), "_db_list", side_effect=AssertionError("bodies read")):
        with pytest.raises(OSError) as info:
            s.remove("/big")
        assert info.value.errno == errno.ENOTEMPTY
        s.remove("/big", recursive=True)
    assert not s.exists("/big")


# ------------------------------------------------------------ SQLite open


@pytest.mark.parametrize("kind", ["not-a-database", "missing-folder", "a-folder"])
def test_sad_a_path_sqlite_cannot_open_is_an_oserror_with_the_path(tmp_path, kind):
    if kind == "not-a-database":
        path = tmp_path / "notes.txt"
        path.write_bytes(b"this is text, not SQLite\n" * 100)
    elif kind == "missing-folder":
        path = tmp_path / "no" / "such" / "x.sqlite"
    else:
        path = tmp_path
    with pytest.raises(OSError) as info:
        SqliteFsSession(str(path))
    assert str(path) in describe(info.value) or info.value.filename == str(path)


def test_sad_sqlite_is_not_connected_after_close(tmp_path):
    s = SqliteFsSession(str(tmp_path / "v.sqlite"))
    assert s.connected
    s.close()
    assert not s.connected


# ------------------------------------------------------------ PostgreSQL


def test_happy_postgres_connects_with_a_time_out_and_notices_a_dropped_link():
    psycopg = pytest.importorskip("psycopg")
    from core import postgres_fs_client as PG

    dsns: list[str] = []

    class Conn:
        closed = False
        broken = False

        def cursor(self):
            conn = self

            class Cur:
                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

                def execute(self, *a, **k):
                    if conn.closed:
                        raise psycopg.OperationalError("the connection is closed")

                def fetchone(self):
                    return ("axross_files",)

                def fetchall(self):
                    return []

            return Cur()

        def close(self):
            self.closed = True

    conn = Conn()

    def connect(dsn, **kw):
        dsns.append(dsn)
        return conn

    with mock.patch.object(PG.psycopg, "connect", side_effect=connect):
        s = PG.PostgresFsSession(host="db.example", username="u", database="files")
    assert f"connect_timeout='{PG.PG_CONNECT_TIMEOUT}'" in dsns[0]
    assert s.connected
    conn.closed = True  # the server went away
    assert not s.connected


def test_happy_a_postgres_url_keeps_its_own_connect_timeout():
    pytest.importorskip("psycopg")
    from core import postgres_fs_client as PG

    dsns: list[str] = []

    def connect(dsn, **kw):
        dsns.append(dsn)
        raise PG.psycopg.OperationalError("stop here")

    with mock.patch.object(PG.psycopg, "connect", side_effect=connect):
        with pytest.raises(OSError):
            PG.PostgresFsSession(url="postgresql://u@db.example/files?connect_timeout=3")
    assert "connect_timeout='3'" in dsns[0] and f"connect_timeout='{PG.PG_CONNECT_TIMEOUT}'" \
        not in dsns[0]


# ------------------------------------------------------------ Redis / MongoDB


@pytest.fixture
def silent_port():
    """A port that takes connections and never answers."""
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(5)
    held: list = []
    threading.Thread(target=lambda: [held.append(srv.accept()) for _ in range(5)],
                     daemon=True).start()
    yield srv.getsockname()[1]
    srv.close()


def _closed_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def test_sad_a_silent_redis_server_fails_in_time(silent_port, monkeypatch):
    pytest.importorskip("redis")
    from core import redis_fs_client as R

    monkeypatch.setitem(R._REDIS_TIMEOUTS, "socket_timeout", 1)
    monkeypatch.setitem(R._REDIS_TIMEOUTS, "socket_connect_timeout", 1)
    started = time.monotonic()
    with pytest.raises(OSError):
        R.RedisFsSession(host="127.0.0.1", port=silent_port)
    assert time.monotonic() - started < 10


def test_sad_a_refused_redis_connect_is_an_oserror():
    pytest.importorskip("redis")
    from core import redis_fs_client as R

    with pytest.raises(OSError) as info:
        R.RedisFsSession(host="127.0.0.1", port=_closed_port())
    assert "refused the connection" in describe(info.value)


def test_sad_a_refused_mongodb_is_an_oserror_in_seconds(monkeypatch):
    pytest.importorskip("pymongo")
    from core import mongo_fs_client as M

    monkeypatch.setitem(M._MONGO_TIMEOUTS, "serverSelectionTimeoutMS", 500)
    started = time.monotonic()
    with pytest.raises(OSError) as info:
        M.MongoFsSession(host="127.0.0.1", port=_closed_port())
    assert time.monotonic() - started < 10
    assert "Topology Description" not in describe(info.value)


def test_happy_a_mongodb_url_keeps_its_own_time_outs(monkeypatch):
    pytest.importorskip("pymongo")
    from core import mongo_fs_client as M

    seen: dict = {}

    def client(**kw):
        seen.update(kw)
        raise M.pymongo.errors.ServerSelectionTimeoutError("no server")

    monkeypatch.setattr(M.pymongo, "MongoClient", client)
    with pytest.raises(OSError):
        M.MongoFsSession(url="mongodb://127.0.0.1:1/db?serverSelectionTimeoutMS=1234")
    assert [k for k in seen if k.lower() == "serverselectiontimeoutms"] == [
        next(k for k in seen if k.lower() == "serverselectiontimeoutms")]
    assert 1234 in [v for k, v in seen.items() if k.lower() == "serverselectiontimeoutms"] or \
        1.234 in [v for k, v in seen.items() if k.lower() == "serverselectiontimeoutms"]
