"""PostgreSQL / MongoDB URLs keep their TLS parameters.

Both sessions took host, port, user, password and database out of a
``url=`` and dropped the query: ``postgres://...?sslmode=verify-full``
reached libpq without sslmode (libpq's default "prefer" falls back to
plaintext), ``mongodb://...?tls=true`` reached pymongo without tls. The
query parameters are passed on now; an unknown one is an error instead
of being ignored. No network: the driver connect is replaced.
"""

from __future__ import annotations

import pytest


class _Stop(Exception):
    pass


# -- PostgreSQL ----------------------------------------------------------------


@pytest.fixture
def pg(monkeypatch):
    pytest.importorskip("psycopg")
    from core import postgres_fs_client as PG

    captured: dict = {}

    def connect(dsn, **kw):
        captured["dsn"] = dsn
        raise _Stop()

    monkeypatch.setattr(PG.psycopg, "connect", connect)
    return PG, captured


def _pg_params(captured) -> dict:
    from psycopg import conninfo

    return conninfo.conninfo_to_dict(captured["dsn"])


def test_happy_postgres_sslmode_and_rootcert_reach_libpq(pg):
    PG, captured = pg
    with pytest.raises(_Stop):
        PG.PostgresFsSession(
            url="postgres://alice:pw@db.example.test:5432/vault"
            "?sslmode=verify-full&sslrootcert=/etc/ssl/ca.pem",
            port=0,
        )
    params = _pg_params(captured)
    assert params["sslmode"] == "verify-full"
    assert params["sslrootcert"] == "/etc/ssl/ca.pem"
    assert params["host"] == "db.example.test" and params["dbname"] == "vault"


def test_sad_postgres_unknown_url_parameter_is_an_error(pg):
    PG, captured = pg
    with pytest.raises(OSError, match="bogus"):
        PG.PostgresFsSession(url="postgres://alice:pw@db.example.test/vault?bogus=1", port=0)
    assert "dsn" not in captured


def test_edge_postgres_url_without_query_and_hostaddr_with_a_tunnel(pg, monkeypatch):
    PG, captured = pg
    with pytest.raises(_Stop):
        PG.PostgresFsSession(url="postgres://alice:pw@db.example.test/vault", port=0)
    assert "sslmode" not in _pg_params(captured)

    # A query hostaddr would send libpq around the proxy tunnel.
    from core import proxy as proxy_mod

    class _Tunnel:
        host, port = "127.0.0.1", 15432

        def close(self):
            pass

    monkeypatch.setattr(proxy_mod, "open_tunnel", lambda kw, host, port: _Tunnel())
    captured.clear()
    with pytest.raises(OSError, match="hostaddr"):
        PG.PostgresFsSession(
            url="postgres://alice:pw@db.example.test/vault?hostaddr=10.0.0.9", port=0
        )
    assert "dsn" not in captured


# -- MongoDB -------------------------------------------------------------------


@pytest.fixture
def mongo(monkeypatch):
    pytest.importorskip("pymongo")
    from core import mongo_fs_client as MG

    captured: dict = {}

    class _Client:
        def __init__(self, **kw):
            captured["kw"] = kw
            raise _Stop()

    monkeypatch.setattr(MG.pymongo, "MongoClient", _Client)
    return MG, captured


def test_happy_mongo_tls_options_reach_the_driver(mongo):
    MG, captured = mongo
    with pytest.raises(_Stop):
        MG.MongoFsSession(
            url="mongodb://alice:pw@db.example.test:27017/vault?tls=true&authSource=admin",
            host="",
            port=0,
        )
    kw = captured["kw"]
    assert kw["tls"] is True
    assert kw["authSource"] == "admin"
    assert kw["host"] == "db.example.test" and kw["username"] == "alice"


def test_sad_mongo_unknown_or_bad_option_is_an_error(mongo):
    MG, captured = mongo
    for query in ("bogus=1", "tls=maybe"):
        with pytest.raises(OSError):
            MG.MongoFsSession(url=f"mongodb://db.example.test/vault?{query}", port=0)
    assert "kw" not in captured


def test_edge_mongo_tunnel_keeps_direct_connection_and_tls(mongo, monkeypatch):
    MG, captured = mongo
    from core import proxy as proxy_mod

    class _Tunnel:
        host, port = "127.0.0.1", 27018

        def close(self):
            pass

    monkeypatch.setattr(proxy_mod, "open_tunnel", lambda kw, host, port: _Tunnel())
    with pytest.raises(_Stop):
        MG.MongoFsSession(
            url="mongodb://db.example.test/vault?tls=true&directConnection=false", port=0
        )
    kw = captured["kw"]
    assert kw["host"] == "127.0.0.1" and kw["port"] == 27018
    assert kw["directConnection"] is True
    assert kw["tls"] is True
