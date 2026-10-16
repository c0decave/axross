"""Fuzz: the DB-FS backends (Redis, MongoDB, PostgreSQL) against hostile stores.

The tree lives in a database any other client can write, so every field
is untrusted. Random rows / Redis hashes / Mongo documents with fields of
every type (missing, None, bytes, invalid UTF-8, negative, huge, NaN,
nested) go through the shared DbFsBackend and the Redis and Mongo
adapters, together with each driver's own errors. Every call returns sane
data or raises OSError.
"""

from __future__ import annotations

import random
import sys
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import check_contract, iterations  # noqa: E402
from test_dbfs_hostile_rows import (  # noqa: E402
    DriverError,
    ScriptedDb,
    _gridout,
    _mongo_session,
    _redis_session,
    _RedisFake,
)

VALUES = [
    None,
    True,
    0,
    -1,
    5,
    2**70,
    1.5,
    float("nan"),
    "",
    "abc",
    "0o755",
    "0o9",
    "420",
    "/",
    "/a",
    "/a/b",
    "/../x",
    b"",
    b"\xff\xfe",
    b"420",
    [],
    {"a": 1},
    datetime(2024, 1, 2),
    datetime(9999, 12, 31, tzinfo=timezone.utc),
]
KEYS = ["path", "parent", "is_dir", "mode", "mtime", "size", "content"]


def _check_items(result) -> None:
    for item in result if isinstance(result, list) else [result]:
        if hasattr(item, "name"):
            assert isinstance(item.name, str) and item.name
            assert isinstance(item.size, int) and item.size >= 0
            assert 0 <= item.permissions <= 0o7777
            assert isinstance(item.modified, datetime)


def _random_row(rng: random.Random) -> dict:
    row = {k: rng.choice(VALUES) for k in rng.sample(KEYS, rng.randint(0, len(KEYS)))}
    if rng.random() < 0.7:
        row["path"] = rng.choice(["/a", "/b/c", "/x y", "/caf�"])
    return row


def test_sad_random_rows_through_the_base():
    rng = random.Random(0x4442)
    for n in range(iterations(400)):
        rows = [_random_row(rng) for _ in range(rng.randint(0, 5))]
        meta = _random_row(rng) if rng.random() < 0.8 else None
        fail = DriverError("down") if rng.random() < 0.1 else None
        db = ScriptedDb(rows, meta, fail)
        for name, op in {
            "list_dir": lambda: db.list_dir("/"),
            "stat": lambda: db.stat("/a"),
            "is_dir": lambda: db.is_dir("/a"),
            "exists": lambda: db.exists("/a"),
            "open_read": lambda: db.open_read("/a").read(),
        }.items():
            result = check_contract(op, (OSError,), context=f"case {n} {name}")
            if name in ("list_dir", "stat"):
                _check_items(result)


def test_sad_random_redis_hashes():
    import pytest

    redis = pytest.importorskip("redis")
    rng = random.Random(0x5244)
    byte_values = [b"", b"0", b"1", b"420", b"0o755", b"abc", b"\xff", b"-1", b"9" * 40]
    for n in range(iterations(300)):
        meta = {
            k.encode(): rng.choice(byte_values)
            for k in rng.sample(["is_dir", "mode", "mtime", "parent"], rng.randint(0, 4))
        }
        strlen = rng.choice([0, 5, -1, b"x", b"5", None, 2**70])
        fail = None
        if rng.random() < 0.1:
            fail = rng.choice(
                [
                    redis.exceptions.ResponseError("WRONGTYPE"),
                    redis.exceptions.ConnectionError("reset"),
                    redis.exceptions.TimeoutError("slow"),
                ]
            )
        s = _redis_session(_RedisFake(meta, strlen=strlen, fail=fail))
        for name, op in {
            "list_dir": lambda: s.list_dir("/"),
            "stat": lambda: s.stat("/a"),
            "open_read": lambda: s.open_read("/a").read(),
        }.items():
            result = check_contract(op, (OSError,), context=f"case {n} {name}")
            if name in ("list_dir", "stat"):
                _check_items(result)


def test_sad_random_mongo_documents():
    import pytest

    errors = pytest.importorskip("pymongo.errors")
    rng = random.Random(0x4D47)
    for n in range(iterations(300)):
        dirs = [
            {k: rng.choice(VALUES) for k in rng.sample(["path", "parent", "mode", "mtime"], 3)}
            for _ in range(rng.randint(0, 3))
        ]
        files = [
            _gridout(
                filename=rng.choice(["/f", None, 5, "", "/g/h"]),
                metadata=rng.choice([None, {}, {"mode": rng.choice(VALUES)}, {"parent": None}]),
                length=rng.choice([0, 3, -1, None, 2**70]),
                upload_date=rng.choice([None, datetime(2024, 1, 2), "x"]),
            )
            for _ in range(rng.randint(0, 3))
        ]
        fail = errors.AutoReconnect("closed") if rng.random() < 0.1 else None
        s = _mongo_session(dirs, files, fail)
        for name, op in {
            "list_dir": lambda: s.list_dir("/"),
            "stat": lambda: s.stat("/f"),
            "is_dir": lambda: s.is_dir("/f"),
        }.items():
            result = check_contract(op, (OSError,), context=f"case {n} {name}")
            if name in ("list_dir", "stat"):
                _check_items(result)
