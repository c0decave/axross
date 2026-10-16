"""Fuzz: the LDAP backend against a hostile LDAP server.

An in-process LDAP server (tests/ldap_fuzz_server.py) answers ldap3's
binds and searches with scripted entries - DNs and values that are not
UTF-8, empty, traversal-shaped, huge, odd objectClass / modifyTimestamp
values - and with byte-mutated BER answers (truncated, wrong lengths,
wrong tags, garbage) after which it hangs up. Every call returns sane
data or raises OSError.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ldap3 = pytest.importorskip("ldap3")

from fuzz_testkit import check_contract, iterations, mutants  # noqa: E402
from ldap_fuzz_server import FakeLdapServer  # noqa: E402

from core.ldap_fs_client import LdapFsSession  # noqa: E402

BASE = "dc=example,dc=com"
ENTRIES = [
    (
        "ou=people,dc=example,dc=com",
        {"objectClass": ["top", "organizationalUnit"], "ou": ["people"]},
    ),
    (
        "cn=alice,dc=example,dc=com",
        {
            "objectClass": ["top", "person"],
            "cn": ["alice"],
            "sn": ["A"],
            "modifyTimestamp": ["20240102030405Z"],
        },
    ),
]


@pytest.fixture
def ldap_server():
    srv = FakeLdapServer()
    srv.entries = list(ENTRIES)
    try:
        yield srv
    finally:
        srv.close()


def _session(srv: FakeLdapServer) -> LdapFsSession:
    s = LdapFsSession.__new__(LdapFsSession)
    s._tunnel = None
    s._use_tls = False
    s._server = ldap3.Server("127.0.0.1", port=srv.port, get_info=ldap3.NONE, connect_timeout=5)
    s._conn = ldap3.Connection(s._server, auto_bind=True, receive_timeout=5)
    s._naming_contexts = [BASE]
    s._display = "ldap://anon@127.0.0.1"
    return s


def _ops(s):
    return {
        "list_dir": lambda: s.list_dir("/" + BASE),
        "stat": lambda: s.stat(f"/{BASE}/cn=alice"),
        "is_dir": lambda: s.is_dir(f"/{BASE}/ou=people"),
        "exists": lambda: s.exists(f"/{BASE}/cn=alice"),
        "open_read": lambda: s.open_read(f"/{BASE}/cn=alice").read(),
        "search": lambda: s.search(BASE, "(objectClass=*)"),
    }


def _check(name, result) -> None:
    if name in ("list_dir", "stat"):
        for item in result if isinstance(result, list) else [result]:
            if hasattr(item, "name"):
                assert isinstance(item.name, str)
                assert isinstance(item.size, int) and item.size >= 0


def _all_ops(srv, ctx, fresh_each: bool = False):
    s = _session(srv)
    for name, op in _ops(s).items():
        if fresh_each:
            s = _session(srv)
            op = _ops(s)[name]
        result = check_contract(op, (OSError,), timeout=15.0, context=f"{ctx} {name}")
        _check(name, result)


def test_happy_listing(ldap_server):
    s = _session(ldap_server)
    items = {i.name: i for i in s.list_dir("/" + BASE)}
    assert set(items) == {"ou=people", "cn=alice"}
    assert items["ou=people"].is_dir and not items["cn=alice"].is_dir
    assert b"cn: alice" in s.open_read(f"/{BASE}/cn=alice").read()


HOSTILE = {
    "dn-latin1": [(b"cn=caf\xe9,dc=example,dc=com", {"cn": [b"caf\xe9"]})],
    "dn-empty": [(b"", {"cn": ["x"]})],
    "dn-traversal": [("..", {"cn": [".."]}), ("cn=a/b,dc=x", {"cn": ["a/b"]})],
    "dn-no-equals": [("garbage", {})],
    "value-binary": [("cn=bin,dc=x", {"cn": ["bin"], "jpegPhoto": [b"\xff\xd8\x00" * 100]})],
    "value-huge": [("cn=big,dc=x", {"cn": ["big"], "description": ["x" * 200000]})],
    "objectclass-odd": [("cn=o,dc=x", {"objectClass": [b"\xff", ""], "cn": ["o"]})],
    "timestamp-odd": [
        ("cn=t,dc=x", {"cn": ["t"], "modifyTimestamp": ["99999999999999Z"]}),
        ("cn=u,dc=x", {"cn": ["u"], "modifyTimestamp": [b"\xff"]}),
    ],
    "many-values": [("cn=m,dc=x", {"cn": ["m"], "member": [f"uid={i}" for i in range(3000)]})],
}


@pytest.mark.parametrize("entries", list(HOSTILE.values()), ids=list(HOSTILE))
def test_sad_hostile_entries(ldap_server, entries):
    ldap_server.entries = entries
    _all_ops(ldap_server, repr(entries)[:60])


def test_sad_mutated_ber_answers(ldap_server):
    corpus = [ldap_server.search_answer(2)]
    for n, mutant in enumerate(mutants(corpus, seed=0x4C44, per_entry=iterations(200))):
        ldap_server.mutate_search = lambda _answer, m=mutant: m
        _all_ops(ldap_server, f"mutant {n}", fresh_each=True)


def test_edge_server_hangs_up_mid_search(ldap_server):
    ldap_server.mutate_search = lambda answer: answer[: len(answer) // 2]
    _all_ops(ldap_server, "half answer", fresh_each=True)
