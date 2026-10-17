"""LDAP list_dir is complete or an error - never a silently cut listing.

Review B7 (2026-10-17): a server that stops a one-level search at its
size limit (Active Directory answers unpaged searches with at most
MaxPageSize = 1000 entries) sends the entries it has and then
sizeLimitExceeded; list_dir ignored the result code and returned 3 of
10 children as if that were all. list_dir now pages (RFC 2696, ldap3's
paged_size / paged_cookie) and raises when the server still ends with
anything but success.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

ldap3 = pytest.importorskip("ldap3")

import ldap_fuzz_server as L  # noqa: E402

from core import ldap_fs_client as M  # noqa: E402

BASE = "dc=example,dc=com"


class _SizeLimited(L.FakeLdapServer):
    LIMIT = 3

    def search_answer(self, msgid, base=b"", scope=1):
        entries = self.entries[: self.LIMIT]
        out = b"".join(L.message(msgid, L.search_entry(dn, a)) for dn, a in entries)
        return out + L.message(msgid, L.ldap_result(0x65, code=4))  # sizeLimitExceeded


def _session(server):
    s = M.LdapFsSession.__new__(M.LdapFsSession)
    s._tunnel = None
    s._use_tls = False
    s._server = ldap3.Server("127.0.0.1", port=server.port, get_info=ldap3.NONE, connect_timeout=5)
    s._conn = ldap3.Connection(s._server, auto_bind=True, receive_timeout=5)
    s._naming_contexts = [BASE]
    s._display = "x"
    return s


def _people(n):
    return [
        (f"cn=user{i},{BASE}", {"objectClass": ["person"], "cn": [f"user{i}"]}) for i in range(n)
    ]


def test_happy_a_server_that_sends_everything_lists_everything():
    server = L.FakeLdapServer()
    server.entries = _people(10)
    try:
        assert len(_session(server).list_dir("/" + BASE)) == 10
    finally:
        server.close()


def test_sad_a_listing_cut_at_the_size_limit_is_an_error():
    server = _SizeLimited()
    server.entries = _people(10)
    try:
        with pytest.raises(OSError, match="incomplete") as caught:
            _session(server).list_dir("/" + BASE)
        assert "3 entries" in str(caught.value)
    finally:
        server.close()


class _PagingConn:
    """ldap3.Connection's search surface, answering in pages of 2 with
    the RFC 2696 cookie."""

    def __init__(self, total):
        self.total = total
        self.calls = []
        self.entries = []
        self.result = {}

    def search(self, **kwargs):
        self.calls.append(kwargs)
        start = int(kwargs.get("paged_cookie") or b"0")
        page = list(range(start, min(start + 2, self.total)))
        self.entries = [_Entry(f"cn=u{i},{BASE}") for i in page]
        nxt = page[-1] + 1 if page and page[-1] + 1 < self.total else None
        self.result = {
            "result": 0,
            "description": "success",
            "controls": {M._PAGED_OID: {"value": {"cookie": str(nxt).encode() if nxt else b""}}},
        }
        return True


class _Entry:
    def __init__(self, dn):
        self.entry_dn = dn

    def __getitem__(self, key):
        raise KeyError(key)


def test_edge_every_page_is_fetched_with_the_cookie():
    s = M.LdapFsSession.__new__(M.LdapFsSession)
    s._conn = _PagingConn(5)
    s._naming_contexts = [BASE]
    items = s.list_dir("/" + BASE)
    assert sorted(i.name for i in items) == [f"cn=u{i}" for i in range(5)]
    assert [c.get("paged_cookie") for c in s._conn.calls] == [None, b"2", b"4"]
    assert all(c.get("paged_size") == M._PAGE_SIZE for c in s._conn.calls)
