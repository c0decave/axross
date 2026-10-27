"""An LDAP answer ldap3 cannot decode is an OSError.

LdapFsSession caught only LDAPException around ``Connection.search``.
ldap3's BER decoder (ldap3.utils.asn1.decode_message_fast) indexes and
slices the raw answer, so an element with an unexpected tag raised
KeyError (its tag-class lookup), a short element IndexError / ValueError,
none of which callers of list_dir / stat / open_read handle. Found by
tests/test_fuzz_ldap.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

ldap3 = pytest.importorskip("ldap3")

from ldap_fuzz_server import FakeLdapServer, ldap_result, message, octets, tlv  # noqa: E402
from test_fuzz_ldap import BASE, ENTRIES, _session  # noqa: E402


@pytest.fixture
def srv():
    server = FakeLdapServer()
    server.entries = list(ENTRIES)
    try:
        yield server
    finally:
        server.close()


def test_happy_listing(srv):
    names = {i.name for i in _session(srv).list_dir("/" + BASE)}
    assert names == {"ou=people", "cn=alice"}


def _unknown_tag_answer(_answer: bytes) -> bytes:
    # A SearchResultDone whose result code carries universal tag 8
    # (EXTERNAL) instead of ENUMERATED: ldap3's decoder has no entry for it.
    op = tlv(0x65, tlv(0x08, b"\x00") + octets(b"") + octets(b""))
    return message(2, op)


def _short_element_answer(_answer: bytes) -> bytes:
    # A SearchResultEntry whose attribute list is an empty INTEGER.
    return message(2, tlv(0x64, octets(b"cn=x") + tlv(0x02, b""))) + message(2, ldap_result(0x65))


@pytest.mark.parametrize(
    "mutate", [_unknown_tag_answer, _short_element_answer], ids=["unknown-tag", "short-element"]
)
@pytest.mark.parametrize("op", ["list_dir", "stat", "open_read", "search"])
def test_sad_undecodable_answer_is_an_oserror(srv, mutate, op):
    srv.mutate_search = mutate
    s = _session(srv)
    call = {
        "list_dir": lambda: s.list_dir("/" + BASE),
        "stat": lambda: s.stat(f"/{BASE}/cn=alice"),
        "open_read": lambda: s.open_read(f"/{BASE}/cn=alice"),
        "search": lambda: s.search(BASE),
    }[op]
    with pytest.raises(OSError):
        call()


def test_edge_exists_raises_on_an_undecodable_answer(srv):
    """An answer that cannot be read says nothing about the entry: exists()
    is False only for "not found" (a False here let a caller take a
    present entry for a missing one and overwrite it)."""
    srv.mutate_search = _unknown_tag_answer
    with pytest.raises(OSError, match="malformed answer"):
        _session(srv).exists(f"/{BASE}/cn=alice")
