"""LDAP stat() says "not found" only for noSuchObject.

core/ldap_fs_client.py stat() raised FileNotFoundError whenever the BASE
search did not succeed (``if not ok or not entries``): insufficient
access rights (50), busy (51), unavailable (52) or a time limit (3) all
read as "the entry does not exist", and exists() - which catches
FileNotFoundError and OSError alike - answered False for every failure.
Only result 32 (noSuchObject) is FileNotFoundError now; a refusal is
PermissionError, anything else OSError with the server's reason, and
exists() raises for them.

Driven through a real ldap3 Connection against the in-process fake LDAP
server (tests/ldap_fuzz_server.py).
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
ENTRY = f"cn=alice,{BASE}"


class _Answers(L.FakeLdapServer):
    """A BASE search answered with no entry and the result code *code*
    (0 = the entry is there)."""

    code = 0

    def search_answer(self, msgid, base=b"", scope=1):
        if self.code == 0:
            return super().search_answer(msgid, base, scope)
        return L.message(msgid, L.ldap_result(0x65, code=self.code))


@pytest.fixture
def server():
    srv = _Answers()
    srv.entries = [(ENTRY, {"objectClass": ["person"], "cn": ["alice"]})]
    yield srv
    srv.close()


def _session(server):
    s = M.LdapFsSession.__new__(M.LdapFsSession)
    s._tunnel = None
    s._use_tls = False
    s._server = ldap3.Server("127.0.0.1", port=server.port, get_info=ldap3.NONE,
                             connect_timeout=5)
    s._conn = ldap3.Connection(s._server, auto_bind=True, receive_timeout=5)
    s._naming_contexts = [BASE]
    s._display = "x"
    return s


def test_happy_an_existing_entry_stats_and_exists(server):
    s = _session(server)
    assert s.stat("/" + BASE + "/cn=alice").name == "cn=alice"
    assert s.exists("/" + BASE + "/cn=alice") is True


def test_happy_no_such_object_is_missing(server):
    server.code = 32
    s = _session(server)
    with pytest.raises(FileNotFoundError):
        s.stat("/" + BASE + "/cn=bob")
    assert s.exists("/" + BASE + "/cn=bob") is False
    assert s.is_dir("/" + BASE + "/cn=bob") is False


def test_sad_insufficient_access_is_a_refusal_not_missing(server):
    server.code = 50
    s = _session(server)
    with pytest.raises(PermissionError):
        s.stat("/" + BASE + "/cn=alice")
    with pytest.raises(PermissionError):
        s.exists("/" + BASE + "/cn=alice")


@pytest.mark.parametrize("code", [3, 51, 52])
def test_sad_a_busy_or_unavailable_server_is_an_error_not_missing(server, code):
    server.code = code
    s = _session(server)
    with pytest.raises(OSError) as caught:
        s.stat("/" + BASE + "/cn=alice")
    assert not isinstance(caught.value, FileNotFoundError)
    with pytest.raises(OSError):
        s.is_dir("/" + BASE + "/cn=alice")


def test_edge_success_without_an_entry_is_missing(server):
    """A server that answers success but sends no entry: nothing there."""
    server.entries = []
    s = _session(server)
    with pytest.raises(FileNotFoundError):
        s.stat("/" + BASE + "/cn=alice")
