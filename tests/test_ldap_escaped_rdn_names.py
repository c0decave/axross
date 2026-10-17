"""LDAP entry names keep RFC 4514 escapes in their RDN.

list_dir / stat named each entry ``entry_dn.split(",", 1)[0]``. A DN
like ``cn=Doe\\, Jane,ou=people,...`` - the usual shape for people
entries - was listed as ``cn=Doe\\``, and navigating that name built a
DN that points at a different entry or none at all.

The directory is a stand-in at the ldap3 Connection boundary that
answers BASE / LEVEL searches with DNs in the escaped form a server
returns. (ldap3's own MOCK_SYNC strategy splits escaped DNs naively at
LEVEL scope, so it cannot serve as the reference here.)
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from ldap3 import BASE as SCOPE_BASE
    from ldap3 import LEVEL

    from core.ldap_fs_client import LdapFsSession

    LDAP3 = True
except ImportError:  # pragma: no cover - optional extra
    LDAP3 = False

ROOT = "dc=example,dc=com"
PEOPLE = f"ou=people,{ROOT}"
# DN -> (parent DN, objectClass)
_DIT = {
    ROOT: ("", "domain"),
    PEOPLE: (ROOT, "organizationalUnit"),
    f"cn=Smith,{PEOPLE}": (PEOPLE, "person"),
    f"cn=Doe\\, Jane,{PEOPLE}": (PEOPLE, "person"),
    f"cn=back\\\\,{PEOPLE}": (PEOPLE, "person"),
}


class _Entry:
    def __init__(self, dn: str, oclass: str) -> None:
        self.entry_dn = dn
        self.entry_attributes = ["objectClass"]
        self._attrs = {"objectClass": SimpleNamespace(values=[oclass])}

    def __getitem__(self, key: str):
        return self._attrs[key]


class _Conn:
    def __init__(self) -> None:
        self.entries: list[_Entry] = []
        self.bases: list[str] = []

    def search(self, search_base, search_filter, search_scope, attributes=None, **_paging):
        self.bases.append(search_base)
        if search_scope == SCOPE_BASE:
            hits = [dn for dn in _DIT if dn == search_base]
        elif search_scope == LEVEL:
            hits = [dn for dn, (parent, _) in _DIT.items() if parent == search_base]
        else:
            hits = []
        self.entries = [_Entry(dn, _DIT[dn][1]) for dn in hits]
        return bool(hits)


@unittest.skipUnless(LDAP3, "ldap3 not installed")
class LdapEscapedRdnTest(unittest.TestCase):
    def setUp(self) -> None:
        s = LdapFsSession.__new__(LdapFsSession)
        s._conn = _Conn()
        s._naming_contexts = [ROOT]
        self.s = s
        self.people = f"/{ROOT}/ou=people"

    def _names(self) -> list[str]:
        return sorted(i.name for i in self.s.list_dir(self.people))

    def test_happy_plain_rdn(self) -> None:
        self.assertIn("cn=Smith", self._names())
        self.assertEqual(self.s.stat(f"{self.people}/cn=Smith").name, "cn=Smith")

    def test_sad_escaped_comma_stays_in_the_name_and_resolves(self) -> None:
        self.assertIn("cn=Doe\\, Jane", self._names())
        item = self.s.stat(f"{self.people}/cn=Doe\\, Jane")
        self.assertEqual(item.name, "cn=Doe\\, Jane")
        self.assertEqual(self.s._conn.bases[-1], f"cn=Doe\\, Jane,{PEOPLE}")

    def test_sad_escaped_backslash_cannot_smuggle_an_rdn(self) -> None:
        # "\\\\," is an escaped backslash followed by a REAL separator: the
        # F31 guard used to delete the "\\," pair and let it through.
        with self.assertRaises(ValueError):
            self.s._path_to_dn(f"{self.people}/cn=a\\\\,ou=admins")
        self.assertEqual(
            self.s._path_to_dn(f"{self.people}/cn=Doe\\, Jane"), f"cn=Doe\\, Jane,{PEOPLE}"
        )

    def test_edge_escaped_backslash_before_the_separator(self) -> None:
        self.assertEqual(self._names(), ["cn=Doe\\, Jane", "cn=Smith", "cn=back\\\\"])
        self.assertEqual(self.s.stat(f"{self.people}/cn=back\\\\").name, "cn=back\\\\")


if __name__ == "__main__":
    unittest.main()
