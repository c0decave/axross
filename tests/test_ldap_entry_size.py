"""An LDAP entry's listed size is the size of what reading it returns.

Probe against ldap.forumsys.com: uid=newton listed 298 bytes, open_read
returned 620. The size was "a rough estimate" - the attribute values
summed - while the file is the entry's LDIF (version line, dn, attribute
names, line folding). A copy, a progress bar or a resume compares the two.
The size is now the length of that LDIF.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("ldap3")

from core.ldap_fs_client import LdapFsSession  # noqa: E402


class _Values:
    def __init__(self, values):
        self.values = values
        self.value = values[0] if values else None


class _Entry:
    def __init__(self, dn: str, attrs: dict, ldif: str | None = None, broken: bool = False):
        self.entry_dn = dn
        self._attrs = attrs
        self._ldif = ldif
        self._broken = broken
        self.entry_attributes = list(attrs)

    def __getitem__(self, key):
        if key not in self._attrs:
            raise KeyError(key)
        return _Values(self._attrs[key])

    def entry_to_ldif(self):
        if self._broken:
            raise ValueError("undecodable attribute")
        if self._ldif is not None:
            return self._ldif
        lines = ["version: 1", f"dn: {self.entry_dn}"]
        lines += [f"{k}: {v}" for k, vs in self._attrs.items() for v in vs]
        return "\n".join(lines) + "\n"


def _session(entry) -> LdapFsSession:
    s = object.__new__(LdapFsSession)
    s._dn = lambda path: "uid=newton,dc=example,dc=com"
    s._search = lambda what, **kw: (True, [entry])
    return s


NEWTON = {
    "objectClass": ["inetOrgPerson", "organizationalPerson", "person", "top"],
    "cn": ["Isaac Newton"],
    "sn": ["Newton"],
    "uid": ["newton"],
    "mail": ["newton@ldap.forumsys.com"],
}


# --- happy ----------------------------------------------------------------


def test_happy_listed_size_is_the_read_size():
    entry = _Entry("uid=newton,dc=example,dc=com", NEWTON)
    s = _session(entry)
    item = s._entry_to_item(entry, "uid=newton")
    assert item.size == len(s.open_read("/x").read())


def test_happy_stat_agrees_with_the_listing():
    entry = _Entry("uid=newton,dc=example,dc=com", NEWTON)
    s = _session(entry)
    assert s.stat("/x").size == len(s.open_read("/x").read())


# --- sad ------------------------------------------------------------------


def test_sad_an_entry_that_cannot_be_rendered_lists_with_size_zero():
    entry = _Entry("uid=newton,dc=example,dc=com", NEWTON, broken=True)
    assert _session(entry)._entry_to_item(entry, "uid=newton").size == 0


# --- edge -----------------------------------------------------------------


def test_edge_non_ascii_values_count_in_bytes():
    attrs = dict(NEWTON, cn=["Émilie du Châtelet"])
    entry = _Entry("uid=emilie,dc=example,dc=com", attrs)
    s = _session(entry)
    assert s._entry_to_item(entry, "uid=emilie").size == len(s.open_read("/x").read())


def test_edge_a_container_stays_size_zero():
    entry = _Entry("ou=scientists,dc=example,dc=com", {"objectClass": ["organizationalUnit"], "ou": ["scientists"]})
    item = _session(entry)._entry_to_item(entry, "ou=scientists")
    assert item.is_dir and item.size == 0
