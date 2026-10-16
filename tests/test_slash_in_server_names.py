"""Server-chosen names that contain "/" stay one path segment and resolve.

* Exchange: an EWS ItemId is standard base64 ("AAMkAD.../ab+c=="), so it
  regularly contains "/". The listing named messages ``<id>_<subject>.eml``
  and the attachments directory ``<id>``; the "/" split those names into
  two path segments, and stat / open_read / remove of the listed path
  looked for a folder that does not exist.
* LDAP: an RDN value may contain "/" ("cn=AC/DC") - RFC 4514 does not
  escape it. The listed name became two segments, and the second one was
  rejected as "not an RDN" (ValueError, not even OSError).

Exchange ids now show "/" as "-" (never part of standard base64) and LDAP
names show it as the RFC 4514 hex escape ``\\2F``, which the server parses
back to "/".
"""

from __future__ import annotations

import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

WHEN = datetime(2026, 1, 2, tzinfo=timezone.utc)

# --------------------------------------------------------------------------
# Exchange
# --------------------------------------------------------------------------

SLASH_ID = "AAMkAGI2/TgxAAA+bc/d=="


class _Folder:
    """exchangelib folder surface: all().only(), filter(id=).only()."""

    def __init__(self, messages) -> None:
        self.messages = messages
        self.name = "Inbox"
        self.filtered: list[str] = []

    def all(self):
        return _Query(self.messages)

    def filter(self, id):  # noqa: A002 - exchangelib keyword
        self.filtered.append(id)
        return _Query([m for m in self.messages if m.id == id])


class _Query(list):
    def only(self, *fields):
        return self


def _exchange(messages):
    EC = pytest.importorskip("core.exchange_client")
    folder = _Folder(messages)
    s = object.__new__(EC.ExchangeSession)
    s._resolve_folder = lambda parts: folder if parts == ["Inbox"] else _missing(parts)
    return s, folder


def _missing(parts):
    raise OSError(f"folder not found: {'/'.join(parts)}")


def _message(mid, **kw):
    deleted = []
    msg = SimpleNamespace(
        id=mid,
        subject="Report",
        size=10,
        datetime_received=WHEN,
        has_attachments=True,
        attachments=[SimpleNamespace(name="a.pdf", size=3, content=b"pdf")],
        mime_content=b"Subject: Report\r\n\r\nbody",
        delete=lambda: deleted.append(mid),
        deleted=deleted,
    )
    return msg


def test_happy_exchange_listed_names_are_single_segments_that_resolve():
    msg = _message(SLASH_ID)
    s, _ = _exchange([msg, _message("AAMkPLAIN==")])
    names = [i.name for i in s.list_dir("/Inbox")]
    assert all("/" not in n for n in names), names
    eml = next(n for n in names if n.endswith(".eml") and n.startswith("AAMkAGI2"))
    assert s.stat(f"/Inbox/{eml}").size == 10
    assert s.open_read(f"/Inbox/{eml}").read() == msg.mime_content


def test_sad_exchange_attachment_dir_and_delete_resolve_the_slash_id():
    msg = _message(SLASH_ID)
    s, folder = _exchange([msg])
    dirname = next(i.name for i in s.list_dir("/Inbox") if i.is_dir)
    assert "/" not in dirname
    assert [i.name for i in s.list_dir(f"/Inbox/{dirname}")] == ["a.pdf"]
    assert s.open_read(f"/Inbox/{dirname}/a.pdf").read() == b"pdf"
    eml = next(i.name for i in s.list_dir("/Inbox") if not i.is_dir)
    s.remove(f"/Inbox/{eml}")
    assert msg.deleted == [SLASH_ID]
    assert set(folder.filtered) == {SLASH_ID}


def test_edge_exchange_plain_id_is_unchanged():
    s, _ = _exchange([_message("AAMkPLAIN==")])
    assert "AAMkPLAIN==_Report.eml" in [i.name for i in s.list_dir("/Inbox")]


# --------------------------------------------------------------------------
# LDAP
# --------------------------------------------------------------------------

ROOT = "o=Rock/Pop,c=DE"
PEOPLE = f"ou=people,{ROOT}"
_DIT = {
    ROOT: ("", "organization"),
    PEOPLE: (ROOT, "organizationalUnit"),
    f"cn=AC/DC,{PEOPLE}": (PEOPLE, "person"),
    f"cn=Smith,{PEOPLE}": (PEOPLE, "person"),
}


def _canonical(dn: str) -> str:
    """What a server compares: hex-pair escapes decoded."""
    return re.sub(r"\\([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), dn).lower()


class _Entry:
    def __init__(self, dn: str, oclass: str) -> None:
        self.entry_dn = dn
        self.entry_attributes = ["objectClass"]
        self._attrs = {"objectClass": SimpleNamespace(values=[oclass])}

    def __getitem__(self, key):
        return self._attrs[key]

    def entry_to_ldif(self):
        return f"dn: {self.entry_dn}\n"


class _Conn:
    def __init__(self) -> None:
        self.entries = []

    def search(self, search_base, search_filter, search_scope, attributes=None):
        from ldap3 import BASE, LEVEL

        want = _canonical(search_base)
        if search_scope == BASE:
            hits = [dn for dn in _DIT if _canonical(dn) == want]
        elif search_scope == LEVEL:
            hits = [dn for dn, (parent, _) in _DIT.items() if parent and _canonical(parent) == want]
        else:
            hits = []
        self.entries = [_Entry(dn, _DIT[dn][1]) for dn in hits]
        return bool(hits)


def _ldap():
    LC = pytest.importorskip("core.ldap_fs_client")
    s = LC.LdapFsSession.__new__(LC.LdapFsSession)
    s._conn = _Conn()
    s._naming_contexts = [ROOT]
    return s


def test_happy_ldap_rdn_with_slash_is_listed_as_one_segment_and_opens():
    s = _ldap()
    (base,) = [i.name for i in s.list_dir("/")]
    assert "/" not in base
    people = f"/{base}/ou=people"
    names = sorted(i.name for i in s.list_dir(people))
    assert names == ["cn=AC\\2FDC", "cn=Smith"]
    item = s.stat(f"{people}/cn=AC\\2FDC")
    assert item.name == "cn=AC\\2FDC"
    assert s.open_read(f"{people}/cn=AC\\2FDC").read() == f"dn: cn=AC/DC,{PEOPLE}\n".encode()


def test_sad_ldap_unescaped_slash_path_is_not_a_valueerror_crash():
    s = _ldap()
    # The raw name as it used to be listed: two segments, second no RDN.
    assert s.exists(f"/o=Rock\\2FPop,c=DE/ou=people/cn=AC/DC") is False


def test_edge_ldap_names_without_slash_are_unchanged():
    s = _ldap()
    assert s.stat("/o=Rock\\2FPop,c=DE/ou=people/cn=Smith").name == "cn=Smith"
