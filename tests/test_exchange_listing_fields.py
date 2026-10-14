"""An Exchange folder listing asks only for the fields it shows.

Before: ``folder.all()`` without ``.only()`` requests every item field;
exchangelib 5.6 (queryset.py: only_fields None -> all allowed fields ->
complex fields requested) then answers with FindItem + GetItem and ships
``mime_content``, ``body`` and ``attachments`` of EVERY message just to
list names, sizes and dates. With ``.only()`` of simple fields FindItem
alone answers.
"""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    from exchangelib import Message

    from core import exchange_client as EC
except ImportError:  # pragma: no cover
    EC = None

WHEN = datetime(2026, 1, 2, tzinfo=timezone.utc)


def _messages():
    return [
        SimpleNamespace(id="AAA1", subject="Hello / World", size=1234, datetime_received=WHEN,
                        has_attachments=True),
        SimpleNamespace(id="AAA2", subject=None, size=None, datetime_received=None,
                        datetime_sent=WHEN, has_attachments=False),
        SimpleNamespace(item_id="AAA3", subject="x", size="bad", last_modified_time=WHEN),
    ]


class _QuerySet:
    def __init__(self, items, log) -> None:
        self._items, self._log = items, log

    def only(self, *fields):
        # Like exchangelib: fields not asked for come back as None.
        self._log.append(fields)
        keep = set(fields) | {"id", "item_id", "changekey"}
        trimmed = [
            SimpleNamespace(**{k: (v if k in keep else None) for k, v in vars(m).items()})
            for m in self._items
        ]
        return _QuerySet(trimmed, self._log)

    def __iter__(self):
        return iter(self._items)


@unittest.skipIf(EC is None, "exchangelib not installed")
class ListingFieldsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.only_calls: list[tuple] = []
        self.folder = SimpleNamespace(all=lambda: _QuerySet(_messages(), self.only_calls))
        self.s = object.__new__(EC.ExchangeSession)

    def test_happy_listing_is_unchanged(self) -> None:
        # Reference: what the listing built from the full items looked like.
        expected = []
        for msg in _messages():
            mid = str(getattr(msg, "id", "") or getattr(msg, "item_id", ""))
            subj = EC._sanitize(getattr(msg, "subject", "") or "no_subject")
            expected.append((f"{mid}_{subj}.eml", EC.ExchangeSession._estimate_size(msg)))
            if getattr(msg, "has_attachments", False):
                expected.append((mid, 0))
        got = [(i.name, i.size) for i in self.s._list_messages(self.folder)]
        mtimes = [i.modified for i in self.s._list_messages(self.folder) if not i.is_dir]
        self.assertEqual(mtimes, [EC.ExchangeSession._msg_mtime(m) for m in _messages()])
        self.assertEqual(got, expected)

    def test_happy_only_the_shown_fields_are_requested(self) -> None:
        self.s._list_messages(self.folder)
        self.assertEqual(len(self.only_calls), 1)
        self.assertEqual(
            set(self.only_calls[0]),
            {"subject", "size", "datetime_received", "datetime_sent", "last_modified_time",
             "has_attachments"},
        )

    def test_edge_every_requested_field_is_simple(self) -> None:
        # A complex field would bring back GetItem for every message.
        for name in EC.LISTING_FIELDS:
            with self.subTest(field=name):
                self.assertFalse(Message.get_field_by_fieldname(name).is_complex)

    def test_sad_a_failing_query_is_an_oserror(self) -> None:
        def boom():
            raise RuntimeError("EWS down")

        with self.assertRaises(OSError):
            self.s._list_messages(SimpleNamespace(all=boom))


class _Filtered:
    """Like exchangelib: after .only(), fields not asked for are None."""

    def __init__(self, msg, log) -> None:
        self._msg, self._log = msg, log

    def only(self, *fields):
        self._log.append(fields)
        if self._msg is not None:
            keep = set(fields) | {"id", "changekey"}
            self._msg = SimpleNamespace(
                **{k: (v if k in keep else None) for k, v in vars(self._msg).items()}
            )
        return self

    def __iter__(self):
        return iter([self._msg] if self._msg else [])


@unittest.skipIf(EC is None, "exchangelib not installed")
class MetadataFetchTest(unittest.TestCase):
    """stat and the attachment listing fetch only what they read."""

    def setUp(self) -> None:
        self.only_calls: list[tuple] = []
        att = SimpleNamespace(name="a.pdf", size=77)
        self.msg = SimpleNamespace(id="M1", subject="s", size=900, datetime_received=WHEN,
                                   has_attachments=True, attachments=[att])
        folder = SimpleNamespace(
            filter=lambda id: _Filtered(self.msg if id == "M1" else None, self.only_calls),
            name="Inbox",
        )
        self.s = object.__new__(EC.ExchangeSession)
        self.s._resolve_folder = lambda parts: folder if parts == ["Inbox"] else self._missing()

    @staticmethod
    def _missing():
        raise OSError("folder not found")

    def test_happy_eml_stat_uses_the_listing_fields(self) -> None:
        item = self.s.stat("/Inbox/M1_s.eml")
        self.assertEqual((item.size, item.modified), (900, WHEN))
        self.assertEqual(self.only_calls, [EC.LISTING_FIELDS])

    def test_happy_attachment_listing_and_stat_fetch_attachments_only(self) -> None:
        folder = self.s._resolve_folder(["Inbox"])
        listed = self.s._list_attachments(folder, "M1")
        self.assertEqual([(i.name, i.size) for i in listed], [("a.pdf", 77)])
        self.assertEqual([i.modified for i in listed], [WHEN])
        item = self.s.stat("/Inbox/M1/a.pdf")
        self.assertEqual((item.size, item.modified), (77, WHEN))
        self.assertEqual(self.only_calls[0], EC.ATTACHMENT_FIELDS)
        self.assertEqual(self.only_calls[-1], EC.ATTACHMENT_FIELDS)

    def test_sad_missing_message_is_still_an_oserror(self) -> None:
        with self.assertRaises(OSError):
            self.s.stat("/Inbox/NOPE_s.eml")

    def test_edge_open_read_still_fetches_everything(self) -> None:
        self.msg.mime_content = b"raw"
        self.only_calls.clear()
        self.s._fetch_message(self.s._resolve_folder(["Inbox"]), "M1")
        self.assertEqual(self.only_calls, [])


if __name__ == "__main__":
    unittest.main()
