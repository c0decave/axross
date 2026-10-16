"""IMAP: an attachment path never deletes or moves its whole message.

``/INBOX/5/report.pdf`` parses to ``("INBOX", "5", "report.pdf")``.
remove() and rename() only tested ``len(parsed) >= 2`` and then acted on
UID 5: deleting one attachment marked the whole mail \\Deleted and
expunged it; renaming an attachment moved the whole mail.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.imap_client import ImapSession  # noqa: E402


class _RecordingImap:
    capabilities = ("IMAP4REV1", "UIDPLUS")

    def __init__(self) -> None:
        self.uid_calls: list[tuple] = []

    def noop(self):
        return ("OK", [b"NOOP"])

    def list(self, *args, **kwargs):
        return ("OK", [b'(\\HasNoChildren) "/" "INBOX"', b'(\\HasNoChildren) "/" "Archive"'])

    def select(self, *args, **kwargs):
        return ("OK", [b"1"])

    def uid(self, cmd, *args):
        self.uid_calls.append((cmd, *args))
        return ("OK", [b""])

    def expunge(self):
        self.uid_calls.append(("EXPUNGE",))
        return ("OK", [b""])


def _session() -> tuple[ImapSession, _RecordingImap]:
    imap = _RecordingImap()
    s = object.__new__(ImapSession)
    s._host, s._port, s._username, s._password = "h", 993, "u", "p"
    s._use_ssl = True
    s._imap = imap
    s._hierarchy_sep = "/"
    s._selected_mailbox = None
    s._mailbox_cache = None
    return s, imap


class ImapAttachmentPathTest(unittest.TestCase):
    def test_happy_message_remove_still_deletes_that_message(self) -> None:
        s, imap = _session()
        s.remove("/INBOX/5_hello.eml")
        self.assertEqual(imap.uid_calls[0], ("STORE", "5", "+FLAGS", "(\\Deleted)"))

    def test_sad_attachment_remove_is_refused_and_touches_nothing(self) -> None:
        s, imap = _session()
        with self.assertRaises(OSError):
            s.remove("/INBOX/5/report.pdf")
        self.assertEqual(imap.uid_calls, [])

    def test_edge_attachment_rename_is_refused_and_touches_nothing(self) -> None:
        s, imap = _session()
        with self.assertRaises(OSError):
            s.rename("/INBOX/5/report.pdf", "/Archive/report.pdf")
        self.assertEqual(imap.uid_calls, [])


if __name__ == "__main__":
    unittest.main()
