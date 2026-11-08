"""IMAP: leaving a mailbox and moving a message never expunge other mail.

CLOSE on a mailbox selected read-write expunges every message flagged
\\Deleted (RFC 3501 6.4.2) - also ones another client only flagged
(Outlook's "mark as deleted") and the very ones _expunge_one refused to
expunge. disconnect() and the rename / delete of the selected mailbox sent
CLOSE after a refused remove, a set_flags or a move had left it selected
read-write. They now LOGOUT alone, UNSELECT (RFC 3691) or EXAMINE first.

rename() of a message skipped remove()'s checks: a stale name moved a
different message, a UID that is gone "moved", and without UIDPLUS the
original stayed in the source while success was reported. move() (the
scripting verb) the same. Both now check the message, use MOVE when it is
offered, and refuse rather than expunge other flagged mail.

Driven against the in-memory server of tests/imap_memory_server.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import imap_memory_server as M  # noqa: E402

PLAIN = ("IMAP4REV1",)
UIDPLUS = ("IMAP4REV1", "UIDPLUS")


def _closes_rw(srv) -> list[str]:
    return [line for line in srv.log if line.startswith("CLOSE") and line.endswith("ro=False")]


# -- leaving a mailbox ----------------------------------------------------


def test_sad_disconnect_after_a_refused_remove_keeps_mail_other_clients_flagged(monkeypatch):
    srv = M.Server(caps=PLAIN)
    srv.add_box("INBOX")
    srv.add_msg("INBOX", "flagged-in-outlook", flags=["\\Deleted"])
    srv.add_msg("INBOX", "hello")
    s = M.session(monkeypatch, srv)
    with pytest.raises(FileNotFoundError):
        s.remove("/INBOX/2_invoice.eml")  # stale: UID 2 is "hello"
    s.disconnect()
    assert srv.subjects("INBOX") == ["flagged-in-outlook", "hello"]
    assert _closes_rw(srv) == []


def test_sad_disconnect_after_set_flags_keeps_flagged_mail(monkeypatch):
    srv = M.Server(caps=PLAIN)
    srv.add_box("INBOX")
    srv.add_msg("INBOX", "flagged-elsewhere", flags=["\\Deleted"])
    uid = srv.add_msg("INBOX", "x")
    s = M.session(monkeypatch, srv)
    s.set_flags(uid, ["\\Flagged"], mailbox="INBOX", mode="add")
    s.disconnect()
    assert srv.subjects("INBOX") == ["flagged-elsewhere", "x"]
    assert srv.log[-1] == "LOGOUT"


def test_sad_renaming_the_mailbox_selected_read_write_expunges_nothing(monkeypatch):
    srv = M.Server(caps=PLAIN)
    srv.add_box("Work")
    srv.add_msg("Work", "flagged-elsewhere", flags=["\\Deleted"])
    uid = srv.add_msg("Work", "x")
    s = M.session(monkeypatch, srv)
    s.set_flags(uid, ["\\Flagged"], mailbox="Work", mode="add")
    s.rename("/Work", "/Work-2025")
    assert srv.subjects("Work-2025") == ["flagged-elsewhere", "x"]
    assert _closes_rw(srv) == []
    assert "EXAMINE Work" in srv.log  # read-only first: CLOSE removes nothing


def test_edge_unselect_is_used_when_offered_after_login(monkeypatch):
    # Announced only to the authenticated client, as Dovecot does.
    srv = M.Server(caps=PLAIN, auth_caps=("IMAP4REV1", "UNSELECT"))
    srv.add_box("Work")
    srv.add_msg("Work", "flagged-elsewhere", flags=["\\Deleted"])
    uid = srv.add_msg("Work", "x")
    s = M.session(monkeypatch, srv)
    s.set_flags(uid, ["\\Flagged"], mailbox="Work", mode="add")
    s.rename("/Work", "/Work-2025")
    assert "UNSELECT Work" in srv.log
    assert not any(line.startswith("CLOSE") for line in srv.log)
    assert srv.subjects("Work-2025") == ["flagged-elsewhere", "x"]


def test_sad_a_refused_delete_of_the_selected_mailbox_keeps_its_flagged_mail(monkeypatch):
    srv = M.Server(caps=PLAIN)
    srv.add_box("Old")
    srv.add_msg("Old", "flagged-elsewhere", flags=["\\Deleted"])
    uid = srv.add_msg("Old", "x")
    s = M.session(monkeypatch, srv)
    s.set_flags(uid, ["\\Flagged"], mailbox="Old", mode="add")
    monkeypatch.setattr(M.FakeIMAP, "delete", lambda self, mb: ("NO", [b"in use"]))
    with pytest.raises(OSError, match="in use"):
        s.remove("/Old", recursive=True)
    assert srv.subjects("Old") == ["flagged-elsewhere", "x"]


# -- moving a message ------------------------------------------------------


def _two_boxes(caps, auth_caps=None, flagged_other=True):
    srv = M.Server(caps=caps, auth_caps=auth_caps)
    srv.add_box("INBOX")
    srv.add_box("Archive")
    if flagged_other:
        srv.add_msg("INBOX", "other-client-flagged", flags=["\\Deleted"])
    uid = srv.add_msg("INBOX", "drag-me")
    return srv, uid


def test_sad_move_without_move_or_uidplus_is_refused_and_copies_nothing(monkeypatch):
    srv, uid = _two_boxes(PLAIN)
    s = M.session(monkeypatch, srv)
    with pytest.raises(OSError, match="neither MOVE nor UIDPLUS"):
        s.rename(f"/INBOX/{uid}_drag-me.eml", "/Archive")
    with pytest.raises(OSError, match="neither MOVE nor UIDPLUS"):
        s.move(uid, "INBOX", "Archive")
    s.disconnect()
    assert srv.subjects("INBOX") == ["drag-me", "other-client-flagged"]
    assert srv.subjects("Archive") == []


def test_happy_move_without_extensions_when_nothing_else_is_flagged(monkeypatch):
    srv, uid = _two_boxes(PLAIN, flagged_other=False)
    s = M.session(monkeypatch, srv)
    s.rename(f"/INBOX/{uid}_drag-me.eml", "/Archive")
    assert srv.subjects("INBOX") == []
    assert srv.subjects("Archive") == ["drag-me"]


def test_sad_a_message_flagged_in_between_keeps_the_original_and_says_so(monkeypatch):
    srv, uid = _two_boxes(PLAIN, flagged_other=False)
    srv.add_msg("INBOX", "late")
    # Another client flags "late" between our STORE and the EXPUNGE check.
    orig_uid = M.FakeIMAP.uid

    def racing_uid(self, cmd, *args):
        if cmd.upper() == "STORE" and args[1] == "+FLAGS":
            srv.flag("INBOX", "late")
        return orig_uid(self, cmd, *args)

    monkeypatch.setattr(M.FakeIMAP, "uid", racing_uid)
    s = M.session(monkeypatch, srv)
    with pytest.raises(OSError, match="stays in 'INBOX'"):
        s.move(uid, "INBOX", "Archive")
    s.disconnect()
    assert srv.subjects("INBOX") == ["drag-me", "late"]  # nothing expunged
    flags = {m["subj"]: m["flags"] for m in srv.boxes["INBOX"]["msgs"].values()}
    assert "\\Deleted" not in flags["drag-me"]  # unflagged again


def test_happy_move_with_uidplus_expunges_only_the_moved_message(monkeypatch):
    srv, uid = _two_boxes(UIDPLUS)
    s = M.session(monkeypatch, srv)
    s.rename(f"/INBOX/{uid}_drag-me.eml", "/Archive")
    s.disconnect()
    assert srv.subjects("INBOX") == ["other-client-flagged"]
    assert srv.subjects("Archive") == ["drag-me"]
    assert f"UID EXPUNGE {uid}" in srv.log


def test_happy_move_uses_the_move_extension_announced_after_login(monkeypatch):
    srv, uid = _two_boxes(PLAIN, auth_caps=("IMAP4REV1", "MOVE"))
    s = M.session(monkeypatch, srv)
    s.move(uid, "INBOX", "Archive")
    s.disconnect()
    assert srv.subjects("INBOX") == ["other-client-flagged"]
    assert srv.subjects("Archive") == ["drag-me"]
    assert not any(line.startswith("UID COPY") for line in srv.log)


def test_sad_rename_of_a_stale_name_moves_no_other_message(monkeypatch):
    srv = M.Server(caps=UIDPLUS)
    srv.add_box("INBOX")
    srv.add_box("Archive")
    srv.add_msg("INBOX", "hello")
    srv.add_msg("INBOX", "lunch")  # UID 2 is "lunch" now
    s = M.session(monkeypatch, srv)
    with pytest.raises(FileNotFoundError):
        s.rename("/INBOX/2_invoice.eml", "/Archive/2_invoice.eml")
    assert srv.subjects("INBOX") == ["hello", "lunch"]
    assert srv.subjects("Archive") == []


def test_sad_rename_and_move_of_a_uid_that_is_gone_are_file_not_found(monkeypatch):
    srv = M.Server(caps=UIDPLUS)
    srv.add_box("INBOX")
    srv.add_box("Archive")
    s = M.session(monkeypatch, srv)
    with pytest.raises(FileNotFoundError):
        s.rename("/INBOX/99_gone.eml", "/Archive/99_gone.eml")
    with pytest.raises(FileNotFoundError):
        s.move(99, "INBOX", "Archive")


def test_edge_rename_within_the_same_mailbox_is_refused(monkeypatch):
    srv = M.Server(caps=UIDPLUS)
    srv.add_box("INBOX")
    uid = srv.add_msg("INBOX", "a")
    s = M.session(monkeypatch, srv)
    with pytest.raises(OSError, match="cannot be renamed"):
        s.rename(f"/INBOX/{uid}_a.eml", "/INBOX/other.eml")
    assert srv.subjects("INBOX") == ["a"]
    assert len(srv.boxes["INBOX"]["msgs"]) == 1


# -- remove() of what is not there -----------------------------------------


def test_sad_remove_of_a_missing_mailbox_is_file_not_found(monkeypatch):
    srv = M.Server(caps=UIDPLUS)
    srv.add_box("INBOX")
    s = M.session(monkeypatch, srv)
    with pytest.raises(FileNotFoundError):
        s.remove("/NoSuchBox")


def test_sad_remove_of_a_name_that_is_no_message_is_file_not_found(monkeypatch):
    srv = M.Server(caps=UIDPLUS)
    srv.add_box("INBOX")
    s = M.session(monkeypatch, srv)
    with pytest.raises(FileNotFoundError):
        s.remove("/INBOX/notes.txt")
