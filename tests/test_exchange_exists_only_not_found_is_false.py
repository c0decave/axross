"""Exchange: exists() and is_dir() say False only for "not found".

exists() and is_dir() turned every stat() failure into False. stat()
already kept a network error apart from "not found" while it tried the
folder and attachment-folder readings of a path, but the message (.eml)
and attachment readings let any OSError through - a reset connection or
an ErrorAccessDenied while fetching the message came back as "absent".

And "not found" itself was recognised by wording only: exchangelib's
folder lookup raises ErrorFolderNotFound("No subfolder with name 'x'"),
which matched none of the markers. stat() of an existing message
therefore raised at its first (folder) reading, exists() said False for
every message, and mkdir() refused every new folder ("duplicate probe
failed"). The not-found check now knows exchangelib's not-found errors
by type.

The folder tree mirrors exchangelib: ``/`` raises ErrorFolderNotFound
with exchangelib's message, ``filter(id=...)`` returns the matches.
"""

from __future__ import annotations

from types import SimpleNamespace
from unittest import mock

import pytest

errors = pytest.importorskip("exchangelib.errors")

from core import exchange_client as EC  # noqa: E402
from core.server_ops import server_side_copy  # noqa: E402


class _Folder:
    def __init__(self, name, children=(), messages=()):
        self.name = name
        self.children = list(children)
        self.messages = list(messages)
        self.fail: Exception | None = None  # raised by every message fetch

    def __truediv__(self, other):
        for c in self.children:
            if c.name.lower() == other.lower():
                return c
        raise errors.ErrorFolderNotFound(f"No subfolder with name {other!r}")

    def filter(self, id):  # noqa: A002 - exchangelib's keyword
        folder = self

        class _Query:
            def only(self, *fields):
                return self

            def __iter__(self):
                if folder.fail is not None:
                    raise folder.fail
                return iter([m for m in folder.messages if m.id == id])

        return _Query()


def _msg(mid, subject, attachments=()):
    return SimpleNamespace(id=mid, subject=subject, size=10, datetime_received=None,
                           has_attachments=bool(attachments), attachments=list(attachments))


def _session():
    inbox = _Folder("Inbox", messages=[
        _msg("M1", "hi"),
        _msg("M2", "files", [SimpleNamespace(name="report.pdf", size=7)]),
    ])
    s = object.__new__(EC.ExchangeSession)
    s._account = SimpleNamespace(root=_Folder("root", [inbox]))
    return s, inbox


def test_happy_present_and_absent():
    s, _ = _session()
    assert s.exists("/Inbox") is True
    assert s.exists("/Inbox/M1_hi.eml") is True
    assert s.exists("/Inbox/M2") is True  # the attachments folder
    assert s.exists("/Inbox/M2/report.pdf") is True
    assert s.exists("/Missing") is False
    assert s.exists("/Inbox/M9_gone.eml") is False
    assert s.exists("/Missing/M1_hi.eml") is False
    assert s.exists("/Inbox/M2/other.pdf") is False


def test_happy_stat_of_a_message_and_of_a_missing_path():
    s, _ = _session()
    item = s.stat("/Inbox/M1_hi.eml")
    assert (item.name, item.is_dir) == ("M1_hi.eml", False)
    with pytest.raises(FileNotFoundError):
        s.stat("/Inbox/M9_gone.eml")


def test_happy_is_dir():
    s, _ = _session()
    assert s.is_dir("/Inbox") is True
    assert s.is_dir("/Inbox/M2") is True
    assert s.is_dir("/Inbox/M1_hi.eml") is False
    assert s.is_dir("/Missing") is False


@pytest.mark.parametrize(
    "fail",
    [
        errors.ErrorAccessDenied("Access is denied. Check credentials and try again."),
        errors.TransportError("HTTPSConnectionPool: Read timed out."),
        ConnectionResetError("connection reset by peer"),
        errors.ErrorServerBusy("The server cannot service this request right now."),
    ],
)
def test_sad_a_failed_message_fetch_is_an_oserror(fail):
    s, inbox = _session()
    inbox.fail = fail
    for path in ("/Inbox/M1_hi.eml", "/Inbox/M2/report.pdf", "/Inbox/M2"):
        with pytest.raises(OSError) as info:
            s.exists(path)
        assert not isinstance(info.value, FileNotFoundError), path
    with pytest.raises(OSError):
        s.is_dir("/Inbox/M2")


def test_sad_a_failed_folder_lookup_is_an_oserror():
    s, _ = _session()
    root = mock.MagicMock()
    root.__truediv__.side_effect = errors.TransportError("connection reset")
    s._account = SimpleNamespace(root=root)
    with pytest.raises(OSError) as info:
        s.exists("/Inbox")
    assert not isinstance(info.value, FileNotFoundError)


def test_sad_no_clobber_copy_keeps_the_target_when_the_probe_fails():
    s, inbox = _session()
    inbox.fail = errors.TransportError("Read timed out.")
    with mock.patch.object(EC.ExchangeSession, "copy") as copy:
        with pytest.raises(OSError):
            server_side_copy(s, "/Inbox/M2_files.eml", "/Inbox/M1_hi.eml", overwrite=False)
    copy.assert_not_called()


@pytest.mark.parametrize(
    "exc",
    [
        errors.ErrorFolderNotFound("No subfolder with name 'x'"),
        errors.ErrorItemNotFound("The specified object was not found in the store."),
        errors.ErrorInvalidIdMalformed("Id is malformed."),
    ],
)
def test_edge_exchangelib_not_found_errors_are_not_found(exc):
    assert EC._is_not_found(exc) is True
    try:
        try:
            raise exc
        except Exception as inner:
            raise OSError(f"Exchange folder lookup x: {inner}") from inner
    except OSError as wrapped:
        assert EC._is_not_found(wrapped) is True


def test_edge_an_upload_name_that_is_no_message_id_is_absent():
    # "notes.eml" names no message: EWS answers its id as malformed.
    s, inbox = _session()
    inbox.fail = errors.ErrorInvalidIdMalformed("Id is malformed.")
    assert s.exists("/Inbox/notes.eml") is False


def test_edge_mkdir_creates_a_folder_exchangelib_does_not_find():
    s, _ = _session()
    created = {}

    class _NewFolder:
        def __init__(self, *, parent, name):
            created["name"] = name

        def save(self):
            created["saved"] = True

    with mock.patch.object(EC, "Folder", _NewFolder):
        s.mkdir("/Inbox/Projects")
    assert created == {"name": "Projects", "saved": True}


def test_edge_a_reset_during_the_fallback_scan_is_not_absence():
    # _child_folder retries a missed lookup by scanning the children; a
    # connection reset during that scan carries the miss only as its
    # context, not as its cause - it is no answer about the folder.
    class _Root(_Folder):
        def __truediv__(self, other):
            raise errors.ErrorFolderNotFound(f"No subfolder with name {other!r}")

        @property
        def children(self):
            raise errors.TransportError("connection reset during FindFolder")

        @children.setter
        def children(self, value):
            pass

    s, _ = _session()
    s._account = SimpleNamespace(root=_Root("root"))
    with pytest.raises(OSError) as info:
        s.exists("/Inbox")
    assert not isinstance(info.value, FileNotFoundError)
