"""POP3 mail reaches the mail docks and the Mail Project.

Review 4 (features/extensions): POP3 lists its mail at "/", but a mail
dock's folder could only be "INBOX" (an empty folder or "/" became
"INBOX"), so a dock on a POP3 mailbox never saw a message. And
``Pop3Session.join("/", "1_x.eml")`` gave "//1_x.eml", which no message
path matches: the Mail Project's import of "/" read nothing ("could not be
read" for every message) and its default "/INBOX" listed nothing.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mail_fuzz_servers import FakePop3Server  # noqa: E402

from core import mail_dock as MD  # noqa: E402
from core import pop3_client as P  # noqa: E402


def _retr(arg: str) -> bytes:
    n = arg.strip()
    return (f"+OK\r\nFrom: a{n}@example.org\r\nSubject: mail {n}\r\n"
            f"Message-ID: <m{n}@example.org>\r\n\r\nbody {n}\r\n.\r\n").encode()


@pytest.fixture
def pop():
    srv = FakePop3Server({"RETR": _retr})
    session = P.Pop3Session(srv.host, srv.port, "u", "p", use_ssl=False)
    yield session
    session.close()
    srv.close()


def test_happy_join_of_the_root_and_a_message_is_one_slash(pop):
    assert pop.join("/", "1_x.eml") == "/1_x.eml"
    assert pop.join("", "1_x.eml") == "/1_x.eml"
    assert pop.join("/") == "/"


@pytest.mark.parametrize("folder", ["INBOX", "/", "", "/INBOX"])
def test_happy_a_dock_on_pop3_sees_the_mail_whatever_its_folder(pop, tmp_path, folder):
    box = MD.Mailbox(pop, folder, tmp_path / "seen.json")
    new = box.new(mark=False)
    assert [m["name"] for m in new] == ["1_hello.eml", "2_hello.eml"]
    msg = box.message(new[0]["id"])
    assert "mail 1" in (msg.subject or "")


def test_sad_a_dock_on_pop3_reads_nothing_outside_the_mailbox(pop, tmp_path):
    box = MD.Mailbox(pop, "INBOX", tmp_path / "seen.json")
    with pytest.raises(KeyError):
        box.message("../1_hello.eml")
    with pytest.raises(KeyError):
        box.message("/Sent/1_hello.eml")


def test_happy_mail_project_imports_pop3_from_root_and_from_the_default_inbox(pop, tmp_path):
    from core.mail_project import MailProject

    project = MailProject(tmp_path / "proj")
    try:
        first = project.import_backend(pop, "/")
        assert (first.added, first.errors) == (2, [])
        again = project.import_backend(pop, "/INBOX")   # the dialog's default
        assert (again.added, again.known, again.errors) == (0, 2, [])
    finally:
        project.close()


def test_edge_an_imap_like_backend_keeps_its_inbox(tmp_path):
    class Folders:
        def list_dir(self, path):
            self.asked = path
            return []

    backend = Folders()
    box = MD.Mailbox(backend, "", tmp_path / "seen.json")
    assert box.folder == "INBOX"
    box.new(mark=False)
    assert backend.asked == "/INBOX"
