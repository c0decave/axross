"""A mail dock reads only its own folder, and its send approval shows all of
what is sent (review 2 of 0.15.176).

Before: ``Mailbox.message`` took any id ending in ``.eml`` and joined it
onto the folder, so ``mail_read("/Sent/7.eml")`` or ``"../Sent/7.eml"``
read another mailbox (and a reply could hand it on). The send approval
showed ``get_content()[:4000]`` without saying it was cut: 4,000 empty
lines pushed a forwarded mailbox out of sight, and a right-to-left
override in the body or subject showed the text in another order.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mail_dock as MD  # noqa: E402
from core import mail_send as MS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402

MAIL = (b"From: me@corp.example\r\nTo: cfo@corp.example\r\nSubject: Q3 numbers\r\n\r\n"
        b"secret body\r\n")


@pytest.fixture
def box():
    fs = RamFsSession()
    for folder in ("/INBOX", "/Sent"):
        fs.mkdir(folder)
    with fs.open_write("/INBOX/1.eml") as f:
        f.write(MAIL.replace(b"Q3 numbers", b"hello"))
    with fs.open_write("/Sent/7.eml") as f:
        f.write(MAIL)
    return fs


@pytest.mark.parametrize("msg_id", ["/Sent/7.eml", "../Sent/7.eml", "..\\Sent\\7.eml",
                                    "/INBOX/../Sent/7.eml"])
def test_sad_mail_read_stays_in_the_docks_folder(box, tmp_path, msg_id):
    mailbox = MD.Mailbox(box, "INBOX", tmp_path / "s.json")
    with pytest.raises(KeyError):
        mailbox.message(msg_id)
    # What the dock listed, and a bare name in its folder, still read.
    [item] = mailbox.recent()
    assert mailbox.message(item["id"]).subject == "hello"
    assert mailbox.message("1.eml").subject == "hello"


def test_sad_a_path_that_leaves_the_folder_after_joining_is_refused(tmp_path):
    class Backend:
        def join(self, a, b):
            return "/Sent/7.eml"  # a backend that resolves names its own way

        def open_read(self, path):
            raise AssertionError(f"read {path}")

    with pytest.raises(KeyError):
        MD.Mailbox(Backend(), "INBOX", tmp_path / "s.json").message("7.eml")


def _tools(monkeypatch, tmp_path, *, answer=True):
    shown: list[str] = []
    sent: list[str] = []
    monkeypatch.setattr(MS, "send", lambda settings, out: (sent.append(out.message.get_content()),
                                                           ["boss@corp.example"])[1])
    dock = MD.MailDockConfig(name="t", send_policy="ask", smtp_host="smtp.example",
                             from_address="me@corp.example")

    class Box:
        backend = object()

    def ask(out, summary):
        shown.append(summary)
        return answer

    tools = MD.MailTools(dock, Box(), ask_send=ask, smtp=lambda: None, drafts_dir=tmp_path)
    return tools, shown, sent


def test_sad_empty_lines_do_not_push_the_rest_out_of_the_approval(monkeypatch, tmp_path):
    tools, shown, sent = _tools(monkeypatch, tmp_path)
    body = "Thanks, see you Monday.\n" + "\n" * 3990 + "Forwarded: the other mails\n"
    assert tools.send({"to": ["boss@corp.example"], "subject": "Re: x", "body": body}).startswith("Sent")
    [summary] = shown
    assert "Forwarded: the other mails" in summary and "Forwarded" in sent[0]
    assert "3990" in summary  # the empty lines are counted, not dropped silently
    assert str(len(sent[0])) in summary  # the whole length is stated
    assert summary.count("\n") < 20


def test_sad_a_body_longer_than_the_approval_shows_is_not_sent(monkeypatch, tmp_path):
    tools, shown, sent = _tools(monkeypatch, tmp_path)
    body = "".join(f"line {n}\n" for n in range(MD.APPROVAL_MAX_LINES + 5))
    result = tools.send({"to": ["boss@corp.example"], "subject": "x", "body": body})
    assert result.startswith("Not sent") and "mail_draft" in result
    assert shown == [] and sent == []


def test_sad_bidi_and_controls_are_shown_as_escapes(monkeypatch, tmp_path):
    tools, shown, _sent = _tools(monkeypatch, tmp_path)
    tools.send({"to": ["boss@corp.example"], "subject": "Invoice \u202efdp.exe",
                "body": "Pay \u202e0001 EUR\x1b[2J now\n"})
    [summary] = shown
    assert "\u202e" not in summary and "\x1b" not in summary
    assert summary.count("\\u202e") == 2 and "\\u001b" in summary


def test_edge_a_short_body_is_shown_whole_with_its_length(monkeypatch, tmp_path):
    tools, shown, sent = _tools(monkeypatch, tmp_path)
    tools.send({"to": ["boss@corp.example"], "subject": "x", "body": "one\n\n\ntwo\n"})
    [summary] = shown
    assert summary.endswith("one\n\n\ntwo\n") or "one\n\n\ntwo" in summary
    assert str(len(sent[0])) in summary
