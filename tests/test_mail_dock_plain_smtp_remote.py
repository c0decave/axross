"""A mail dock with SMTP without TLS to a remote server is refused when saved.

core.mail_send refuses plain SMTP to anything but this machine at every
send, so such a dock was saved and then failed at each run; the password
never went out in clear, but the setting was accepted without a word. The
dock's validate() refuses it now, and the dialog shows its sentences in the
interface language.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import mail_dock as MD  # noqa: E402


def _dock(**kw):
    base = dict(name="d", mailbox_profile="box", send_policy="ask", smtp_host="mail.example.org",
                smtp_security="plain", from_address="me@example.org")
    base.update(kw)
    return MD.MailDockConfig(**base)


def test_sad_plain_smtp_to_a_remote_server_is_refused():
    with pytest.raises(ValueError, match="without TLS"):
        _dock().validate()


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_happy_plain_smtp_to_this_machine_is_allowed(host):
    _dock(smtp_host=host).validate()


def test_edge_no_sending_means_no_smtp_check():
    _dock(send_policy="never").validate()
    _dock(smtp_security="starttls").validate()


def test_happy_every_validate_sentence_has_a_german_entry():
    catalogue = json.loads((Path(__file__).resolve().parents[1] / "resources" / "i18n" / "de.json")
                           .read_text("utf-8"))
    sentences = []
    for dock in (_dock(name=" "), _dock(mailbox_profile=""), _dock(interval_minutes=0),
                 _dock(smtp_host=""), _dock()):
        with pytest.raises(ValueError) as caught:
            dock.validate()
        sentences.append(str(caught.value))
    assert [s for s in sentences if s not in catalogue] == []
