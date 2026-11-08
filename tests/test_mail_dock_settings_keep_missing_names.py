"""A mail dock's settings never swap a gone name for the first entry, and
an SMTP password that no keyring took is reported.

Review 4 (features/extensions):
- OK in Settings… put the first combo entry in place of a saved mailbox,
  LLM or sandbox profile that had been renamed or deleted: a dock set up
  with the "strict" sandbox ran with "(no sandbox)" from then on, without
  a word (a security downgrade).
- The SMTP password went to ``keyring`` directly, bypassing
  core.credentials, and its result was ignored: with no usable keyring it
  was dropped silently and every send failed at the login.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

from core import credentials  # noqa: E402
from core import mail_dock as MD  # noqa: E402

APP = QApplication.instance() or QApplication([])


def _dialog(dock, **kw):
    from ui.mail_docks import MailDockDialog

    args = dict(mailboxes=["private-imap", "boss-imap"], llms=["cloud-llm"], sandboxes=["other"], docks=[])
    args.update(kw)
    return MailDockDialog(dock, **args)


GONE = MD.MailDockConfig(name="Work", mailbox_profile="old-imap", sandbox="strict",
                         llm_profile="work-llm", interval_minutes=10)


def test_happy_gone_names_are_shown_as_missing_and_not_saved_silently():
    dlg = _dialog(GONE)
    assert "old-imap" in dlg.mailbox.currentText() and "missing" in dlg.mailbox.currentText()
    assert "strict" in dlg.sandbox.currentText() and "missing" in dlg.sandbox.currentText()
    assert "work-llm" in dlg.llm.currentText() and "missing" in dlg.llm.currentText()
    dlg.interval.setValue(15)   # the user only changes the interval
    with mock.patch.object(QMessageBox, "warning") as warn:
        dlg._accept()
    assert dlg.result_dock is None
    text = warn.call_args.args[2]
    assert "strict" in text and "old-imap" in text and "work-llm" in text
    dlg.deleteLater()


def test_happy_choosing_present_entries_saves_them():
    dlg = _dialog(GONE)
    dlg.mailbox.setCurrentIndex(dlg.mailbox.findData("boss-imap"))
    dlg.sandbox.setCurrentIndex(dlg.sandbox.findData(""))   # "(no sandbox)" on purpose
    dlg.llm.setCurrentIndex(dlg.llm.findData("cloud-llm"))
    with mock.patch.object(QMessageBox, "warning") as warn:
        dlg._accept()
    assert not warn.called
    got = dlg.result_dock
    assert (got.mailbox_profile, got.sandbox, got.llm_profile) == ("boss-imap", "", "cloud-llm")
    dlg.deleteLater()


def test_sad_only_a_missing_sandbox_still_blocks_the_save():
    dock = MD.MailDockConfig(name="Work", mailbox_profile="boss-imap", sandbox="strict")
    dlg = _dialog(dock)
    assert dlg.mailbox.currentData() == "boss-imap"
    with mock.patch.object(QMessageBox, "warning") as warn:
        dlg._accept()
    assert dlg.result_dock is None and "strict" in warn.call_args.args[2]
    dlg.deleteLater()


def test_edge_a_present_saved_name_round_trips_unchanged():
    dock = MD.MailDockConfig(name="Work", mailbox_profile="boss-imap", sandbox="other",
                             llm_profile="cloud-llm")
    dlg = _dialog(dock)
    assert dlg.missing_choices() == []
    got = dlg.config()
    assert (got.mailbox_profile, got.sandbox, got.llm_profile) == ("boss-imap", "other", "cloud-llm")
    dlg.deleteLater()


def _send_dock():
    return MD.MailDockConfig(name="W", mailbox_profile="imap", send_policy="ask",
                             smtp_host="smtp.example.org", from_address="me@example.org")


def test_sad_an_smtp_password_no_keyring_took_is_reported(monkeypatch):
    monkeypatch.setattr(credentials, "_keyring_checked", True)
    monkeypatch.setattr(credentials, "_keyring_usable", False)
    monkeypatch.setattr(credentials, "recheck_keyring", lambda: False)
    dlg = _dialog(_send_dock(), mailboxes=["imap"], llms=[], sandboxes=[])
    dlg.smtp_password.setText("s3cret")
    with mock.patch.object(QMessageBox, "warning") as warn:
        dlg._accept()
    assert warn.called and "not saved" in warn.call_args.args[2]
    assert dlg.result_dock is not None      # the other settings are kept
    assert MD.smtp_password(dlg.result_dock) == ""
    dlg.deleteLater()


def test_happy_the_smtp_password_goes_through_core_credentials(monkeypatch):
    stored = {}
    monkeypatch.setattr(credentials, "store_password",
                        lambda name, pw: stored.__setitem__(name, pw) or True)
    monkeypatch.setattr(credentials, "get_password", lambda name: stored.get(name))
    dlg = _dialog(_send_dock(), mailboxes=["imap"], llms=[], sandboxes=[])
    dlg.smtp_password.setText("s3cret")
    with mock.patch.object(QMessageBox, "warning") as warn:
        dlg._accept()
    assert not warn.called
    assert MD.smtp_password(dlg.result_dock) == "s3cret"
    assert list(stored) == [f"mail-dock-smtp:{dlg.result_dock.dock_id}"]
    dlg.deleteLater()
