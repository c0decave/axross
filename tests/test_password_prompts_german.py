"""The password and passphrase prompts speak the interface language.

UX review round 5 (blocker): every Quick Connect, session-restore and host
terminal prompt was an f-string outside tr() - "Password for SMB \\\\nas\\share:",
"Passphrase for the key …:", "Wrong passphrase. …", "Session restore:
Password for '…'" - English in the German window.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from core.profiles import ConnectionProfile  # noqa: E402


@pytest.fixture
def german(monkeypatch):
    from core import i18n

    monkeypatch.setattr(i18n, "_ACTIVE", i18n.Translator("de"))


def _profile(protocol: str, **kw) -> ConnectionProfile:
    return ConnectionProfile(name="p", protocol=protocol, host="nas", username="bob", **kw)


@pytest.mark.parametrize(
    ("protocol", "extra", "expected"),
    [
        ("smb", {"smb_share": "data"}, "Passwort für SMB \\\\nas\\data:"),
        ("ftp", {}, "Passwort für FTP bob@nas:"),
        ("imap", {}, "Passwort für IMAP bob@nas:"),
        ("webdav", {"webdav_url": "https://dav/x"}, "Passwort für WebDAV https://dav/x:"),
    ],
)
def test_happy_quick_connect_asks_in_german(german, protocol, extra, expected):
    from ui.main_window import _simple_password_prompt

    ask, label = _simple_password_prompt(_profile(protocol, **extra))
    assert ask and label == expected


def test_sad_no_english_word_in_any_german_prompt(german):
    from ui.main_window import SIMPLE_PASSWORD_PROTOCOLS, _simple_password_prompt

    seen = 0
    for protocol in sorted(SIMPLE_PASSWORD_PROTOCOLS):
        ask, label = _simple_password_prompt(_profile(protocol, s3_bucket="b",
                                                      azure_account_name="acc"))
        if not ask:
            continue
        seen += 1
        assert "Password for" not in label and "for S3" not in label, (protocol, label)
    assert seen >= 5


def test_edge_the_passphrase_prompt_and_its_retry(german):
    from ui.main_window import _passphrase_prompt

    assert _passphrase_prompt("/k/id", False) == "Passphrase für den Schlüssel /k/id:"
    assert _passphrase_prompt("/k/id", True) == (
        "Falsche Passphrase. Passphrase für den Schlüssel /k/id:")


def test_edge_english_stays_as_it_was():
    from ui.main_window import _passphrase_prompt, _simple_password_prompt

    assert _passphrase_prompt("/k/id", True) == "Wrong passphrase. Passphrase for the key /k/id:"
    assert _simple_password_prompt(_profile("ftp"))[1] == "Password for FTP bob@nas:"
