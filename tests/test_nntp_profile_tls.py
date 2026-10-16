"""An NNTP profile chooses between TLS and plain, like IMAP and POP3.

news.gmane.io serves NNTP on 119 only (with STARTTLS), no NNTPS on 563.
A profile could not reach it: ConnectionManager never passed use_tls,
so NntpSession's default (implicit TLS) applied on every port and 119
failed with "WRONG_VERSION_NUMBER" - although the registry promised
"profile can override to 119". ``nntp_ssl`` (default True, port 563)
now travels from the profile and the dialog to the backend. open_url
builds NNTP directly from nntp:// / nntps:// and needs no profile.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import connection_manager as CM  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402


class _Recorder:
    calls: list[dict] = []

    def __init__(self, **kw):
        _Recorder.calls.append(kw)


@pytest.fixture
def recorded(monkeypatch):
    _Recorder.calls = []
    monkeypatch.setattr(CM, "load_backend_class", lambda proto: _Recorder)
    return _Recorder.calls


def _build(profile):
    return CM.ConnectionManager()._create_session(profile, "", None, None)


# --- happy ----------------------------------------------------------------


def test_happy_a_plain_profile_reaches_port_119_without_tls(recorded):
    _build(ConnectionProfile(name="g", protocol="nntp", host="news.example.org",
                             port=119, nntp_ssl=False))
    assert recorded[-1]["use_tls"] is False and recorded[-1]["port"] == 119


def test_happy_the_default_stays_implicit_tls(recorded):
    p = ConnectionProfile(name="g", protocol="nntp", host="news.example.org", port=563)
    assert p.nntp_ssl is True
    _build(p)
    assert recorded[-1]["use_tls"] is True


def test_happy_the_choice_survives_a_save(recorded):
    p = ConnectionProfile(name="g", protocol="nntp", host="h", port=119, nntp_ssl=False)
    d = p.to_dict()
    assert d["nntp_ssl"] is False
    assert ConnectionProfile.from_dict(d).nntp_ssl is False


# --- sad ------------------------------------------------------------------


def test_sad_an_old_profile_without_the_field_keeps_tls():
    p = ConnectionProfile.from_dict({"name": "old", "protocol": "nntp", "host": "h", "port": 563})
    assert p.nntp_ssl is True


def test_sad_other_protocols_do_not_carry_the_field():
    d = ConnectionProfile(name="f", protocol="ftp", host="h", nntp_ssl=False).to_dict()
    assert "nntp_ssl" not in d


# --- edge -----------------------------------------------------------------


def test_edge_the_dialog_shows_and_keeps_the_choice(tmp_path, monkeypatch):
    from core import profiles as P

    monkeypatch.setattr(P, "PROFILES_FILE", tmp_path / "profiles.json")
    from PyQt6.QtWidgets import QApplication

    from ui.connection_dialog import ConnectionDialog

    from core.profiles import ProfileManager

    _app = QApplication.instance() or QApplication([])
    dlg = ConnectionDialog(ProfileManager(), profile=ConnectionProfile(
        name="g", protocol="nntp", host="news.example.org", port=119, nntp_ssl=False))
    dlg.show()
    assert dlg._nntp_ssl.isVisible() and not dlg._nntp_ssl.isChecked()
    assert dlg._build_profile().nntp_ssl is False
    dlg._nntp_ssl.setChecked(True)
    assert dlg._build_profile().nntp_ssl is True
    dlg.close()
