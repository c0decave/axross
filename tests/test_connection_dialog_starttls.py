"""Connect to Server: IMAP, POP3 and LDAP show their TLS mode - implicit TLS,
STARTTLS before the login (the default without it) or, with the STARTTLS box
unticked, plain text - and a saved profile keeps it."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from test_registry_only_protocols_connect import APP, dialog  # noqa: E402,F401

from core import conn_security as CS  # noqa: E402
from core.profiles import ProfileManager  # noqa: E402


@pytest.mark.parametrize("proto", ["imap", "pop3", "ldap"])
def test_happy_the_starttls_box_is_shown_and_kept(dialog, proto):  # noqa: F811
    pick, _warnings = dialog
    dlg = pick(proto)
    tls_box, starttls_box = getattr(dlg, f"_{proto}_ssl"), getattr(dlg, f"_{proto}_starttls")
    assert starttls_box.isVisible() and starttls_box.isChecked()
    tls_box.setChecked(True)
    assert not starttls_box.isEnabled()  # implicit TLS: STARTTLS means nothing
    tls_box.setChecked(False)
    assert starttls_box.isEnabled()
    dlg._host.setText("dir.example")
    dlg._username.setText("u")
    profile = dlg._build_profile()
    assert profile.tls_mode() == "starttls"
    assert CS.from_profile(profile).level == CS.LEVEL_TLS

    starttls_box.setChecked(False)
    dlg._save_profile()
    saved = ProfileManager().get(f"my-{proto}")
    assert saved.tls_mode() == "plain"
    assert CS.from_profile(saved).level == CS.LEVEL_CLEARTEXT
    dlg._clear_fields()
    assert starttls_box.isChecked()
    dlg._load_profile(saved)
    assert not starttls_box.isChecked() and not tls_box.isChecked()


@pytest.mark.parametrize("proto", ["imap", "pop3", "ldap"])
def test_happy_other_protocols_hide_the_box(dialog, proto):  # noqa: F811
    pick, _warnings = dialog
    dlg = pick("sftp")
    assert not getattr(dlg, f"_{proto}_starttls").isVisible()
