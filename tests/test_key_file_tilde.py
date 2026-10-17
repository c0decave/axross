"""A key file typed as ``~/.ssh/<key>`` is the key in the home directory.

Before: the connection dialog checked ``Path(key_file).expanduser()`` but
stored the text as typed, and the SSH / SCP clients opened the literal
path ``~/.ssh/<key>``: FileNotFoundError on every connect of a profile
that had passed validation. A profile stored with ``~`` (an import, a
script, a hand edit) failed the same way.

Now the dialog stores the expanded path it validated, and the connection
manager expands a leading ``~`` once, centrally, in the profile every
backend sees (``effective_profile``) - without changing the caller's
profile.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.connection_manager import ConnectionManager, effective_profile  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402

_APP = None


def _key_profile(key_file: str) -> ConnectionProfile:
    return ConnectionProfile(
        name="k", protocol="sftp", host="h.example", username="u",
        auth_type="key", key_file=key_file,
    )


def test_happy_the_backend_sees_the_expanded_key_path():
    profile = _key_profile("~/.ssh/id_test")
    resolved = effective_profile(profile)
    assert resolved.key_file == os.path.join(str(Path.home()), ".ssh", "id_test")


def test_sad_the_callers_profile_is_not_changed():
    profile = _key_profile("~/.ssh/id_test")
    effective_profile(profile)
    assert profile.key_file == "~/.ssh/id_test"


def test_edge_an_absolute_or_empty_key_path_is_left_alone():
    absolute = _key_profile("/keys/id")
    assert effective_profile(absolute) is absolute
    empty = _key_profile("")
    assert effective_profile(empty) is empty


def test_happy_connect_hands_the_ssh_session_the_expanded_path():
    seen: list[str] = []

    class _Session:
        def __init__(self, profile):
            seen.append(profile.key_file)

        def connect(self, **_kw):
            raise OSError("stop here")

    cm = ConnectionManager()
    with mock.patch("core.connection_manager._session_class", return_value=_Session):
        with pytest.raises(OSError):
            cm.connect(_key_profile("~/.ssh/id_test"))
    assert seen == [os.path.join(str(Path.home()), ".ssh", "id_test")]


def test_edge_the_session_key_uses_the_expanded_path():
    cm = ConnectionManager()
    home = os.path.join(str(Path.home()), ".ssh", "id_test")
    assert cm._session_key(_key_profile("~/.ssh/id_test")) == cm._session_key(_key_profile(home))


def test_happy_the_dialog_stores_the_path_it_validated():
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from PyQt6.QtWidgets import QApplication

    global _APP  # a QApplication nobody references is collected at once
    _APP = QApplication.instance() or QApplication([])
    from core.profiles import ProfileManager
    from ui.connection_dialog import ConnectionDialog

    key = Path.home() / ".ssh" / "id_dialog"
    key.parent.mkdir(exist_ok=True)
    key.write_text("not a real key")
    try:
        dlg = ConnectionDialog(ProfileManager())
        dlg._host.setText("h.example")
        dlg._username.setText("u")
        dlg._auth_key.setChecked(True)
        dlg._key_file.setText("~/.ssh/id_dialog")
        assert dlg._validate() is True
        assert dlg._build_profile().key_file == str(key)
    finally:
        key.unlink()
