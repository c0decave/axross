"""Connect to Server offers SQLite, PostgreSQL, Redis, MongoDB, Git, LDAP,
SLP and Exchange - and every one of them failed.

Before: the protocol list of the dialog is the backend registry, so all
eight were there to pick. But

* a saved profile came back as SFTP: ``ProfileManager`` threw an unknown
  protocol away on load (``VALID_PROTOCOLS`` did not name them);
* Connect and Test Connection ended in "Unsupported protocol: sqlite" -
  ``ConnectionManager._create_session`` had no branch for any of them;
* the dialog had no row for what they need (the database file, the
  database name, the LDAP TLS switch, the SLP scope, the Exchange
  mailbox) and demanded a username that SQLite, Git, Redis and SLP do
  not have.

Also here, of the same kind:

* Subversion asked for a username (an anonymous checkout has none) and
  had no password field, so a repository behind a login could not be
  opened at all; its URL went into a row labelled "Host" with the
  placeholder "hostname or IP".
* POP3 had a ``pop3_ssl`` profile field but no check box: plain POP3
  (port 110) could not be chosen.
* An imported profile without a port got 22 (the SFTP port) for IMAP,
  POP3, NNTP, LDAP, PostgreSQL, ...
"""

from __future__ import annotations

import os
import subprocess
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core.backend_registry import init_registry  # noqa: E402
from core.profiles import ConnectionProfile, ProfileManager  # noqa: E402

init_registry()

NEW = ("sqlite", "postgres", "redis", "mongodb", "git", "ldap", "slp", "exchange")


def _profile(proto: str, **kw) -> ConnectionProfile:
    base = dict(name=f"my-{proto}", protocol=proto)
    base.update(kw)
    return ConnectionProfile(**base)


#: A filled profile per protocol and the keyword arguments its backend
#: must be built with.
CASES = {
    "sqlite": (
        dict(host="/data/files.sqlite"),
        dict(url="/data/files.sqlite"),
    ),
    "postgres": (
        dict(host="db.example", port=5433, username="alice", db_name="files"),
        dict(host="db.example", port=5433, username="alice", password="pw", database="files"),
    ),
    "redis": (
        dict(host="cache.example", port=6380, db_name="3", db_tls=True),
        dict(host="cache.example", port=6380, password="pw", database=3, use_tls=True),
    ),
    "mongodb": (
        dict(host="mongo.example", port=27018, username="bob", db_name="store"),
        dict(host="mongo.example", port=27018, username="bob", password="pw", database="store"),
    ),
    "git": (
        dict(host="https://git.example/team/repo.git"),
        dict(url="https://git.example/team/repo.git"),
    ),
    "ldap": (
        dict(host="ldap.example", port=636, username="cn=admin,dc=example", ldap_ssl=True),
        dict(host="ldap.example", port=636, username="cn=admin,dc=example", password="pw",
             use_tls=True),
    ),
    "slp": (
        dict(host="10.0.0.9", port=427, slp_scope="LAB"),
        dict(host="10.0.0.9", port=427, scope="LAB"),
    ),
    "exchange": (
        dict(host="mail.example", username="EXAMPLE\\carol", exchange_email="carol@example.org"),
        dict(smtp_address="carol@example.org", username="EXAMPLE\\carol", password="pw",
             server="mail.example", autodiscover=False),
    ),
}


# ------------------------------------------------------------ profiles


@pytest.mark.parametrize("proto", NEW)
def test_happy_a_saved_profile_comes_back_with_its_protocol_and_fields(proto):
    fields, _kwargs = CASES[proto]
    profile = _profile(proto, **fields)
    back = ConnectionProfile.from_dict(profile.to_dict())
    assert back.protocol == proto
    for key, value in fields.items():
        assert getattr(back, key) == value, key


def test_happy_profiles_survive_the_file(tmp_path):
    with mock.patch("core.profiles.CONFIG_DIR", tmp_path), mock.patch(
        "core.profiles.PROFILES_FILE", tmp_path / "profiles.json"
    ):
        pm = ProfileManager()
        for proto in NEW:
            pm.add(_profile(proto, **CASES[proto][0]))
        again = ProfileManager()
        assert {n: again.get(n).protocol for n in again.list_names()} == {
            f"my-{p}": p for p in NEW
        }


@pytest.mark.parametrize(
    "proto, port",
    [("imap", 993), ("pop3", 995), ("nntp", 563), ("gopher", 70), ("pjl", 9100),
     ("ldap", 389), ("postgres", 5432), ("redis", 6379), ("mongodb", 27017), ("slp", 427)],
)
def test_edge_an_imported_profile_without_a_port_gets_the_protocols_port(proto, port):
    """Not 22, the SFTP port, for every protocol."""
    back = ConnectionProfile.from_dict({"name": "x", "protocol": proto, "host": "h"})
    assert back.port == port


def test_edge_an_imported_profile_without_a_port_of_plain_imap_and_pop3():
    """The TLS switch picks the port of the plain variant."""
    assert ConnectionProfile.from_dict(
        {"name": "x", "protocol": "imap", "host": "h", "imap_ssl": False}).port == 143
    assert ConnectionProfile.from_dict(
        {"name": "x", "protocol": "pop3", "host": "h", "pop3_ssl": False}).port == 110
    assert ConnectionProfile.from_dict(
        {"name": "x", "protocol": "nntp", "host": "h", "nntp_ssl": False}).port == 119


# ------------------------------------------------------------ connection manager


@pytest.mark.parametrize("proto", NEW)
def test_happy_the_connection_manager_builds_each_backend(proto):
    from core.connection_manager import ConnectionManager

    fields, expected = CASES[proto]
    built: dict = {}

    class FakeBackend:
        connected = True

        def __init__(self, *args, **kwargs):
            built.update(kwargs)

        def close(self):
            pass

    with mock.patch("core.connection_manager.load_backend_class", return_value=FakeBackend):
        ConnectionManager()._create_session(_profile(proto, **fields), "pw", "", None)
    for key, value in expected.items():
        assert built.get(key) == value, (key, built)


def test_happy_exchange_without_server_autodiscovers_with_the_username_as_mailbox():
    from core.connection_manager import ConnectionManager

    built: dict = {}

    class FakeBackend:
        def __init__(self, *args, **kwargs):
            built.update(kwargs)

    with mock.patch("core.connection_manager.load_backend_class", return_value=FakeBackend):
        ConnectionManager()._create_session(
            _profile("exchange", username="dave@example.org"), "pw", "", None)
    assert built["smtp_address"] == "dave@example.org"
    assert built["autodiscover"] is True
    assert "server" not in built or not built["server"]


def test_happy_git_local_path_opens_the_repository_itself():
    from core.connection_manager import ConnectionManager

    built: dict = {}

    class FakeBackend:
        def __init__(self, *args, **kwargs):
            built.update(kwargs)

    with mock.patch("core.connection_manager.load_backend_class", return_value=FakeBackend):
        ConnectionManager()._create_session(_profile("git", host="~/src/repo"), "", "", None)
    assert built.get("path") == os.path.expanduser("~/src/repo")
    assert not built.get("url")


def test_e2e_a_sqlite_profile_connects_and_lists(tmp_path):
    from core.connection_manager import ConnectionManager

    db = tmp_path / "files.sqlite"
    cm = ConnectionManager()
    session = cm.connect(_profile("sqlite", host=str(db)))
    try:
        session.mkdir("/docs")
        with session.open_write("/docs/a.txt") as fh:
            fh.write(b"hello")
        assert [i.name for i in session.list_dir("/docs")] == ["a.txt"]
    finally:
        cm.disconnect_all()


def test_e2e_a_local_git_repository_connects_and_lists(tmp_path):
    pytest.importorskip("dulwich")
    from core.connection_manager import ConnectionManager

    repo = tmp_path / "repo"
    env = dict(os.environ, GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@e",
               GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@e")
    subprocess.run(["git", "init", "-q", "-b", "main", str(repo)], check=True, env=env)
    (repo / "readme.txt").write_text("hi")
    subprocess.run(["git", "-C", str(repo), "add", "readme.txt"], check=True, env=env)
    subprocess.run(["git", "-C", str(repo), "commit", "-q", "-m", "one"], check=True, env=env)
    cm = ConnectionManager()
    session = cm.connect(_profile("git", host=str(repo)))
    try:
        assert session.home() == "/main"
        assert "readme.txt" in [i.name for i in session.list_dir("/main")]
    finally:
        cm.disconnect_all()


def test_sad_two_sqlite_profiles_on_two_files_are_two_sessions(tmp_path):
    from core.connection_manager import ConnectionManager

    cm = ConnectionManager()
    a = _profile("sqlite", name="a", host=str(tmp_path / "a.sqlite"))
    b = _profile("sqlite", name="b", host=str(tmp_path / "b.sqlite"))
    assert cm._session_key(a) != cm._session_key(b)
    for field_name, one, two in (("db_name", "x", "y"), ("db_tls", False, True),
                                 ("ldap_ssl", False, True), ("slp_scope", "A", "B"),
                                 ("exchange_email", "a@x", "b@x")):
        p1 = _profile("redis", host="h", **{field_name: one})
        p2 = _profile("redis", host="h", **{field_name: two})
        assert cm._session_key(p1) != cm._session_key(p2), field_name


# ------------------------------------------------------------ passwords


@pytest.mark.parametrize(
    "proto, fields, needed",
    [
        ("svn", dict(host="https://svn.example/r", username="u"), True),
        ("svn", dict(host="svn://svn.example/r"), False),
        ("postgres", dict(host="h", username="u", db_name="d"), True),
        ("mongodb", dict(host="h", username="u"), True),
        ("mongodb", dict(host="h"), False),
        ("ldap", dict(host="h", username="cn=a"), True),
        ("ldap", dict(host="h"), False),
        ("exchange", dict(username="a@b"), True),
        ("sqlite", dict(host="/x.db"), False),
        ("git", dict(host="/x"), False),
        ("slp", dict(host="h"), False),
    ],
)
def test_happy_a_password_is_asked_for_where_one_is_used(proto, fields, needed):
    from core.profiles import password_needed

    assert password_needed(_profile(proto, **fields)) is needed


def test_happy_redis_asks_for_a_password_when_one_is_kept():
    from core.profiles import password_needed

    assert password_needed(_profile("redis", host="h")) is False
    assert password_needed(_profile("redis", host="h", store_password=True)) is True


# ------------------------------------------------------------ the dialog

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")

from PyQt6.QtWidgets import QApplication, QMessageBox  # noqa: E402

APP = QApplication.instance() or QApplication([])


@pytest.fixture
def dialog():
    from ui.connection_dialog import ConnectionDialog

    warnings: list[str] = []
    with tempfile.TemporaryDirectory() as tmp, mock.patch(
        "core.profiles.CONFIG_DIR", Path(tmp)
    ), mock.patch("core.profiles.PROFILES_FILE", Path(tmp) / "profiles.json"), mock.patch.object(
        QMessageBox, "warning", side_effect=lambda *a, **k: warnings.append(a[2])
    ), mock.patch.object(QMessageBox, "information"), mock.patch.object(
        ConnectionDialog, "_validate_backend_available", return_value=True
    ):
        dlg = ConnectionDialog(ProfileManager())
        dlg.show()
        APP.processEvents()

        def pick(proto: str):
            dlg._clear_fields()
            dlg._protocol_combo.setCurrentIndex(dlg._protocol_ids.index(proto))
            APP.processEvents()
            dlg._profile_name.setText(f"my-{proto}")
            warnings.clear()
            return dlg

        yield pick, warnings
        dlg.close()


#: What the user types per protocol: widget attribute -> value.
TYPED = {
    "sqlite": {"_host": "/data/my files.sqlite"},
    "postgres": {"_host": "db.example", "_username": "alice", "_db_name": "files"},
    "redis": {"_host": "cache.example", "_db_name": "2"},
    "mongodb": {"_host": "mongo.example", "_db_name": "store"},
    "git": {"_host": "git@git.example:team/repo.git"},
    "ldap": {"_host": "ldap.example", "_username": "cn=admin,dc=example,dc=org"},
    "slp": {"_host": "10.0.0.9", "_slp_scope": "LAB"},
    "exchange": {"_username": "carol@example.org"},
    "svn": {"_host": "https://svn.example.org/repo"},
}


@pytest.mark.parametrize("proto", sorted(TYPED))
def test_e2e_the_dialog_saves_and_loads_each_protocol(dialog, proto):
    pick, warnings = dialog
    dlg = pick(proto)
    for attr, value in TYPED[proto].items():
        widget = getattr(dlg, attr)
        assert widget.isVisible(), f"{proto}: {attr} is hidden"
        widget.setText(value)
    assert dlg._validate(), warnings
    dlg._save_profile()
    assert not warnings, warnings
    saved = ProfileManager().get(f"my-{proto}")
    assert saved is not None and saved.protocol == proto
    dlg._clear_fields()
    dlg._load_profile(saved)
    APP.processEvents()
    assert dlg._selected_protocol() == proto
    for attr, value in TYPED[proto].items():
        assert getattr(dlg, attr).text() == value, attr


@pytest.mark.parametrize("proto", ["sqlite", "git", "redis", "slp"])
def test_happy_no_username_where_the_protocol_has_none(dialog, proto):
    pick, _warnings = dialog
    dlg = pick(proto)
    assert not dlg._username.isVisible()


@pytest.mark.parametrize("proto", ["sqlite", "git", "svn", "exchange"])
def test_happy_no_port_where_the_protocol_has_none(dialog, proto):
    pick, _warnings = dialog
    dlg = pick(proto)
    assert not dlg._port.isVisible()


@pytest.mark.parametrize("proto", ["svn", "postgres", "redis", "mongodb", "ldap", "exchange"])
def test_happy_the_password_row_is_shown(dialog, proto):
    pick, _warnings = dialog
    dlg = pick(proto)
    assert dlg._simple_password.isVisible()


@pytest.mark.parametrize(
    "proto, typed, message",
    [
        ("sqlite", {}, "Database file is required."),
        ("git", {}, "Repository is required."),
        ("svn", {}, "Repository URL is required."),
        ("postgres", {"_host": "h"}, "Database is required."),
        ("redis", {"_host": "h", "_db_name": "two"}, "The Redis database is a number"),
        ("exchange", {}, "Username is required."),
        ("slp", {}, "Host is required."),
    ],
)
def test_sad_a_missing_field_is_named(dialog, proto, typed, message):
    pick, warnings = dialog
    dlg = pick(proto)
    for attr, value in typed.items():
        getattr(dlg, attr).setText(value)
    assert not dlg._validate()
    assert warnings and warnings[-1].startswith(message), warnings


def test_happy_pop3_has_its_tls_switch(dialog):
    pick, warnings = dialog
    dlg = pick("pop3")
    assert dlg._pop3_ssl.isVisible()
    dlg._host.setText("mail.example")
    dlg._username.setText("u")
    dlg._pop3_ssl.setChecked(False)
    dlg._save_profile()
    saved = ProfileManager().get("my-pop3")
    assert saved.pop3_ssl is False
    dlg._clear_fields()
    dlg._load_profile(saved)
    assert dlg._pop3_ssl.isChecked() is False


@pytest.mark.parametrize(
    "proto, box, on, off",
    [("imap", "_imap_ssl", 993, 143), ("pop3", "_pop3_ssl", 995, 110),
     ("nntp", "_nntp_ssl", 563, 119), ("ldap", "_ldap_ssl", 636, 389)],
)
def test_happy_the_tls_switch_moves_the_default_port(dialog, proto, box, on, off):
    pick, _warnings = dialog
    dlg = pick(proto)
    assert dlg._port.value() == (on if getattr(dlg, box).isChecked() else off)
    getattr(dlg, box).setChecked(not getattr(dlg, box).isChecked())
    assert dlg._port.value() == (on if getattr(dlg, box).isChecked() else off)
    # A port the user typed is kept.
    dlg._port.setValue(10993)
    getattr(dlg, box).setChecked(not getattr(dlg, box).isChecked())
    assert dlg._port.value() == 10993


@pytest.mark.parametrize(
    "proto", ["sqlite", "git", "svn", "imap", "pop3", "nntp", "postgres", "redis", "mongodb",
              "ldap", "slp", "exchange", "gopher", "pjl"])
def test_happy_no_ip_version_that_the_backend_would_ignore(dialog, proto):
    pick, _warnings = dialog
    dlg = pick(proto)
    assert not dlg._addr_family.isVisible()


@pytest.mark.parametrize(
    "proto, fields, level",
    [
        ("sqlite", dict(host="/x.sqlite"), "local"),
        ("git", dict(host="/src/repo"), "local"),
        ("git", dict(host="g@host:repo"), "encrypted"),
        ("ldap", dict(host="h"), "cleartext"),
        ("ldap", dict(host="h", ldap_ssl=True), "tls"),
        ("redis", dict(host="h", db_tls=True), "tls"),
        ("exchange", dict(username="a@b"), "tls"),
    ],
)
def test_happy_the_padlock_of_each_new_protocol(proto, fields, level):
    from core.conn_security import from_profile

    assert from_profile(_profile(proto, **fields)).level == level
