"""A profile's stored keyring password reaches every backend that takes one.

Before: ``axross.open("<profile>")`` (scripting) called
``ConnectionManager.connect(profile, password="")`` and the manager handed
that empty password straight to the backend. Only the SSH and SCP clients
looked the stored password up themselves, so a saved FTP / SMB / WebDAV /
S3 ... profile with "Store password" connected without it.

Now ``ConnectionManager.connect`` reads the keyring once, centrally, when
no password is passed, the profile stores one and the protocol takes one
(``core.profiles.password_needed``, the decision Quick Connect and the
MCP server share). The keyring here is an in-memory dict.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import credentials  # noqa: E402
from core.connection_manager import ConnectionManager  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402


class _FakeKeyring:
    def __init__(self) -> None:
        self.store: dict[tuple[str, str], str] = {}
        self.reads: list[str] = []

    def set_password(self, service, name, value):
        self.store[(service, name)] = value

    def get_password(self, service, name):
        self.reads.append(name)
        return self.store.get((service, name))

    def delete_password(self, service, name):
        self.store.pop((service, name), None)


class _Recorder:
    """Stands in for a backend class: records what it was built with."""

    seen: list[dict] = []

    def __init__(self, **kw) -> None:
        _Recorder.seen.append(kw)

    connected = True

    def disconnect(self) -> None:
        pass

    def close(self) -> None:
        pass


class StoredPasswordTest(unittest.TestCase):
    def setUp(self) -> None:
        self.ring = _FakeKeyring()
        _Recorder.seen = []
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        for target, value in (
            ("keyring.set_password", self.ring.set_password),
            ("keyring.get_password", self.ring.get_password),
            ("keyring.delete_password", self.ring.delete_password),
            ("core.credentials._keyring_checked", True),
            ("core.credentials._keyring_usable", True),
            ("core.profiles.PROFILES_FILE", self.tmp / "profiles.json"),
            ("core.connection_manager.load_backend_class", lambda proto: _Recorder),
        ):
            patcher = mock.patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _profile(self, **kw) -> ConnectionProfile:
        kw.setdefault("name", "nas-ftp")
        kw.setdefault("protocol", "ftp")
        kw.setdefault("host", "127.0.0.1")
        kw.setdefault("port", 21)
        kw.setdefault("username", "backup")
        kw.setdefault("store_password", True)
        return ConnectionProfile(**kw)

    def _stored(self, name: str, value: str) -> None:
        self.ring.set_password(credentials.SERVICE_NAME, name, value)

    def _connect(self, profile: ConnectionProfile, password: str = "") -> dict:
        cm = ConnectionManager()
        try:
            cm.connect(profile, password=password)
        finally:
            cm.disconnect_all()
        return _Recorder.seen[-1]

    def test_happy_a_stored_password_reaches_an_ftp_backend(self) -> None:
        self._stored("nas-ftp", "s3cret")
        self.assertEqual(self._connect(self._profile())["password"], "s3cret")

    def test_happy_scripting_open_uses_the_stored_password(self) -> None:
        from core import scripting
        from core.profiles import ProfileManager

        ProfileManager().add(self._profile())
        self._stored("nas-ftp", "s3cret")
        session = scripting.open("nas-ftp")
        try:
            self.assertEqual(_Recorder.seen[-1]["password"], "s3cret")
        finally:
            session.close()

    def test_sad_a_profile_that_stores_no_password_does_not_read_the_keyring(self) -> None:
        self._stored("nas-ftp", "stale")
        seen = self._connect(self._profile(store_password=False))
        self.assertEqual(seen["password"], "")
        self.assertNotIn("nas-ftp", self.ring.reads)

    def test_sad_no_stored_entry_leaves_the_password_empty(self) -> None:
        self.assertEqual(self._connect(self._profile())["password"], "")

    def test_edge_a_password_passed_in_wins_over_the_stored_one(self) -> None:
        self._stored("nas-ftp", "stored")
        self.assertEqual(self._connect(self._profile(), password="typed")["password"], "typed")

    def test_edge_a_protocol_without_a_password_does_not_read_the_keyring(self) -> None:
        self._stored("anon-s3", "stale")
        profile = self._profile(name="anon-s3", protocol="s3", username="", s3_bucket="b")
        self._connect(profile)
        self.assertNotIn("anon-s3", self.ring.reads)


if __name__ == "__main__":
    unittest.main()
