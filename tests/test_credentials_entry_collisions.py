"""A connection profile's keyring entries never share a slot with another secret.

Before: entries are ``<name>``, ``<name>:proxy`` and
``<name>:secret:<field>`` and profile names were not validated. A
profile named ``X:proxy`` stored its password in the slot of profile
``X``'s proxy password, so saving ``X`` without a proxy password (or
removing ``X``) deleted the other profile's password. A profile named
``__default_proxy__`` owned the global default proxy password, and one
named ``llm-profile:<n>:api-key`` owned an LLM profile's API key.

Now ``ProfileManager.add`` rejects such names, and a profile file from
before that still holding both ``X`` and ``X:proxy`` never deletes an
entry another loaded profile owns.
"""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import credentials, llm_profiles, proxy_settings  # noqa: E402
from core.profiles import SENSITIVE_PROFILE_FIELDS, ConnectionProfile, ProfileManager  # noqa: E402


class _FakeKeyring:
    """In-memory stand-in for the ``keyring`` module functions."""

    def __init__(self) -> None:
        self.store: dict[tuple[str, str], str] = {}

    def set_password(self, service, name, value):
        self.store[(service, name)] = value

    def get_password(self, service, name):
        return self.store.get((service, name))

    def delete_password(self, service, name):
        import keyring.errors

        if (service, name) not in self.store:
            raise keyring.errors.PasswordDeleteError(name)
        del self.store[(service, name)]

    def entry(self, name):
        return self.store.get((credentials.SERVICE_NAME, name))


class _Base(unittest.TestCase):
    def setUp(self) -> None:
        self.ring = _FakeKeyring()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.profiles_file = Path(tmp.name) / "profiles.json"
        for target, value in (
            ("keyring.set_password", self.ring.set_password),
            ("keyring.get_password", self.ring.get_password),
            ("keyring.delete_password", self.ring.delete_password),
            ("core.credentials._keyring_checked", True),
            ("core.credentials._keyring_usable", True),
            ("core.profiles.PROFILES_FILE", self.profiles_file),
        ):
            patcher = mock.patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def _write_legacy_file(self, *names: str) -> None:
        data = {
            name: ConnectionProfile(name=name, host="h", store_password=True).to_dict()
            for name in names
        }
        self.profiles_file.write_text(json.dumps(data), encoding="utf-8")


class RejectedNamesTest(_Base):
    def _reserved_names(self) -> list[str]:
        # Derived from the real entry constructors, not typed in again.
        names = ["X:proxy", proxy_settings.KEYRING_NAME, llm_profiles._key_entry("gpt")]
        names += [f"X:secret:{field}" for field in SENSITIVE_PROFILE_FIELDS]
        return names

    def test_sad_add_rejects_a_name_that_is_another_secrets_entry(self) -> None:
        manager = ProfileManager()
        for name in self._reserved_names():
            with self.assertRaises(ValueError, msg=name):
                manager.add(ConnectionProfile(name=name, host="h"))
            self.assertIsNone(manager.get(name), name)
        self.assertEqual(self.ring.store, {})

    def test_sad_the_reported_scenario_keeps_the_other_password(self) -> None:
        manager = ProfileManager()
        manager.add(ConnectionProfile(name="X", host="h", store_proxy_password=True))
        manager.get("X").set_proxy_password("x-proxy-pw")
        with self.assertRaises(ValueError):
            manager.add(ConnectionProfile(name="X:proxy", host="h", store_password=True))
        manager.remove("X")
        self.assertIsNone(self.ring.entry("X:proxy"))  # X's own entry went with X

    def test_happy_ordinary_names_with_colons_still_work(self) -> None:
        manager = ProfileManager()
        for name in ("s3://bucket", "SharePoint: https://x", "user@host:22", "proxy", "a:proxyx"):
            profile = ConnectionProfile(name=name, host="h", store_password=True)
            manager.add(profile)
            profile.set_password(f"pw-{name}")
            self.assertEqual(manager.get(name).get_password(), f"pw-{name}")

    def test_edge_every_reserved_name_is_reported_by_the_validator(self) -> None:
        for name in self._reserved_names():
            self.assertIsNotNone(credentials.profile_name_problem(name), name)
        self.assertIsNone(credentials.profile_name_problem("X"))
        self.assertIsNone(credentials.profile_name_problem(""))


class SshConfigImportTest(_Base):
    def test_sad_a_reserved_alias_is_skipped_and_the_rest_imported(self) -> None:
        from types import SimpleNamespace

        from ui import main_window

        manager = ProfileManager()
        hosts = [
            SimpleNamespace(alias=alias, hostname="h", port=22, user="u", identity_file="",
                            proxy_command="", address_family="any")
            for alias in ("jump:proxy", "web")
        ]
        with mock.patch.object(main_window, "QMessageBox") as box:
            main_window.MainWindow._import_ssh_hosts(
                SimpleNamespace(_profile_manager=manager), hosts, "~/.ssh/config"
            )
        self.assertEqual(manager.list_names(), ["web"])
        box.information.assert_called_once()


class LegacyFileTest(_Base):
    """Profile files written before the validator may hold both names."""

    def test_edge_saving_x_keeps_the_legacy_profiles_password(self) -> None:
        self._write_legacy_file("X:proxy")
        self.ring.set_password(credentials.SERVICE_NAME, "X:proxy", "pw-other")
        manager = ProfileManager()
        manager.add(ConnectionProfile(name="X", host="h", store_proxy_password=False))
        self.assertEqual(manager.get("X:proxy").get_password(), "pw-other")

    def test_edge_removing_x_keeps_the_legacy_profiles_password(self) -> None:
        self._write_legacy_file("X", "X:proxy")
        self.ring.set_password(credentials.SERVICE_NAME, "X", "pw-x")
        self.ring.set_password(credentials.SERVICE_NAME, "X:proxy", "pw-other")
        manager = ProfileManager()
        manager.remove("X")
        self.assertIsNone(self.ring.entry("X"))
        self.assertEqual(self.ring.entry("X:proxy"), "pw-other")

    def test_edge_removing_the_legacy_profile_keeps_xs_proxy_password(self) -> None:
        self._write_legacy_file("X", "X:proxy")
        self.ring.set_password(credentials.SERVICE_NAME, "X:proxy", "x-proxy-pw")
        manager = ProfileManager()
        manager.remove("X:proxy")
        self.assertIsNone(manager.get("X:proxy"))
        self.assertEqual(self.ring.entry("X:proxy"), "x-proxy-pw")

    def test_edge_removing_a_legacy_default_proxy_profile_keeps_the_global_password(self) -> None:
        self._write_legacy_file(proxy_settings.KEYRING_NAME)
        global_entry = f"{proxy_settings.KEYRING_NAME}:proxy"
        self.ring.set_password(credentials.SERVICE_NAME, global_entry, "global-proxy-pw")
        manager = ProfileManager()
        manager.remove(proxy_settings.KEYRING_NAME)
        self.assertEqual(self.ring.entry(global_entry), "global-proxy-pw")


if __name__ == "__main__":
    unittest.main()
