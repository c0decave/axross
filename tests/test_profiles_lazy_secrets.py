"""A profile's keyring secrets are read when the profile is used, not at load.

``ProfileManager()`` read the four sensitive fields (Azure connection
string and SAS token, Google Drive and Dropbox app secrets) of EVERY saved
profile from the keyring - four keyring lookups per profile, a D-Bus round
trip each with the Secret Service - before anything was asked of it. The
scripting API (``axross.list_profiles()``, ``axross.get_profile()``) and
the MCP server's remote group make a new manager per call: listing the
names of 30 profiles cost 120 lookups, looking up one profile 120 too.

Now ``get()`` and ``all_profiles()`` fill a profile's secrets on its first
use, so a name listing reads none and one profile reads its own four. What
they return is what the eager read returned.
"""

from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import profiles as P  # noqa: E402
from core.profiles import SENSITIVE_PROFILE_FIELDS, ConnectionProfile, ProfileManager  # noqa: E402

SECRETS = {
    ("store-azure", "azure_connection_string"): "DefaultEndpointsProtocol=https;AccountKey=k",
    ("store-azure", "azure_sas_token"): "sv=2024&sig=abc",
    ("drive", "gdrive_client_secret"): "gsecret",
    ("box", "dropbox_app_secret"): "dsecret",
    ("old-azure-now-sftp", "azure_sas_token"): "kept-from-before",
}


class LazySecretsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.file = self.dir / "profiles.json"
        self.calls: list[tuple[str, str]] = []
        self.secrets = dict(SECRETS)

        def get_secret(name, field):
            self.calls.append((name, field))
            return self.secrets.get((name, field))

        for patcher in (
            mock.patch.object(P, "CONFIG_DIR", self.dir),
            mock.patch.object(P, "PROFILES_FILE", self.file),
            mock.patch.object(P, "get_secret", side_effect=get_secret),
            mock.patch.object(P, "store_secret", side_effect=self._store),
            mock.patch.object(P, "delete_secret", side_effect=self._delete),
            mock.patch.object(P, "delete_password", return_value=True),
            mock.patch.object(P, "delete_proxy_password", return_value=True),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        profiles = {
            "store-azure": ConnectionProfile(name="store-azure", protocol="azure_blob",
                                             host="acct.blob.core.windows.net"),
            "drive": ConnectionProfile(name="drive", protocol="gdrive"),
            "box": ConnectionProfile(name="box", protocol="dropbox"),
            "old-azure-now-sftp": ConnectionProfile(name="old-azure-now-sftp", protocol="sftp",
                                                    host="h"),
        }
        for i in range(26):
            profiles[f"host{i:02d}"] = ConnectionProfile(name=f"host{i:02d}", protocol="sftp",
                                                         host=f"10.0.0.{i}", username="u")
        # The writer's own format (ProfileManager._write).
        self.file.write_text(json.dumps({n: p.to_dict() for n, p in profiles.items()}, indent=2,
                                        ensure_ascii=False) + "\n")

    def _store(self, name, field, value) -> bool:
        self.secrets[(name, field)] = value
        return True

    def _delete(self, name, field) -> bool:
        self.secrets.pop((name, field), None)
        return True

    def _eager(self) -> dict[str, dict]:
        """What the former load gave: every profile with its secrets read."""
        data = json.loads(self.file.read_text())
        out = {}
        for name, raw in data.items():
            profile = ConnectionProfile.from_dict(raw)
            for field in SENSITIVE_PROFILE_FIELDS:
                value = SECRETS.get((name, field))
                if value is not None:
                    setattr(profile, field, value)
            out[name] = profile
        return out

    def test_happy_listing_reads_no_secret_and_one_profile_reads_its_own(self) -> None:
        manager = ProfileManager()
        self.assertEqual(len(manager.list_names()), 30)
        self.assertEqual(self.calls, [])
        azure = manager.get("store-azure")
        self.assertEqual(sorted(self.calls),
                         sorted(("store-azure", f) for f in SENSITIVE_PROFILE_FIELDS))
        self.assertEqual(azure.azure_connection_string,
                         SECRETS[("store-azure", "azure_connection_string")])
        self.assertEqual(azure.azure_sas_token, SECRETS[("store-azure", "azure_sas_token")])
        self.assertIs(manager.get("store-azure"), azure)  # the same object, read once
        self.assertEqual(len(self.calls), len(SENSITIVE_PROFILE_FIELDS))

    def test_happy_all_profiles_equals_the_eager_load(self) -> None:
        manager = ProfileManager()
        got = {p.name: p for p in manager.all_profiles()}
        self.assertEqual(got, self._eager())
        self.assertEqual(len(self.calls), 30 * len(SENSITIVE_PROFILE_FIELDS))
        manager.all_profiles()
        self.assertEqual(len(self.calls), 30 * len(SENSITIVE_PROFILE_FIELDS))
        # A secret of another protocol stays with its profile, as before.
        self.assertEqual(got["old-azure-now-sftp"].azure_sas_token, "kept-from-before")

    def test_happy_the_scripting_api_reads_only_what_it_returns(self) -> None:
        from core import scripting

        self.assertEqual(len(scripting.list_profiles()), 30)
        self.assertEqual(self.calls, [])
        profile = scripting.get_profile("drive")
        self.assertEqual(profile.gdrive_client_secret, "gsecret")
        self.assertEqual({name for name, _field in self.calls}, {"drive"})

    def test_sad_an_unknown_name_and_an_empty_keyring(self) -> None:
        manager = ProfileManager()
        self.assertIsNone(manager.get("nope"))
        self.assertEqual(self.calls, [])
        self.secrets.clear()
        host = manager.get("host03")
        self.assertEqual([getattr(host, f) for f in SENSITIVE_PROFILE_FIELDS], [""] * 4)

    def test_edge_saving_with_unread_secrets_writes_the_same_file_and_keeps_them(self) -> None:
        before = self.file.read_bytes()
        manager = ProfileManager()
        manager.save()
        self.assertEqual(self.file.read_bytes(), before)
        self.assertEqual(self.calls, [])
        self.assertEqual(self.secrets, SECRETS)  # nothing deleted for an unread profile

    def test_edge_added_profile_needs_no_read_and_a_removed_one_none(self) -> None:
        manager = ProfileManager()
        fresh = ConnectionProfile(name="new-box", protocol="dropbox", dropbox_app_secret="n1")
        manager.add(fresh)
        self.calls.clear()
        self.assertIs(manager.get("new-box"), fresh)
        self.assertEqual(self.calls, [])
        manager.remove("host05")
        self.assertIsNone(manager.get("host05"))
        self.assertNotIn("host05", {name for name, _ in self.calls})

    def test_edge_a_profile_another_writer_added_is_read_on_use(self) -> None:
        manager = ProfileManager()
        data = json.loads(self.file.read_text())
        data["late"] = ConnectionProfile(name="late", protocol="azure_files", host="x").to_dict()
        self.file.write_text(json.dumps(data))
        self.secrets[("late", "azure_connection_string")] = "late-conn"
        manager.add(ConnectionProfile(name="mine", protocol="sftp", host="m"))  # merges "late"
        self.assertNotIn("late", {name for name, _ in self.calls})
        self.assertEqual(manager.get("late").azure_connection_string, "late-conn")

    def test_edge_a_profile_replaced_during_its_first_use_still_gets_its_secrets(self) -> None:
        """get() found the object, then a save merged another writer's edit
        of it: the caller's object is filled all the same, the new one later."""
        manager = ProfileManager()
        held = manager._profiles["store-azure"]
        replacement = ConnectionProfile(name="store-azure", protocol="azure_blob", host="other")
        manager._profiles["store-azure"] = replacement
        manager._read_secrets("store-azure", held)
        self.assertEqual(held.azure_sas_token, SECRETS[("store-azure", "azure_sas_token")])
        self.assertIn("store-azure", manager._secrets_unread)
        self.assertIs(manager.get("store-azure"), replacement)
        self.assertEqual(replacement.azure_sas_token, SECRETS[("store-azure", "azure_sas_token")])

    def test_edge_concurrent_first_use_reads_once_and_never_returns_half_filled(self) -> None:
        manager = ProfileManager()
        gate = threading.Barrier(8)
        seen = []

        def use() -> None:
            gate.wait()
            seen.append(manager.get("store-azure").azure_sas_token)

        threads = [threading.Thread(target=use) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(seen, [SECRETS[("store-azure", "azure_sas_token")]] * 8)
        self.assertEqual(len(self.calls), len(SENSITIVE_PROFILE_FIELDS))


if __name__ == "__main__":
    unittest.main()
