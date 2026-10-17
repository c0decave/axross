"""A long-lived bookmark / profile manager never writes a stale copy back.

Before: the main window keeps one ``BookmarkManager`` and one
``ProfileManager`` from startup (ui/main_window.py) while the scripting
API (REPL, Scripts dock) saves through fresh managers. Every save wrote
the whole in-memory tree, so the next GUI change silently dropped what a
script had added and brought back what a script had deleted.

Now each save re-reads the file under a lock and merges: entries another
writer added since this manager last read or wrote the file are kept,
entries another writer deleted stay deleted, and this manager's own
changes win over an unchanged copy.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import bookmarks as BM  # noqa: E402
from core import credentials  # noqa: E402
from core.profiles import ConnectionProfile, ProfileManager  # noqa: E402


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

    def names(self) -> set[str]:
        return {name for service, name in self.store if service == credentials.SERVICE_NAME}


class _BookmarkBase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.file = self.tmp / "bookmarks.json"
        patcher = mock.patch.object(BM, "BOOKMARKS_FILE", self.file)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _on_disk(self) -> list[str]:
        return [b.name for b in BM.BookmarkManager().all()]


class BookmarkMergeTest(_BookmarkBase):
    def test_happy_a_bookmark_a_script_added_survives_the_gui_save(self) -> None:
        gui = BM.BookmarkManager()
        BM.BookmarkManager().add(BM.Bookmark(name="from-script", path="/srv"))
        gui.add(BM.Bookmark(name="from-gui", path="/etc"))
        self.assertEqual(sorted(self._on_disk()), ["from-gui", "from-script"])
        # The stale manager now knows the merged entry too.
        self.assertEqual(sorted(b.name for b in gui.all()), ["from-gui", "from-script"])

    def test_happy_a_bookmark_a_script_removed_stays_removed(self) -> None:
        seed = BM.BookmarkManager()
        seed.add(BM.Bookmark(name="old", path="/old"))
        seed.add(BM.Bookmark(name="keep", path="/keep"))
        gui = BM.BookmarkManager()
        script = BM.BookmarkManager()
        script.remove(0)
        gui.add(BM.Bookmark(name="new", path="/new"))
        self.assertEqual(self._on_disk(), ["keep", "new"])

    def test_happy_a_gui_removal_is_not_undone_by_a_script_add(self) -> None:
        seed = BM.BookmarkManager()
        seed.add(BM.Bookmark(name="gone", path="/gone"))
        gui = BM.BookmarkManager()
        BM.BookmarkManager().add(BM.Bookmark(name="script", path="/script"))
        gui.remove_node(gui.all()[0])
        self.assertEqual(self._on_disk(), ["script"])

    def test_edge_the_same_path_added_by_both_is_kept_once(self) -> None:
        gui = BM.BookmarkManager()
        BM.BookmarkManager().add(BM.Bookmark(name="script", path="/same"))
        gui.add(BM.Bookmark(name="gui", path="/same"))
        self.assertEqual(len(self._on_disk()), 1)

    def test_edge_an_external_rename_is_adopted_when_unchanged_here(self) -> None:
        BM.BookmarkManager().add(BM.Bookmark(name="before", path="/p"))
        gui = BM.BookmarkManager()
        script = BM.BookmarkManager()
        script.update(0, BM.Bookmark(name="after", path="/p"))
        gui.add(BM.Bookmark(name="other", path="/q"))
        self.assertEqual(self._on_disk(), ["after", "other"])

    def test_edge_an_external_bookmark_keeps_its_group(self) -> None:
        gui = BM.BookmarkManager()
        script = BM.BookmarkManager()
        group = script.add_group("servers")
        script.add(BM.Bookmark(name="web", path="/web"), group=group)
        gui.add(BM.Bookmark(name="local", path="/local"))
        again = BM.BookmarkManager()
        groups = [g.name for _depth, g in again.groups()]
        self.assertEqual(groups, ["servers"])
        web = next(b for b in again.all() if b.name == "web")
        self.assertEqual(again.parent_of(web).name, "servers")
        self.assertEqual(sorted(self._on_disk()), ["local", "web"])

    def test_edge_nodes_of_the_stale_manager_stay_usable(self) -> None:
        gui = BM.BookmarkManager()
        gui.add(BM.Bookmark(name="mine", path="/mine"))
        mine = gui.all()[0]
        BM.BookmarkManager().add(BM.Bookmark(name="script", path="/script"))
        gui.add(BM.Bookmark(name="second", path="/second"))
        # Identity-based calls on nodes the sidebar still holds keep working.
        gui.remove_node(mine)
        self.assertEqual(sorted(self._on_disk()), ["script", "second"])

    def test_sad_a_file_broken_by_another_writer_is_set_aside_not_lost(self) -> None:
        gui = BM.BookmarkManager()
        self.file.write_bytes(b"[{broken")
        gui.add(BM.Bookmark(name="gui", path="/gui"))
        kept = [p for p in self.tmp.iterdir() if p.name.startswith("bookmarks.json.unreadable-")]
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].read_bytes(), b"[{broken")
        self.assertEqual(self._on_disk(), ["gui"])

    def test_sad_a_file_deleted_by_another_writer_does_not_resurrect_entries(self) -> None:
        BM.BookmarkManager().add(BM.Bookmark(name="old", path="/old"))
        gui = BM.BookmarkManager()
        self.file.unlink()
        gui.add(BM.Bookmark(name="new", path="/new"))
        self.assertEqual(self._on_disk(), ["new"])


class _ProfileBase(unittest.TestCase):
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

    def _on_disk(self) -> list[str]:
        return sorted(json.loads(self.profiles_file.read_text(encoding="utf-8")))

    @staticmethod
    def _profile(name: str, host: str = "h.example", **kw) -> ConnectionProfile:
        return ConnectionProfile(name=name, protocol="sftp", host=host, username="u", **kw)


class ProfileMergeTest(_ProfileBase):
    def test_happy_a_profile_a_script_saved_survives_the_gui_save(self) -> None:
        gui = ProfileManager()
        ProfileManager().add(self._profile("scripted"))
        gui.add(self._profile("gui"))
        self.assertEqual(self._on_disk(), ["gui", "scripted"])
        self.assertIsNotNone(gui.get("scripted"))

    def test_happy_a_profile_a_script_deleted_stays_deleted(self) -> None:
        ProfileManager().add(self._profile("old", store_password=True))
        gui = ProfileManager()
        ProfileManager().remove("old")
        gui.add(self._profile("new"))
        self.assertEqual(self._on_disk(), ["new"])
        self.assertIsNone(gui.get("old"))

    def test_happy_a_gui_deletion_stays_deleted_and_drops_its_secrets(self) -> None:
        ProfileManager().add(self._profile("victim", azure_sas_token="sv=1"))
        gui = ProfileManager()
        # A script edits the same profile after the GUI read the file.
        ProfileManager().add(self._profile("victim", host="moved.example", azure_sas_token="sv=2"))
        gui.remove("victim")
        self.assertEqual(self._on_disk(), [])
        self.assertEqual(self.ring.names(), set())

    def test_edge_an_external_edit_is_adopted_when_unchanged_here(self) -> None:
        ProfileManager().add(self._profile("p", host="before.example"))
        gui = ProfileManager()
        ProfileManager().add(self._profile("p", host="after.example"))
        gui.add(self._profile("other"))
        data = json.loads(self.profiles_file.read_text(encoding="utf-8"))
        self.assertEqual(data["p"]["host"], "after.example")
        self.assertEqual(gui.get("p").host, "after.example")

    def test_edge_an_adopted_profile_gets_its_keyring_secret(self) -> None:
        gui = ProfileManager()
        ProfileManager().add(self._profile("cloud", azure_sas_token="sv=9"))
        gui.add(self._profile("other"))
        self.assertEqual(gui.get("cloud").azure_sas_token, "sv=9")

    def test_edge_this_managers_own_edit_wins(self) -> None:
        ProfileManager().add(self._profile("p", host="one.example"))
        gui = ProfileManager()
        ProfileManager().add(self._profile("p", host="script.example"))
        gui.add(self._profile("p", host="gui.example"))
        data = json.loads(self.profiles_file.read_text(encoding="utf-8"))
        self.assertEqual(data["p"]["host"], "gui.example")

    def test_edge_in_place_change_then_save_keeps_external_adds(self) -> None:
        # The proxy dialog changes profile objects in place and calls save().
        ProfileManager().add(self._profile("p"))
        gui = ProfileManager()
        ProfileManager().add(self._profile("scripted"))
        gui.get("p").host = "changed.example"
        gui.save()
        data = json.loads(self.profiles_file.read_text(encoding="utf-8"))
        self.assertEqual(sorted(data), ["p", "scripted"])
        self.assertEqual(data["p"]["host"], "changed.example")

    def test_sad_a_file_broken_by_another_writer_is_kept_aside(self) -> None:
        gui = ProfileManager()
        self.profiles_file.write_text("{broken", encoding="utf-8")
        gui.add(self._profile("gui"))
        kept = [
            p
            for p in self.profiles_file.parent.iterdir()
            if p.name.startswith("profiles.json.corrupt-")
        ]
        self.assertEqual(len(kept), 1)
        self.assertEqual(kept[0].read_text(encoding="utf-8"), "{broken")
        self.assertEqual(self._on_disk(), ["gui"])

    def test_sad_profiles_file_stays_private(self) -> None:
        ProfileManager().add(self._profile("p"))
        self.assertEqual(self.profiles_file.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
