"""preview_delete finds hidden entries, can be cancelled and says when it is incomplete.

The pane's Delete / Move to Trash run this walk before the confirmation.
A folder that holds hidden entries (dotfiles, or a backend's ``hidden``
attribute) gets a second, explicit confirmation; a walk that could not see
every entry cannot rule hidden entries out. The walk runs on a worker
thread, so it takes a ``cancel`` callable and a ``progress`` callback.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.destructive_preview import preview_delete  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _tree(root: Path) -> Path:
    top = root / "top"
    (top / "sub").mkdir(parents=True)
    (top / "a.txt").write_text("a")
    (top / ".env").write_text("secret")
    (top / "sub" / ".cache").mkdir()
    (top / "sub" / ".cache" / "x").write_text("x")
    (top / "sub" / "b.txt").write_text("b")
    return top


def test_happy_hidden_entries_inside_a_folder_are_counted_with_examples(tmp_path):
    top = _tree(tmp_path)
    preview = preview_delete(LocalFS(), [str(top)])
    assert preview.hidden_count == 2
    assert sorted(preview.hidden) == sorted([str(top / ".env"), str(top / "sub" / ".cache")])
    assert not preview.incomplete
    assert not preview.cancelled
    # The counts are unchanged by the hidden check.
    assert (preview.dirs, preview.files) == (3, 4)


def test_happy_a_folder_without_hidden_entries_has_none(tmp_path):
    top = tmp_path / "plain"
    top.mkdir()
    (top / "a.txt").write_text("a")
    preview = preview_delete(LocalFS(), [str(top)])
    assert preview.hidden_count == 0
    assert preview.hidden == []
    assert not preview.incomplete


def test_edge_a_selected_root_that_is_hidden_itself_is_not_counted(tmp_path):
    # The user picked it by name in the listing; only what is INSIDE counts.
    root = tmp_path / ".dotdir"
    root.mkdir()
    (root / "visible.txt").write_text("v")
    preview = preview_delete(LocalFS(), [str(root)])
    assert preview.hidden_count == 0


def test_edge_a_hidden_attribute_counts_even_without_a_dot(tmp_path):
    @dataclass
    class Item:
        name: str
        is_dir: bool = False
        size: int = 0
        hidden: bool = False

    class AttrFS:
        def stat(self, path):
            return Item(name=path.rsplit("/", 1)[-1], is_dir=path == "/d")

        def list_dir(self, path):
            return [Item("desktop.ini", hidden=True), Item("plain.txt")]

        def join(self, *parts):
            return "/".join(p.rstrip("/") for p in parts)

        def normalize(self, path):
            return path

        def separator(self):
            return "/"

    preview = preview_delete(AttrFS(), ["/d"])
    assert preview.hidden_count == 1
    assert preview.hidden == ["/d/desktop.ini"]


def test_edge_examples_are_bounded_but_the_count_is_not(tmp_path):
    top = tmp_path / "many"
    top.mkdir()
    for i in range(50):
        (top / f".h{i}").write_text("")
    preview = preview_delete(LocalFS(), [str(top)])
    assert preview.hidden_count == 50
    assert 0 < len(preview.hidden) <= 20


def test_sad_a_truncated_walk_is_incomplete(tmp_path):
    top = _tree(tmp_path)
    preview = preview_delete(LocalFS(), [str(top)], max_entries=2)
    assert preview.truncated
    assert preview.incomplete


def test_sad_an_unreadable_folder_makes_the_walk_incomplete(tmp_path):
    top = _tree(tmp_path)

    class FailingFS(LocalFS):
        def list_dir(self, path):
            if path.endswith("sub"):
                raise PermissionError(13, "Permission denied")
            return super().list_dir(path)

    preview = preview_delete(FailingFS(), [str(top)])
    assert preview.incomplete
    assert preview.hidden_count == 1  # .env was still seen


def test_sad_cancel_stops_the_walk_and_marks_it(tmp_path):
    top = _tree(tmp_path)
    seen: list[str] = []

    def progress(dirs, files, path):
        seen.append(path)

    preview = preview_delete(
        LocalFS(), [str(top)], cancel=lambda: len(seen) >= 1, progress=progress
    )
    assert preview.cancelled
    assert preview.incomplete
    assert preview.total_items < 7


def test_happy_progress_reports_counts_and_the_current_path(tmp_path):
    top = _tree(tmp_path)
    reports: list[tuple[int, int, str]] = []
    preview_delete(LocalFS(), [str(top)], progress=lambda d, f, p: reports.append((d, f, p)))
    assert reports
    assert reports[-1][0] + reports[-1][1] >= 1
    assert all(isinstance(r[2], str) for r in reports)


def test_edge_the_summary_names_hidden_entries_only_when_there_are_some(tmp_path):
    top = _tree(tmp_path)
    assert "2 hidden" in preview_delete(LocalFS(), [str(top)]).summary()
    plain = tmp_path / "plain"
    plain.mkdir()
    assert "hidden" not in preview_delete(LocalFS(), [str(plain)]).summary()


def test_edge_a_file_item_flagged_hidden_by_its_backend_counts(tmp_path):
    """FileItem.attr_hidden (Windows / SMB / macOS hidden flag) is what the
    listings carry; the delete check must see it like the pane's filter."""
    from models.file_item import FileItem

    class FlagFS:
        def stat(self, path):
            return FileItem(name=path.rsplit("/", 1)[-1], is_dir=path == "/d")

        def list_dir(self, path):
            return [FileItem(name="Thumbs.db", attr_hidden=True), FileItem(name="plain.txt")]

        def join(self, *parts):
            return "/".join(p.rstrip("/") for p in parts)

        def normalize(self, path):
            return path

        def separator(self):
            return "/"

    preview = preview_delete(FlagFS(), ["/d"])
    assert preview.hidden == ["/d/Thumbs.db"]
