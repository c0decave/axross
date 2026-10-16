"""Collecting the media files a folder (or a selection) holds.

The walk runs in a background thread for the media viewer; these tests
drive it directly: type filter, recursion and its caps, symlink loops,
unreadable folders, hostile names, cancel and the selection mode.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import media_collect as MC  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from models.file_item import FileItem  # noqa: E402

ALL = frozenset({MC.IMAGE, MC.PDF, MC.VIDEO})


def _touch(path: Path, data: bytes = b"x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


@pytest.fixture
def tree(tmp_path: Path) -> Path:
    root = tmp_path / "root"
    _touch(root / "a.png")
    _touch(root / "b.JPG")
    _touch(root / "doc.pdf")
    _touch(root / "clip.mp4")
    _touch(root / "notes.txt")
    _touch(root / "drawing.svg")
    _touch(root / ".hidden.png")
    _touch(root / "sub" / "c.gif")
    _touch(root / "sub" / "deep" / "d.webp")
    _touch(root / "sub" / "deep" / "deeper" / "e.tiff")
    return root


def _names(scan) -> list[str]:
    return sorted(i.name for i in scan.items)


# -- classification ---------------------------------------------------------


def test_happy_classify_by_extension_ignores_case():
    assert MC.classify("x.PNG") == MC.IMAGE
    assert MC.classify("x.jpeg") == MC.IMAGE
    assert MC.classify("x.svg") == MC.IMAGE
    assert MC.classify("x.Pdf") == MC.PDF
    assert MC.classify("x.mkv") == MC.VIDEO
    assert MC.classify("x.webm") == MC.VIDEO


def test_sad_classify_rejects_unknown_and_extensionless_names():
    assert MC.classify("notes.txt") is None
    assert MC.classify("png") is None
    assert MC.classify(".png") is None  # a dot file named after an extension
    assert MC.classify("") is None


def test_edge_every_image_extension_maps_to_an_allow_listed_mime_or_svg():
    """The walk offers nothing the decoder will refuse by MIME later."""
    from PyQt6.QtCore import QMimeDatabase

    from core import previews

    db = QMimeDatabase()
    for ext in MC.IMAGE_EXTENSIONS:
        mime = db.mimeTypeForFile(f"x{ext}", QMimeDatabase.MatchMode.MatchExtension).name()
        assert mime in previews.ALLOWED_THUMBNAIL_MIMES or mime == "image/svg+xml", (ext, mime)


# -- one folder -------------------------------------------------------------


def test_happy_one_folder_with_all_types(tree):
    scan = MC.collect_media(LocalFS(), str(tree), kinds=ALL)
    assert _names(scan) == ["a.png", "b.JPG", "clip.mp4", "doc.pdf", "drawing.svg"]
    assert scan.folders_scanned == 1
    assert not scan.truncated and not scan.cancelled
    item = next(i for i in scan.items if i.name == "doc.pdf")
    assert item.kind == MC.PDF
    assert item.path == str(tree / "doc.pdf")
    assert item.folder == ""
    assert item.size == 1


def test_happy_type_filter_keeps_only_the_chosen_kinds(tree):
    images = MC.collect_media(LocalFS(), str(tree), kinds={MC.IMAGE})
    assert _names(images) == ["a.png", "b.JPG", "drawing.svg"]
    pdfs = MC.collect_media(LocalFS(), str(tree), kinds={MC.PDF})
    assert _names(pdfs) == ["doc.pdf"]


def test_sad_no_kind_chosen_is_refused(tree):
    with pytest.raises(ValueError):
        MC.collect_media(LocalFS(), str(tree), kinds=set())
    with pytest.raises(ValueError):
        MC.collect_media(LocalFS(), str(tree), kinds={"audio"})


def test_edge_hidden_files_follow_the_pane_setting(tree):
    assert ".hidden.png" not in _names(MC.collect_media(LocalFS(), str(tree), kinds=ALL))
    shown = MC.collect_media(LocalFS(), str(tree), kinds=ALL, include_hidden=True)
    assert ".hidden.png" in _names(shown)


# -- recursion --------------------------------------------------------------


def test_happy_recursive_walk_finds_nested_files_with_their_folder(tree):
    scan = MC.collect_media(LocalFS(), str(tree), kinds={MC.IMAGE}, recursive=True)
    assert _names(scan) == ["a.png", "b.JPG", "c.gif", "d.webp", "drawing.svg", "e.tiff"]
    folders = {i.name: i.folder for i in scan.items}
    assert folders["c.gif"] == "sub"
    assert folders["e.tiff"] == os.path.join("sub", "deep", "deeper")
    assert scan.folders_scanned == 4


def test_edge_depth_cap_stops_the_descent_and_says_so(tree):
    scan = MC.collect_media(LocalFS(), str(tree), kinds={MC.IMAGE}, recursive=True, max_depth=1)
    assert "c.gif" in _names(scan)
    assert "d.webp" not in _names(scan)
    assert scan.depth_capped


def test_edge_non_recursive_never_descends(tree):
    scan = MC.collect_media(LocalFS(), str(tree), kinds={MC.IMAGE}, recursive=False, max_depth=9)
    assert "c.gif" not in _names(scan)
    assert not scan.depth_capped  # not a cap: the user asked for one folder


def test_edge_item_cap_truncates_the_result(tmp_path):
    for n in range(30):
        _touch(tmp_path / f"{n:02}.png")
    scan = MC.collect_media(LocalFS(), str(tmp_path), kinds={MC.IMAGE}, max_items=10)
    assert len(scan.items) == 10
    assert scan.truncated


def test_edge_folder_cap_bounds_a_wide_tree(tmp_path):
    for n in range(12):
        _touch(tmp_path / f"d{n:02}" / "x.png")
    scan = MC.collect_media(
        LocalFS(), str(tmp_path), kinds={MC.IMAGE}, recursive=True, max_folders=5
    )
    assert scan.folders_scanned == 5
    assert scan.truncated


def test_sad_out_of_range_caps_are_refused(tree):
    with pytest.raises(ValueError):
        MC.collect_media(LocalFS(), str(tree), kinds=ALL, max_items=0)
    with pytest.raises(ValueError):
        MC.collect_media(LocalFS(), str(tree), kinds=ALL, max_depth=-1)
    with pytest.raises(ValueError):
        MC.collect_media(LocalFS(), str(tree), kinds=ALL, max_items=MC.MAX_ITEMS + 1)


# -- loops, unreadable folders, hostile names --------------------------------


def test_edge_a_symlink_loop_terminates_and_lists_each_file_once(tmp_path):
    root = tmp_path / "r"
    _touch(root / "one.png")
    _touch(root / "sub" / "two.png")
    os.symlink(root, root / "sub" / "loop")
    os.symlink(root / "sub", root / "again")
    scan = MC.collect_media(LocalFS(), str(root), kinds={MC.IMAGE}, recursive=True, max_depth=30)
    assert _names(scan) == ["one.png", "two.png"]
    assert scan.links_skipped == 2


class _CyclingBackend:
    """A remote-style backend whose server resolves a link to the parent
    folder and reports it as a plain directory (no is_link): the same
    folder reappears under ever longer paths."""

    def __init__(self) -> None:
        self.listed: list[str] = []

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        return "/".join(p.rstrip("/") for p in parts)

    def normalize(self, path: str) -> str:
        return path

    def list_dir(self, path: str) -> list[FileItem]:
        self.listed.append(path)
        return [
            FileItem(name="pic.png", size=5, modified=datetime(2026, 1, 1)),
            FileItem(name="self", is_dir=True),
        ]


def test_edge_a_transparent_server_side_loop_is_bounded_by_the_depth_cap():
    backend = _CyclingBackend()
    scan = MC.collect_media(backend, "/r", kinds={MC.IMAGE}, recursive=True, max_depth=4)
    assert len(backend.listed) == 5  # root + four levels, then the cap
    assert scan.depth_capped
    assert len(scan.items) == 5


def test_sad_an_unreadable_subfolder_is_skipped_and_counted(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root reads every folder")
    _touch(tmp_path / "ok.png")
    locked = tmp_path / "locked"
    _touch(locked / "hidden.png")
    locked.chmod(0)
    try:
        scan = MC.collect_media(LocalFS(), str(tmp_path), kinds={MC.IMAGE}, recursive=True)
    finally:
        locked.chmod(0o755)
    assert _names(scan) == ["ok.png"]
    assert scan.unreadable == 1
    assert scan.unreadable_paths == [str(locked)]


def test_sad_an_unreadable_root_yields_nothing_and_counts_one(tmp_path):
    scan = MC.collect_media(LocalFS(), str(tmp_path / "missing"), kinds=ALL)
    assert scan.items == []
    assert scan.unreadable == 1


class _HostileBackend(_CyclingBackend):
    def list_dir(self, path: str) -> list[FileItem]:
        return [
            FileItem(name="../escape.png", size=1),
            FileItem(name="a/b.png", size=1),
            FileItem(name="fine.png", size=1),
        ]


def test_sad_hostile_names_from_a_server_are_dropped():
    scan = MC.collect_media(_HostileBackend(), "/r", kinds={MC.IMAGE})
    assert [i.name for i in scan.items] == ["fine.png"]
    assert scan.items[0].path == "/r/fine.png"


# -- cancel and progress ------------------------------------------------------


def test_happy_progress_reports_folders_and_items(tree):
    seen = []
    MC.collect_media(
        LocalFS(),
        str(tree),
        kinds={MC.IMAGE},
        recursive=True,
        progress=lambda folders, items, path: seen.append((folders, items, path)),
    )
    assert seen
    assert seen[-1][0] == 4
    assert seen[-1][1] == 6


def test_edge_cancel_stops_the_walk_and_marks_the_result(tree):
    calls = {"n": 0}

    def cancel() -> bool:
        calls["n"] += 1
        return calls["n"] > 1  # allow the root, stop before the first subfolder

    scan = MC.collect_media(LocalFS(), str(tree), kinds={MC.IMAGE}, recursive=True, cancel=cancel)
    assert scan.cancelled
    assert scan.folders_scanned == 1
    assert "c.gif" not in _names(scan)


# -- selection ----------------------------------------------------------------


def test_happy_selection_takes_chosen_files_and_walks_chosen_folders(tree):
    scan = MC.collect_media(
        LocalFS(), str(tree), kinds={MC.IMAGE}, only_names={"a.png", "sub", "notes.txt"}
    )
    assert _names(scan) == ["a.png", "c.gif"]


def test_edge_selection_with_recursion_descends_below_chosen_folders(tree):
    scan = MC.collect_media(
        LocalFS(), str(tree), kinds={MC.IMAGE}, only_names={"sub"}, recursive=True
    )
    assert _names(scan) == ["c.gif", "d.webp", "e.tiff"]


def test_sad_a_selection_without_media_is_empty(tree):
    scan = MC.collect_media(LocalFS(), str(tree), kinds=ALL, only_names={"notes.txt"})
    assert scan.items == []
