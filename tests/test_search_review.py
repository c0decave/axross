"""Find Files after the search review (2026-11-19): names in every Unicode
form and case.

Every engine case runs twice: with fd / rg when they are installed, and
with the built-in walker and reader (``use_tools=False``, as on a machine
without them) - both must give the same answer.
"""

from __future__ import annotations

import os
import sys
import unicodedata
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import file_search as FS  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.search_federation import SearchQuery  # noqa: E402

NFD = lambda s: unicodedata.normalize("NFD", s)  # noqa: E731

TOOLS = [pytest.param(False, id="python")]
if FS.find_tool("rg") or FS.find_tool("fd"):
    TOOLS.append(pytest.param(True, id="fd-rg"))


def found(root: Path, query: SearchQuery, use_tools: bool, backend=None) -> list[str]:
    hits = []
    FS.run_search([FS.SearchScope(backend or LocalFS(), str(root))], query,
                  on_hit=lambda _s, h: hits.append(h), use_tools=use_tools)
    return sorted(os.path.relpath(h.path, root) if os.path.isabs(h.path) and
                  h.path.startswith(str(root)) else h.path.lstrip("/") for h in hits)


# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------


@pytest.fixture
def names(tmp_path):
    root = tmp_path / "names"
    root.mkdir()
    # A decomposed name, as macOS (and files copied from it) writes it.
    (root / NFD("Ärger.txt")).write_text("x")
    (root / "Straße.pdf").write_text("x")
    (root / "Song [Remix].mp3").write_text("x")
    (root / "plain.txt").write_text("x")
    with zipfile.ZipFile(root / "pack.zip", "w") as zf:
        zf.writestr(NFD("Übersicht.txt"), "x")
    return root


@pytest.mark.parametrize("use_tools", TOOLS)
@pytest.mark.parametrize("pattern", ["*ärger*", "*ÄRGER*", "ärger.txt", "?rger.txt"])
def test_a_composed_needle_finds_a_decomposed_name(names, use_tools, pattern):
    assert found(names, SearchQuery(name=pattern), use_tools) == [NFD("Ärger.txt")]


@pytest.mark.parametrize("use_tools", TOOLS)
def test_a_decomposed_needle_finds_a_composed_name(names, use_tools):
    assert found(names, SearchQuery(name=NFD("*straße*")), use_tools) == ["Straße.pdf"]


@pytest.mark.parametrize("use_tools", TOOLS)
def test_strasse_finds_strasse_with_sharp_s_as_the_index_does(names, use_tools):
    assert found(names, SearchQuery(name="*STRASSE*"), use_tools) == ["Straße.pdf"]


@pytest.mark.parametrize("use_tools", TOOLS)
def test_a_name_regex_sees_the_composed_name(names, use_tools):
    assert found(names, SearchQuery(regex="^Är"), use_tools) == [NFD("Ärger.txt")]


@pytest.mark.parametrize("use_tools", TOOLS)
def test_an_archive_member_with_a_decomposed_name(names, use_tools):
    assert found(names, SearchQuery(name="*übersicht*", search_archives=True),
                 use_tools) == [f"pack.zip!/{NFD('Übersicht.txt')}"]


# ---------------------------------------------------------------------------
# fd / rg absent: a PATH without the tools gives the same results
# ---------------------------------------------------------------------------


def test_without_tools_on_path(names, monkeypatch, tmp_path):
    query = lambda: SearchQuery(name="*ärger*")  # noqa: E731
    with_tools = found(names, query(), True)
    empty = tmp_path / "emptybin"
    empty.mkdir()
    monkeypatch.setenv("PATH", str(empty))
    assert FS.find_tool("rg") is None and FS.find_tool("fd") is None
    assert found(names, query(), True) == with_tools == [NFD("Ärger.txt")]


# ---------------------------------------------------------------------------
# Folders found by name
# ---------------------------------------------------------------------------


@pytest.fixture
def folders(tmp_path):
    root = tmp_path / "folders"
    (root / "Steuer 2025" / "belege").mkdir(parents=True)
    (root / "Steuer 2025" / "belege" / "rechnung.pdf").write_text("steuer")
    (root / "archiv" / "steuer-alt").mkdir(parents=True)
    (root / ".steuer-hidden").mkdir()
    (root / "node_modules" / "steuer-pkg").mkdir(parents=True)
    (root / "steuer.txt").write_text("x")
    return root


def dir_hits(root, query, use_tools, backend=None, include_dirs=True):
    hits = []
    FS.run_search([FS.SearchScope(backend or LocalFS(), str(root))], query,
                  on_hit=lambda _s, h: hits.append(h), use_tools=use_tools,
                  include_dirs=include_dirs)
    return sorted((os.path.relpath(h.path, root) if h.path.startswith(str(root))
                   else h.path.lstrip("/"), h.is_dir) for h in hits)


@pytest.mark.parametrize("use_tools", TOOLS)
def test_a_name_search_finds_folders(folders, use_tools):
    assert dir_hits(folders, SearchQuery(name="*steuer*"), use_tools) == [
        (".steuer-hidden", True), ("Steuer 2025", True), ("archiv/steuer-alt", True),
        ("steuer.txt", False)]


@pytest.mark.parametrize("use_tools", TOOLS)
def test_folders_follow_hidden_and_depth(folders, use_tools):
    q = SearchQuery(name="*steuer*", include_hidden=False, max_depth=0)
    assert dir_hits(folders, q, use_tools) == [("Steuer 2025", True), ("steuer.txt", False)]


@pytest.mark.parametrize("use_tools", TOOLS)
@pytest.mark.parametrize("extra", [dict(contains="steuer"), dict(min_size=0),
                                   dict(categories=("documents",))])
def test_no_folders_when_the_query_is_about_files(folders, use_tools, extra):
    assert all(not is_dir for _p, is_dir in
               dir_hits(folders, SearchQuery(name="*steuer*", **extra), use_tools))


def test_no_folders_without_a_name(folders):
    assert dir_hits(folders, SearchQuery(), False) == [
        ("Steuer 2025/belege/rechnung.pdf", False), ("steuer.txt", False)]


def test_callers_that_do_not_ask_get_files_only(folders):
    assert dir_hits(folders, SearchQuery(name="*steuer*"), False, include_dirs=False) == [
        ("steuer.txt", False)]


def test_a_remote_name_search_finds_folders(folders):
    from core.ram_fs import RamFsSession

    ram = RamFsSession()
    for path in ("/r/Steuer 2025/belege", "/r/archiv/steuer-alt", "/r/.steuer-hidden",
                 "/r/node_modules/steuer-pkg"):
        ram.mkdir(path, parents=True)
    with ram.open_write("/r/steuer.txt") as fh:
        fh.write(b"x")
    assert dir_hits(Path("/r"), SearchQuery(name="*steuer*"), True, backend=ram) == [
        (".steuer-hidden", True), ("Steuer 2025", True), ("archiv/steuer-alt", True),
        ("steuer.txt", False)]


def test_index_folders_are_found_by_name(folders, tmp_path):
    from core import metadata_index as MX

    db = tmp_path / "index.sqlite"
    MX.index_dir(LocalFS(), str(folders), backend_id="LocalFS:Local", db_path=db)
    hits = []
    FS.run_search([], SearchQuery(name="*steuer 2025*"), on_hit=lambda _s, h: hits.append(h),
                  use_index=True, index_db=db, include_dirs=True)
    assert [(os.path.basename(h.path), h.is_dir) for h in hits] == [("Steuer 2025", True)]


# ---------------------------------------------------------------------------
# Folders that overlap
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("use_tools", TOOLS)
def test_a_file_in_two_ticked_folders_is_listed_once(tmp_path, use_tools):
    """Look in: the active pane's folder and another pane's subfolder of it
    both ticked - every file of the subfolder came twice."""
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "a.txt").write_text("needle")
    (tmp_path / "b.txt").write_text("needle")
    for query in (SearchQuery(name="*.txt"), SearchQuery(contains="needle")):
        hits = []
        summary = FS.run_search(
            [FS.SearchScope(LocalFS(), str(tmp_path)), FS.SearchScope(LocalFS(), str(tmp_path / "sub"))],
            query, on_hit=lambda _s, h: hits.append(h.path), use_tools=use_tools)
        assert sorted(hits) == [str(tmp_path / "b.txt"), str(tmp_path / "sub" / "a.txt")]
        assert summary.found == 2
