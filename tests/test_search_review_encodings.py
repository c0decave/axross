"""Find Files after the search review (2026-11-19): text in Latin-1 /
Windows-1252 and UTF-16 files.

Every engine case runs twice: with fd / rg when they are installed, and
with the built-in walker and reader (``use_tools=False``, as on a machine
without them) - both must give the same answer.
"""

from __future__ import annotations

import os
import sys
import unicodedata
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
# Content in other encodings
# ---------------------------------------------------------------------------


@pytest.fixture
def texts(tmp_path):
    root = tmp_path / "texts"
    root.mkdir()
    (root / "latin1.txt").write_bytes("Viele Grüße für dich\n".encode("latin-1"))
    (root / "cp1252.txt").write_bytes("Preis: 5 € für alles\n".encode("cp1252"))
    (root / "utf8.txt").write_text("Grüße für alle\n", encoding="utf-8")
    (root / "utf16le.txt").write_bytes("\ufeffWindows needle für dich\r\n".encode("utf-16-le"))
    (root / "utf16be.txt").write_bytes("\ufeffBig needle\n".encode("utf-16-be"))
    (root / "utf8bom.txt").write_bytes("\ufeffneedle bom\n".encode("utf-8"))
    (root / "upper.txt").write_bytes("FÜR GROSS\n".encode("latin-1"))
    (root / "other.txt").write_text("nothing here fur\n")
    return root


@pytest.mark.parametrize("use_tools", TOOLS)
def test_a_literal_with_umlauts_is_found_in_latin1_and_utf8_and_utf16(texts, use_tools):
    assert found(texts, SearchQuery(contains="für"), use_tools) == [
        "cp1252.txt", "latin1.txt", "upper.txt", "utf16le.txt", "utf8.txt"]


@pytest.mark.parametrize("use_tools", TOOLS)
def test_case_sensitive_umlauts_in_latin1(texts, use_tools):
    assert found(texts, SearchQuery(contains="FÜR", case_sensitive=True), use_tools) == [
        "upper.txt"]


@pytest.mark.parametrize("use_tools", TOOLS)
def test_the_euro_sign_of_windows_1252(texts, use_tools):
    assert found(texts, SearchQuery(contains="5 €"), use_tools) == ["cp1252.txt"]


@pytest.mark.parametrize("use_tools", TOOLS)
def test_utf16_files_with_a_byte_order_mark(texts, use_tools):
    assert found(texts, SearchQuery(contains="needle"), use_tools) == [
        "utf16be.txt", "utf16le.txt", "utf8bom.txt"]


@pytest.mark.parametrize("use_tools", TOOLS)
def test_a_regex_in_a_utf16_file(texts, use_tools):
    assert found(texts, SearchQuery(contains=r"^Big\s+needle$", contains_is_regex=True),
                 use_tools) == ["utf16be.txt"]


@pytest.mark.parametrize("use_tools", TOOLS)
def test_the_snippet_of_a_latin1_hit_is_readable(texts, use_tools):
    hits = []
    FS.run_search([FS.SearchScope(LocalFS(), str(texts / "latin1.txt").rsplit("/", 1)[0])],
                  SearchQuery(name="latin1.txt", contains="grüße"),
                  on_hit=lambda _s, h: hits.append(h), use_tools=use_tools)
    assert [h.snippet for h in hits] == ["Viele Grüße für dich"]


def test_a_remote_latin1_file(texts):
    """A backend other than LocalFS reads through open_read: the same
    answer."""
    from core.ram_fs import RamFsSession

    ram = RamFsSession()
    ram.mkdir("/t")
    for path in sorted(texts.iterdir()):
        with ram.open_write(f"/t/{path.name}") as fh:
            fh.write(path.read_bytes())
    assert found(Path("/t"), SearchQuery(contains="für"), True, backend=ram) == [
        "cp1252.txt", "latin1.txt", "upper.txt", "utf16le.txt", "utf8.txt"]


def test_a_utf8_file_stays_utf8_after_a_stray_byte(tmp_path):
    """One broken byte early in a UTF-8 file does not hide the UTF-8 text
    after it."""
    (tmp_path / "mixed.txt").write_bytes(b"bad \xff byte\n" + "später für uns\n".encode())
    for use_tools in (False, True):
        assert found(tmp_path, SearchQuery(contains="für"), use_tools) == ["mixed.txt"]


@pytest.mark.parametrize("use_tools", TOOLS)
def test_a_literal_with_regex_characters_and_umlauts(tmp_path, use_tools):
    """The literal stays a literal in both of rg's patterns."""
    (tmp_path / "a.txt").write_bytes("Größe [m²] (ca.) +-~#&\n".encode("cp1252"))
    (tmp_path / "b.txt").write_text("Größe [m²] (ca.) +-~#&\n")
    (tmp_path / "c.txt").write_text("Größe m² ca +-~#&\n")
    assert found(tmp_path, SearchQuery(contains="größe [m²] (ca.) +-~#&"), use_tools) == [
        "a.txt", "b.txt"]
