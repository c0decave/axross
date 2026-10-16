"""What the READMEs promise on their first screen, and the screenshots.

- Every README opens with the same ten benefits, one line each, right
  under the tagline - the same count in every language.
- The three language READMEs show the same screenshots; each one exists,
  and docs/screenshots holds no image that none of them shows.
- A screenshot carries no metadata chunk (text, EXIF, time, ICC profile):
  only the pixels and their density.
- pyproject names no operating system that no CI job runs on, and names
  (with the description and the language READMEs' binaries item) all three
  the release builds for: Linux, macOS and Windows.
"""

from __future__ import annotations

import re
import struct
from pathlib import Path

import pytest

try:
    import tomllib
except ModuleNotFoundError:  # Python 3.10
    import tomli as tomllib  # type: ignore[no-redef]

ROOT = Path(__file__).resolve().parents[1]
LANGUAGE_READMES = ("README.md", "README_de.md", "README_es.md")
ALL_READMES = (*LANGUAGE_READMES, "README_PYPI.md")
SHOTS = ROOT / "docs" / "screenshots"
BENEFITS = 10
_IMAGE = re.compile(r"!\[[^\]]*\]\((docs/screenshots/[^)\s]+)\)")
_PNG_CHUNKS_ALLOWED = {b"IHDR", b"IDAT", b"IEND", b"pHYs"}


def benefit_block(text: str) -> list[str]:
    """The bullet lines of the first list after the bold tagline."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("**"))
    while start < len(lines) and lines[start].strip():
        start += 1  # the rest of the tagline paragraph
    while start < len(lines) and not lines[start].strip():
        start += 1
    block = []
    for line in lines[start:]:
        if not line.strip():
            break
        block.append(line)
    return block


def png_chunks(data: bytes) -> list[bytes]:
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("not a PNG")
    chunks, i = [], 8
    while i + 8 <= len(data):
        (length,) = struct.unpack(">I", data[i : i + 4])
        chunks.append(data[i + 4 : i + 8])
        i += 12 + length
    return chunks


def ci_operating_systems() -> set[str]:
    """Trove names of the OSes a GitHub workflow runs the tests on.

    Only a workflow that runs pytest counts: CodeQL's template names
    macos-latest for Swift, which tests nothing of axross.
    """
    found = {"POSIX :: Linux"}
    for wf in (ROOT / ".github" / "workflows").glob("*.yml"):
        text = wf.read_text(encoding="utf-8")
        if "pytest" not in text:
            continue
        if re.search(r"\bmacos-", text):
            found.add("MacOS")
        if re.search(r"\bwindows-", text):
            found.add("Microsoft :: Windows")
    return found


# --- happy ----------------------------------------------------------------


@pytest.mark.parametrize("name", ALL_READMES)
def test_happy_each_readme_opens_with_ten_one_line_benefits(name):
    block = benefit_block((ROOT / name).read_text(encoding="utf-8"))
    assert len(block) == BENEFITS, block
    for line in block:
        assert line.startswith("- **"), line  # a bullet that starts bold
        assert "**" in line[4:], line


def test_happy_the_language_readmes_show_the_same_existing_screenshots():
    shown = {
        name: _IMAGE.findall((ROOT / name).read_text(encoding="utf-8")) for name in LANGUAGE_READMES
    }
    assert shown["README.md"], "README.md shows no screenshot"
    assert shown["README_de.md"] == shown["README.md"] == shown["README_es.md"]
    for rel in shown["README.md"]:
        assert (ROOT / rel).is_file(), rel


def test_happy_every_screenshot_is_metadata_free():
    pngs = sorted(SHOTS.glob("*.png"))
    assert pngs
    for png in pngs:
        assert set(png_chunks(png.read_bytes())) <= _PNG_CHUNKS_ALLOWED, png.name


RELEASE_OSES = ("Linux", "macOS", "Windows")


def test_happy_pyproject_names_every_os_a_release_is_built_for():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    classifiers = set(meta["project"]["classifiers"])
    for trove in ("POSIX :: Linux", "MacOS", "Microsoft :: Windows"):
        assert f"Operating System :: {trove}" in classifiers, trove
    for name in RELEASE_OSES:
        assert name in meta["project"]["description"], name


@pytest.mark.parametrize("name", LANGUAGE_READMES)
def test_happy_the_binaries_item_names_every_release_os(name):
    text = (ROOT / name).read_text(encoding="utf-8")
    item = next(p for p in text.split("\n\n") if "`axross-slim`" in p and "22." in p)
    for os_name in RELEASE_OSES:
        assert os_name in item, (name, os_name)


# --- sad ------------------------------------------------------------------


def test_sad_no_screenshot_lies_unused():
    shown = set(_IMAGE.findall((ROOT / "README.md").read_text(encoding="utf-8")))
    on_disk = {f"docs/screenshots/{p.name}" for p in SHOTS.iterdir()}
    assert on_disk == shown


def test_sad_pyproject_claims_no_os_without_a_ci_job():
    meta = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    claimed = {
        c.removeprefix("Operating System :: ")
        for c in meta["project"]["classifiers"]
        if c.startswith("Operating System ::")
    }
    assert claimed <= ci_operating_systems(), claimed


def test_sad_the_benefit_parser_rejects_wrapped_and_short_lists():
    wrapped = "# A\n\n**Tag.**\n\n- **One** first\n  continued\n- **Two** x\n"
    assert benefit_block(wrapped) == ["- **One** first", "  continued", "- **Two** x"]
    with pytest.raises(ValueError):
        png_chunks(b"GIF89a")


# --- edge -----------------------------------------------------------------


def test_edge_a_multi_line_tagline_is_skipped_whole():
    text = "# A\n\n**Line one\nline two.**\n\n- **a** b\n- **c** d\n\nProse.\n"
    assert benefit_block(text) == ["- **a** b", "- **c** d"]


def test_edge_a_metadata_chunk_is_seen():
    ihdr = struct.pack(">I", 13) + b"IHDR" + bytes(13) + bytes(4)
    text = struct.pack(">I", 3) + b"tEXt" + b"a\x00b" + bytes(4)
    iend = struct.pack(">I", 0) + b"IEND" + bytes(4)
    chunks = png_chunks(b"\x89PNG\r\n\x1a\n" + ihdr + text + iend)
    assert chunks == [b"IHDR", b"tEXt", b"IEND"]
    assert not set(chunks) <= _PNG_CHUNKS_ALLOWED
