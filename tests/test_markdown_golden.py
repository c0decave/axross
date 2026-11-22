"""Golden images of the Markdown reader: committed showcase documents
(tests/golden/markdown/*.md - alerts, tables, tasks, notes, math, details,
code, images, badges, lists, quotes) rendered in both of Qt's paths
(markdown-it's page and Qt's own parser, md4c), light and dark, at a fixed
width and font, compared with committed reference PNGs - an unintended
change of the look fails here (twice a fix of one thing broke another
unnoticed: the task boxes, raw HTML in prose).

The references change only on purpose, with this file as a script - and
the commit says so::

    python tests/test_markdown_golden.py --update

They are made for one font and one Qt (``golden.json``): elsewhere the
test is skipped, not failed. The font is the test's own - DejaVu Sans, Bold
and Mono in tests/golden/fonts (their licence beside them) - and the child that
draws the pages sees no other (a fontconfig file of that folder alone): a CI
runner's fonts drew the signs DejaVu has not (✓, ⚠, the formulas' and the
emoji's) in fonts of their own, 1.66 % of the pixels apart. Where fontconfig
does not take the file (no fontconfig: macOS, Windows) the fonts the child sees
are others than the record's - skipped, said why.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
GOLDEN = Path(__file__).resolve().parent / "golden" / "markdown"
#: A pixel differs when a channel differs by more than this (anti-aliasing
#: of the same text varies by a few levels) ...
PIXEL_TOLERANCE = 40
#: ... and an image differs when more than this share of its pixels do.
SHARE_TOLERANCE = 0.002
#: ... or more than this many pixels in a band of this many rows (a line moved, a formula set anew).
BAND_ROWS, BAND_PIXELS = 24, 60
WIDTH = 900
#: A reference's name: <showcase>_<parser>_<theme>.png
_REFERENCE = re.compile(r".+_(?:full|md4c)_(?:light|dark)\.png")
FONT = ("DejaVu Sans", 9)
#: The fonts the pages are drawn with - and the only ones the drawing child sees (_fontconfig).
FONTS = Path(__file__).resolve().parent / "golden" / "fonts"

_RENDER = r"""
import json, os, sys, time
sys.path.insert(0, {root!r})
os.environ["QT_QPA_PLATFORM"] = "offscreen"
from PyQt6.QtCore import QT_VERSION_STR
from PyQt6.QtGui import QColor, QFont, QFontInfo, QPalette
from PyQt6.QtWidgets import QApplication
app = QApplication([])
font = QFont({family!r}, {size!r})
app.setFont(font)
from PyQt6.QtGui import QFontDatabase
info = {{"family": QFontInfo(font).family(), "qt": QT_VERSION_STR,
        "families": sorted(QFontDatabase.families())}}
from core.local_fs import LocalFS
from ui import markdown_view as MV

def dark_palette():
    palette = QPalette()
    for role, colour in ((QPalette.ColorRole.Window, "#1f1f1f"), (QPalette.ColorRole.Base, "#181818"),
                         (QPalette.ColorRole.Text, "#e6e6e6"), (QPalette.ColorRole.WindowText, "#e6e6e6"),
                         (QPalette.ColorRole.Button, "#2b2b2b"), (QPalette.ColorRole.ButtonText, "#e6e6e6"),
                         (QPalette.ColorRole.AlternateBase, "#232323"), (QPalette.ColorRole.Mid, "#444444")):
        palette.setColor(role, QColor(colour))
    return palette

def settle(view, seconds):
    end = time.monotonic() + seconds
    while time.monotonic() < end:
        app.processEvents()
        time.sleep(0.005)

out = {out!r}
for path in {paths!r}:
    name = os.path.splitext(os.path.basename(path))[0]
    for parser in ("full", "md4c"):
        for theme in ("light", "dark"):
            view = MV.MarkdownView(MV.ImageSource(LocalFS(), path), outline=False)
            view.full = view.full and parser == "full"
            view.setPalette(dark_palette() if theme == "dark" else QPalette())
            view.resize({width!r}, 900)
            view.show()
            view.render(open(path, encoding="utf-8").read())
            end = time.monotonic() + 20
            while time.monotonic() < end and (view.status.text() or view.asked - set(view.images)):
                app.processEvents()
                time.sleep(0.005)
            settle(view, 0.3)
            height = int(view.browser.document().size().height()) + 40
            view.resize({width!r}, height + view.status.sizeHint().height() + 8)
            settle(view, 0.3)
            view.browser.viewport().grab().save(os.path.join(out, f"{{name}}_{{parser}}_{{theme}}.png"))
            view.deleteLater()
print(json.dumps(info))
"""


def _fontconfig(folder: Path) -> Path:
    """A fontconfig file that knows the fonts of FONTS alone (sans-serif, serif and monospace: theirs), its
    cache in *folder*."""
    config = folder / "fonts.conf"
    alias = "".join(f"<alias><family>{generic}</family><prefer><family>{family}</family></prefer></alias>"
                    for generic, family in (("sans-serif", "DejaVu Sans"), ("serif", "DejaVu Sans"),
                                            ("monospace", "DejaVu Sans Mono")))
    config.write_text('<?xml version="1.0"?><!DOCTYPE fontconfig SYSTEM "fonts.dtd"><fontconfig>'
                      f"<dir>{FONTS}</dir><cachedir>{folder / 'cache'}</cachedir>{alias}</fontconfig>\n",
                      encoding="utf-8")
    return config


def render(out: str) -> dict:
    """Every showcase rendered into *out*; the font and Qt they were made with, and the fonts the drawing
    child saw (those of FONTS alone)."""
    paths = sorted(str(p) for p in GOLDEN.glob("*.md"))
    script = _RENDER.format(root=str(ROOT), family=FONT[0], size=FONT[1], out=out, paths=paths, width=WIDTH)
    with tempfile.TemporaryDirectory() as fonts:
        done = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, timeout=300,
                              env={**os.environ, "QT_QPA_PLATFORM": "offscreen",
                                   "FONTCONFIG_FILE": str(_fontconfig(Path(fonts)))})
    assert done.returncode == 0, done.stderr[-3000:]
    return json.loads(done.stdout.strip().splitlines()[-1])


def difference(reference: Path, image: Path) -> tuple[float, str]:
    """(the share of pixels that differ, why the images differ - "" when alike)."""
    import numpy
    from PIL import Image

    a = numpy.asarray(Image.open(reference).convert("RGB"), dtype=numpy.int16)
    b = numpy.asarray(Image.open(image).convert("RGB"), dtype=numpy.int16)
    if a.shape != b.shape:
        return 1.0, f"size {b.shape[1]}x{b.shape[0]}, the reference {a.shape[1]}x{a.shape[0]}"
    differ = numpy.abs(a - b).max(axis=2) > PIXEL_TOLERANCE
    share = float(differ.mean())
    if share > SHARE_TOLERANCE:
        return share, f"{share:.2%} of the pixels differ"
    # (each band of rows on its own: a line moved is few pixels of all of the page - a footnote moved 21 px
    # and a fraction set anew were 0.065 % - but many of its own band's)
    rows = differ.sum(axis=1)
    for top in range(0, len(rows), BAND_ROWS // 2):  # (bands overlapping by half: a line across two seen whole)
        count = int(rows[top:top + BAND_ROWS].sum())
        if count > BAND_PIXELS:
            return share, f"{count} pixels differ in the rows {top} to {top + BAND_ROWS} (moved?)"
    return share, ""


def update() -> None:
    """The references made anew (on purpose: say so in the commit)."""
    for old in GOLDEN.glob("*.png"):
        if _REFERENCE.fullmatch(old.name):  # (a reference - not a picture a showcase shows, a_b.png)
            old.unlink()
    info = render(str(GOLDEN))
    (GOLDEN / "golden.json").write_text(json.dumps(info, indent=1) + "\n", encoding="utf-8")
    print(f"references made with {info}: {sum(bool(_REFERENCE.fullmatch(p.name)) for p in GOLDEN.glob('*.png'))} images")


def test_sad_a_line_moved_is_a_difference(tmp_path):
    """A line of the page moved 21 px is few pixels of all of it (0.065 %:
    under the share allowed for all of the page - a footnote moved and a
    fraction set anew went unseen): the bands of rows are compared each."""
    pytest.importorskip("numpy")
    pytest.importorskip("PIL")
    import numpy
    from PIL import Image

    reference = sorted(p for p in GOLDEN.glob("*.png") if _REFERENCE.fullmatch(p.name))[0]
    pixels = numpy.asarray(Image.open(reference).convert("RGB")).copy()
    rows = numpy.nonzero((numpy.abs(pixels.astype(int) - pixels[0, 0].astype(int)).max(axis=2) > 80).any(axis=1))[0]
    line = int(rows[len(rows) * 2 // 3])  # (a line of text two thirds down)
    band = pixels[line - 8:line + 8].copy()
    moved = pixels.copy()
    moved[line - 8:line + 8] = pixels[0, 0]
    moved[line - 8:line + 8, 21:] = band[:, :-21]
    path = tmp_path / reference.name
    Image.fromarray(moved).save(path)
    share, why = difference(reference, path)
    assert share < SHARE_TOLERANCE  # (as the whole page sees it: alike)
    assert why, "a line moved 21 px went unseen"
    assert not difference(reference, reference)[1]


def test_happy_the_showcases_look_as_their_references(tmp_path):
    pytest.importorskip("PyQt6.QtWidgets")
    pytest.importorskip("markdown_it")
    pytest.importorskip("numpy")
    pytest.importorskip("PIL")
    made_with = json.loads((GOLDEN / "golden.json").read_text(encoding="utf-8"))
    with tempfile.TemporaryDirectory() as out:
        info = render(out)
        if info != made_with:
            pytest.skip(f"references made with {made_with}, here {info}")
        failures = []
        for reference in sorted(p for p in GOLDEN.glob("*.png") if _REFERENCE.fullmatch(p.name)):
            image = Path(out) / reference.name
            if not image.exists():
                failures.append(f"{reference.name}: not rendered")
                continue
            _share, why = difference(reference, image)
            if why:
                kept = tmp_path / f"golden-{reference.name}"  # (the test's own folder, not the system's /tmp)
                kept.write_bytes(image.read_bytes())
                failures.append(f"{reference.name}: {why} (rendered: {kept})")
        assert not failures, "the look changed - on purpose? python tests/test_markdown_golden.py --update\n" \
            + "\n".join(failures)


if __name__ == "__main__":
    if sys.argv[1:] == ["--update"]:
        update()
    else:
        print(__doc__)
