"""Round 3 (lows from round 2): counts said "{files} file(s)".

The Duplicate Finder's folder details read "/data · 1 file(s) · 4 bytes",
Metadata "Metadata removed from 1 file(s)", Compare "Apply 1 change(s)?",
and some fifty more texts across ui/ - "1 connection(s)" reads as a bug,
and German had "Datei(en)", "unsichere(r) Name(n)". Others said "{n} files"
also of one ("1 files selected", "Searching 1 hosts…", "Total: 1 B, 1
files, 0 folders").

Each is a ``tr_n`` pair now (core.i18n.tr_n), with German for both forms.
"""

from __future__ import annotations

import ast
import json
import os
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

#: "file(s)", "Datei(en)": a word with its plural ending in brackets.
_BRACKETED_PLURAL = re.compile(r"[A-Za-z]\((?:s|es)\)|\bcopy/copies\b")
#: Not counts: an address scheme, a unit.
_NOT_A_COUNT = ("http(s)", "Time (s)")


def _translated_literals(path: Path):
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        if node.func.id == "tr":
            args = node.args[:1]
        elif node.func.id == "tr_n":
            args = node.args[1:3]
        else:
            continue
        for arg in args:
            if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                yield node.lineno, node.func.id, arg.value


def bracketed_plurals(path: Path) -> list[str]:
    found = []
    for lineno, _fn, text in _translated_literals(path):
        rest = text
        for keep in _NOT_A_COUNT:
            rest = rest.replace(keep, "")
        if _BRACKETED_PLURAL.search(rest):
            found.append(f"{path.relative_to(ROOT)}:{lineno}: {text[:70]!r}")
    return found


def test_sad_no_text_of_the_window_counts_with_a_bracketed_plural():
    found = [hit for path in sorted((ROOT / "ui").rglob("*.py")) for hit in bracketed_plurals(path)]
    assert not found, "\n".join(found)


def test_sad_the_scan_finds_a_bracketed_plural(tmp_path):
    probe = tmp_path / "probe.py"
    probe.write_text('x = tr("{path} · {files} file(s) · {size:,} bytes").format(files=1)\n'
                     'y = tr("http(s) URL")\n')
    probe_root = tmp_path
    hits = [t for _l, _f, t in _translated_literals(probe) if _BRACKETED_PLURAL.search(
        t.replace("http(s)", ""))]
    assert hits == ["{path} · {files} file(s) · {size:,} bytes"], probe_root


def test_happy_every_tr_n_pair_of_the_window_has_german_for_both_forms():
    de = json.loads((ROOT / "resources" / "i18n" / "de.json").read_text(encoding="utf-8"))
    missing = []
    for path in sorted((ROOT / "ui").rglob("*.py")):
        for lineno, fn, text in _translated_literals(path):
            if fn == "tr_n" and text not in de:
                missing.append(f"{path.relative_to(ROOT)}:{lineno}: {text[:70]!r}")
    assert not missing, "\n".join(missing)
    german = [v for k, v in de.items() if "(s)" not in k]
    assert not [v for v in german if re.search(r"\w\((?:en|e|n|er|se|r)\)", v)], \
        "German with a bracketed plural of a counted text"


def test_happy_the_duplicate_finder_details_count_one_file():
    pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
    from core.i18n import tr_n

    one = tr_n(1, "{path} · {n} file · {size:,} bytes", "{path} · {n} files · {size:,} bytes",
               path="/data", size=4)
    many = tr_n(3, "{path} · {n} file · {size:,} bytes", "{path} · {n} files · {size:,} bytes",
                path="/data", size=4096)
    assert one == "/data · 1 file · 4 bytes"
    assert many == "/data · 3 files · 4,096 bytes"
    src = (ROOT / "ui" / "cas_dialog.py").read_text(encoding="utf-8")
    assert '"{path} · {n} file · {size:,} bytes"' in src
