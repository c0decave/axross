"""The group/tool table of docs/MCP.md §9.2 (and its German and Spanish
twins) lists exactly the group tools of docs/mcp-tools.json, with the
same kind, required flags and timeout class.

docs/mcp-tools.json is held against the code by test_mcp_manifest.py;
this test holds the hand-written tables against that file, so a tool
added to a group cannot ship undocumented, and a table row cannot
outlive its tool.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from core import mcp_groups as G

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = json.loads((ROOT / "docs" / "mcp-tools.json").read_text(encoding="utf-8"))

#: doc file -> (heading of the table section, word for read-only, word for mutating)
DOCS = {
    "MCP.md": ("### 9.2 ", "read-only", "mutating"),
    "MCP_de.md": ("### 9.2 ", "read-only", "mutating"),
    "MCP_es.md": ("### 9.2 ", "solo lectura", "modifica"),
}

_ROW = re.compile(
    r"^\| `(?P<group>[a-z_]+)` \| `(?P<tool>[a-z_]+)` "
    r"\|(?P<kind>[^|]+)\|(?P<flags>[^|]+)\|(?P<cls>[^|]+)\|$"
)


def _section(text: str, heading: str) -> list[str]:
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith(heading))
    end = next((i for i in range(start + 1, len(lines)) if lines[i].startswith("#")), len(lines))
    return lines[start:end]


def _rows(doc: str) -> dict[str, dict]:
    heading, read_only, mutating = DOCS[doc]
    text = (ROOT / "docs" / doc).read_text(encoding="utf-8")
    rows: dict[str, dict] = {}
    for line in _section(text, heading):
        match = _ROW.match(line)
        if not match:
            continue
        kind = match["kind"].strip()
        assert kind in (read_only, mutating), f"{doc}: unknown kind {kind!r} in {line!r}"
        assert match["tool"] not in rows, f"{doc}: {match['tool']} listed twice"
        rows[match["tool"]] = {
            "group": match["group"],
            "mutating": kind == mutating,
            "required_flags": re.findall(r"`([^`]+)`", match["flags"]),
            "timeout_class": match["cls"].strip(),
        }
    return rows


def _expected() -> dict[str, dict]:
    return {
        t["name"]: {
            "group": t["group"],
            "mutating": t["mutating"],
            "required_flags": t["required_flags"],
            "timeout_class": t["timeout_class"],
        }
        for t in MANIFEST["tools"]
        if t["group"] in G.GROUPS
    }


@pytest.mark.parametrize("doc", sorted(DOCS))
def test_happy_the_table_matches_the_manifest(doc):
    assert _rows(doc) == _expected()


def test_edge_the_manifest_covers_every_group():
    # The comparison is only complete if the committed manifest was
    # generated with every group switched on.
    assert set(MANIFEST["generated_for"]["mcp_tools"]) == set(G.GROUPS)
    assert {t["group"] for t in MANIFEST["tools"]} >= set(G.GROUPS)


def test_sad_a_missing_or_wrong_row_is_caught():
    # Negative control: the parser really sees rows; dropping one or
    # flipping its kind makes the comparison fail.
    rows = _rows("MCP.md")
    assert len(rows) == len(_expected()) > 20
    expected = _expected()
    name = next(iter(expected))
    broken = dict(rows)
    broken.pop(name)
    assert broken != expected
    flipped = dict(rows)
    flipped[name] = {**rows[name], "mutating": not rows[name]["mutating"]}
    assert flipped != expected
