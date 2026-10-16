"""docs/LLM_GUIDE.md stays true to the code.

Its tool catalog is generated from docs/mcp-tools.json
(``python -m core.llm_guide``) and must match byte for byte; the prose may
name only tools and arguments that exist, and the flag table names
every capability group.
"""

from __future__ import annotations

import copy
import json
import re
from pathlib import Path

from core import llm_guide as gen
from core import mcp_groups as G

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "LLM_GUIDE.md"
MANIFEST = json.loads((ROOT / "docs" / "mcp-tools.json").read_text(encoding="utf-8"))

#: snake_case names the prose uses that are not tools or tool arguments:
#: a field of the script_run reply and a keyword of axross.confirm().
RESULT_FIELDS = {"error_type", "assume_yes"}


def _guide() -> str:
    return GUIDE.read_text(encoding="utf-8")


def _prose() -> str:
    text = _guide()
    return text[: text.index(gen.BEGIN)] + text[text.index(gen.END) + len(gen.END):]


def test_happy_the_catalog_is_the_generator_output():
    text = _guide()
    assert gen.splice(text, gen.render_catalog(MANIFEST)) == text, (
        "docs/LLM_GUIDE.md is stale: run python -m core.llm_guide"
    )


def test_happy_every_tool_has_a_catalog_entry():
    headings = set(re.findall(r"^#### `([a-z_0-9]+)`", _guide(), re.M))
    assert headings == {t["name"] for t in MANIFEST["tools"]}


def test_sad_a_stale_catalog_is_caught():
    smaller = copy.deepcopy(MANIFEST)
    dropped = smaller["tools"].pop()
    smaller["groups"][dropped["group"]]["tools"].remove(dropped["name"])
    assert gen.splice(_guide(), gen.render_catalog(smaller)) != _guide()


def test_edge_the_prose_names_only_tools_and_arguments_that_exist():
    known = {t["name"] for t in MANIFEST["tools"]}
    for tool in MANIFEST["tools"]:
        known |= set(tool["input_schema"].get("properties", {}))
    named = set(re.findall(r"`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b", _prose()))
    assert named - known - RESULT_FIELDS == set()


def test_edge_the_flag_table_names_every_group():
    section = _prose().split("## 2.")[0]
    missing = [g for g in G.GROUPS if g not in section]
    assert missing == []


def test_edge_links_point_at_files_that_exist():
    for target in re.findall(r"\]\(([^)#]+)\)", _prose()):
        assert (GUIDE.parent / target).exists(), target
    llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
    targets = re.findall(r"\]\(([^)#]+)\)", llms)
    assert "docs/LLM_GUIDE.md" in targets
    for target in targets:
        assert (ROOT / target).exists(), target
