"""docs/LLM_GUIDE.md stays true to the code.

Its tool catalog is generated from docs/mcp-tools.json and its scripting
catalog from docs/scripting-api.json (``python -m core.llm_guide``); both
must match byte for byte. The prose may name only tools, arguments and
``axross.*`` names that exist, and the flag table names every capability
group.
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
SCRIPTING = json.loads((ROOT / "docs" / "scripting-api.json").read_text(encoding="utf-8"))

#: snake_case names the prose uses that are not tools, tool arguments or
#: scripting names: fields of the script_run reply.
RESULT_FIELDS = {"error_type", "timed_out"}


def _guide() -> str:
    return GUIDE.read_text(encoding="utf-8")


def _prose() -> str:
    text = _guide()
    for begin, end in ((gen.BEGIN, gen.END), (gen.SCRIPTING_BEGIN, gen.SCRIPTING_END)):
        text = text[: text.index(begin)] + text[text.index(end) + len(end):]
    return text


def _scripting_names() -> set[str]:
    """Every name a script can use: functions, classes, their parameters,
    the session methods and their parameters, and the fields, properties
    and methods of the described types."""
    names = {f["name"] for f in SCRIPTING["functions"]} | {c["name"] for c in SCRIPTING["classes"]}
    for entry in SCRIPTING["functions"] + SCRIPTING["backend_protocol"]:
        names.add(entry["name"])
        names |= {p["name"] for p in entry.get("parameters", [])}
    for entry in SCRIPTING["types"] + SCRIPTING["classes"]:
        for key in ("fields", "properties", "methods"):
            names |= {m["name"] for m in entry.get(key, [])}
    return names


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
    known = {t["name"] for t in MANIFEST["tools"]} | _scripting_names()
    for tool in MANIFEST["tools"]:
        known |= set(tool["input_schema"].get("properties", {}))
    named = set(re.findall(r"`([a-z][a-z0-9]*(?:_[a-z0-9]+)+)\b", _prose()))
    assert named - known - RESULT_FIELDS == set()


def test_edge_the_prose_names_only_axross_functions_that_exist():
    public = {f["name"] for f in SCRIPTING["functions"]} | {c["name"] for c in SCRIPTING["classes"]}
    named = set(re.findall(r"\baxross\.([A-Za-z_][A-Za-z0-9_]*)", _prose()))
    assert named, "the scripting section names no axross.* function"
    assert named - public == set()


# -- the scripting catalog ----------------------------------------------------------


def test_happy_the_scripting_catalog_is_the_generator_output():
    text = _guide()
    rendered = gen.render_scripting_catalog(SCRIPTING)
    assert gen.splice(text, rendered, gen.SCRIPTING_BEGIN, gen.SCRIPTING_END) == text, (
        "docs/LLM_GUIDE.md is stale: run python -m core.llm_guide"
    )


def test_happy_every_function_and_session_method_has_a_catalog_line():
    text = _guide()
    catalog = text[text.index(gen.SCRIPTING_BEGIN): text.index(gen.SCRIPTING_END)]
    for function in SCRIPTING["functions"]:
        assert f"`axross.{function['signature']}`" in catalog, function["name"]
    for method in SCRIPTING["backend_protocol"]:
        assert f"`b.{method.get('signature') or method['name']}`" in catalog, method["name"]
    for entry in SCRIPTING["types"]:
        assert f"`{entry['name']}`" in catalog, entry["name"]


def test_sad_a_stale_scripting_catalog_is_caught():
    smaller = copy.deepcopy(SCRIPTING)
    dropped = smaller["functions"].pop()
    for group in smaller["groups"]:
        if dropped["name"] in group["functions"]:
            group["functions"].remove(dropped["name"])
    rendered = gen.render_scripting_catalog(smaller)
    assert gen.splice(_guide(), rendered, gen.SCRIPTING_BEGIN, gen.SCRIPTING_END) != _guide()


def test_edge_the_scripting_catalog_marks_changes_and_prompts():
    catalog = gen.render_scripting_catalog(SCRIPTING)
    line = next(ln for ln in catalog.splitlines() if ln.startswith("- `axross.remove("))
    assert "mutates" in line and "prompts" in line and "PermissionError" in line
    line = next(ln for ln in catalog.splitlines() if ln.startswith("- `axross.read_bytes("))
    assert "read-only" in line


def test_edge_the_flag_table_names_every_group():
    section = _prose().split("## 2.")[0]
    missing = [g for g in G.GROUPS if g not in section]
    assert missing == []


def test_edge_links_point_at_files_that_exist():
    for target in re.findall(r"\]\(([^)#]+)\)", _prose()):
        assert (GUIDE.parent / target).exists(), target
    llms = (ROOT / "llms.txt").read_text(encoding="utf-8")
    targets = re.findall(r"\]\(([^)#]+)\)", llms)
    assert "docs/LLM_GUIDE.md" in targets and "docs/scripting-api.json" in targets
    for target in targets:
        assert (ROOT / target).exists(), target
