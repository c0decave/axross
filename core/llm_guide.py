"""Generate the machine-readable docs: docs/scripting-api.json and the two
catalogs of docs/LLM_GUIDE.md.

docs/scripting-api.json is ``axross.api_schema()`` (core.scripting) as
indented JSON; tests/test_scripting_api_manifest.py holds it against the
code. The guide's prose is written by hand; the tool catalog (from
docs/mcp-tools.json, which tests/test_mcp_manifest.py holds against the
code) and the scripting catalog (from docs/scripting-api.json) between
their marker lines are generated, so neither can drift.

    python -m core.llm_guide          # rewrite the manifest and the catalogs
    python -m core.llm_guide --check  # exit 1 when any of them is stale
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "mcp-tools.json"
SCRIPTING_MANIFEST = ROOT / "docs" / "scripting-api.json"
GUIDE = ROOT / "docs" / "LLM_GUIDE.md"
BEGIN = "<!-- BEGIN GENERATED TOOL CATALOG (python -m core.llm_guide) -->"
END = "<!-- END GENERATED TOOL CATALOG -->"
SCRIPTING_BEGIN = "<!-- BEGIN GENERATED SCRIPTING CATALOG (python -m core.llm_guide) -->"
SCRIPTING_END = "<!-- END GENERATED SCRIPTING CATALOG -->"

#: The base tool sets first, then the capability groups alphabetically.
_BASE_ORDER = ("core", "write", "scripts")


def _group_order(groups: dict) -> list[str]:
    return [g for g in _BASE_ORDER if g in groups] + sorted(
        g for g in groups if g not in _BASE_ORDER
    )


def _seconds(value: float) -> str:
    return f"{int(value)} s" if float(value).is_integer() else f"{value} s"


def _argument(name: str, spec: dict, required: bool) -> str:
    kind = spec.get("type", "any")
    if kind == "array":
        kind = f"array of {spec.get('items', {}).get('type', 'any')}"
    facts = [kind]
    if required:
        facts.append("required")
    if "enum" in spec:
        facts.append("one of " + ", ".join(f"`{v}`" for v in spec["enum"]))
    if "default" in spec:
        facts.append(f"default `{json.dumps(spec['default'])}`")
    if "minimum" in spec and "maximum" in spec:
        facts.append(f"{spec['minimum']}..{spec['maximum']}")
    elif "minimum" in spec:
        facts.append(f">= {spec['minimum']}")
    elif "maximum" in spec:
        facts.append(f"<= {spec['maximum']}")
    if spec.get("writeOnly"):
        facts.append("secret, never echoed")
    text = f"`{name}` ({', '.join(facts)})"
    description = (spec.get("description") or "").strip()
    return f"{text}: {description}" if description else text


def render_catalog(manifest: dict) -> str:
    """The Markdown catalog for *manifest*, between the marker lines."""
    tools = {t["name"]: t for t in manifest["tools"]}
    classes = manifest["timeout_classes"]
    lines = [
        BEGIN,
        "",
        f"{len(tools)} tools in {len(manifest['groups'])} sets, from `docs/mcp-tools.json` "
        f"(generated for `{' '.join(_flags(manifest['generated_for']))}`). "
        "A tool marked *backend* takes the optional `backend` argument "
        "(an id from `list_backends`; omit it for the default backend).",
        "",
        "Timeout classes: "
        + ", ".join(
            f"`{name}` {_seconds(secs)}"
            for name, secs in sorted(classes.items(), key=lambda kv: kv[1])
        )
        + ".",
    ]
    for group in _group_order(manifest["groups"]):
        info = manifest["groups"][group]
        lines += ["", f"### `{group}`", "", info["description"].strip()]
        for name in info["tools"]:
            tool = tools[name]
            schema = tool["input_schema"]
            props = dict(schema.get("properties", {}))
            takes_backend = props.pop("backend", None) is not None
            tags = [
                "mutating" if tool["mutating"] else "read-only",
                f"{tool['timeout_class']} ({_seconds(tool['timeout_seconds'])})",
                " + ".join(tool["transports"]),
            ]
            if takes_backend:
                tags.append("*backend*")
            lines += ["", f"#### `{name}` — {' · '.join(tags)}", "", tool["description"].strip()]
            if tool["required_flags"]:
                lines += ["", "Needs: " + " ".join(f"`{f}`" for f in tool["required_flags"]) + "."]
            if props:
                required = set(schema.get("required", []))
                ordered = sorted(props, key=lambda p: (p not in required, p))
                lines += [""] + [f"- {_argument(p, props[p], p in required)}" for p in ordered]
    lines += ["", END]
    return "\n".join(lines)


def _flags(generated_for: dict) -> list[str]:
    flags = (
        ["--mcp-tools " + ",".join(generated_for.get("mcp_tools") or [])]
        if generated_for.get("mcp_tools")
        else []
    )
    for key, flag in (("mcp_write", "--mcp-write"), ("mcp_allow_scripts", "--mcp-allow-scripts"),
                      ("mcp_allow_exec", "--mcp-allow-exec")):
        if generated_for.get(key):
            flags.append(flag)
    return flags


def splice(guide: str, catalog: str, begin: str = BEGIN, end: str = END) -> str:
    """*guide* with the text between the markers replaced by *catalog*."""
    start = guide.index(begin)
    stop = guide.index(end, start) + len(end)
    return guide[:start] + catalog + guide[stop:]


# -- the scripting API ----------------------------------------------------------------


def render_scripting_manifest(schema: dict) -> str:
    """docs/scripting-api.json for *schema*: indented, keys in schema order."""
    return json.dumps(schema, indent=2, ensure_ascii=False) + "\n"


def _traits(entry: dict) -> str:
    tags = ["mutates" if entry.get("mutates") else "read-only"]
    if entry.get("prompts"):
        tags.append("prompts (NonInteractiveError without a human)")
    if entry.get("raises"):
        tags.append("raises " + ", ".join(entry["raises"]))
    return " · ".join(tags)


def _one_line(text: str) -> str:
    text = " ".join((text or "").split())
    return text[:-2] + ":" if text.endswith("::") else text


def render_scripting_catalog(schema: dict) -> str:
    """The Markdown catalog of the scripting API, between its markers."""
    functions = {f["name"]: f for f in schema["functions"]}
    lines = [
        SCRIPTING_BEGIN,
        "",
        f"{len(functions)} functions, {len(schema['classes'])} classes, "
        f"{len(schema['backend_protocol'])} session members and {len(schema['types'])} "
        f"further types, from `docs/scripting-api.json` (schema version "
        f"{schema['schema_version']}). Each line: signature, then whether the call can "
        "change something, whether it can need a human, and what the axross layer "
        "raises itself; then the first paragraph of its docstring. The manifest has "
        "the whole docstring, the examples and the parameters.",
        "",
        "### Rules",
        "",
    ]
    lines += [f"- **{r['id']}**: {r['text']}" for r in schema["rules"]]
    lines += [
        "",
        "### Errors",
        "",
        "| Exception | Base | Meaning | What to do |",
        "|---|---|---|---|",
    ]
    lines += [
        f"| `{e['name']}` | `{e['base']}` | {e['meaning']} | {e['action']} |"
        for e in schema["errors"]
    ]
    for group in schema["groups"]:
        lines += ["", f"### {group['name']}", ""]
        for name in group["functions"]:
            entry = functions.get(name)
            if entry is None:  # a stale or hand-edited manifest; --check reports it
                continue
            lines.append(
                f"- `axross.{entry['signature']}` — {_traits(entry)}. {_one_line(entry['summary'])}"
            )
        for name in group["classes"]:
            lines.append(f"- class `axross.{name}`")
    lines += [
        "",
        "### Session methods (`b` = what `open`, `open_url`, `localfs` and `ramfs` return)",
        "",
    ]
    for entry in schema["backend_protocol"]:
        call = entry.get("signature") or entry["name"]
        notes = [_traits(entry)]
        if entry.get("optional"):
            notes.append("only some sessions: test `hasattr(b, name)`")
        if entry.get("fallback"):
            notes.append("without support: " + _one_line(entry["fallback"]))
        lines.append(f"- `b.{call}` — {' · '.join(notes)}. {_one_line(entry['summary'])}")
    lines += ["", "### Types", ""]
    public = {c["name"] for c in schema["classes"]}
    for entry in schema["classes"] + schema["types"]:
        members = [f["name"] for f in entry.get("fields", [])]
        members += [p["name"] for p in entry.get("properties", [])]
        members += [m["name"] + "()" for m in entry.get("methods", [])]
        members += entry.get("members", [])
        where = f"`axross.{entry['name']}`" if entry["name"] in public else f"`{entry['name']}`"
        text = f"- {where} ({entry['kind']}, `{entry['module']}`)"
        if members:
            text += ": " + ", ".join(members)
        summary = _one_line(entry["summary"])
        lines.append(text + (f" — {summary}" if summary else ""))
    lines += ["", SCRIPTING_END]
    return "\n".join(lines)


def _live_schema() -> dict:
    from core import scripting

    return scripting.api_schema()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when anything is stale")
    args = parser.parse_args(argv)
    stale: list[str] = []
    wanted_manifest = render_scripting_manifest(_live_schema())
    current_manifest = (
        SCRIPTING_MANIFEST.read_text(encoding="utf-8") if SCRIPTING_MANIFEST.exists() else ""
    )
    if wanted_manifest != current_manifest:
        stale.append(SCRIPTING_MANIFEST.name)
        if not args.check:
            SCRIPTING_MANIFEST.write_text(wanted_manifest, encoding="utf-8")
    # The catalogs come from the files, as a reader of the files sees them.
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    scripting = json.loads(
        SCRIPTING_MANIFEST.read_text(encoding="utf-8")
        if SCRIPTING_MANIFEST.exists()
        else wanted_manifest
    )
    current = GUIDE.read_text(encoding="utf-8")
    wanted = splice(current, render_catalog(manifest))
    wanted = splice(wanted, render_scripting_catalog(scripting), SCRIPTING_BEGIN, SCRIPTING_END)
    if wanted != current:
        stale.append(GUIDE.name)
        if not args.check:
            GUIDE.write_text(wanted, encoding="utf-8")
    if args.check and stale:
        for name in stale:
            print(f"{name} is stale; run python -m core.llm_guide", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
