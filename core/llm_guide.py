"""Render the tool catalog of docs/LLM_GUIDE.md from docs/mcp-tools.json.

The guide's prose is written by hand; the catalog between the two marker
lines is generated, so it cannot drift from the manifest (which
tests/test_mcp_manifest.py holds against the code).

    python -m core.llm_guide          # rewrite the catalog in place
    python -m core.llm_guide --check  # exit 1 when it is stale
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "docs" / "mcp-tools.json"
GUIDE = ROOT / "docs" / "LLM_GUIDE.md"
BEGIN = "<!-- BEGIN GENERATED TOOL CATALOG (python -m core.llm_guide) -->"
END = "<!-- END GENERATED TOOL CATALOG -->"

#: The base tool sets first, then the capability groups alphabetically.
_BASE_ORDER = ("core", "write", "scripts")


def _group_order(groups: dict) -> list[str]:
    return [g for g in _BASE_ORDER if g in groups] + sorted(g for g in groups if g not in _BASE_ORDER)


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
        + ", ".join(f"`{name}` {_seconds(secs)}" for name, secs in sorted(classes.items(), key=lambda kv: kv[1]))
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
    flags = ["--mcp-tools " + ",".join(generated_for.get("mcp_tools") or [])] if generated_for.get("mcp_tools") else []
    for key, flag in (("mcp_write", "--mcp-write"), ("mcp_allow_scripts", "--mcp-allow-scripts"),
                      ("mcp_allow_exec", "--mcp-allow-exec")):
        if generated_for.get(key):
            flags.append(flag)
    return flags


def splice(guide: str, catalog: str) -> str:
    """*guide* with the text between the markers replaced by *catalog*."""
    start = guide.index(BEGIN)
    end = guide.index(END, start) + len(END)
    return guide[:start] + catalog + guide[end:]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 when the catalog is stale")
    args = parser.parse_args(argv)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    current = GUIDE.read_text(encoding="utf-8")
    wanted = splice(current, render_catalog(manifest))
    if args.check:
        if wanted != current:
            print(f"{GUIDE.relative_to(ROOT)} is stale; run python -m core.llm_guide", file=sys.stderr)
            return 1
        return 0
    if wanted != current:
        GUIDE.write_text(wanted, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
