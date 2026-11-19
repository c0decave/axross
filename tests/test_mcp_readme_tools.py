"""The headless MCP's README names its tools: the line "The 55 tools" in
scripts/export_standalone.py (the mcp App's readme_short) holds every tool
of every group of docs/mcp-tools.json, and the count in its heading and in
the points above is the real one."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
sys.path.insert(0, str(ROOT))


def test_happy_the_readme_table_lists_every_tool_of_every_group():
    import export_standalone as EXP

    manifest = json.loads((ROOT / "docs" / "mcp-tools.json").read_text(encoding="utf-8"))
    tools = [t for group in manifest["groups"].values() for t in group["tools"]]
    readme = EXP.short_readme(EXP.APPS["mcp"])
    line = next(l for l in readme.splitlines() if l.startswith(f"**The {len(tools)} tools**"))
    listed = re.findall(r"`([a-z_]+)`", line.split("): ", 1)[1])
    assert sorted(listed) == sorted(tools)
    assert f"**{len(tools)} tools in {len(manifest['groups'])} groups, opt in:**" in readme
