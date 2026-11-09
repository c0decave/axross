"""Numbers the guides state that the code decides: the third-party projects
of Help > Third-Party Software… (README and its translations), the
protocols of the at-a-glance line (docs/USAGE*.md), the timeout classes of
the MCP manifest example (docs/MCP*.md §9.7).

A doc audit found all three behind the code (222 projects where the data
file has 240, "22 protocols" where list_backends() gives 40, six timeout
classes where the manifest has seven); this keeps them in step.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import third_party as T  # noqa: E402

PROJECTS = {"README.md": r"lists the (\d+) projects axross uses or ships",
            "README_de.md": r"listet die (\d+) Projekte, die axross nutzt",
            "README_es.md": r"lista los (\d+) proyectos que axross usa"}
GLANCE = {"USAGE.md": r"file manager for more than (\d+)\s+protocols",
          "USAGE_de.md": r"Dateimanager für mehr als (\d+)\s+Protokolle",
          "USAGE_es.md": r"Total Commander para más de (\d+)\s+protocolos"}


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


@pytest.mark.parametrize("name", sorted(PROJECTS))
def test_happy_the_readmes_name_as_many_projects_as_the_data_file(name):
    found = re.findall(PROJECTS[name], " ".join(_read(ROOT / name).split()))
    assert found, f"{name}: the Third-Party Software entry is gone or re-worded"
    assert {int(n) for n in found} == {len(T.load())}, name


@pytest.mark.parametrize("name", sorted(GLANCE))
def test_happy_the_usage_guides_claim_no_more_protocols_than_there_are(name):
    from core import scripting

    found = re.findall(GLANCE[name], _read(ROOT / "docs" / name))
    assert found == ["30"], f"{name}: the at-a-glance line should say 30+, as README.md and SPEC.md"
    assert len(scripting.list_backends()) >= 30


def test_edge_no_usage_guide_names_an_exact_protocol_count():
    for name in GLANCE:
        head = _read(ROOT / "docs" / name)[:2000]
        assert not re.search(r"\b(?:for|für|para) \d+\s+(?:protocols|Protokolle|protocolos)", head), name


def _manifest_classes() -> dict:
    return json.loads(_read(ROOT / "docs" / "mcp-tools.json"))["timeout_classes"]


def test_happy_the_mcp_manifest_example_has_every_timeout_class():
    text = _read(ROOT / "docs" / "MCP.md")
    m = re.search(r'"timeout_classes": (\{[^}]*\})', text)
    assert m, "docs/MCP.md §9.7 lost its timeout_classes example"
    assert json.loads(m.group(1)) == _manifest_classes()


@pytest.mark.parametrize("name", ["MCP_de.md", "MCP_es.md"])
def test_happy_the_translated_manifest_sections_name_every_timeout_class(name):
    text = _read(ROOT / "docs" / name)
    section = text[text.index("### 9.7"):text.index("### 9.8")]
    missing = [c for c in _manifest_classes() if f"`{c}`" not in section]
    assert not missing, f"{name} §9.7 does not name {missing}"
