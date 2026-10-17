"""docs/scripting-api.json is ``axross.api_schema()`` committed to the tree.

A model that writes scripts reads the file (llms.txt points at it) without
starting axross; it must say exactly what the code does.
``python -m core.llm_guide`` writes it; this test fails when the file and
the code drift apart.
"""

from __future__ import annotations

import json
from pathlib import Path

from core import llm_guide as gen
from core import scripting as axross

ROOT = Path(__file__).resolve().parents[1]
COMMITTED = ROOT / "docs" / "scripting-api.json"
REGENERATE = "python -m core.llm_guide"


def test_happy_the_committed_manifest_is_the_live_schema() -> None:
    assert COMMITTED.exists(), f"docs/scripting-api.json is missing; regenerate: {REGENERATE}"
    committed = json.loads(COMMITTED.read_text(encoding="utf-8"))
    assert committed == json.loads(json.dumps(axross.api_schema())), (
        f"docs/scripting-api.json is stale; regenerate: {REGENERATE}"
    )


def test_happy_the_committed_manifest_is_the_generator_output_byte_for_byte() -> None:
    assert COMMITTED.read_text(encoding="utf-8") == gen.render_scripting_manifest(
        axross.api_schema()
    )


def test_sad_a_stale_manifest_is_reported_by_check(tmp_path, monkeypatch, capsys) -> None:
    stale = json.loads(COMMITTED.read_text(encoding="utf-8"))
    stale["functions"].pop()
    target = tmp_path / "scripting-api.json"
    target.write_text(json.dumps(stale), encoding="utf-8")
    monkeypatch.setattr(gen, "SCRIPTING_MANIFEST", target)
    assert gen.main(["--check"]) == 1
    assert "scripting-api.json is stale" in capsys.readouterr().err
    # --check never writes.
    assert json.loads(target.read_text(encoding="utf-8")) == stale


def test_edge_the_rendering_is_stable_text() -> None:
    text = gen.render_scripting_manifest(axross.api_schema())
    assert text.endswith("}\n") and not text.endswith("\n\n")
    assert text == gen.render_scripting_manifest(json.loads(text))
