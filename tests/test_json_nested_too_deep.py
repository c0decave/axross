"""A JSON file or answer nested past the recursion limit is unreadable, not
an exception out of every caller.

Found in review (2026-11-02): Python 3.11's C JSON decoder honours the
recursion limit and raises RecursionError for a document some thousand
levels deep. 0.14.203 caught it for session.json only; the other readers
caught OSError and ValueError - a nested logging settings file stopped
axross from starting, and a nested answer of an MCP server or a model
escaped as an unexpected error. Every reader that catches ValueError of a
json.load now catches RecursionError too, and this test holds new ones to
it.
"""

from __future__ import annotations

import ast
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DEEP = "[" * 100_000 + "]" * 100_000


def _calls_json_load(node: ast.AST) -> bool:
    for sub in ast.walk(node):
        if (isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute)
                and sub.func.attr in ("load", "loads")
                and isinstance(sub.func.value, ast.Name) and sub.func.value.id == "json"):
            return True
    return False


def _caught(handler: ast.ExceptHandler) -> set[str]:
    kinds = handler.type
    if kinds is None:
        return {"BaseException"}
    items = kinds.elts if isinstance(kinds, ast.Tuple) else [kinds]
    return {item.id for item in items if isinstance(item, ast.Name)}


def test_happy_every_reader_that_catches_valueerror_of_json_catches_recursionerror():
    missing = []
    for folder in ("core", "ui", "models", "resources"):
        for path in sorted((ROOT / folder).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Try) or not any(map(_calls_json_load, node.body)):
                    continue
                # an earlier handler of the same try may catch RecursionError
                # (the lint rule of 0.15.119 forbids repeating it)
                before: set[str] = set()
                for handler in node.handlers:
                    caught = _caught(handler)
                    if "ValueError" in caught and not (caught | before) & {
                            "RecursionError", "RuntimeError", "Exception", "BaseException"}:
                        missing.append(f"{path.relative_to(ROOT)}:{handler.lineno}")
                    before |= caught
    assert missing == []


def test_sad_a_deeply_nested_logging_settings_file_gives_the_defaults(tmp_path):
    """Read at every start: it stopped axross from starting."""
    from core.log_config import LogSettings

    path = tmp_path / "logging.json"
    path.write_text(DEEP, encoding="utf-8")
    assert LogSettings.load(path) == LogSettings()


def test_edge_the_decoder_of_this_python_raises_for_the_test_document():
    """What the readers guard against (a Python that decodes it hands the
    list back, and the readers' type checks refuse it)."""
    import json

    try:
        assert isinstance(json.loads(DEEP), list)
    except RecursionError:
        pass
