"""docs/EXTENSIONS.md lists exactly the extensions bundled with axross.

The names come from each module's ``EXTENSION["name"]``, read with ``ast``
so no extension (and no PyQt6) is imported. The README counts them in
words; that word follows the number of bundled extensions.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUNDLED = ROOT / "resources" / "extensions"
DOC = ROOT / "docs" / "EXTENSIONS.md"
NUMBER_WORDS = {6: "six", 7: "seven", 8: "eight", 9: "nine", 10: "ten", 11: "eleven",
                12: "twelve", 13: "thirteen", 14: "fourteen", 15: "fifteen"}


def extension_name(source: str) -> str | None:
    """The ``EXTENSION["name"]`` of a module's source, or None."""
    for node in ast.parse(source).body:
        if not (isinstance(node, ast.Assign) and isinstance(node.value, ast.Dict)):
            continue
        if not any(isinstance(t, ast.Name) and t.id == "EXTENSION" for t in node.targets):
            continue
        for key, value in zip(node.value.keys, node.value.values):
            if isinstance(key, ast.Constant) and key.value == "name":
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    return value.value
    return None


def bundled_names() -> set[str]:
    names = set()
    for path in BUNDLED.glob("*.py"):
        name = extension_name(path.read_text(encoding="utf-8"))
        if name:
            names.add(name)
    return names


def documented_names(text: str) -> set[str]:
    """First cells of the table under '## Bundled examples'."""
    section = text.split("## Bundled examples", 1)[1].split("\n## ", 1)[0]
    rows = re.findall(r"^\| ([^|]+?) \|", section, flags=re.M)
    return {r for r in rows if r not in ("Extension",) and not set(r) <= {"-"}}


# --- happy ----------------------------------------------------------------


def test_happy_every_bundled_extension_is_documented():
    missing = bundled_names() - documented_names(DOC.read_text(encoding="utf-8"))
    assert not missing, missing


def test_happy_the_readme_counts_the_bundled_extensions_in_words():
    word = NUMBER_WORDS[len(bundled_names())]
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"{word.capitalize()} bundled ones" in text
    assert f"the {word} bundled extensions" in text


# --- sad ------------------------------------------------------------------


def test_sad_no_documented_extension_is_missing_from_the_bundle():
    extra = documented_names(DOC.read_text(encoding="utf-8")) - bundled_names()
    assert not extra, extra


def test_sad_a_module_without_an_extension_dict_has_no_name():
    assert extension_name('"""Package."""\n') is None
    assert extension_name("EXTENSION = {'version': '1'}\n") is None
    assert extension_name("OTHER = {'name': 'x'}\n") is None


# --- edge -----------------------------------------------------------------


def test_edge_the_table_header_and_rule_are_not_names():
    text = "## Bundled examples\n\n| Extension | What |\n|---|---|\n| A | x |\n\n## Next\n| B | y |\n"
    assert documented_names(text) == {"A"}


def test_edge_a_non_literal_name_is_ignored():
    assert extension_name("EXTENSION = {'name': NAME}\n") is None
