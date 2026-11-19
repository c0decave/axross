"""The plain-text message boxes (ui.plain_text.plain_message) speak the
interface language.

Reproduced 2026-11-19 (independent review): "Transfer incomplete" - the
box shown when reading the folders of a copy or move stopped part-way -
was an English literal, its text an English f-string, in the German
window too; so was the "Not saved" box of a bookmark or profile store
that could not be written. tests/test_german_no_untranslated_literals.py
does not count plain_message among its sinks: this test reads every call
of it.
"""

from __future__ import annotations

import ast
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

TRANSLATORS = {"tr", "tr_n"}


def _translated(node: ast.AST) -> bool:
    """A text argument is fine when it is no literal (a name, an attribute,
    a call of anything) or a tr() / tr_n() call - possibly .format()ed."""
    if isinstance(node, ast.Call):
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr == "format":
            return _translated(func.value)
        return True
    if isinstance(node, ast.BinOp):
        return _translated(node.left) and _translated(node.right)
    if isinstance(node, ast.Constant):
        # A separator ("\n\n", ": ") holds no words.
        return not (isinstance(node.value, str) and any(c.isalpha() for c in node.value))
    return not isinstance(node, ast.JoinedStr)


def _untranslated_calls() -> list[str]:
    found = []
    for folder in ("ui", "core"):
        for path in sorted((ROOT / folder).rglob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"), str(path))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = node.func.attr if isinstance(node.func, ast.Attribute) else getattr(
                    node.func, "id", "")
                if name != "plain_message":
                    continue
                for arg in node.args[2:4]:
                    if not _translated(arg):
                        found.append(f"{path.relative_to(ROOT)}:{node.lineno}")
    return found


def test_happy_every_plain_message_text_goes_through_tr():
    assert _untranslated_calls() == []


def test_sad_the_scan_flags_a_literal_and_an_fstring():
    assert not _translated(ast.parse('"Transfer incomplete"').body[0].value)
    assert not _translated(ast.parse('f"stopped: {e}"').body[0].value)
    assert _translated(ast.parse('tr("Transfer incomplete")').body[0].value)
    assert _translated(ast.parse('tr("x {e}").format(e=e)').body[0].value)
    assert not _translated(ast.parse('tr("a") + "\\n\\nb"').body[0].value)
    assert _translated(ast.parse('tr("a") + "\\n\\n" + b').body[0].value)


@pytest.mark.parametrize("key", [
    "Transfer incomplete",
    "Reading the folders to copy stopped: {error}",
    "Reading the folders to move stopped: {error}",
    "{n} file was queued; the rest of the selection was not transferred.",
    "{n} files were queued; the rest of the selection was not transferred.",
    "The bookmarks could not be saved: {error}",
    "The connection profiles could not be saved: {error}",
    "{what} could not be saved: {error}",
    "The change is kept until axross ends; free some space or fix the permissions "
    "of ~/.config/axross to keep it.",
])
def test_happy_the_german_catalogue_has_the_texts(key):
    german = json.loads((ROOT / "resources" / "i18n" / "de.json").read_text(encoding="utf-8"))
    assert german.get(key), key
    for field in ("{error}", "{n}", "{what}"):
        assert (field in key) == (field in german[key]), (key, german[key])
