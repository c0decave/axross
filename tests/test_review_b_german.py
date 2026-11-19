"""Review B: the texts the fixes added speak German in the German window."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

GERMAN = json.loads((ROOT / "resources" / "i18n" / "de.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("text", [
    "Open with the S&ystem Application…", "Open with the System Application?",
    "{name} is no document axross recognises: {what}.",
    "The desktop's default application for it may run it as a program. Open it anyway?",
    "unknown data",
    "This file belongs to the MCP server {name}, which runs on this machine with your "
    "rights: what is written here runs at the server's next start.",
    "the folder of the files it runs on this machine ({folder}) holds more than axross can "
    "check at each start (more than {count} entries, {size} MB or {depth} levels, or a "
    "folder it cannot read) – it runs every file there, so put the server in a folder of "
    "its own",
    "{path} is a link: the call changes {target}.",
    "not on the allow-list: {addresses}", "the body holds text of another message: {text}",
])
def test_happy_every_new_text_has_its_german_entry_with_the_same_fields(text):
    import re

    german = GERMAN[text]
    assert german and german != text
    assert sorted(re.findall(r"\{\w+\}", german)) == sorted(re.findall(r"\{\w+\}", text))


def test_happy_the_menu_entry_has_the_handbooks_wording():
    assert GERMAN["Open with the S&ystem Application…"].replace("&", "") == \
        "Mit der System-Anwendung öffnen…"
