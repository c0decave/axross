"""English messages say "is not a …", not the German "kein" construction.

Review round 6 (F5): "This folder is no restic, Borg or duplicity
repository.", "That is no world code.", "the playlist is no regular file",
"… is no e-mail address" and more read as translated from German; the
scheduler told the user to save a script "in the Script Editor" while the
window calls it the Scripts dock. The German entries moved with their keys.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

#: file -> the corrected message it holds now.
FIXED = {
    "resources/extensions/backup_repos.py": "is not a restic, Borg or duplicity repository.",
    "ui/arcade_window.py": "That is not a world code.",
    "resources/extensions/media_player.py": "the playlist is not a regular file",
    "core/mail_send.py": "is not an e-mail address",
    "core/bookmarks.py": "is not a host name or IP address.",
    "core/iscsi_client.py": "is not a network interface name",
    "core/loop_mount.py": "is not a loop device",
    "core/nfs_user_client.py": "is not a symbolic link",
    "ui/main_window.py": "A terminal bookmark is not a folder: nothing was moved.",
    "core/scheduler.py": "save it in the Scripts \"\n            \"dock",
}

#: A quoted message (not a comment or docstring line) with "is no <word>".
_GERMANISM = re.compile(r'''["'][^"'#]*(?<!here )\b(?:is|are) no (?!longer|more|one|other)[a-z]''')


@pytest.mark.parametrize("path", sorted(FIXED))
def test_happy_the_message_reads_is_not_a(path):
    assert FIXED[path] in (ROOT / path).read_text(encoding="utf-8")


def test_sad_no_quoted_message_in_these_files_says_is_no():
    found = []
    for path in FIXED:
        for number, line in enumerate((ROOT / path).read_text("utf-8").splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith(("#", '"""', "'''")):
                continue
            if _GERMANISM.search(line) and ("raise" in line or "tr(" in line
                                            or "return f" in line or "Error(" in line):
                found.append(f"{path}:{number}: {stripped}")
    assert found == []


def test_edge_the_german_entries_moved_with_their_keys():
    catalogue = json.loads((ROOT / "resources/i18n/de.json").read_text("utf-8"))
    for old, new in (
        ("That is no world code.", "That is not a world code."),
        ("A terminal bookmark is no folder: nothing was moved.",
         "A terminal bookmark is not a folder: nothing was moved."),
        ("There is no saved script {name!r}. Save it in the Script Editor first, or choose "
         "one of: {scripts}",
         "There is no saved script {name!r}. Save it in the Scripts dock first, or choose "
         "one of: {scripts}"),
    ):
        assert old not in catalogue
        assert catalogue.get(new), new
