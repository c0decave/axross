"""bookmarks_export.py — export saved axross bookmarks to JSON / CSV.

Useful for sharing the bookmark set with a colleague or for
versioning it via git. ``import_json`` reverses the process for the
JSON variant - for folder bookmarks: a terminal bookmark or a Smart Folder
is exported with its kind, and the import leaves it out and names it (the
scripting API adds folder bookmarks only; one came back as a broken folder).

Usage::

    write_json("/tmp/axross-bookmarks.json")
    write_csv("/tmp/axross-bookmarks.csv")
"""

from __future__ import annotations

import csv
import io
import json


def write_json(path: str) -> int:
    bms = axross.list_bookmarks()
    payload = (
        json.dumps(
            [
                {
                    "name": b.name,
                    "path": b.path,
                    "backend_name": b.backend_name,
                    "profile_name": b.profile_name,
                    "icon_name": b.icon_name,
                    "kind": b.kind,
                    "smart_folder": bool(b.search),
                }
                for b in bms
            ],
            indent=2,
            ensure_ascii=False,
        )
        + "\n"
    )
    axross.write_text(axross.localfs(), path, payload)
    return len(bms)


def write_csv(path: str) -> int:
    bms = axross.list_bookmarks()
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["name", "path", "backend_name", "profile_name", "icon_name"])
    for b in bms:
        writer.writerow([b.name, b.path, b.backend_name, b.profile_name, b.icon_name])
    axross.write_text(axross.localfs(), path, buf.getvalue())
    return len(bms)


def import_json(path: str) -> int:
    text = axross.read_text(axross.localfs(), path)
    entries = json.loads(text)
    n = 0
    for entry in entries:
        if entry.get("kind", "folder") != "folder" or entry.get("smart_folder"):
            what = "a Smart Folder" if entry.get("smart_folder") else f"a {entry.get('kind')} bookmark"
            print(f"left out {entry.get('name')!r}: {what} is not imported here")
            continue
        axross.add_bookmark(
            name=entry["name"],
            path=entry["path"],
            backend_name=entry.get("backend_name", "Local"),
            profile_name=entry.get("profile_name", ""),
            icon_name=entry.get("icon_name", "bookmark"),
        )
        n += 1
    return n
