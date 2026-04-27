"""bookmarks_export.py — export saved axross bookmarks to JSON / CSV.

Useful for sharing the bookmark set with a colleague or for
versioning it via git. ``import_json`` reverses the process for the
JSON variant.

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
    payload = json.dumps(
        [
            {
                "name": b.name, "path": b.path,
                "backend_name": b.backend_name,
                "profile_name": b.profile_name,
                "icon_name": b.icon_name,
            }
            for b in bms
        ],
        indent=2, ensure_ascii=False,
    ) + "\n"
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
        axross.add_bookmark(
            name=entry["name"], path=entry["path"],
            backend_name=entry.get("backend_name", "Local"),
            profile_name=entry.get("profile_name", ""),
            icon_name=entry.get("icon_name", "bookmark"),
        )
        n += 1
    return n
