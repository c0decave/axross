"""bookmark_audit.py — verify every saved bookmark still resolves.

Walks ``core.bookmarks.BookmarkManager``, opens the matching profile
(if any), and probes each bookmark's path. Reports broken bookmarks
so the user can clean them up after a server retirement / path
rename.

Local bookmarks (``backend_name == 'Local'``) are checked against
:func:`os.path.exists`; remote bookmarks open the saved profile and
call ``backend.exists(path)``.

Usage::

    report = audit_bookmarks()
    for entry in report["broken"]:
        print(entry)
"""
from __future__ import annotations

import os

from core.bookmarks import BookmarkManager
from core.profiles import ProfileManager


def audit_bookmarks() -> dict[str, list]:
    mgr = BookmarkManager()
    profiles = {p.name: p for p in ProfileManager().all_profiles()}
    ok: list[str] = []
    broken: list[dict] = []
    skipped: list[dict] = []
    for bm in mgr._bookmarks:  # noqa: SLF001 — read-only walk
        if bm.backend_name == "Local":
            if os.path.exists(bm.path):
                ok.append(bm.name)
            else:
                broken.append({"name": bm.name, "path": bm.path,
                               "reason": "local path missing"})
            continue
        profile = profiles.get(bm.profile_name)
        if profile is None:
            skipped.append({"name": bm.name,
                            "reason": "no matching saved profile"})
            continue
        try:
            sess = axross.open(profile.name)
        except (KeyError, OSError, ImportError) as exc:
            skipped.append({"name": bm.name, "reason": f"connect: {exc}"})
            continue
        try:
            if sess.exists(bm.path):
                ok.append(bm.name)
            else:
                broken.append({"name": bm.name, "path": bm.path,
                               "reason": "remote path missing"})
        finally:
            try:
                sess.close()
            except Exception:  # noqa: BLE001
                pass
    return {"ok": ok, "broken": broken, "skipped": skipped}
