"""Crash-recovery sweep for orphaned ``.tmp-*.tmp`` files.

When :func:`core.atomic_io.atomic_write` is interrupted (crash, kill,
network drop) between writing the temp file and the final rename,
the temp lingers as ``.tmp-<hex>.tmp`` in the target directory. This
module sweeps a directory for such orphans that are old enough to be
safely assumed dead.

Two safety knobs make this conservative on purpose:

* **Age threshold** — only files whose mtime is at least
  :data:`DEFAULT_MAX_AGE_SECONDS` old are removed, so a temp file
  that another process is mid-rename'ing is left alone.
* **Strict name pattern** — ``.tmp-`` literal prefix (or the legacy
  ``.axross-atomic-`` prefix for backward compatibility) followed by
  exactly the 12 lowercase-hex characters that
  ``secrets.token_hex(6)`` produces + ``.tmp`` suffix. Any deviation
  (different length, uppercase, extra chars) is left untouched, so a
  user's manually-named ``.tmp-foo.tmp`` won't be accidentally
  deleted.

Non-recursive by design: the call site (a file pane after a
successful navigate, or a startup hook for LocalFS home) sweeps the
single directory the user is actually looking at. Walking the whole
tree recursively would be too aggressive — better to let the
opportunistic per-directory sweep get them organically.
"""
from __future__ import annotations

import logging
import re
import time
from datetime import datetime

log = logging.getLogger("core.atomic_recovery")

# Conservative default — one hour. Tighter than this risks racing a
# legitimate slow write; looser leaves debris around longer than the
# user expects.
DEFAULT_MAX_AGE_SECONDS = 3600

# Match what core.atomic_io._temp_sibling produces. Two shapes:
#   current:  ".tmp-" + secrets.token_hex(6) + ".tmp"
#   legacy:   ".axross-atomic-" + secrets.token_hex(6) + ".tmp"
# token_hex(6) is always 12 lowercase hex characters in both cases.
#
# The legacy pattern is kept only so orphaned temp files from
# pre-scrub installs still get cleaned up. New writes never produce
# the legacy form. Don't let this list grow — add a migration path
# if we change the prefix again.
_ORPHAN_PATTERN = re.compile(
    r"^\.(?:tmp|axross-atomic)-[0-9a-f]{12}\.tmp$"
)


def is_orphan_name(name: str) -> bool:
    """True iff *name* matches the canonical orphan-temp pattern."""
    return bool(_ORPHAN_PATTERN.match(name or ""))


def _entry_mtime_epoch(entry) -> float | None:
    """Pull a unix-epoch mtime out of a backend list_dir entry.
    Returns None when the backend didn't populate one — caller
    decides whether to be conservative (skip) or aggressive (remove
    anyway). We default to skip, see ``sweep_orphans``."""
    mod = getattr(entry, "modified", None)
    if mod is None:
        return None
    if isinstance(mod, datetime):
        try:
            return mod.timestamp()
        except (OverflowError, OSError, ValueError):
            return None
    if isinstance(mod, (int, float)):
        return float(mod)
    return None


def sweep_orphans(backend, root: str, *,
                  max_age_seconds: int = DEFAULT_MAX_AGE_SECONDS,
                  now_epoch: float | None = None,
                  prefetched_entries=None) -> int:
    """Sweep *root* on *backend* for orphaned atomic-write temp files.

    Returns the number of files actually removed. Files that match
    the orphan pattern but are too young (less than *max_age_seconds*
    old) or whose age can't be determined are left in place — being
    aggressive here would race in-progress writes from another
    instance of axross.

    *prefetched_entries* is the optional list returned by an earlier
    ``backend.list_dir(root)``. Passing it skips a redundant remote
    round-trip when the caller (e.g. a file-pane navigate hook) has
    already paid for the listing. The contract: entries must be from
    the SAME root or you'll be sweeping the wrong directory.

    Failures on individual entries (permission, race, gone) are
    logged and skipped so one bad entry doesn't abort the sweep.
    Failures on the directory listing itself propagate: the caller
    needs to know that the sweep didn't even start.
    """
    cutoff = (now_epoch if now_epoch is not None else time.time()) - max_age_seconds
    if prefetched_entries is not None:
        entries = prefetched_entries
    else:
        try:
            entries = backend.list_dir(root)
        except OSError:
            # Caller (a UI pane, a startup hook) decides whether to log
            # this one — re-raising means the sweep is a no-op rather
            # than a silent partial.
            raise
    removed = 0
    for entry in entries:
        name = getattr(entry, "name", "") or ""
        if not is_orphan_name(name):
            continue
        mtime = _entry_mtime_epoch(entry)
        if mtime is None:
            log.debug("atomic_recovery: skipping %s — no mtime", name)
            continue
        if mtime > cutoff:
            log.debug(
                "atomic_recovery: skipping %s — too young (mtime %.0f > "
                "cutoff %.0f)", name, mtime, cutoff,
            )
            continue
        try:
            full = backend.join(root, name)
        except Exception as exc:
            log.warning(
                "atomic_recovery: join(%s, %s) failed: %s", root, name, exc,
            )
            continue
        try:
            backend.remove(full)
            removed += 1
            log.info("atomic_recovery: removed orphan %s", full)
        except OSError as exc:
            log.warning(
                "atomic_recovery: remove(%s) failed: %s", full, exc,
            )
    return removed


__all__ = [
    "DEFAULT_MAX_AGE_SECONDS",
    "is_orphan_name",
    "sweep_orphans",
]
