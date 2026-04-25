"""Default ``list_versions`` / ``open_version_read`` for backends
without native history support.

Apply to a backend class by inheriting from :class:`NoVersionHistory`
or by assigning the two methods manually. The registry's
``has_version_history`` capability already advertises to callers
whether these methods will return anything useful — the stubs are
just there so the :class:`FileBackend` protocol is satisfied.
"""
from __future__ import annotations


class NoVersionHistory:
    """Mixin: backends that don't track revisions return an empty list
    and refuse open_version_read. Inherit BEFORE the backend class in
    the MRO so its potential native implementation wins."""

    def list_versions(self, path: str) -> list:  # noqa: D401
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError(
            f"{type(self).__name__} does not expose file version history"
        )
