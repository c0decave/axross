"""DFS-N (Distributed File System Namespaces) backend.

Microsoft DFS-N lets a single virtual path like
``\\\\company.local\\dfs\\projects`` resolve to a set of physical
SMB targets (with referral failover, geographic load balancing,
etc.). To a Linux client without DFS support, the namespace path
is opaque: ``ls`` works on the *root* but not on a *link* because
every link entry needs the server to walk the referral table.

How this backend bridges that
-----------------------------
:class:`DFSNamespaceSession` is a thin specialisation of
:class:`core.smb_client.SmbSession` that turns smbclient's global
DFS resolution on (``ClientConfig(skip_dfs=False)``) at construction
time. With it on, smbprotocol auto-resolves DFS referrals on the wire so
every existing FileBackend operation (list_dir / stat / open_read /
open_write / rename / remove) "just works" against a DFS path —
the user sees one unified namespace.

Why subclass instead of compose
-------------------------------
Every operation we'd want to forward already lives on SmbSession;
the only delta is the DFS toggle and the way we construct UNC paths
(``\\\\<domain>\\<namespace>`` instead of
``\\\\<server>\\<share>``). Subclassing keeps the surface 1:1 with
SMB so the rest of axross treats DFS panes identically. Anything
DFS-specific (referral lookups, target listing) goes through
``list_targets`` / ``referral_for`` so the UI can introspect when
it wants to.
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass

from core import smb_client

log = logging.getLogger(__name__)


# Single global lock around the smbclient.set_options() call —
# multiple sessions toggling DFS at the same time was racing on the
# library's module-level config dict.
_DFS_OPTION_LOCK = threading.Lock()


@dataclass(frozen=True)
class DfsReferral:
    """One referral returned by the DFS server.

    Mirrors what the MS-DFSC ReferralResp record carries: the
    namespace path the user typed and the actual UNC path it
    points at, plus a TTL the server suggested.
    """

    namespace_path: str
    target_path: str
    ttl_seconds: int = 0


class DFSNamespaceSession(smb_client.SmbSession):
    """SMB-with-DFS-resolution backend (FileBackend protocol).

    Constructor takes the DFS namespace as ``host`` + ``namespace``;
    e.g. ``DFSNamespaceSession("company.local", "dfs", ...)``
    speaks against ``\\\\company.local\\dfs``.
    """

    def __init__(
        self,
        host: str,
        namespace: str,
        username: str = "",
        password: str = "",
        port: int = 445,
        proxy_type: str = "none",
        proxy_host: str = "",
        proxy_port: int = 0,
        proxy_username: str = "",
        proxy_password: str = "",
    ):
        # The DFS toggle and the parent's eager-listdir probe must
        # both run while we hold the global config lock. Releasing
        # between toggle and super().__init__() would let another
        # thread (e.g. a parallel SmbSession ctor) overwrite the
        # ClientConfig back to dfs=False before our probe runs.
        with _DFS_OPTION_LOCK:
            self._enable_dfs_locked()
            super().__init__(
                host=host,
                share=namespace,
                username=username,
                password=password,
                port=port,
                proxy_type=proxy_type,
                proxy_host=proxy_host,
                proxy_port=proxy_port,
                proxy_username=proxy_username,
                proxy_password=proxy_password,
            )
        self._namespace = namespace
        log.info(
            "DFS-N session opened: \\\\%s\\%s (DFS resolution enabled)",
            host,
            namespace,
        )

    # ------------------------------------------------------------------
    # Display / identity
    # ------------------------------------------------------------------
    @property
    def name(self) -> str:
        return f"\\\\{self._host}\\{self._namespace} (DFS-N)"

    # ------------------------------------------------------------------
    # smbprotocol toggle — module-level dict, one writer at a time
    # ------------------------------------------------------------------
    @staticmethod
    def _enable_dfs_locked() -> None:
        """Turn smbclient's global DFS resolution on: ``skip_dfs=False``.
        MUST be called while holding ``_DFS_OPTION_LOCK`` — the lock
        is acquired by ``__init__`` and held across the parent's
        connection probe so a parallel SmbSession ctor can't toggle
        DFS off in between.

        The switch used to be ``client_dfs_enabled=True``, an option
        smbclient does not have: ClientConfig.set() ignored it, so the
        "switch" did nothing and a ``skip_dfs=True`` set elsewhere stayed.
        A config that still skips DFS afterwards is an OSError - this
        backend is useless without referrals.
        """
        if smb_client.smbclient is None:
            return
        config = smb_client.smbclient.ClientConfig(skip_dfs=False)
        if getattr(config, "skip_dfs", False):
            raise OSError("DFS-N: smbclient refused to turn DFS resolution on (skip_dfs)")

    # ------------------------------------------------------------------
    # DFS-specific introspection (not part of FileBackend, but useful
    # for the UI's "show targets" hook)
    # ------------------------------------------------------------------
    def referral_for(self, path: str) -> DfsReferral | None:
        """Return the resolved referral for *path*, or ``None`` when
        smbprotocol's internal referral cache doesn't have an entry.

        Best-effort: this reads the library's referral cache
        (``ClientConfig.lookup_referral``) after a list_dir/stat
        round-trip has populated it. We don't send a fresh GetReferrals
        RPC ourselves — the client library already does that during
        normal operations. (It asked ``smbclient._pool.lookup_tree``,
        which does not exist: the answer was always None.)
        """
        entry = self._lookup_referral(self._unc(path))
        if entry is None:
            return None
        try:
            target = entry.target_hint.target_path
        except Exception as exc:  # noqa: BLE001 — a cache entry without targets
            log.debug("DFS referral for %s has no target: %s", path, exc)
            return None
        if not target:
            return None
        try:
            # The TTL of the hinted referral (no public accessor).
            ttl = int(entry._referrals[entry._target_hint_idx]["time_to_live"].get_value())
        except Exception:  # noqa: BLE001
            ttl = 0
        return DfsReferral(namespace_path=path, target_path=str(target), ttl_seconds=ttl)

    def _lookup_referral(self, unc: str):
        """The smbclient referral-cache entry for *unc*, or None.
        Wrapped as a method so tests can patch a single seam."""
        if smb_client.smbclient is None:
            return None
        try:
            config = smb_client.smbclient.ClientConfig()
            return config.lookup_referral([p for p in unc.split("\\") if p])
        except Exception as exc:  # noqa: BLE001 — best-effort introspection
            log.debug("DFS lookup_referral(%s) failed: %s", unc, exc)
            return None

    def list_targets(self) -> list[str]:
        """Return the names of the physical link targets directly
        under the namespace root, as they appear in DFS browsing.

        Uses the SMB list_dir surface — DFS-resolved lookups make
        each link look like a regular directory entry, so we just
        list and let the user know which entries are real links via
        the optional ``referral_for`` lookup."""
        items = self.list_dir("/")
        return [it.name for it in items]


__all__ = [
    "DfsReferral",
    "DFSNamespaceSession",
]
