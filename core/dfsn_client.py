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
:class:`core.smb_client.SmbSession` that flips smbclient's global
``client_dfs_enabled`` switch on at construction time. With that
switch on, smbprotocol auto-resolves DFS referrals on the wire so
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
            )
        self._namespace = namespace
        log.info(
            "DFS-N session opened: \\\\%s\\%s (DFS resolution enabled)",
            host, namespace,
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
        """Flip smbclient's global ``client_dfs_enabled`` switch on.
        MUST be called while holding ``_DFS_OPTION_LOCK`` — the lock
        is acquired by ``__init__`` and held across the parent's
        connection probe so a parallel SmbSession ctor can't toggle
        DFS off in between.

        Older smbprotocol versions treated DFS as always-on; newer
        ones gate it behind an explicit option. We swallow any
        AttributeError / TypeError so the worst case is "behaves
        like SMB", not a crash.
        """
        if smb_client.smbclient is None:
            return
        try:
            smb_client.smbclient.ClientConfig(
                client_dfs_enabled=True,
            )
        except Exception as exc:  # noqa: BLE001
            log.debug(
                "smbclient.ClientConfig(dfs=True) not accepted (%s); "
                "smbprotocol may already enable DFS by default", exc,
            )

    # ------------------------------------------------------------------
    # DFS-specific introspection (not part of FileBackend, but useful
    # for the UI's "show targets" hook)
    # ------------------------------------------------------------------
    def referral_for(self, path: str) -> DfsReferral | None:
        """Return the resolved referral for *path*, or ``None`` when
        smbprotocol's internal referral cache doesn't have an entry.

        Best-effort: this prods the library's referral cache after a
        list_dir/stat round-trip has already populated it. We don't
        send a fresh GetReferrals RPC ourselves — the client library
        already does that during normal operations.
        """
        tree = self._lookup_tree(self._unc(path))
        if tree is None:
            return None
        target = getattr(tree, "share_name", None)
        if not target:
            return None
        return DfsReferral(
            namespace_path=path,
            target_path=str(target),
            ttl_seconds=int(getattr(tree, "tree_connect_andx_response", 0) or 0),
        )

    def _lookup_tree(self, unc: str):
        """Return the smbprotocol Tree object for *unc* or ``None``
        when the library doesn't expose its referral cache. Wrapped
        as a method so tests can patch a single seam without touching
        smbclient's module-private internals."""
        try:
            return smb_client.smbclient._pool.lookup_tree(  # type: ignore[attr-defined]
                unc, None,
            )
        except Exception as exc:  # noqa: BLE001 — best-effort introspection
            log.debug("DFS _lookup_tree(%s) failed: %s", unc, exc)
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
