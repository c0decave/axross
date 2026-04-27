"""LDAP directory-as-FileBackend (slice 8 of API_GAPS).

Maps an LDAP tree onto axross's FileBackend protocol so a script can
walk a directory the same way it walks SFTP or S3::

    b = axross.open("ldap_lab")
    for item in b.list_dir("/dc=example,dc=com/ou=people"):
        print(item.name)

Path scheme:
* The root ``/`` lists the namingContexts the server publishes
  (e.g. ``dc=example,dc=com``).
* Every subsequent path segment is one **RDN** (relative DN), in
  left-to-right tree-walk order. This is the OPPOSITE of LDAP's
  native right-to-left DN encoding — the mapping is consistent with
  how a filesystem reads.
* A path that points at a non-leaf entry (an entry that has
  children) behaves like a directory; ``list_dir`` returns its
  children. A path that points at a leaf entry behaves like a file
  whose content is the LDIF rendering of the entry's attributes.

This backend is **read-only**; LDAP modify / add / delete are out
of scope for the FileBackend surface (they are nominally writes, but
the semantics — replace vs. add vs. delete-attribute — don't fit
``open_write`` cleanly). For mutations, drop down to the underlying
``self._conn`` (an ``ldap3.Connection``) and call ``modify`` directly.

Requires: ``pip install axross[ldap]`` — ldap3>=2.9.
"""
from __future__ import annotations

import io
import logging
from datetime import datetime
from typing import IO

from models.file_item import FileItem

log = logging.getLogger(__name__)

try:
    import ldap3  # type: ignore[import-not-found]
    from ldap3 import (
        Server, Connection, ALL, SUBTREE, LEVEL, BASE,
    )
    from ldap3.core.exceptions import LDAPException
except ImportError:  # pragma: no cover
    ldap3 = None  # type: ignore[assignment]


class LdapFsSession:
    """Read-only LDAP-as-FileBackend.

    ``host`` / ``port`` / ``use_tls`` configure the transport. Bind
    creds are passed to ``connect()`` so the session can be
    instantiated lazily.
    """

    supports_symlinks = False
    supports_hardlinks = False

    def __init__(
        self,
        host: str = "",
        port: int = 389,
        username: str = "",        # bind DN
        password: str = "",
        use_tls: bool = False,
        timeout: float = 10.0,
        **_ignored,
    ):
        if ldap3 is None:
            raise OSError(
                "LDAP backend requires ldap3. "
                "Install with: pip install axross[ldap]"
            )
        self._host = host
        self._port = int(port)
        self._username = username
        self._password = password
        self._use_tls = bool(use_tls)
        self._timeout = float(timeout)
        self._server = Server(
            host, port=self._port,
            use_ssl=self._use_tls, get_info=ALL,
            connect_timeout=int(self._timeout),
        )
        try:
            self._conn = Connection(
                self._server,
                user=username or None,
                password=password or None,
                auto_bind=True,
                receive_timeout=int(self._timeout),
            )
        except LDAPException as exc:
            raise OSError(f"LDAP bind to {host}:{port} failed: {exc}") from exc
        # Cache the namingContexts for root-listing (single SEARCH on
        # the rootDSE; cheap).
        self._naming_contexts: list[str] = []
        try:
            info = self._server.info
            ncs = getattr(info, "naming_contexts", None) or []
            self._naming_contexts = [str(n) for n in ncs]
        except Exception:  # noqa: BLE001
            pass
        self._display = f"ldap{'s' if self._use_tls else ''}://" \
                        f"{username or 'anon'}@{host}:{self._port}"
        log.info("LDAP-FS connected: %s", self._display)

    # ------------------------------------------------------------------
    # Identity / lifecycle
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return f"LDAP: {self._display}"

    @property
    def connected(self) -> bool:
        return bool(getattr(self._conn, "bound", False))

    def close(self) -> None:
        try:
            self._conn.unbind()
        except Exception:  # noqa: BLE001
            pass

    def disconnect(self) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Path ↔ DN translation
    # ------------------------------------------------------------------

    @staticmethod
    def _path_to_dn(path: str) -> str:
        """Convert an axross-style left-to-right path into an LDAP DN.

        ``"/dc=example,dc=com/ou=people/cn=alice"``  →
        ``"cn=alice,ou=people,dc=example,dc=com"``

        Empty path / root → ``""``.

        Each path segment is treated as ONE RDN. If a segment itself
        contains an *unescaped* comma (RFC 4514's RDN separator), it
        could otherwise smuggle additional RDNs into the resulting DN
        — e.g. ``/dc=test/ou=evil,ou=admins`` would become
        ``ou=evil,ou=admins,dc=test``, granting access to a parallel
        OU. We refuse such segments. Callers needing a literal comma
        in an attribute value must escape it RFC-4514 style (``\\,``).
        Each segment must also contain at least one ``=`` (every RDN
        is ``attribute=value``); the root path bypasses the check.
        """
        # The base case (root) is allowed to be empty without further
        # validation — represents the LDAP namingContext list.
        if not path.strip("/"):
            return ""
        parts = [p for p in path.strip("/").split("/") if p]
        # The FIRST segment is the base DN (the namingContext) and is
        # allowed to be a multi-RDN string ``dc=example,dc=com`` —
        # that's the canonical way users navigate LDAP-as-FS in axross.
        # SUBSEQUENT segments must be single RDNs (one ``attr=value``
        # pair) — an unescaped comma there would smuggle additional
        # RDNs into the resulting DN. F31.
        for seg in parts[1:]:
            unescaped = seg.replace("\\,", "")
            if "," in unescaped:
                raise ValueError(
                    f"LDAP path segment {seg!r} contains an unescaped "
                    f"comma — would smuggle additional RDNs into the DN. "
                    f"Only the base-DN (first segment) may contain "
                    f"multiple comma-joined RDNs; deeper segments must "
                    f"be a single RDN. Use the RFC-4514 escape `\\,` "
                    f"for a literal comma inside an attribute value."
                )
            if "=" not in seg:
                raise ValueError(
                    f"LDAP path segment {seg!r} is not an RDN "
                    f"(must contain `=`)"
                )
        # Every non-root path must point inside a base — reject paths
        # whose first segment isn't a recognisable DN-shape.
        if "=" not in parts[0]:
            raise ValueError(
                f"LDAP path base {parts[0]!r} is not a DN "
                f"(must contain `=`)"
            )
        # Reverse so the leaf RDN comes first (LDAP convention).
        return ",".join(reversed(parts))

    @staticmethod
    def _dn_to_path(dn: str, base: str = "") -> str:
        """Convert an LDAP DN back into an axross-style path. ``base``
        is dropped from the right when present so children of a base
        DN don't repeat their ancestry in every path."""
        if not dn:
            return "/"
        if base and dn.lower().endswith("," + base.lower()):
            dn = dn[: -(len(base) + 1)]
            parts = [p.strip() for p in dn.split(",")]
            full = list(reversed(parts)) + base.split(",")[::-1]
        else:
            full = list(reversed([p.strip() for p in dn.split(",")]))
        return "/" + "/".join(full)

    # ------------------------------------------------------------------
    # FileBackend surface
    # ------------------------------------------------------------------

    def list_dir(self, path: str) -> list[FileItem]:
        """List children of the entry at ``path``. At ``"/"`` returns
        the namingContexts (each as a directory)."""
        dn = self._path_to_dn(path)
        if not dn:
            # Root → namingContexts.
            return [
                FileItem(name=nc, is_dir=True)
                for nc in self._naming_contexts
            ]
        # SCOPE=LEVEL — direct children only.
        try:
            self._conn.search(
                search_base=dn, search_filter="(objectClass=*)",
                search_scope=LEVEL,
                attributes=["*", "+"],
            )
        except LDAPException as exc:
            raise OSError(f"LDAP search {dn}: {exc}") from exc
        out: list[FileItem] = []
        for entry in self._conn.entries:
            entry_dn = entry.entry_dn
            # Take the leftmost RDN as the display name.
            rdn = entry_dn.split(",", 1)[0]
            out.append(self._entry_to_item(entry, rdn))
        return out

    def stat(self, path: str) -> FileItem:
        """Return a FileItem for the entry at ``path``. Treats every
        entry as is_dir=True if it has children, file otherwise."""
        dn = self._path_to_dn(path)
        if not dn:
            return FileItem(name="/", is_dir=True)
        try:
            ok = self._conn.search(
                search_base=dn, search_filter="(objectClass=*)",
                search_scope=BASE, attributes=["*", "+"],
            )
        except LDAPException as exc:
            raise OSError(f"LDAP stat {path}: {exc}") from exc
        if not ok or not self._conn.entries:
            raise FileNotFoundError(f"LDAP entry not found: {path}")
        entry = self._conn.entries[0]
        rdn = entry.entry_dn.split(",", 1)[0]
        return self._entry_to_item(entry, rdn)

    def is_dir(self, path: str) -> bool:
        try:
            return self.stat(path).is_dir
        except FileNotFoundError:
            return False

    def exists(self, path: str) -> bool:
        try:
            self.stat(path)
            return True
        except (FileNotFoundError, OSError):
            return False

    def open_read(self, path: str) -> IO[bytes]:
        """Return the entry serialised as LDIF. Useful for ``cat``-
        style inspection of all attributes on one entry."""
        dn = self._path_to_dn(path)
        if not dn:
            # Root has no LDIF — synthesize a tiny summary.
            text = "# axross-ldap root\n" + \
                "\n".join(f"# namingContext: {n}" for n in self._naming_contexts)
            return io.BytesIO(text.encode("utf-8"))
        try:
            self._conn.search(
                search_base=dn, search_filter="(objectClass=*)",
                search_scope=BASE, attributes=["*", "+"],
            )
        except LDAPException as exc:
            raise OSError(f"LDAP open_read {path}: {exc}") from exc
        if not self._conn.entries:
            raise FileNotFoundError(f"LDAP entry not found: {path}")
        ldif = self._conn.entries[0].entry_to_ldif()
        if isinstance(ldif, str):
            ldif = ldif.encode("utf-8")
        return io.BytesIO(ldif)

    def open_write(self, path: str, append: bool = False) -> IO[bytes]:
        raise OSError(
            "LDAP backend is read-only — drop down to ``self._conn.modify``"
            " for direct attribute changes."
        )

    def remove(self, path: str, recursive: bool = False) -> None:
        raise OSError("LDAP backend is read-only")

    def mkdir(self, path: str) -> None:
        raise OSError("LDAP backend is read-only")

    def rename(self, src: str, dst: str) -> None:
        raise OSError("LDAP backend is read-only")

    def chmod(self, path: str, mode: int) -> None:
        raise OSError("LDAP entries don't have POSIX permissions")

    def copy(self, src: str, dst: str) -> None:
        raise OSError("LDAP backend is read-only")

    def readlink(self, path: str) -> str:
        raise OSError("LDAP entries are not symlinks")

    def disk_usage(self, path: str) -> tuple[int, int, int]:
        return (0, 0, 0)

    def list_versions(self, path: str) -> list:
        return []

    def open_version_read(self, path: str, version_id: str):
        raise OSError("LDAP has no per-entry version history")

    def checksum(self, path: str, algorithm: str = "sha256") -> str:
        return ""

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    def normalize(self, path: str) -> str:
        return "/" + "/".join(p for p in path.split("/") if p)

    def separator(self) -> str:
        return "/"

    def join(self, *parts: str) -> str:
        cleaned = [p.strip("/") for p in parts if p.strip("/")]
        return "/" + "/".join(cleaned)

    def parent(self, path: str) -> str:
        if path in ("/", ""):
            return "/"
        parts = path.rstrip("/").rsplit("/", 1)
        return parts[0] if parts[0] else "/"

    def home(self) -> str:
        return "/"

    # ------------------------------------------------------------------
    # LDAP-specific verbs (slice 8 — exposed via axross.ldap_search)
    # ------------------------------------------------------------------

    def search(self, base_dn: str, filter: str = "(objectClass=*)",
               *, scope: str = "subtree",
               attributes: list[str] | None = None,
               limit: int = 1000) -> list[dict]:
        """Run a raw LDAP search against ``base_dn``. Returns up to
        ``limit`` entries as dicts ``{dn, attributes}``.

        ``scope`` is ``base`` / ``onelevel`` / ``subtree``.

        ``attributes`` defaults to ``["*"]`` (all user attributes);
        pass ``["*", "+"]`` to also include operational attributes.
        """
        scope_map = {"base": BASE, "onelevel": LEVEL, "subtree": SUBTREE}
        sc = scope_map.get(scope.lower())
        if sc is None:
            raise ValueError(
                f"search scope must be base/onelevel/subtree, got {scope!r}"
            )
        try:
            ok = self._conn.search(
                search_base=base_dn, search_filter=filter,
                search_scope=sc, attributes=attributes or ["*"],
                size_limit=int(limit),
            )
        except LDAPException as exc:
            raise OSError(f"LDAP search {base_dn} {filter}: {exc}") from exc
        out: list[dict] = []
        for entry in (self._conn.entries if ok else []):
            attrs: dict = {}
            for attr_name in entry.entry_attributes:
                vals = entry[attr_name].values
                attrs[attr_name] = vals if len(vals) != 1 else vals[0]
            out.append({"dn": entry.entry_dn, "attributes": attrs})
        return out

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _entry_to_item(self, entry, name: str) -> FileItem:
        """Turn an ldap3 entry into a FileItem. Children-presence is a
        secondary search; we estimate is_dir from objectClass first
        (objects like ``organizationalUnit`` / ``container`` are
        almost always containers) and only fall through to a SEARCH
        for ambiguous classes."""
        oclass = []
        try:
            oclass = [c.lower() for c in entry["objectClass"].values]
        except Exception:  # noqa: BLE001
            pass
        container_classes = {
            "organizationalunit", "container", "domain", "country",
            "groupofnames", "groupofuniquenames", "organizationalrole",
            "dcobject",
        }
        is_dir = bool(set(oclass) & container_classes)
        # Modified time from operational attribute when present.
        modified = datetime.fromtimestamp(0)
        try:
            ts = entry["modifyTimestamp"].value
            if isinstance(ts, datetime):
                modified = ts
        except Exception:  # noqa: BLE001
            pass
        # Size: rough estimate = total bytes of attribute values.
        size = 0
        try:
            for a in entry.entry_attributes:
                for v in entry[a].values:
                    size += len(str(v).encode("utf-8"))
        except Exception:  # noqa: BLE001
            pass
        return FileItem(
            name=name,
            size=size if not is_dir else 0,
            modified=modified,
            permissions=0o555 if is_dir else 0o444,
            is_dir=is_dir,
        )
