"""Universal trash for any FileBackend.

Most protocols (FTP, SMB, S3, ...) lack a native recycle bin. The
:func:`trash` helper gives the GUI a uniform "send to trash" primitive
on top of whatever the backend *does* support — typically
``rename()``. Items are moved into ``<root>/.axross-trash/<uuid>``
with a sidecar metadata file; :func:`restore` moves them back.

Why a per-entry sidecar and not one central manifest
----------------------------------------------------
A single manifest would require read-modify-write under races: two
clients trashing at once would clobber each other's entries. One
sidecar per entry means every trash/restore/empty is a single
rename + write_small_file, never a read-modify-write on shared
state.

Why not a generation counter / lock file
----------------------------------------
We target protocols that don't offer atomic compare-and-swap (FTP,
SMB, WebDAV). A locking scheme would be either best-effort or
protocol-specific. Per-entry sidecars sidestep the problem
entirely.

Authenticated sidecars
----------------------
The trash is a confused deputy waiting to happen: whoever can write into
it (an agent, a shared server) plants an entry whose ``original_path`` is
``~/.bashrc``, or rewrites a trashed autostart entry, and the user's
Restore puts it there with axross's rights. Every sidecar written here
carries an HMAC (``mac``) of its id, original path, kind and a fingerprint
of the data (a local file's SHA-256 - its size and time above
:data:`MAX_HASH_BYTES` -, a local folder's tree), keyed with this user's
secret (the one of core.extension_code_cache, in ``~/.config/axross``,
under a key of its own). On a local backend :func:`restore` refuses an
entry whose HMAC or fingerprint does not verify (:class:`TamperedTrashEntry`),
puts an unauthenticated one (made before, or without a secret) back only
outside the protected places (core.protected_places), and an authenticated
one there only when the caller says the user confirmed it
(``allow_protected``; :class:`ProtectedRestoreError` otherwise). The local
trash itself is a protected place and secret: no MCP or agent tool reads
or writes it.

Trash root
----------
Defaults to ``<backend.home()>/.axross-trash``. Callers can pin a
different root via the ``root`` argument — useful for chroot'd
setups or when the backend has multiple writable trees (e.g.
multi-bucket S3 wrappers).
"""

from __future__ import annotations

import errno
import hashlib
import hmac
import json
import logging
import os
import shutil
import stat
import uuid
from datetime import datetime

from core.path_policy import safe_join
from models.trash_entry import TrashEntry

log = logging.getLogger(__name__)

TRASH_DIRNAME = ".axross-trash"
META_SUFFIX = ".meta.json"

# Bound on sidecar JSON size — protects us from malicious actors who
# gain write access to the trash dir and plant a multi-MB "sidecar".
MAX_META_SIZE = 64 * 1024
#: The data of a local entry hashed into its sidecar's fingerprint, at most
#: (a folder's files together); beyond, their size and modification time.
MAX_HASH_BYTES = 64 * 1024 * 1024
#: Most entries of a trashed local folder in its fingerprint.
MAX_TREE_ENTRIES = 10_000
#: Domain of the sidecar HMAC key (derived from core.extension_code_cache's secret).
_MAC_CONTEXT = b"axross-trash-sidecar-v1\n"
#: The sidecar fields the HMAC covers.
_SIGNED_FIELDS = ("trash_id", "original_path", "is_dir", "kept_copy", "fingerprint")


class TrashRestoreRefused(OSError):
    """A restore core.trash refuses to do on its own (see the module docstring)."""


class TamperedTrashEntry(TrashRestoreRefused):
    """The entry's sidecar or data is not what axross wrote (its HMAC or the
    fingerprint of the data does not verify): never restored."""


class ProtectedRestoreError(TrashRestoreRefused):
    """The entry would go back into a protected place (core.protected_places).
    *verified*: its sidecar is authenticated - the user may confirm it
    (``restore(..., allow_protected=True)``); an unauthenticated one is not
    put there at all."""

    def __init__(self, message: str, *, target: str, reason: str, verified: bool) -> None:
        super().__init__(message)
        self.target = target
        self.reason = reason
        self.verified = verified


#: Backends that cannot move an entry into a trash folder: read-only ones
#: and ones without a rename (their ``rename`` always raises). A backend
#: can also say so itself with a ``supports_trash`` attribute.
_NO_TRASH_BACKENDS = frozenset({
    "GopherSession", "LdapFsSession", "NntpSession", "PjlSession", "Pop3Session",
    "SlpSession", "SvnFsSession", "TftpSession", "WMISession",
})


def supports_trash(backend) -> bool:
    """Whether Move to Trash can work on *backend*: the trash is a rename
    into ``<home>/.axross-trash``, so a backend without a rename has none.
    The Del key moves to the trash where there is one and asks for a
    permanent delete elsewhere."""
    if backend is None:
        return False
    flag = getattr(backend, "supports_trash", None)
    if isinstance(flag, bool):
        return flag
    return type(backend).__name__ not in _NO_TRASH_BACKENDS


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _resolve_root(backend, root: str | None) -> str:
    """Pick the trash root directory for this backend."""
    if root is not None:
        return root
    try:
        base = backend.home()
    except Exception:
        base = "/"
    if not base:
        base = "/"
    return safe_join(backend, base, TRASH_DIRNAME)


class TrashFolderRefused(OSError):
    """The trash folder's name is taken by something that is no folder.
    Its text is written for the user (core.user_errors keeps it)."""


def _ensure_trash_dir(backend, trash_root: str) -> None:
    try:
        if not backend.exists(trash_root):
            backend.mkdir(trash_root)
            return
        is_folder = backend.is_dir(trash_root) or _links_to_a_folder(backend, trash_root)
    except OSError as exc:
        raise OSError(f"Cannot create trash directory {trash_root}: {exc}") from exc
    if not is_folder:
        # Not "x.txt is not a folder" for the file being trashed (review
        # round 8): the trash folder is what is wrong.
        from core.i18n import tr

        # No errno: core.user_errors would say "<path> is not a folder".
        raise TrashFolderRefused(
            tr("The trash folder {path} is not a folder: a file has its name. Rename or "
               "move that file, then try again.").format(path=trash_root))


def _links_to_a_folder(backend, path: str) -> bool:
    """*path* is a symbolic link that may lead to a folder (a trash folder
    on another disk): on this machine's disk where it points is looked
    at, elsewhere it is taken as one (the move into it reports)."""
    try:
        item = backend.stat(path)
    except Exception:  # noqa: BLE001 - no answer: not known to be a link
        return False
    if not getattr(item, "is_link", False):
        return False
    from core.local_fs import LocalFS

    if isinstance(backend, LocalFS) and type(backend).stat is LocalFS.stat:
        return os.path.isdir(path)
    return True


def _meta_path(backend, trash_root: str, trash_id: str) -> str:
    return safe_join(backend, trash_root, trash_id + META_SUFFIX)


def _data_path(backend, trash_root: str, trash_id: str) -> str:
    return safe_join(backend, trash_root, trash_id)


def _write_meta(backend, meta_file: str, payload: dict) -> None:
    data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    from core.atomic_io import atomic_write

    atomic_write(backend, meta_file, data)


def _mac_key() -> bytes | None:
    """The sidecar HMAC key: derived from this user's secret of
    core.extension_code_cache (``~/.config/axross``), or None when there is
    none to be had safely (sidecars are then written unauthenticated)."""
    try:
        from core import extension_code_cache

        secret = extension_code_cache._secret()
    except Exception as exc:  # noqa: BLE001 - no key: unauthenticated sidecars
        log.debug("trash: no sidecar key: %s", exc)
        return None
    if not secret:
        return None
    return hmac.new(secret, _MAC_CONTEXT, hashlib.sha256).digest()


def _mac_of(key: bytes, payload: dict) -> str:
    signed = {name: payload.get(name) for name in _SIGNED_FIELDS}
    text = json.dumps(signed, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hmac.new(key, text.encode("ascii"), hashlib.sha256).hexdigest()


def _file_digest(path: str) -> str:
    digest = hashlib.sha256()
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0))
    with os.fdopen(fd, "rb") as fh:
        while True:
            chunk = fh.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk)
    return digest.hexdigest()


def _fingerprint(backend, path: str) -> dict | None:
    """What a local entry's data is, for its sidecar: a file's size and
    SHA-256 (size and time above :data:`MAX_HASH_BYTES`), a link's target,
    a folder's tree (names, kinds, sizes and the files' hashes, within the
    same budget). None on another backend or when it cannot be read."""
    if not _is_local(backend):
        return None
    try:
        st = os.lstat(path)
        if stat.S_ISLNK(st.st_mode):
            return {"kind": "link", "target": os.readlink(path)}
        if stat.S_ISREG(st.st_mode):
            if st.st_size <= MAX_HASH_BYTES:
                return {"kind": "file", "size": st.st_size, "sha256": _file_digest(path)}
            return {"kind": "file", "size": st.st_size, "mtime_ns": st.st_mtime_ns}
        if not stat.S_ISDIR(st.st_mode):
            return {"kind": "other", "mode": stat.S_IFMT(st.st_mode)}
        tree = hashlib.sha256()
        budget = MAX_HASH_BYTES
        count = 0
        complete = True
        for dirpath, dirnames, filenames in os.walk(path, followlinks=False):
            dirnames.sort()
            rel = os.path.relpath(dirpath, path)
            for name in sorted(filenames) + [d for d in dirnames
                                             if os.path.islink(os.path.join(dirpath, d))]:
                count += 1
                if count > MAX_TREE_ENTRIES:
                    complete = False
                    break
                full = os.path.join(dirpath, name)
                fst = os.lstat(full)
                line = [os.path.join(rel, name), stat.S_IFMT(fst.st_mode), fst.st_size]
                if stat.S_ISLNK(fst.st_mode):
                    line.append(os.readlink(full))
                elif stat.S_ISREG(fst.st_mode) and fst.st_size <= budget:
                    budget -= fst.st_size
                    line.append(_file_digest(full))
                else:
                    line.append(fst.st_mtime_ns)
                tree.update(json.dumps(line).encode("utf-8") + b"\n")
            if not complete:
                break
            for d in dirnames:
                tree.update(json.dumps([os.path.join(rel, d), "dir"]).encode("utf-8") + b"\n")
        return {"kind": "dir", "tree": tree.hexdigest(), "complete": complete}
    except OSError as exc:
        log.debug("trash: no fingerprint of %s: %s", path, exc)
        return None


def _signed(backend, payload: dict, data_file: str) -> dict:
    """*payload* with the data's fingerprint and the HMAC (when there is a key)."""
    key = _mac_key()
    if key is None:
        return payload
    payload = dict(payload)
    payload["fingerprint"] = _fingerprint(backend, data_file)
    payload["mac"] = _mac_of(key, payload)
    return payload


def _verify(backend, meta: dict | None, trash_id: str, data_file: str) -> str:
    """"ok" (axross wrote this sidecar and the data is unchanged), "unsigned"
    (no HMAC: older than authenticated sidecars, or no key) or "bad"."""
    if not isinstance(meta, dict) or "mac" not in meta:
        return "unsigned"
    key = _mac_key()
    mac = meta.get("mac")
    if key is None or not isinstance(mac, str):
        return "bad" if not isinstance(mac, str) else "unsigned"
    if meta.get("trash_id") != trash_id or not hmac.compare_digest(_mac_of(key, meta), mac):
        return "bad"
    expected = meta.get("fingerprint")
    if expected is not None and _is_local(backend):
        if _fingerprint(backend, data_file) != expected:
            return "bad"
    return "ok"


def _refuse_unverified(backend, meta, trash_id: str, data_file: str) -> str:
    """:func:`_verify`; TamperedTrashEntry for "bad" on a local backend (a
    remote trash may hold another user's entries, signed with their key)."""
    status = _verify(backend, meta, trash_id, data_file)
    if status == "bad":
        if _is_local(backend):
            raise TamperedTrashEntry(
                f"restore: trash entry {trash_id} was changed after it was trashed (its "
                "record or data is not what axross wrote) - it is not restored"
            )
        log.info("trash: entry %s is not signed with this user's key", trash_id)
        return "unsigned"
    return status


def _refuse_protected(backend, dst: str, status: str, allow_protected: bool) -> None:
    """ProtectedRestoreError when the local *dst* is a protected place
    (core.protected_places) - unless the entry is authenticated and the
    caller says the user confirmed it."""
    if not _is_local(backend):
        return
    from core import protected_places

    reason = protected_places.refusal(dst, entry=True)
    if reason is None:
        return
    if status != "ok":
        raise ProtectedRestoreError(
            f"restore: {dst} is a protected place and this trash entry is not authenticated "
            "(trashed by an older axross, or its record was written by someone else): it is "
            "not put back there - restore it to another folder and move it yourself",
            target=dst, reason=reason, verified=False)
    if not allow_protected:
        raise ProtectedRestoreError(
            f"restore: {dst} is a protected place (programs run code from there): "
            "confirm the restore in the Trash window",
            target=dst, reason=reason, verified=True)


def _read_meta(backend, meta_file: str) -> dict | None:
    try:
        handle = backend.open_read(meta_file)
    except OSError:
        return None
    # Pre-bind: if read() raises, the finally block runs and we return
    # None via the OSError branch; the later ``isinstance(raw, str)``
    # line is never reached, but pre-binding removes the linter warning
    # and guarantees no NameError if control flow changes later.
    raw: bytes | str = b""
    try:
        # Bound sidecar size. Legit sidecars are <1 KiB; 64 KiB is a
        # generous ceiling that stops an attacker who can write to the
        # trash dir from using a multi-MB sidecar to OOM the client.
        raw = handle.read(MAX_META_SIZE + 1)
    except OSError as exc:
        log.debug("trash: sidecar read(%s) failed: %s", meta_file, exc)
        return None
    finally:
        try:
            handle.close()
        except Exception as close_exc:
            log.debug("trash: sidecar handle close failed: %s", close_exc)
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    if len(raw) > MAX_META_SIZE:
        log.warning("Corrupt trash sidecar %s: exceeds %d bytes", meta_file, MAX_META_SIZE)
        return None
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (ValueError, RecursionError) as exc:
        # ValueError covers UnicodeDecodeError; a sidecar nested deeper
        # than the decoder's stack raises RecursionError.
        log.warning("Corrupt trash sidecar %s: %s", meta_file, exc)
        return None
    if not isinstance(parsed, dict):
        log.warning("Corrupt trash sidecar %s: not a JSON object", meta_file)
        return None
    return parsed


def _stat_safely(backend, path: str):
    try:
        return backend.stat(path)
    except OSError:
        return None


def _finish_journal(op_id: str, operation: str, **fields) -> None:
    if not op_id:
        return
    try:
        from core.operation_journal import finish_operation

        finish_operation(op_id, operation, **fields)
    except Exception as exc:  # noqa: BLE001
        log.debug("%s: journal finish failed: %s", operation, exc)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def trash(backend, path: str, root: str | None = None, *, journal: bool = True) -> str:
    """Move *path* into the trash and return its ``trash_id``.

    The returned id is a UUID4 without dashes. After the call, the
    original *path* no longer exists; ``<root>/.axross-trash/<id>``
    (file or directory) and ``<id>.meta.json`` (sidecar) do.

    The move is attempted via :meth:`FileBackend.rename`. If rename
    across directories isn't supported by the backend, OSError
    propagates — callers can fall back to a copy + delete themselves.

    ``journal=False`` is for callers that journal the trashing as part
    of an operation of their own (undoing a metadata removal): a second,
    separate "trash" entry would be offered to the next Ctrl+Z.
    """
    op_id = ""
    # Every event carries the label, not just the start: undo reads a
    # bounded window of the journal, and a finish event whose start has
    # scrolled out must still name the connection it belongs to.
    label = getattr(backend, "name", "") or type(backend).__name__
    try:
        from core.operation_journal import start_operation

        if journal:
            op_id = start_operation(
                "trash",
                source=path,
                backend=label,
            )
    except Exception as exc:  # noqa: BLE001
        log.debug("trash: journal start failed: %s", exc)
    trash_root = _resolve_root(backend, root)
    try:
        _ensure_trash_dir(backend, trash_root)
    except OSError as exc:
        _finish_journal(
            op_id,
            "trash",
            backend=label,
            status="error",
            source=path,
            error=str(exc),
        )
        raise

    info = _stat_safely(backend, path)
    if info is None:
        err = f"trash: source does not exist: {path}"
        _finish_journal(op_id, "trash", backend=label, status="error", source=path, error=err)
        raise OSError(err)

    trash_id = uuid.uuid4().hex
    dst = _data_path(backend, trash_root, trash_id)
    meta = _meta_path(backend, trash_root, trash_id)

    try:
        from core.server_ops import server_side_move

        server_side_move(backend, path, dst)
    except OSError as exc:
        if _stat_safely(backend, dst) is not None:
            # A move across devices copied everything, then could not remove
            # all of the source: the trash holds the only complete copy. It
            # gets its sidecar, or the Trash window would not list it and
            # Empty Trash would delete it unseen.
            try:
                _write_meta(backend, meta, {
                    "trash_id": trash_id,
                    "original_path": path,
                    "trashed_at": datetime.now().isoformat(timespec="seconds"),
                    "size": int(getattr(info, "size", 0) or 0),
                    "is_dir": bool(getattr(info, "is_dir", False)),
                    "label": getattr(info, "name", "") or "",
                    "incomplete": str(exc),
                })
            except OSError as meta_exc:
                log.error("trash: %s is at %s with no metadata: %s", path, dst, meta_exc)
        _finish_journal(
            op_id, "trash", backend=label, status="error", source=path, dest=dst, error=str(exc)
        )
        raise OSError(f"trash: move {path} -> {dst} failed: {exc}") from exc

    payload = _signed(backend, {
        "trash_id": trash_id,
        "original_path": path,
        "trashed_at": datetime.now().isoformat(timespec="seconds"),
        "size": int(getattr(info, "size", 0) or 0),
        "is_dir": bool(getattr(info, "is_dir", False)),
        "label": getattr(info, "name", "") or "",
    }, dst)
    try:
        _write_meta(backend, meta, payload)
    except OSError as exc:
        # Best-effort rollback: try to move the data back to avoid an
        # orphaned trash entry. If rollback also fails we re-raise the
        # original write error — users at least see *something* went
        # wrong and the data is still there under a known id.
        try:
            from core.server_ops import server_side_move

            server_side_move(backend, dst, path)
        except OSError:
            log.error(
                "trash: sidecar write failed AND rollback failed; data is at %s with no metadata",
                dst,
            )
        _finish_journal(
            op_id, "trash", backend=label, status="error", source=path, dest=dst, error=str(exc)
        )
        raise OSError(f"trash: metadata write failed: {exc}") from exc

    _finish_journal(
        op_id,
        "trash",
        backend=label,
        status="done",
        source=path,
        dest=dst,
        # A trash of its own (the agent's dedupe, a script's root=): undo
        # has to look there, not in the backend's default trash.
        details={"trash_id": trash_id,
                 **({"trash_root": trash_root} if root is not None else {})},
    )
    return trash_id


def _is_local(backend) -> bool:
    from core.local_fs import LocalFS

    return isinstance(backend, LocalFS)


def _sha256_of(backend, path: str) -> str:
    digest = hashlib.sha256()
    handle = open(path, "rb") if _is_local(backend) else backend.open_read(path)  # noqa: SIM115
    try:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            digest.update(chunk.encode("utf-8") if isinstance(chunk, str) else chunk)
    finally:
        handle.close()
    return digest.hexdigest()


def recreate_parent_folders(backend, path: str) -> list[str]:
    """Create the folder *path* belongs in, with any missing above it, and
    return the folders created, outermost first.

    Restoring a trashed entry, or undoing a move, leads back into a folder
    that may be gone since (emptied and deleted, or a folder move that
    removed its emptied source folders); a rename or a transfer into it
    cannot succeed until it is there again. Raises :class:`OSError` when
    something that is not a folder holds the place of one - a link to a
    folder (``~/Pictures -> /data/pics``) is left to the caller's write.
    A folder that cannot be created takes the ones made before it back.
    """
    missing: list[str] = []
    current = backend.parent(path)
    while current and not backend.exists(current):
        missing.append(current)
        above = backend.parent(current)
        if above == current:
            current = ""
            break
        current = above
    if current:
        info = backend.stat(current)
        if not getattr(info, "is_dir", False) and not getattr(info, "is_link", False):
            raise OSError(f"{current} is not a folder; {path} cannot be put back there")
    created: list[str] = []
    try:
        for folder in reversed(missing):
            backend.mkdir(folder)
            created.append(folder)
            log.info("recreated the folder %s", folder)
    except BaseException:
        remove_created_folders(backend, created)
        raise
    return created


def remove_created_folders(backend, created: list[str]) -> None:
    """Take back what :func:`recreate_parent_folders` made, innermost
    first, as far as the folders are still empty."""
    for folder in reversed(created):
        try:
            backend.remove(folder)
        except OSError as exc:
            log.debug("could not remove the recreated folder %s: %s", folder, exc)
            return


def _into_parent_folder(backend, path: str, put) -> None:
    """Run *put* (which writes *path*); when it fails because the folder of
    *path* is gone (emptied and deleted since the entry was trashed),
    recreate that folder and run it once more - and take the folders back
    if it still fails. A backend that writes a path without its folder (an
    object store's keys) never gets one created."""
    try:
        put()
        return
    except OSError as first:
        try:
            parent_there = backend.exists(backend.parent(path))
        except OSError:
            raise first from None
        if parent_there:
            raise
    created = recreate_parent_folders(backend, path)
    try:
        put()
    except BaseException:
        remove_created_folders(backend, created)
        raise


def _remove_quietly(backend, path: str) -> None:
    try:
        if backend.exists(path):
            backend.remove(path)
    except OSError as exc:
        log.warning("trash: could not remove %s: %s", path, exc)


def trash_copy(
    backend, path: str, *, local_source: str | None = None, root: str | None = None
) -> str:
    """Keep a copy of the file *path* in the trash and return its ``trash_id``.

    Unlike :func:`trash`, *path* stays where it is: this is the backup a
    caller takes right before it replaces the file atomically (removing a
    file's metadata in place), so the path is never missing in between.
    The entry lists and restores like any other; :func:`restore_over`
    puts it back over the replacement.

    On a local file system the copy is a hard link when the trash is on
    the same file system - the original bytes then cost nothing, and the
    atomic replace that follows leaves them with the trash alone. A
    remote file is uploaded from *local_source* (the caller's bounded
    local copy) when given, else streamed from the backend.

    Not journaled: the caller records its own operation.
    """
    info = _stat_safely(backend, path)
    if info is None or getattr(info, "is_dir", False):
        raise OSError(f"trash_copy: not a file: {path}")
    trash_root = _resolve_root(backend, root)
    _ensure_trash_dir(backend, trash_root)
    trash_id = uuid.uuid4().hex
    dst = _data_path(backend, trash_root, trash_id)
    meta = _meta_path(backend, trash_root, trash_id)
    from core.atomic_io import atomic_write_stream

    try:
        if local_source is None and _is_local(backend):
            try:
                os.link(path, dst, follow_symlinks=False)
            except OSError:
                # Another file system: a copy with the mode and times, which
                # restore_over puts back (copyfile alone left the umask's).
                shutil.copyfile(path, dst, follow_symlinks=False)
                try:
                    shutil.copystat(path, dst, follow_symlinks=False)
                except OSError:  # a file system without modes keeps the data
                    log.debug("trash_copy: no mode or times for %s", dst, exc_info=True)
        elif local_source is not None:
            with open(local_source, "rb") as src:
                atomic_write_stream(backend, dst, src)
        else:
            with backend.open_read(path) as src:
                atomic_write_stream(backend, dst, src)
    except OSError as exc:
        _remove_quietly(backend, dst)
        raise OSError(f"trash_copy: cannot keep a copy of {path}: {exc}") from exc
    payload = _signed(backend, {
        "trash_id": trash_id,
        "original_path": path,
        "trashed_at": datetime.now().isoformat(timespec="seconds"),
        "size": int(getattr(info, "size", 0) or 0),
        "is_dir": False,
        "label": getattr(info, "name", "") or "",
        "kept_copy": True,
    }, dst)
    try:
        _write_meta(backend, meta, payload)
    except OSError as exc:
        _remove_quietly(backend, dst)
        raise OSError(f"trash_copy: metadata write failed: {exc}") from exc
    return trash_id


def entry_exists(backend, trash_id: str, root: str | None = None) -> bool:
    """Whether trash entry *trash_id* is still there to restore. False for
    an id that is not a safe name; raises OSError when the backend cannot
    tell."""
    trash_root = _resolve_root(backend, root)
    try:
        data_file = _data_path(backend, trash_root, trash_id)
    except ValueError:
        return False
    return bool(backend.exists(data_file))


def discard(backend, trash_id: str, root: str | None = None) -> None:
    """Remove one trash entry for good (a kept copy that is not needed after
    all, because the replacement it guarded never happened)."""
    trash_root = _resolve_root(backend, root)
    try:
        data_file = _data_path(backend, trash_root, trash_id)
        meta_file = _meta_path(backend, trash_root, trash_id)
    except ValueError as exc:
        raise OSError(f"discard: unsafe trash id {trash_id!r}: {exc}") from exc
    _remove_quietly(backend, data_file)
    _remove_quietly(backend, meta_file)


def _replace_across_devices(backend, data_file: str, target: str) -> None:
    """Put local *data_file* over *target* on another file system: copy it
    (data, mode, times) to a temp sibling of *target*, rename that over
    *target* - atomic on the target's file system, as the rename would
    have been - and drop *data_file*. ``trash_copy`` copies for the same
    reason on the way in (a USB stick, a data disk)."""
    from core.atomic_io import _temp_sibling

    tmp = _temp_sibling(backend, target)
    try:
        shutil.copy2(data_file, tmp, follow_symlinks=False)
        os.replace(tmp, target)
    except BaseException:
        _remove_quietly(backend, tmp)
        raise
    _remove_quietly(backend, data_file)


def restore_over(
    backend,
    trash_id: str,
    *,
    target: str,
    expected_sha256: str,
    root: str | None = None,
) -> str:
    """Put the kept copy *trash_id* back at *target*, replacing what is there.

    Only while *target* still holds exactly the content its replacement
    wrote (``expected_sha256``): anything else means it was edited since,
    and putting the original back would throw that edit away, so this
    raises and leaves both the file and the trash entry alone. A target
    that no longer exists is simply restored.

    Locally the kept copy is renamed over the target (atomic, and the
    original file - its inode and times - comes back as it was). On other
    backends it is streamed through :func:`core.atomic_io.atomic_write_stream`.
    """
    trash_root = _resolve_root(backend, root)
    try:
        meta_file = _meta_path(backend, trash_root, trash_id)
        data_file = _data_path(backend, trash_root, trash_id)
    except ValueError as exc:
        raise OSError(f"restore: unsafe trash id {trash_id!r}: {exc}") from exc
    if not backend.exists(data_file):
        raise OSError(f"restore: trash entry not found: {trash_id}")
    # The kept copy must still be what was kept (the target comes from the
    # caller's own record, not from the sidecar).
    _refuse_unverified(backend, _read_meta(backend, meta_file), trash_id, data_file)
    from core.remote_name import MAX_REMOTE_PATH_BYTES, RemoteNameError, validate_remote_name

    try:
        validate_remote_name(target, max_bytes=MAX_REMOTE_PATH_BYTES, allow_separators=True)
    except RemoteNameError as exc:
        raise OSError(f"restore: unsafe target {target!r}: {exc}") from exc
    if backend.exists(target):
        if _sha256_of(backend, target) != expected_sha256:
            raise OSError(
                f"{target} was changed after its metadata was removed; putting the "
                "original back would discard that change. The original is still in the trash."
            )

    def put_back() -> None:
        if _is_local(backend):
            try:
                os.replace(data_file, target)
            except OSError as exc:
                if exc.errno != errno.EXDEV:
                    raise
                _replace_across_devices(backend, data_file, target)
        else:
            from core.atomic_io import atomic_write_stream

            with backend.open_read(data_file) as src:
                atomic_write_stream(backend, target, src)

    _into_parent_folder(backend, target, put_back)
    if not _is_local(backend):
        _remove_quietly(backend, data_file)
    _remove_quietly(backend, meta_file)
    return target


def _text(value) -> str:
    return value if isinstance(value, str) else ""


def _size(value) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return 0
    if not 0 <= value < 2**63:  # also NaN and infinity
        return 0
    return int(value)


def _trashed_at(value) -> datetime:
    """The sidecar's timestamp as naive local time, which is what trash()
    writes; an aware one is converted so the listing can be sorted."""
    if isinstance(value, str) and value:
        try:
            when = datetime.fromisoformat(value)
        except ValueError:
            return datetime.now()
        if when.tzinfo is not None:
            when = when.astimezone().replace(tzinfo=None)
        return when
    return datetime.now()


def list_trash(backend, root: str | None = None) -> list[TrashEntry]:
    """Enumerate trash entries, newest first.

    Sidecars without a matching data object are treated as stale and
    logged but otherwise skipped — we don't auto-delete them to avoid
    turning a read-only browse into a silent cleanup.
    """
    trash_root = _resolve_root(backend, root)
    if not backend.exists(trash_root):
        return []
    try:
        items = backend.list_dir(trash_root)
    except OSError as exc:
        log.warning("list_trash: cannot list %s: %s", trash_root, exc)
        return []

    out: list[TrashEntry] = []
    known_ids: set[str] = set()
    # Data objects the listing already shows as plain entries need no
    # exists() round trip. Symlinks (the backend decides whether exists()
    # follows them) and names missing here (case-insensitive servers)
    # still ask, as before.
    plain_names = {
        getattr(it, "name", "") for it in items if not getattr(it, "is_link", False)
    }
    for it in items:
        name = getattr(it, "name", "") or ""
        if not name.endswith(META_SUFFIX):
            continue
        trash_id = name[: -len(META_SUFFIX)]
        try:
            meta_file = _meta_path(backend, trash_root, trash_id)
            data_file = _data_path(backend, trash_root, trash_id)
        except ValueError as exc:
            log.warning(
                "list_trash: skipping unsafe trash entry %r: %s",
                name,
                exc,
            )
            continue
        meta = _read_meta(backend, meta_file)
        if meta is None:
            continue
        if trash_id not in plain_names and not backend.exists(data_file):
            log.warning("list_trash: sidecar %s without data — skipped", meta_file)
            continue
        # A sidecar is data on the server, possibly written by someone
        # else: a field of the wrong type is shown as empty instead of
        # raising out of the listing and hiding every other entry.
        out.append(
            TrashEntry(
                trash_id=trash_id,
                original_path=_text(meta.get("original_path")),
                trashed_at=_trashed_at(meta.get("trashed_at")),
                size=_size(meta.get("size")),
                is_dir=bool(meta.get("is_dir", False)),
                label=_text(meta.get("label")),
            )
        )
        known_ids.add(trash_id)
    # Newest-first so UIs don't have to re-sort.
    out.sort(key=lambda e: e.trashed_at, reverse=True)
    return out


def restore(backend, trash_id: str, root: str | None = None, target: str | None = None,
            *, allow_protected: bool = False) -> str:
    """Move a trashed entry back to its original path (or *target*).

    Returns the path where the entry now lives. If the destination
    already exists the caller's rename will fail; this is intentional
    — silently overwriting is surprising and hard to undo.

    On a local backend the entry must verify (:class:`TamperedTrashEntry`)
    and a protected destination needs an authenticated entry and
    *allow_protected* - the user confirmed it (:class:`ProtectedRestoreError`).
    """
    trash_root = _resolve_root(backend, root)
    try:
        meta_file = _meta_path(backend, trash_root, trash_id)
        data_file = _data_path(backend, trash_root, trash_id)
    except ValueError as exc:
        raise OSError(f"restore: unsafe trash id {trash_id!r}: {exc}") from exc

    if not backend.exists(data_file):
        raise OSError(f"restore: trash entry not found: {trash_id}")

    meta = _read_meta(backend, meta_file)
    if meta is None and target is None:
        raise OSError(f"restore: metadata missing for {trash_id}; pass an explicit target=")
    dst = target if target is not None else str(meta.get("original_path", ""))
    if not dst:
        raise OSError(f"restore: original path not recorded for {trash_id}")

    # Sidecars live alongside user data. An attacker who can write to
    # the trash directory (shared S3 bucket, collaborative WebDAV)
    # could plant a sidecar whose ``original_path`` contains NUL
    # bytes, bidi overrides, or path-traversal components — reuse the
    # central validator so the restore move never sees attacker-
    # controlled nastiness.
    from core.remote_name import (
        MAX_REMOTE_PATH_BYTES,
        RemoteNameError,
        validate_remote_name,
    )

    try:
        validate_remote_name(
            dst,
            max_bytes=MAX_REMOTE_PATH_BYTES,
            allow_separators=True,
        )
    except RemoteNameError as exc:
        raise OSError(f"restore: sidecar {trash_id} has an unsafe original_path: {exc}") from exc

    status = _refuse_unverified(backend, meta, trash_id, data_file)
    _refuse_protected(backend, dst, status, allow_protected)
    if status == "unsigned":
        log.info("restore: trash entry %s has no authenticated record (an older one)", trash_id)

    if backend.exists(dst):
        raise OSError(f"restore: target already exists: {dst}")

    from core.server_ops import server_side_move

    try:
        _into_parent_folder(backend, dst, lambda: server_side_move(backend, data_file, dst))
    except OSError as exc:
        raise OSError(f"restore: move {data_file} -> {dst} failed: {exc}") from exc

    # Best-effort sidecar cleanup. A stale sidecar is survivable
    # (list_trash skips it) so we don't raise if it fails.
    try:
        backend.remove(meta_file)
    except OSError as exc:
        log.warning("restore: leftover sidecar %s: %s", meta_file, exc)

    return dst


def _remove_entry(backend, data_file: str, meta_file: str, data_is_dir: bool | None) -> bool:
    """Remove one trash entry: its data first (*data_is_dir* None: there is
    none), its sidecar only once the data is gone. An OSError removing the
    data propagates and the sidecar stays - without it what is left of the
    data would vanish from the Trash window and from every later Empty
    Trash. True when data was removed."""
    removed = False
    if data_is_dir is not None:
        if data_is_dir:
            backend.remove(data_file, recursive=True)
        else:
            backend.remove(data_file)
        removed = True
    try:
        backend.remove(meta_file)
    except OSError as exc:
        # The data is gone; a sidecar without data is not listed and goes
        # with the next Empty Trash.
        log.warning("trash: remove %s failed: %s", meta_file, exc)
    return removed


def delete_entry(backend, trash_id: str, root: str | None = None) -> bool:
    """Permanently remove trash entry *trash_id* (Delete Permanently in the
    Trash window), as :func:`empty_trash` removes each entry: the data
    first, the sidecar only on success. Raises OSError when the data could
    not be removed - the entry then stays listed. True when there was data
    to remove (False: only a sidecar was left)."""
    trash_root = _resolve_root(backend, root)
    try:
        meta_file = _meta_path(backend, trash_root, trash_id)
        data_file = _data_path(backend, trash_root, trash_id)
    except ValueError as exc:
        raise OSError(f"delete: unsafe trash id {trash_id!r}: {exc}") from exc
    st = _stat_safely(backend, data_file)
    data_is_dir = None
    if st is not None:
        data_is_dir = bool(getattr(st, "is_dir", False))
    elif backend.exists(data_file):
        data_is_dir = True  # cannot tell: a recursive remove takes a file too
    return _remove_entry(backend, data_file, meta_file, data_is_dir)


class EmptyTrashIncomplete(OSError):
    """:func:`empty_trash` removed what it could, but not every entry.

    ``removed`` is the count of entries that went, ``failed`` lists
    ``(trash_id, error)`` for each entry that stays - still listed in the
    Trash window, with its sidecar, so the next Empty Trash tries again."""

    def __init__(self, removed: int, failed: list[tuple[str, str]]) -> None:
        self.removed = removed
        self.failed = failed
        shown = "; ".join(f"{trash_id}: {error}" for trash_id, error in failed[:10])
        more = f" (and {len(failed) - 10} more)" if len(failed) > 10 else ""
        super().__init__(
            f"removed {removed} entr{'y' if removed == 1 else 'ies'}; "
            f"{len(failed)} could not be removed and stay in the trash: {shown}{more}"
        )


def empty_trash(backend, root: str | None = None) -> int:
    """Permanently remove every trash entry. Returns count removed.

    Per entry the data goes first and its sidecar only once the data is
    gone. In listing order the sidecar could go first: a data folder whose
    removal then failed part way was no longer listed in the Trash window,
    and every later Empty Trash kept it as "no sidecar" - hidden for good.
    Raises :class:`EmptyTrashIncomplete` after trying every entry when some
    could not be removed.
    """
    trash_root = _resolve_root(backend, root)
    if not backend.exists(trash_root):
        return 0
    try:
        items = backend.list_dir(trash_root)
    except OSError as exc:
        log.warning("empty_trash: cannot list %s: %s", trash_root, exc)
        return 0
    removed = 0
    failed: list[tuple[str, str]] = []
    # Only what the Trash window lists goes: a data object without its
    # sidecar (list_trash does not show it - say a move that stopped half
    # way) may be the only copy of the user's files, so it stays.
    sidecar_ids: list[str] = []
    data_items = {}
    for it in items:
        name = getattr(it, "name", "") or ""
        if name.endswith(META_SUFFIX):
            sidecar_ids.append(name[: -len(META_SUFFIX)])
        else:
            data_items[name] = it
    for name in data_items.keys() - set(sidecar_ids):
        log.warning("empty_trash: keeping %r in %s - it has no sidecar, the Trash "
                    "window does not show it", name, trash_root)
    for trash_id in sidecar_ids:
        try:
            meta_file = _meta_path(backend, trash_root, trash_id)
            data_file = _data_path(backend, trash_root, trash_id)
        except ValueError as exc:
            log.warning(
                "empty_trash: skipping unsafe trash entry %r: %s",
                trash_id,
                exc,
            )
            continue
        data_item = data_items.get(trash_id)
        data_is_dir = None if data_item is None else bool(getattr(data_item, "is_dir", False))
        try:
            # Count only the data entries (not sidecars) to give the
            # caller a useful "how many files did I empty" number.
            if _remove_entry(backend, data_file, meta_file, data_is_dir):
                removed += 1
        except OSError as exc:
            log.warning("empty_trash: remove %s failed: %s", data_file, exc)
            failed.append((trash_id, str(exc)))
    if failed:
        raise EmptyTrashIncomplete(removed, failed)
    return removed
