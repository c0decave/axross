"""Which storage does a backend path live on?

The Duplicate Finder may only trash a copy while another copy survives on
*different* storage. Two backends are not two storages when they reach the
same machine — SMB and SFTP to one NAS, LocalFS on a kernel NFS / CIFS /
sshfs mount next to a session to that server, LocalFS next to SFTP to
localhost. :func:`may_be_same_file` answers "cannot rule it out" for all of
those and for every backend that does not say where it lives.

A backend locates itself in one of two ways:

* ``local_path(path)`` — the path on this machine's filesystem (LocalFS,
  and sessions that mount the remote side: NFS, iSCSI, MTP). The storage
  host then comes from ``/proc/self/mountinfo`` (the server of a network
  mount, else ``localhost``), and two local paths are compared by inode.
* ``_profile.host`` / ``_host`` — the server a network session talks to.
"""

from __future__ import annotations

import ipaddress
import os
import posixpath
import socket
import stat as stat_module

# Filesystems whose files live on another machine; the mount source names it.
NETWORK_FS = frozenset(
    {
        "nfs",
        "nfs4",
        "cifs",
        "smb3",
        "smbfs",
        "9p",
        "ceph",
        "glusterfs",
        "fuse.glusterfs",
        "fuse.sshfs",
        "sshfs",
        "davfs",
        "fuse.davfs2",
        "afs",
        "lustre",
    }
)


def _read_mountinfo() -> str:
    with open("/proc/self/mountinfo", encoding="utf-8", errors="replace") as fh:
        return fh.read()


def normalise_host(host: str) -> str:
    """Case- and dot-folded host; every name for this machine is ``localhost``."""
    h = host.strip().strip("[]").rstrip(".").lower()
    if h in ("localhost", "localhost.localdomain"):
        return "localhost"
    try:
        if ipaddress.ip_address(h).is_loopback:
            return "localhost"
    except ValueError:
        pass
    if h and h == socket.gethostname().rstrip(".").lower():
        return "localhost"
    return h


def _host_of_source(source: str) -> str | None:
    """Server named by a mount source: ``//host/share``, ``host:/export``,
    ``user@host:/path``, ``[v6]:/path``."""
    if source.startswith("//"):
        host = source[2:].split("/", 1)[0]
    elif source.startswith("["):
        host = source[1:].split("]", 1)[0]
    elif ":" in source:
        host = source.split(":", 1)[0].rsplit("@", 1)[-1]
    else:
        return None
    return normalise_host(host) if host else None


def storage_host_of_local_path(path: str) -> str | None:
    """``localhost`` for a local filesystem, the server for a network mount,
    None when it cannot be told (no mountinfo, unknown device)."""
    try:
        dev = os.stat(path).st_dev
        text = _read_mountinfo()
    except OSError:
        return None
    want = f"{os.major(dev)}:{os.minor(dev)}"
    for line in text.splitlines():
        left, sep, right = line.partition(" - ")
        fields = left.split()
        if not sep or len(fields) < 3 or fields[2] != want:
            continue
        tail = right.split()
        fstype = tail[0] if tail else ""
        source = tail[1] if len(tail) > 1 else ""
        if fstype in NETWORK_FS:
            return _host_of_source(source)
        return "localhost"
    return None


def _local_path(backend, path: str) -> str | None:
    fn = getattr(backend, "local_path", None)
    if not callable(fn):
        return None
    try:
        return fn(path) or None
    except (OSError, ValueError):
        return None


def _remote_host(backend) -> str | None:
    profile = getattr(backend, "_profile", None)
    host = getattr(profile, "host", None) if profile is not None else None
    if not host:
        host = getattr(backend, "_host", None)
    return normalise_host(host) if isinstance(host, str) and host.strip() else None


def _remote_port(backend):
    profile = getattr(backend, "_profile", None)
    port = getattr(profile, "port", None) if profile is not None else None
    return port if port is not None else getattr(backend, "_port", None)


def _same_view(backend_a, backend_b) -> bool:
    """True when both backends provably show one namespace: the same
    object, or two sessions of one kind to the same server and port."""
    if backend_a is backend_b:
        return True
    if type(backend_a) is not type(backend_b):
        return False
    host = _remote_host(backend_a)
    return (
        host is not None
        and host == _remote_host(backend_b)
        and _remote_port(backend_a) == _remote_port(backend_b)
    )


def _norm_view_path(backend, path: str) -> str:
    text = _norm_view_path_exact(backend, path)
    return text if getattr(backend, "case_sensitive", True) else text.casefold()


def _norm_view_path_exact(backend, path: str) -> str:
    """_norm_view_path without the case folding (the server resolves
    the name as spelled)."""
    try:
        sep = backend.separator() or "/"
    except Exception:  # noqa: BLE001 - a backend without separator() is POSIX-like
        sep = "/"
    text = path.replace("\\", "/") if sep == "\\" else path
    return posixpath.normpath("/" + text.lstrip("/"))


def _local_entry(path: str) -> str:
    """The path with every folder resolved but the last component kept:
    a symlink is its own entry, a symlinked folder is not."""
    head, name = os.path.split(os.path.abspath(path))
    return os.path.join(os.path.realpath(head), name)


def _strict_local_path(backend, path: str) -> str | None:
    local = _local_path(backend, path)
    return local if isinstance(local, str) else None


def same_entry(backend_a, path_a: str, backend_b, path_b: str) -> bool:
    """True only when both name provably the same directory entry.

    A transfer from one to the other would replace its own source, and a
    move would then delete the only copy. ``False`` means "not proven",
    not "different": two unrelated network sessions are never compared.
    """
    try:
        return _same_entry(backend_a, path_a, backend_b, path_b)
    except (OSError, TypeError, ValueError):
        return False


def _same_local_entry(local_a: str, local_b: str) -> bool:
    """:func:`_local_entry` of both paths equal, or one inode under both.

    Without ``realpath`` (a Python walk with an lstat per path component,
    on both paths, for every file a transfer copies), with the same
    verdict: the entries are one entry when their names are equal and
    their folders are one folder - ``stat`` of each folder follows its
    symlinks as realpath does, and also sees a bind mount as the same
    folder - or when the entries are one inode (lstat of the absolute
    path: the kernel resolves the folder's symlinks itself, the last
    component stays unfollowed)."""
    head_a, name_a = os.path.split(os.path.abspath(local_a))
    head_b, name_b = os.path.split(os.path.abspath(local_b))
    entry_a, entry_b = os.path.join(head_a, name_a), os.path.join(head_b, name_b)
    if entry_a == entry_b:
        return True
    # One file has more than one path: a bind mount, a share mounted
    # twice, a case-insensitive filesystem (Docs/File.txt and
    # docs/file.txt), a hard link, a symlinked folder. Paths cannot tell;
    # the device and inode of the entries can. lstat, so a symlink stays
    # its own entry.
    try:
        st_b = os.lstat(entry_b)
    except OSError:
        st_b = None
    if st_b is not None:
        try:
            return os.path.samestat(os.lstat(entry_a), st_b)
        except OSError:
            return False
    # No entry b (the usual destination): the same only as the same name
    # in the same folder, which is then not there either.
    if name_a != name_b:
        return False
    try:
        return os.path.samestat(os.stat(head_a), os.stat(head_b))
    except OSError:
        return False


def _same_entry(backend_a, path_a: str, backend_b, path_b: str) -> bool:
    local_a = _strict_local_path(backend_a, path_a)
    local_b = _strict_local_path(backend_b, path_b)
    if local_a and local_b:
        return _same_local_entry(local_a, local_b)
    if local_a or local_b or not _same_view(backend_a, backend_b):
        return False
    return _norm_view_path(backend_a, path_a) == _norm_view_path(backend_b, path_b)


def is_hard_link_of(backend_a, path_a: str, backend_b, path_b: str) -> bool:
    """True when the local *path_a* and *path_b* are two names of one file
    (hard links): two entries each listed in its own folder, one inode. A
    case-insensitive spelling, a bind mount or a symlinked folder of one
    entry is not that - its folder lists the one name only once."""
    try:
        local_a = _strict_local_path(backend_a, path_a)
        local_b = _strict_local_path(backend_b, path_b)
        if not (local_a and local_b):
            return False
        head_a, name_a = os.path.split(os.path.abspath(local_a))
        head_b, name_b = os.path.split(os.path.abspath(local_b))
        st_a, st_b = os.lstat(local_a), os.lstat(local_b)
        if not (os.path.samestat(st_a, st_b) and st_a.st_nlink > 1
                and stat_module.S_ISREG(st_a.st_mode)):
            return False
        if name_a == name_b and os.path.samestat(os.stat(head_a), os.stat(head_b)):
            return False  # one entry under two paths of its folder
        # Each name as its folder lists it: a case-insensitive spelling of
        # the one entry is not listed.
        return name_a in os.listdir(head_a) and name_b in os.listdir(head_b)
    except (OSError, TypeError, ValueError):
        return False


def same_target_message(backend_a, path_a: str, backend_b, path_b: str) -> str:
    """Why a copy or move of *path_a* to *path_b* (one entry, see
    :func:`same_entry`) does nothing - said apart for hard links."""
    if is_hard_link_of(backend_a, path_a, backend_b, path_b):
        return (f"{path_b} is the same file as {path_a} (a hard link): nothing is copied "
                "or moved, both names stay")
    return f"source and destination are the same: {path_b}"


def is_within(backend_a, root_a: str, backend_b, path_b: str) -> bool:
    """True when ``path_b`` is provably ``root_a`` itself or lies below it.

    Copying a folder to such a place lists the copy while it is being
    made, which recurses until the path length or the stack gives out.
    """
    try:
        return _is_within(backend_a, root_a, backend_b, path_b)
    except (OSError, TypeError, ValueError):
        return False


def _is_within(backend_a, root_a: str, backend_b, path_b: str) -> bool:
    local_a = _strict_local_path(backend_a, root_a)
    local_b = _strict_local_path(backend_b, path_b)
    if local_a and local_b:
        root, target = os.path.realpath(local_a), os.path.realpath(local_b)
        if target == root or target.startswith(root.rstrip(os.sep) + os.sep):
            return True
        return _local_ancestor_is(root, target)
    if local_a or local_b or not _same_view(backend_a, backend_b):
        return False
    root = _norm_view_path(backend_a, root_a)
    target = _norm_view_path(backend_b, path_b)
    if _is_below(root, target):
        return True
    # As text the two are apart; a symlink on the server may still lead
    # the one into the other (/b/link -> /a): the server's realpath says.
    root = resolved_path(backend_a, root_a)
    target = resolved_path(backend_b, path_b) if root is not None else None
    return root is not None and target is not None and _is_below(root, target)


def _is_below(root: str, target: str) -> bool:
    return target == root or target.startswith(root.rstrip("/") + "/")


def resolved_path(backend, path: str) -> str | None:
    """*path* with every symlink resolved, or None where that cannot be
    known.

    A local path: os.path.realpath. A remote one: the backend's
    ``realpath`` where it has one (SFTP's REALPATH, which OpenSSH answers
    with the server's realpath(3)); the parts below the deepest existing
    folder are kept as they are, so a folder about to be made resolves
    too. Other backends compare paths as text only: None.
    """
    local = _strict_local_path(backend, path)
    if local:
        return os.path.realpath(local)
    realpath = getattr(backend, "realpath", None)
    if not callable(realpath):
        return None
    current = _norm_view_path_exact(backend, path)
    tail: list[str] = []
    for _ in range(MAX_RESOLVE_STEPS):
        try:
            base = realpath(current)
        except (OSError, UnicodeError, ValueError):
            base = None
        if isinstance(base, str) and base.startswith("/"):
            text = posixpath.normpath(posixpath.join(base, *reversed(tail)))
            return text if getattr(backend, "case_sensitive", True) else text.casefold()
        parent = posixpath.dirname(current)
        if parent == current:
            return None
        tail.append(posixpath.basename(current))
        current = parent
    return None


#: Missing path parts resolved_path walks up past at most.
MAX_RESOLVE_STEPS = 64


def same_namespace(backend_a, path_a: str, backend_b, path_b: str) -> bool:
    """True when the two paths provably name places in one file tree: both
    on this machine, or one server seen through the same kind of session."""
    local_a = _strict_local_path(backend_a, path_a)
    local_b = _strict_local_path(backend_b, path_b)
    if local_a and local_b:
        return True
    return not local_a and not local_b and _same_view(backend_a, backend_b)


def folder_key(backend, path: str) -> str:
    """The resolved path where it can be had (resolved_path), else the
    normalised text; equal keys of two paths in one namespace
    (same_namespace) name the same folder."""
    resolved = resolved_path(backend, path)
    return resolved if resolved is not None else _norm_view_path(backend, path)


def _local_ancestor_is(root: str, target: str) -> bool:
    """True when *target* or one of its existing ancestors is the folder
    *root* under another path (bind mount, case-insensitive spelling)."""
    try:
        root_st = os.stat(root)
    except OSError:
        return False
    path = target
    while True:
        try:
            if os.path.samestat(os.stat(path), root_st):
                return True
        except OSError:
            pass  # not created yet: its parent decides
        parent = os.path.dirname(path)
        if parent == path:
            return False
        path = parent


def may_be_same_file(backend_a, path_a: str, backend_b, path_b: str) -> bool:
    """False only when the two paths are provably on different storage, or
    provably different files on the same machine."""
    local_a, local_b = _local_path(backend_a, path_a), _local_path(backend_b, path_b)
    if local_a and local_b:
        try:
            if os.path.samefile(local_a, local_b):
                return True
        except OSError:
            return True
    host_a = storage_host_of_local_path(local_a) if local_a else _remote_host(backend_a)
    host_b = storage_host_of_local_path(local_b) if local_b else _remote_host(backend_b)
    if host_a is None or host_b is None:
        return True
    if host_a != host_b:
        return False
    # Same machine: only two paths this kernel can see were compared above;
    # anything reached over the network may be the same file under another name.
    return not (local_a and local_b and host_a == "localhost")
