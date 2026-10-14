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
import socket

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
