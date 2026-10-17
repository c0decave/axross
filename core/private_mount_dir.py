"""Mount points that no other local user can reach.

NFS and iSCSI are mounted by root (via sudo). A mount point made with
``tempfile.mkdtemp`` is 0700 only until the mount: from then on the
mounted file system's own root mode (often 0755) guards the path, and a
mount point directly in /tmp lets every local user browse the export.
The mount point therefore sits one level down, in a fresh 0700 folder
of this user, which nobody else can enter whatever is mounted below it.
"""

from __future__ import annotations

import logging
import os
import tempfile

log = logging.getLogger(__name__)


def make_private_mount_point(prefix: str) -> str:
    """A new, empty mount point inside a new 0700 folder; returns its path."""
    parent = tempfile.mkdtemp(prefix=prefix)  # 0700, owned by this user
    mount_point = os.path.join(parent, "mnt")
    os.mkdir(mount_point, 0o700)
    return mount_point


def remove_private_mount_point(mount_point: str) -> None:
    """Remove a mount point made by make_private_mount_point, and its folder.

    Never recursively: a mount still in place (an unmount that failed)
    keeps the mount point non-empty, rmdir refuses, and nothing of the
    export is touched."""
    for path in (mount_point, os.path.dirname(mount_point)):
        try:
            os.rmdir(path)
        except FileNotFoundError:
            continue
        except OSError as exc:
            log.warning("Mount point %s is kept: %s", path, exc)
            return
