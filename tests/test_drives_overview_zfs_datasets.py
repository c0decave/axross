"""Drives Overview shows ZFS pools and datasets (review round 3).

Before: a drive counted as local only when its source was a /dev/ path. A
ZFS dataset's source is its name ("tank/media"), so every pool and dataset
but "/" was classed as "system" and hidden by default - a NAS's data pool
was missing from the overview. Now a ZFS dataset is a local drive (or a
removable one under /media); a container engine's per-layer datasets stay
system mounts.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

_spec = importlib.util.spec_from_file_location(
    "drives_overview_zfs", ROOT / "resources" / "extensions" / "drives_overview.py")
DO = importlib.util.module_from_spec(_spec)
sys.modules["drives_overview_zfs"] = DO
_spec.loader.exec_module(DO)

MOUNTS = """\
rpool/ROOT/ubuntu / zfs rw,relatime,xattr,posixacl 0 0
tank /tank zfs rw,xattr,noacl 0 0
tank/media /tank/media zfs rw,xattr,noacl 0 0
rpool/USERDATA/anna_x1 /home/anna zfs rw,relatime 0 0
usbpool/backup /media/anna/backup zfs rw 0 0
tank/docker/3f1a9c /var/lib/docker/zfs/graph/3f1a9c zfs rw 0 0
"""


def _kinds():
    return {d.mount: d.kind for d in DO.parse_proc_mounts(MOUNTS)}


def test_sad_a_zfs_pool_and_its_datasets_are_local_drives():
    kinds = _kinds()
    assert kinds["/tank"] == "local"
    assert kinds["/tank/media"] == "local"
    assert kinds["/home/anna"] == "local"
    assert all(kind in DO.SHOWN_KINDS for mount, kind in kinds.items()
               if not mount.startswith("/var/lib/docker/"))


def test_edge_a_zfs_pool_under_media_is_removable():
    assert _kinds()["/media/anna/backup"] == "removable"


def test_edge_a_container_engines_layer_datasets_stay_system():
    kinds = _kinds()
    assert kinds["/var/lib/docker/zfs/graph/3f1a9c"] == "system"
    assert kinds["/"] == "local"
    # The macOS / BSD mount output names the type the same way.
    (drive,) = DO.parse_mount_output("tank/media on /tank/media (zfs, local, noatime)")
    assert drive.kind == "local"
