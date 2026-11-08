"""The capabilities a backend declares are the ones its code has.

Review round 3 found:

* ``can_symlink=True`` for NFS, SCP, Telnet, RSH (Telnet's caps), rsync
  and iSCSI, none of which has a ``symlink()``.
* MTP inherited ``supports_symlinks`` / ``supports_hardlinks = True``
  from LocalFS - the pane read them and offered "New symlink" - while
  its symlink() / hardlink() always raise.
* RamFs and Git declared ``has_disk_usage`` and answered (0, 0, 0).
* ``CLOUD_CAPS.can_server_side_copy`` was False although OneDrive,
  Google Drive and Dropbox copy natively: a failed native copy fell
  back to a client-side stream copy instead of being reported.
"""

from __future__ import annotations

import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import backend_registry as br  # noqa: E402


def _classes():
    br.ensure_initialized()
    for info in br.all_backends():
        try:
            cls = getattr(importlib.import_module(info.module), info.class_name)
        except Exception:  # noqa: BLE001 - an optional SDK that is not installed
            continue
        yield info, cls


def _defines(cls, name: str) -> bool:
    skip = {"SessionLifecycle", "object", "Protocol", "FileBackend"}
    return any(name in vars(k) for k in cls.__mro__ if k.__name__ not in skip)


def test_sad_can_symlink_only_where_symlink_exists() -> None:
    wrong = [
        info.protocol_id
        for info, cls in _classes()
        if info.capabilities.can_symlink and not _defines(cls, "symlink")
    ]
    assert wrong == []
    for proto in ("nfs", "scp", "telnet", "rsh", "rsync", "iscsi"):
        assert br.get(proto).capabilities.can_symlink is False


def test_sad_supports_symlinks_agrees_with_can_symlink() -> None:
    """What the pane reads (``supports_symlinks``) and what the registry
    says (``can_symlink``) must not disagree."""
    wrong = [
        (info.protocol_id, cls.__name__)
        for info, cls in _classes()
        if bool(getattr(cls, "supports_symlinks", False)) != bool(info.capabilities.can_symlink)
    ]
    assert wrong == []


def test_sad_mtp_does_not_offer_links() -> None:
    from core.mtp_client import MtpSession

    assert MtpSession.supports_symlinks is False
    assert MtpSession.supports_hardlinks is False


def test_sad_ramfs_disk_usage_is_real() -> None:
    from core.ram_fs import RamFsSession

    s = RamFsSession("caps", max_bytes=1000)
    with s.open_write("/a") as fh:
        fh.write(b"x" * 100)
    assert s.disk_usage("/") == (1000, 100, 900)
    assert br.get("ramfs").capabilities.has_disk_usage is True


def test_sad_git_does_not_claim_disk_usage() -> None:
    caps = br.get("git").capabilities
    assert caps.has_disk_usage is False
    assert caps.can_chmod == br.DBFS_CAPS.can_chmod  # the rest stays DBFS


@pytest.mark.parametrize("proto", ["onedrive", "sharepoint", "gdrive", "dropbox"])
def test_sad_cloud_backends_declare_their_native_copy(proto) -> None:
    assert br.get(proto).capabilities.can_server_side_copy is True
