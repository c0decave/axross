"""Runtime capability contracts derived from backend registry entries."""

from __future__ import annotations

from dataclasses import dataclass

from core.backend_registry import BackendCapabilities


@dataclass(frozen=True)
class CapabilityContract:
    can_rename: bool
    can_stream_read: bool
    can_stream_write: bool
    can_recursive_delete: bool
    rename_overwrites: bool
    rename_atomic: bool
    append_native: bool
    seekable_reads: bool
    symlink_follows: bool
    delete_recursive_safe: bool

    @classmethod
    def from_caps(cls, caps: BackendCapabilities) -> "CapabilityContract":
        seekable = bool(caps.seekable_reads and caps.can_seek)
        return cls(
            can_rename=bool(caps.can_rename),
            can_stream_read=bool(caps.can_stream_read),
            can_stream_write=bool(caps.can_stream_write),
            can_recursive_delete=bool(caps.can_recursive_delete),
            rename_overwrites=bool(caps.rename_overwrites),
            rename_atomic=bool(caps.rename_atomic and caps.can_rename),
            append_native=bool(caps.append_native),
            seekable_reads=seekable,
            symlink_follows=bool(caps.symlink_follows),
            delete_recursive_safe=bool(caps.delete_recursive_safe and caps.can_recursive_delete),
        )


def caps_for_backend(backend) -> BackendCapabilities:
    """Return registry capabilities for a backend instance."""
    try:
        from core.local_fs import LocalFS

        if isinstance(backend, LocalFS) and type(backend).rename is LocalFS.rename:
            from core.backend_registry import POSIX_CAPS

            return POSIX_CAPS
    except Exception:
        pass
    try:
        from core.db_fs_base import DbFsBackend

        if isinstance(backend, DbFsBackend):
            from core.backend_registry import DBFS_CAPS

            return DBFS_CAPS
    except Exception:
        pass
    try:
        from core import backend_registry

        class_name = type(backend).__name__
        for info in backend_registry.all_backends():
            if info.class_name == class_name:
                return info.capabilities
    except Exception:
        pass
    return BackendCapabilities()


def contract_for_backend(backend) -> CapabilityContract:
    return CapabilityContract.from_caps(caps_for_backend(backend))


def validate_contract(contract: CapabilityContract) -> list[str]:
    """Return human-readable contract contradictions."""
    problems: list[str] = []
    if contract.rename_atomic and not contract.can_rename:
        problems.append("rename_atomic requires can_rename")
    if contract.rename_overwrites and not contract.can_rename:
        problems.append("rename_overwrites requires can_rename")
    if contract.append_native and not contract.can_stream_write:
        problems.append("append_native requires can_stream_write")
    if contract.delete_recursive_safe and not contract.can_recursive_delete:
        problems.append("delete_recursive_safe requires can_recursive_delete")
    if contract.seekable_reads and not contract.can_stream_read:
        problems.append("seekable_reads requires can_stream_read")
    return problems


__all__ = [
    "CapabilityContract",
    "caps_for_backend",
    "contract_for_backend",
    "validate_contract",
]
