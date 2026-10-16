"""Every backend answers the optional FileBackend methods.

URL write matrix: RamFsSession had no checksum(), so the MCP checksum
tool (core/mcp_server.py, _hash_one_path) and the GUI's checksum action
(ui/file_pane.py, which only catches OSError) met an AttributeError.
An audit of every registered backend class against core.backend's
FileBackend found pop3, ramfs, svn and tftp without checksum,
disk_usage, readlink, list_versions and open_version_read. The contract
already says what "not supported" is for each; SessionLifecycle, which
every session inherits, now answers that by default. ``copy``,
``symlink`` and ``hardlink`` stay out on purpose: callers test them
with hasattr (core/server_ops.py, core/reverse_serve.py) or the
capability flags.
"""

from __future__ import annotations

import hashlib
import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import backend_registry as R  # noqa: E402
from core.backend import SessionLifecycle  # noqa: E402

DEFAULTED = ("checksum", "disk_usage", "readlink", "list_versions", "open_version_read")


def _classes():
    R.init_registry()
    for info in R.all_backends():
        try:
            yield info.protocol_id, getattr(importlib.import_module(info.module), info.class_name)
        except Exception:  # noqa: BLE001 - optional SDK missing here
            continue


# --- happy ----------------------------------------------------------------


@pytest.mark.parametrize("name", DEFAULTED)
def test_happy_every_backend_class_has_the_method(name):
    missing = [pid for pid, cls in _classes() if not hasattr(cls, name)]
    assert not missing, (name, missing)


def test_happy_the_mcp_checksum_works_on_a_ram_fs():
    from core.mcp_server import _hash_one_path, _ToolContext
    from core.ram_fs import RamFsSession

    ram = RamFsSession()
    with ram.open_write("/a.bin") as fh:
        fh.write(b"axross" * 1000)
    result = _hash_one_path(ram, "/a.bin", "sha256", _ToolContext())
    assert hashlib.sha256(b"axross" * 1000).hexdigest() in str(result)


# --- sad ------------------------------------------------------------------


def test_sad_versions_and_links_are_refused_as_oserror():
    class Bare(SessionLifecycle):
        pass

    b = Bare()
    with pytest.raises(OSError):
        b.open_version_read("/x", "v1")
    with pytest.raises(OSError):
        b.readlink("/x")


# --- edge -----------------------------------------------------------------


def test_edge_the_defaults_are_the_contract_values():
    class Bare(SessionLifecycle):
        pass

    b = Bare()
    assert b.checksum("/x") == "" and b.disk_usage("/") == (0, 0, 0) and b.list_versions("/x") == []


def test_edge_copy_and_links_stay_absent_for_hasattr_callers():
    for name in ("copy", "symlink", "hardlink"):
        assert not hasattr(SessionLifecycle, name)


def test_edge_a_backend_with_its_own_checksum_keeps_it():
    from core.local_fs import LocalFS

    assert LocalFS.checksum is not SessionLifecycle.checksum


@pytest.mark.parametrize("name", DEFAULTED)
def test_edge_no_real_implementation_is_shadowed_by_the_default(name):
    default = getattr(SessionLifecycle, name)
    shadowed = [
        pid
        for pid, cls in _classes()
        if getattr(cls, name) is default
        and any(k is not SessionLifecycle and name in vars(k) for k in cls.__mro__)
    ]
    assert not shadowed, (name, shadowed)
