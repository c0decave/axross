"""The phone learns no user or host name of this computer.

Review 2026-11-18 (finding 9): ensure_adb_key meant to strip the
``user@hostname`` comment from adbkey.pub (docs/OPSEC.md) but kept both
tokens of "<base64> user@host", so the comment reached the phone on the
first pairing and stays in /data/misc/adb/adb_keys. adb_shell's connect
banner also carried the host name (``host::<hostname>``).
"""

from __future__ import annotations

import getpass
import socket
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

adb = pytest.importorskip("core.adb_client")
if not adb.ADB_SHELL_AVAILABLE:  # pragma: no cover - optional dependency
    pytest.skip("adb-shell not installed", allow_module_level=True)

from tests.fake_adbd import FakeAdbd, make_device_tree  # noqa: E402

IDENTITIES = [getpass.getuser().encode(), socket.gethostname().encode()]


def _pair(tmp_path, key: Path):
    root = str(tmp_path / "device")
    make_device_tree(root)
    device = FakeAdbd(root, auth="key")
    try:
        adb.AdbSession("127.0.0.1", device.port, adb_key_path=str(key)).close()
    finally:
        device.stop()
    return device


def test_happy_a_new_key_names_nobody(tmp_path):
    key = tmp_path / "android" / "adbkey"
    device = _pair(tmp_path, key)
    pub = Path(str(key) + ".pub").read_bytes()
    assert pub.split()[1:] == [adb.NEUTRAL_KEY_COMMENT.encode()]
    sent = device.received_pubkeys[0]
    assert sent.rstrip(b"\0").split()[1:] == [adb.NEUTRAL_KEY_COMMENT.encode()]
    for name in IDENTITIES:
        if len(name) > 3:
            assert name not in sent and name not in device.banners[0]


def test_happy_an_old_key_with_user_at_host_is_sent_without_it(tmp_path):
    key = tmp_path / "android" / "adbkey"
    adb.ensure_adb_key(str(key))
    pub_path = Path(str(key) + ".pub")
    pub_path.write_text(pub_path.read_text().split()[0] + " alice@workstation.example\n")
    device = _pair(tmp_path, key)
    assert b"alice" not in device.received_pubkeys[0]
    assert b"workstation" not in device.received_pubkeys[0]
