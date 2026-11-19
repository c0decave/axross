"""An ADB profile connects where it says: port 5555, the IP version asked.

Review 2026-11-18 (finding 15): an ADB profile without "port" in
profiles.json loaded with ConnectionProfile's default 22 (SSH), which
``profile.port or 5555`` let through; the IP Version the dialog shows for
ADB never reached the backend.
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.profiles import ConnectionProfile, ProfileManager  # noqa: E402


def test_happy_an_adb_profile_without_a_port_gets_5555():
    with tempfile.TemporaryDirectory() as tmp:
        with mock.patch("core.profiles.CONFIG_DIR", Path(tmp)), mock.patch(
                "core.profiles.PROFILES_FILE", Path(tmp) / "profiles.json"):
            (Path(tmp) / "profiles.json").write_text(json.dumps({
                "phone": {"name": "phone", "protocol": "adb", "host": "192.168.1.5"},
                "box": {"name": "box", "protocol": "sftp", "host": "h"},
            }))
            manager = ProfileManager()
            assert manager.get("phone").port == 5555
            assert manager.get("box").port == 22


adb = pytest.importorskip("core.adb_client")


@pytest.mark.skipif(not adb.ADB_SHELL_AVAILABLE, reason="adb-shell not installed")
@pytest.mark.parametrize("family, works", [("ipv4", True), ("auto", True), ("ipv6", False)])
def test_happy_the_ip_version_reaches_the_connect(tmp_path, monkeypatch, family, works):
    from core.connection_manager import ConnectionManager
    from tests.fake_adbd import FakeAdbd, make_device_tree

    key = tmp_path / "adbkey"
    monkeypatch.setattr(adb, "DEFAULT_ADB_KEY_PATH", str(key))
    root = str(tmp_path / "device")
    make_device_tree(root)
    device = FakeAdbd(root)  # listens on 127.0.0.1 only
    profile = ConnectionProfile(name="p", protocol="adb", host="localhost", port=device.port,
                                address_family=family)
    mgr = ConnectionManager()
    try:
        if works:
            assert mgr.connect(profile).list_dir("/sdcard")
        else:
            with pytest.raises(OSError):
                mgr.connect(profile)  # ::1 has no fake phone
    finally:
        mgr.disconnect_all()
        device.stop()
