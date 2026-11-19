"""The ADB key: made once under concurrent connects, usable without .pub.

Review 2026-11-18:

* finding 10 - two connects at once on a machine without a key both ran
  keygen; the second key overwrote the first, which the phone had just
  been asked to trust (2 of 3 runs). The process-wide ``os.umask`` bracket
  around keygen also changed the mode of files other threads created
  meanwhile.
* finding 14 - an ``adbkey`` without ``adbkey.pub`` (copied from another
  machine; the adb tool needs only the private key) was refused, and the
  user read "...adbkey.pub was not found ... refresh the folder".
"""

from __future__ import annotations

import os
import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

adb = pytest.importorskip("core.adb_client")
if not adb.ADB_SHELL_AVAILABLE:  # pragma: no cover - optional dependency
    pytest.skip("adb-shell not installed", allow_module_level=True)

from tests.fake_adbd import FakeAdbd, make_device_tree, parse_android_pubkey  # noqa: E402


def test_sad_concurrent_first_connects_make_one_key(tmp_path, monkeypatch):
    key = str(tmp_path / "android" / "adbkey")
    calls: list[str] = []
    real = adb.keygen
    barrier = threading.Barrier(4)

    def slow_keygen(path):
        calls.append(path)
        real(path)

    monkeypatch.setattr(adb, "keygen", slow_keygen)
    seen: list[bytes] = []

    def connect_like():
        barrier.wait()
        adb.ensure_adb_key(key)
        seen.append(Path(key).read_bytes())

    threads = [threading.Thread(target=connect_like) for _ in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join(60)
    assert len(calls) == 1
    assert len(set(seen)) == 1
    assert os.stat(key).st_mode & 0o777 == 0o600
    assert sorted(os.listdir(os.path.dirname(key))) == ["adbkey", "adbkey.pub"]


def test_sad_making_a_key_leaves_the_process_umask_alone(tmp_path, monkeypatch):
    def no_umask(_mask):
        raise AssertionError("os.umask is process-wide: other threads' files change mode")

    monkeypatch.setattr(os, "umask", no_umask)
    key = str(tmp_path / "android" / "adbkey")
    adb.ensure_adb_key(key)
    assert os.stat(key).st_mode & 0o777 == 0o600


def test_happy_a_private_key_alone_connects(tmp_path):
    key = tmp_path / "android" / "adbkey"
    adb.ensure_adb_key(str(key))
    pub = Path(str(key) + ".pub").read_text()
    os.unlink(str(key) + ".pub")
    root = str(tmp_path / "device")
    make_device_tree(root)
    device = FakeAdbd(root, auth="key", authorized=[pub])
    try:
        s = adb.AdbSession("127.0.0.1", device.port, adb_key_path=str(key))
        assert s.list_dir("/sdcard")
        s.close()
    finally:
        device.stop()
    signer = adb._load_signer(str(key))
    assert parse_android_pubkey(signer.GetPublicKey()) == parse_android_pubkey(pub)
