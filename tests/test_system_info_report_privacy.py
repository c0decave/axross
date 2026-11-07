"""The System Information report with identifiers hidden hides the
network ones it shows outside the MAC and IP columns too.

Such reports are meant to be pasted in public ("Identifiers (serial
numbers, MAC/IP addresses, UUIDs): hidden"). Two kinds still came through:

* a network mount's source in the File systems table and the JSON data:
  ``192.168.1.10:/export/alice``, ``//fileserver.corp.example/alice$``,
  ``alice@10.0.0.5:~`` - the server, its address, the account;
* the MAC inside a USB network adapter's systemd name
  (``enx00e04c680a1b``) in the interface list and "Default route via".

Hiding only the server of the two forms above still let others through
(sshfs ``alice@nas.corp.example:``, davfs
``https://cloud.corp.example/remote.php/dav/files/alice``, rclone
``remote:path``, ceph ``10.0.0.1:6789:/``) and kept the account in the
path (``/export/alice``). A mount's source is now shown only for a local
block device; every other one is hidden whole. The computer name is an
identifier too.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import system_info as SI  # noqa: E402

MOUNTS = [
    ("/dev/nvme0n1p2", "/", "ext4", ""),
    ("192.168.1.10:/export/alice", "/mnt/nfs", "nfs4", ""),
    ("//fileserver.corp.example/alice$", "/mnt/smb", "cifs", ""),
    ("alice@10.0.0.5:~", "/mnt/ssh", "fuse.sshfs", ""),
    ("[fd00::5]:/srv", "/mnt/v6", "nfs4", ""),
    ("alice@nas.corp.example:", "/mnt/nas", "fuse.sshfs", ""),
    ("nas2.corp.example:", "/mnt/nas2", "fuse.sshfs", ""),
    ("https://cloud.corp.example/remote.php/dav/files/alice", "/mnt/dav", "davfs", ""),
    ("gdrive-alice:Documents", "/mnt/drive", "fuse.rclone", ""),
    ("10.0.0.7:6789:/", "/mnt/ceph", "ceph", ""),
    ("gluster.corp.example:/vol0", "/mnt/gluster", "fuse.glusterfs", ""),
    ("hostshare-alice", "/mnt/9p", "9p", ""),
    ("tmpfs", "/tmp", "tmpfs", ""),
]
SECRETS = ("192.168.1.10", "fileserver.corp.example", "alice", "10.0.0.5", "fd00::5",
           "corp.example", "gdrive", "10.0.0.7", "Documents", "hostshare",
           "00e04c680a1b")


def _storage_section(tmp_path) -> dict:
    info = SI.SystemInfo(tmp_path, system="Linux", usage=lambda path: (100, 50, 50))
    filesystems = info._filesystems(MOUNTS)
    rows = [[f["mount"], f["device"], f["fstype"]] for f in filesystems]
    return SI.make_section("storage", "Storage", [],
                           [SI.table("File systems", ["Mount point", "Device", "Type"], rows)],
                           {"filesystems": filesystems})


def _network_section() -> dict:
    name = "enx00e04c680a1b"
    return SI.make_section(
        "network", "Network", [SI.field("Default route via", name)],
        [SI.table("Interfaces", ["Name", "MAC address"], [[name, "00:e0:4c:68:0a:1b"]],
                  ident_columns=(1,))],
        {"interfaces": [{"name": name, "mac": "00:e0:4c:68:0a:1b"}],
         "default_interface": name})


def test_sad_network_mount_sources_are_hidden_in_the_report(tmp_path):
    report = {"sections": [_storage_section(tmp_path)]}
    hidden = SI.redact(report)
    text = json.dumps(hidden) + SI.export_text(report)
    for secret in SECRETS[:-1]:
        assert secret not in text, secret
    rows = hidden["sections"][0]["tables"][0]["rows"]
    devices = {r[0]: r[1] for r in rows}
    assert devices.pop("/") == "/dev/nvme0n1p2"  # a local device is no identifier
    assert devices.pop("/tmp") == "tmpfs"
    assert set(devices.values()) == {SI.HIDDEN}, devices  # every network source whole
    assert all(f["device"] in ("/dev/nvme0n1p2", "tmpfs", SI.HIDDEN)
               for f in hidden["sections"][0]["data"]["filesystems"])


def test_sad_a_network_source_named_elsewhere_in_the_report_is_hidden(tmp_path):
    """The source is hidden wherever the report repeats it - another
    section's field or reason, too."""
    other = SI.make_section("x", "X", [SI.field("Note", "from alice@nas.corp.example: ok")])
    other["reason"] = "https://cloud.corp.example/remote.php/dav/files/alice timed out"
    report = {"sections": [_storage_section(tmp_path), other]}
    assert "corp.example" not in json.dumps(SI.redact(report))


def test_happy_only_local_block_devices_keep_their_source():
    for device, fstype in (("/dev/sda1", "ext4"), ("/dev/mapper/root", "btrfs"),
                           ("tmpfs", "tmpfs"), ("C:\\", "NTFS"), ("/dev/disk3s1", "apfs")):
        assert SI.mount_source_shown(device, fstype), device
    for device, fstype in (("/dev/nbd0", "nfs4"), ("nas:", "fuse.sshfs"),
                           ("\\\\nas\\share", "NTFS"), ("remote:", "fuse.rclone"),
                           ("//alice@nas/share", "smbfs"), ("rpool~", "zfs")):
        assert not SI.mount_source_shown(device, fstype), device


def test_sad_the_computer_name_is_hidden():
    section = SI.make_section("os", "Operating System",
                              [SI.field("Computer name", "alice-laptop", ident=True)],
                              data={"hostname": "alice-laptop"})
    report = {"sections": [section]}
    assert "alice-laptop" not in json.dumps(SI.redact(report)) + SI.export_text(report)
    assert "alice-laptop" in SI.export_text(report, show_identifiers=True)


def test_sad_the_probe_marks_the_computer_name_as_identifier(tmp_path):
    info = SI.SystemInfo(tmp_path, system="Linux", hostname="alice-laptop",
                         usage=lambda path: (100, 50, 50))
    report = {"sections": [info.probe_os()]}
    assert "alice-laptop" not in json.dumps(SI.redact(report))


def test_sad_a_mac_inside_an_interface_name_is_hidden():
    report = {"sections": [_network_section()]}
    text = json.dumps(SI.redact(report)) + SI.export_text(report)
    assert "00e04c680a1b" not in text
    assert f"enx{SI.HIDDEN}" in text


def test_happy_values_that_only_look_alike_stay():
    assert SI.scrub_text("alice@nas.corp.example:") == f"{SI.HIDDEN}:"
    for text in ("https://www.debian.org/", "Intel(R) Core(TM) i7-1165G7", "eth0",
                 "enp0s31f6", "/dev/sda1", "Linux 6.1.0-18-amd64", "firmware 1.0.0.12"):
        assert SI.scrub_text(text) == text
