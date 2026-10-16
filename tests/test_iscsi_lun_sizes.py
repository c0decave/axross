"""iSCSI lun_list asks lsblk for sizes in bytes.

``lsblk -J -O`` prints human sizes (``"size": "280G"``); only ``-b``
makes them byte counts (``"size": 300647710720``) - checked against
util-linux 2.42.4. lun_list called ``int()`` on the human string, so it
raised ValueError (not even an OSError) as soon as one iSCSI disk was
attached. The existing test fed byte strings and could not see it.

lsblk is a stand-in that answers the way the real tool does for the
flags it is given.
"""

from __future__ import annotations

import json
import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import iscsi_client  # noqa: E402

_DEVICES = [
    ("sda", 300647710720, "280G", "sata", "0xabc"),
    ("sdb", 107374182400, "100G", "iscsi", "0xdef"),
    ("sdc", 0, "0B", "iscsi", None),
]


def _fake_lsblk(argv, **kwargs):
    in_bytes = "-b" in argv or "--bytes" in argv
    devices = [
        {"name": n, "size": b if in_bytes else h, "tran": t, "wwn": w}
        for n, b, h, t, w in _DEVICES
    ]
    return mock.Mock(returncode=0, stdout=json.dumps({"blockdevices": devices}), stderr="")


class IscsiLunSizeTest(unittest.TestCase):
    def _luns(self) -> dict[str, dict]:
        s = iscsi_client.IscsiSession.__new__(iscsi_client.IscsiSession)
        with mock.patch.object(iscsi_client.shutil, "which", return_value="/usr/bin/lsblk"), \
                mock.patch.object(iscsi_client.subprocess, "run", side_effect=_fake_lsblk):
            return {d["device"]: d for d in s.lun_list()}

    def test_happy_sizes_in_bytes(self) -> None:
        self.assertEqual(self._luns()["/dev/sdb"]["size_bytes"], 107374182400)

    def test_sad_only_iscsi_devices(self) -> None:
        self.assertEqual(sorted(self._luns()), ["/dev/sdb", "/dev/sdc"])

    def test_edge_empty_lun_and_missing_wwn(self) -> None:
        sdc = self._luns()["/dev/sdc"]
        self.assertEqual((sdc["size_bytes"], sdc["scsi_id"]), (0, ""))


if __name__ == "__main__":
    unittest.main()
