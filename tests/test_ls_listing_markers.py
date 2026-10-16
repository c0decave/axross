"""Shell backends parse the ``ls -la`` lines GNU and BSD ls really print.

The parsers (telnet's ``_parse_ls_la``, also used by SCP, and rsh's
``_LS_RE``) wanted whitespace right after the nine permission letters.
GNU ls appends a tenth character when a file carries an SELinux label
(``.``) or an ACL (``+``); macOS ls appends ``@`` for extended
attributes. Those lines did not match and were dropped without a word:
on an SELinux host (RHEL, Fedora, CentOS) every entry has a label, so
every directory listed as empty. Device files (``4, 64`` in the size
column) were dropped the same way, and rsh cut a regular file's name at
`` -> `` as if it were a symlink.

SCP and rsh are driven through list_dir with the remote command
replaced by canned output; the shell round trip is not under test.
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

_PLAIN = (
    "total 12\n"
    "drwxr-xr-x  3 root root 4096 Oct 15 08:00 .\n"
    "drwxr-xr-x 20 root root 4096 Oct 15 08:00 ..\n"
    "drwxr-xr-x  2 root root 4096 Oct 15 08:00 conf.d\n"
    "-rw-r--r--  1 root root  123 Oct 15 08:00 hosts\n"
    "lrwxrwxrwx  1 root root   11 Oct 15 08:00 mtab -> /proc/mounts\n"
)

# GNU ls on an SELinux host, a file with an ACL, a macOS xattr marker.
_MARKED = (
    "total 12\n"
    "drwxr-xr-x. 3 root root 4096 Oct 15 08:00 .\n"
    "drwxr-xr-x. 2 root root 4096 Oct 15 08:00 conf.d\n"
    "-rw-r--r--. 1 root root  123 Oct 15 08:00 hosts\n"
    "-rw-rw----+ 1 root adm   77 Oct 15 08:00 shared.log\n"
    "-rwxr-xr-x@ 1 user staff  9 Oct 15 08:00 tool\n"
    "lrwxrwxrwx. 1 root root   11 Oct 15 08:00 mtab -> /proc/mounts\n"
)

_EDGE = (
    "crw-rw----. 1 root tty  4, 64 Oct 15 08:00 ttyS0\n"
    "brw-rw---- 1 root disk 259,   0 Oct 15 08:00 nvme0n1\n"
    "-rw-r--r-- 1 root root   5 Oct 15 08:00 a -> b\n"
)


def _scp_names(output: str) -> dict[str, tuple]:
    from core.scp_client import SCPSession

    s = SCPSession.__new__(SCPSession)
    s._exec = lambda cmd, timeout=None: output
    return {
        i.name: (i.is_dir, i.is_link, i.size, i.permissions) for i in s.list_dir("/etc")
    }


def _rsh_names(output: str) -> dict[str, tuple]:
    from core.rsh_client import RshSession

    s = RshSession.__new__(RshSession)
    with mock.patch.object(RshSession, "_run_remote", return_value=output.encode()):
        items = s.list_dir("/etc")
    return {i.name: (i.is_dir, i.is_link, i.size, i.permissions) for i in items}


class LsMarkersTest(unittest.TestCase):
    def test_happy_plain_listing(self) -> None:
        for names in (_scp_names(_PLAIN), _rsh_names(_PLAIN)):
            self.assertEqual(sorted(names), ["conf.d", "hosts", "mtab"])
            self.assertEqual(names["hosts"][2], 123)
            self.assertTrue(names["conf.d"][0])

    def test_sad_selinux_acl_and_xattr_markers_are_listed(self) -> None:
        for names in (_scp_names(_MARKED), _rsh_names(_MARKED)):
            self.assertEqual(sorted(names), ["conf.d", "hosts", "mtab", "shared.log", "tool"])
            self.assertEqual(names["hosts"][2:], (123, 0o644))
            self.assertEqual(names["shared.log"][2:], (77, 0o660))
            self.assertEqual(names["tool"][3], 0o755)
            self.assertTrue(names["conf.d"][0])
            self.assertTrue(names["mtab"][1])

    def test_edge_device_files_and_arrow_in_a_regular_name(self) -> None:
        for names in (_scp_names(_EDGE), _rsh_names(_EDGE)):
            self.assertEqual(sorted(names), ["a -> b", "nvme0n1", "ttyS0"])
            self.assertEqual(names["ttyS0"][2], 0)
            self.assertEqual(names["a -> b"][:3], (False, False, 5))


if __name__ == "__main__":
    unittest.main()
