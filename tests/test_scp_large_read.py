"""SCP reads stream the file instead of capping it at 4 MiB of output.

``open_read`` ran ``base64 < file`` through ``_exec_raw``, which reads at
most ``COMMAND_STDOUT_CAP`` (4 MiB) of stdout and raises beyond it. Base64
inflates by 4/3, so every file above ~3 MiB failed to download — copy,
open, preview, compare. The raw ``cat`` fallback also round-tripped the
bytes through ``str`` and corrupted any non-UTF-8 content.

Driven end to end: paramiko client -> in-process paramiko server whose
exec handler runs the command through ``/bin/sh -c`` in a temp directory.
"""

from __future__ import annotations

import os
import shutil
import sys
import tempfile
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import paramiko  # noqa: E402

from core.scp_client import SCPSession, _Capabilities  # noqa: E402
from tests.test_scp_large_upload import _ShellServer  # noqa: E402


@unittest.skipUnless(shutil.which("base64") and os.path.exists("/bin/sh"), "needs sh + base64")
class ScpLargeReadTest(unittest.TestCase):
    def setUp(self) -> None:
        self.root = tempfile.mkdtemp(prefix="axross-scp-read-")
        self.addCleanup(shutil.rmtree, self.root, True)
        self.srv = _ShellServer(self.root)
        self.addCleanup(self.srv.close)
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            "127.0.0.1",
            port=self.srv.port,
            username="u",
            password="p",
            allow_agent=False,
            look_for_keys=False,
        )
        self.addCleanup(client.close)
        self.client = client

    def session(self, method: str) -> SCPSession:
        s = SCPSession.__new__(SCPSession)
        s._client = self.client
        s._lock = threading.Lock()
        s._caps = _Capabilities(has_base64=method == "base64", transfer_method=method)
        return s

    def put(self, name: str, data: bytes) -> str:
        path = os.path.join(self.root, name)
        with open(path, "wb") as fh:
            fh.write(data)
        return path

    def test_happy_file_above_the_old_cap_reads_completely(self) -> None:
        data = os.urandom(5 * 1024 * 1024 + 7)  # base64: ~6.7 MiB of output
        path = self.put("big.bin", data)
        self.assertEqual(self.session("base64").open_read(path).read(), data)

    def test_happy_raw_method_keeps_binary_bytes(self) -> None:
        data = bytes(range(256)) * 64 + b"\xff\xfe\x00"
        path = self.put("bin.dat", data)
        self.assertEqual(self.session("raw").open_read(path).read(), data)

    def test_sad_missing_file_raises(self) -> None:
        for method in ("base64", "raw"):
            with self.subTest(method), self.assertRaises(OSError):
                self.session(method).open_read(os.path.join(self.root, "nope.bin"))

    def test_edge_empty_file_and_small_file(self) -> None:
        self.assertEqual(self.session("base64").open_read(self.put("e", b"")).read(), b"")
        self.assertEqual(self.session("base64").open_read(self.put("s", b"abc")).read(), b"abc")


if __name__ == "__main__":
    unittest.main()
