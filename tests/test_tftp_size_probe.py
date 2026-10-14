"""The TFTP size probe stops at the server's tsize answer.

Before: ``_probe_size`` (used per file by ``list_dir``, by ``stat`` and
by ``find_files``) downloaded every file completely and measured the
temp file - a listing transferred every listed file. tftpy hands each
received packet to the packet hook, the option acknowledgement (OACK)
included, so a server that reports ``tsize`` answers the probe before a
single data block. Servers without tsize still get the full download, as
before.
"""

from __future__ import annotations

import socket
import sys
import threading
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

try:
    import tftpy  # noqa: F401

    from core.tftp_client import TftpSession
except ImportError:  # pragma: no cover
    TftpSession = None

BLOCK = 512


class _FakeTftpServer:
    """Serves one file per RRQ from a fresh port; counts DATA blocks sent.

    ``tsize=True``: answers a tsize request with an OACK first.
    ``tsize=False``: ignores options and sends data right away.
    """

    def __init__(self, files: dict[str, bytes], *, tsize: bool) -> None:
        self.files, self.tsize = files, tsize
        self.blocks_sent = 0
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self._sock.bind(("127.0.0.1", 0))
        self.port = self._sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                data, addr = self._sock.recvfrom(65535)
            except OSError:
                return
            if data[:2] != b"\x00\x01":
                continue
            fields = data[2:].split(b"\x00")
            name = fields[0].decode()
            opts = dict(zip(fields[2::2], fields[3::2]))
            threading.Thread(target=self._transfer, args=(name, opts, addr), daemon=True).start()

    def _transfer(self, name: str, opts: dict, addr) -> None:
        t = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        t.settimeout(1.0)
        try:
            if name not in self.files:
                t.sendto(b"\x00\x05\x00\x01File not found\x00", addr)
                return
            payload = self.files[name]
            if self.tsize and b"tsize" in opts:
                t.sendto(b"\x00\x06tsize\x00" + str(len(payload)).encode() + b"\x00", addr)
                try:
                    ack, _ = t.recvfrom(1024)
                except OSError:
                    return  # client walked away after reading the size
                if ack[:2] != b"\x00\x04":
                    return
            block = 1
            while True:
                chunk = payload[(block - 1) * BLOCK : block * BLOCK]
                t.sendto(b"\x00\x03" + block.to_bytes(2, "big") + chunk, addr)
                self.blocks_sent += 1
                try:
                    t.recvfrom(1024)
                except OSError:
                    return
                if len(chunk) < BLOCK:
                    return
                block += 1
        finally:
            t.close()

    def close(self) -> None:
        self._sock.close()


@unittest.skipIf(TftpSession is None, "tftpy not installed")
class SizeProbeTest(unittest.TestCase):
    FILES = {"big.bin": b"x" * (BLOCK * 40 + 7), "empty.bin": b"", "one.bin": b"y" * BLOCK}

    def session(self, server) -> TftpSession:
        self.addCleanup(server.close)
        return TftpSession(host="127.0.0.1", port=server.port, timeout=2, retries=1)

    def test_happy_tsize_server_answers_without_data_blocks(self) -> None:
        server = _FakeTftpServer(self.FILES, tsize=True)
        s = self.session(server)
        for name, payload in self.FILES.items():
            with self.subTest(name=name):
                self.assertEqual(s._probe_size(name), len(payload))
        self.assertEqual(server.blocks_sent, 0)

    def test_sad_server_without_tsize_still_measures_by_download(self) -> None:
        server = _FakeTftpServer(self.FILES, tsize=False)
        s = self.session(server)
        self.assertEqual(s._probe_size("big.bin"), len(self.FILES["big.bin"]))
        self.assertEqual(server.blocks_sent, 41)

    def test_sad_missing_file_is_zero(self) -> None:
        server = _FakeTftpServer(self.FILES, tsize=True)
        self.assertEqual(self.session(server)._probe_size("nope.bin"), 0)

    def test_edge_stat_uses_the_cheap_probe(self) -> None:
        server = _FakeTftpServer(self.FILES, tsize=True)
        item = self.session(server).stat("/big.bin")
        self.assertEqual(item.size, len(self.FILES["big.bin"]))
        self.assertEqual(server.blocks_sent, 0)


if __name__ == "__main__":
    unittest.main()
