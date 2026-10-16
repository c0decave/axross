"""Reverse-WebDAV MOVE/COPY honour ``Overwrite: F``.

RFC 4918 (9.8.4, 9.9.3): with ``Overwrite: F`` an existing destination
must make the request fail with 412 Precondition Failed. Clients rely on
it to ask before replacing -- GIO (gnome-files, one of the clients the
module names) sends F for a move without the overwrite flag and expects
"exists" back. Measured before: the header was never read, and on a
LocalFS backend ``rename``/``copy`` replaced the destination silently
(201), so a rename onto a taken name destroyed that file without the
client ever getting the chance to ask.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import reverse_serve  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


class DavOverwriteHeaderTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        (self.tmp / "a.txt").write_bytes(b"A")
        (self.tmp / "b.txt").write_bytes(b"B")
        self.srv = reverse_serve.serve_webdav(
            LocalFS(), bind="127.0.0.1", port=0, root_path=str(self.tmp)
        )
        self.addCleanup(self.srv.shutdown)

    def request(self, method: str, src: str, dst: str, overwrite: str | None) -> int:
        headers = {"Destination": f"{self.srv.base_url}{dst}"}
        if overwrite is not None:
            headers["Overwrite"] = overwrite
        req = urllib.request.Request(
            f"{self.srv.base_url}{src}", method=method, headers=headers
        )
        try:
            with urllib.request.urlopen(req) as r:
                return r.status
        except urllib.error.HTTPError as exc:
            return exc.code

    def test_happy_move_to_a_free_name_with_overwrite_f(self) -> None:
        self.assertEqual(self.request("MOVE", "/a.txt", "/c.txt", "F"), 201)
        self.assertEqual((self.tmp / "c.txt").read_bytes(), b"A")

    def test_sad_move_onto_a_taken_name_with_overwrite_f_is_refused(self) -> None:
        self.assertEqual(self.request("MOVE", "/a.txt", "/b.txt", "F"), 412)
        self.assertEqual((self.tmp / "a.txt").read_bytes(), b"A")
        self.assertEqual((self.tmp / "b.txt").read_bytes(), b"B")

    def test_sad_copy_onto_a_taken_name_with_overwrite_f_is_refused(self) -> None:
        self.assertEqual(self.request("COPY", "/a.txt", "/b.txt", "f"), 412)
        self.assertEqual((self.tmp / "b.txt").read_bytes(), b"B")

    def test_edge_without_the_header_a_move_still_replaces(self) -> None:
        # RFC 4918: a missing Overwrite header means T.
        self.assertEqual(self.request("MOVE", "/a.txt", "/b.txt", None), 201)
        self.assertEqual((self.tmp / "b.txt").read_bytes(), b"A")


if __name__ == "__main__":
    unittest.main()
