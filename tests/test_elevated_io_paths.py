"""pkexec helpers must come from root-owned system directories, not $PATH."""
from __future__ import annotations

import os
import stat
import tempfile
import unittest
from unittest import mock

from core import elevated_io


class TrustedResolveTest(unittest.TestCase):
    def test_planted_binary_on_path_is_ignored(self) -> None:
        bait = tempfile.mkdtemp()
        for name in ("cat", "tee", "stat", "ls", "pkexec"):
            path = os.path.join(bait, name)
            with open(path, "w") as fh:
                fh.write("#!/bin/sh\nexit 0\n")
            os.chmod(path, 0o755)
        with mock.patch.dict(os.environ, {"PATH": bait + os.pathsep + os.environ.get("PATH", "")}):
            resolved = elevated_io._resolve_helpers()
        if resolved is None:
            self.skipTest("pkexec is not installed in a trusted directory on this host")
        self.assertFalse(resolved.binary.startswith(bait))
        for name, full in resolved.helpers.items():
            self.assertFalse(full.startswith(bait), name)
            st = os.stat(full)
            self.assertEqual(st.st_uid, 0, full)
            self.assertFalse(st.st_mode & (stat.S_IWGRP | stat.S_IWOTH), full)

    def test_user_writable_directory_is_not_trusted(self) -> None:
        d = tempfile.mkdtemp()
        path = os.path.join(d, "cat")
        with open(path, "w") as fh:
            fh.write("x")
        os.chmod(path, 0o755)
        self.assertIsNone(elevated_io._trusted_which("cat", dirs=(d,)))

    def test_missing_binary(self) -> None:
        self.assertIsNone(elevated_io._trusted_which("no-such-binary-xyz"))


class BoundedReadTest(unittest.TestCase):
    """``elevated_read`` must stop reading once the output cap is passed,
    not buffer everything the helper prints until the timeout."""

    CAP = 1024 * 1024

    def setUp(self) -> None:
        from core.local_fs import LocalFS

        self.backend = LocalFS()
        self.dir = tempfile.mkdtemp()
        # Stand-in for pkexec: drop --disable-internal-agent, run the rest.
        self.pkexec = self._script("pkexec", 'shift\nexec "$@"\n')
        for patcher in (
            mock.patch.object(elevated_io, "MAX_OUTPUT_SIZE", self.CAP),
            mock.patch.object(elevated_io, "ELEVATED_TIMEOUT_SECS", 20),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)

    def _script(self, name: str, body: str) -> str:
        path = os.path.join(self.dir, name)
        with open(path, "w") as fh:
            fh.write("#!/bin/sh\n" + body)
        os.chmod(path, 0o755)
        return path

    def _helpers(self, cat: str):
        return elevated_io._Pkexec(
            binary=self.pkexec,
            helpers={"cat": cat, "tee": "/bin/false", "stat": "/bin/false", "ls": "/bin/false"},
        )

    def _read(self, cat: str, path: str) -> bytes:
        with mock.patch.object(elevated_io, "_resolve_helpers", return_value=self._helpers(cat)):
            return elevated_io.elevated_read(self.backend, path)

    def test_sad_endless_output_is_cut_at_the_cap(self) -> None:
        import time

        # Prints four times the cap, then keeps the pipe open like a
        # reader of /dev/urandom would.
        flood = self._script(
            "flood", f"head -c {self.CAP * 4} /dev/zero\nexec sleep 30\n"
        )
        start = time.monotonic()
        with self.assertRaises(elevated_io.ElevatedOutputTooLarge):
            self._read(flood, "/etc/hostname")
        self.assertLess(time.monotonic() - start, 10.0)

    def test_happy_small_file_is_returned_whole(self) -> None:
        target = os.path.join(self.dir, "small.bin")
        payload = bytes(range(256)) * 16
        with open(target, "wb") as fh:
            fh.write(payload)
        self.assertEqual(self._read("/usr/bin/cat", target), payload)

    def test_edge_exactly_the_cap_is_allowed(self) -> None:
        target = os.path.join(self.dir, "cap.bin")
        with open(target, "wb") as fh:
            fh.write(b"\x01" * self.CAP)
        self.assertEqual(len(self._read("/usr/bin/cat", target)), self.CAP)
        with open(target, "ab") as fh:
            fh.write(b"\x01")
        with self.assertRaises(elevated_io.ElevatedOutputTooLarge):
            self._read("/usr/bin/cat", target)

    def test_sad_cancelled_prompt_and_helper_error_are_reported(self) -> None:
        cancelled = self._script("cancel", "exit 126\n")
        with self.assertRaises(elevated_io.ElevatedCancelled):
            self._read(cancelled, "/etc/hostname")
        failing = self._script("fail", "echo 'no such file' >&2\nexit 1\n")
        with self.assertRaises(elevated_io.ElevatedIOError) as ctx:
            self._read(failing, "/etc/hostname")
        self.assertIn("no such file", str(ctx.exception))

    def test_sad_helper_that_hangs_times_out(self) -> None:
        hang = self._script("hang", "exec sleep 30\n")
        with (
            mock.patch.object(elevated_io, "ELEVATED_TIMEOUT_SECS", 1),
            self.assertRaises(elevated_io.ElevatedIOError) as ctx,
        ):
            self._read(hang, "/etc/hostname")
        self.assertIn("timed out", str(ctx.exception))


if __name__ == "__main__":
    unittest.main()
