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


if __name__ == "__main__":
    unittest.main()
