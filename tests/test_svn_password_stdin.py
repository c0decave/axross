"""The SVN password travels over stdin, never in the child's argv.

A fake ``svn`` executable on PATH records exactly what the real binary
would see: its argument vector (what ``/proc/<pid>/cmdline`` exposes to
every local user) and its stdin.
"""

from __future__ import annotations

import os
import stat
import tempfile
import unittest
from unittest import mock

_INFO_XML = (
    "<?xml version='1.0'?><info>"
    "<entry kind='dir' revision='42'>"
    "<repository><root>https://svn.example.com/repo</root></repository>"
    "</entry></info>"
)

_FAKE_SVN = """#!/bin/sh
out="$AXROSS_FAKE_SVN_DIR"
n=$(ls "$out" | grep -c '^argv' )
for a in "$@"; do printf '%s\\n' "$a"; done > "$out/argv$n"
case " $* " in
  *" --password-from-stdin "*) cat > "$out/stdin$n" ;;
esac
if [ -f "$out/fail_stderr" ]; then
  cat "$out/fail_stderr" >&2
  exit 1
fi
cat "$out/info.xml"
"""


class SvnPasswordFromStdinTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.bin_dir = os.path.join(self._tmp.name, "bin")
        self.rec_dir = os.path.join(self._tmp.name, "rec")
        os.makedirs(self.bin_dir)
        os.makedirs(self.rec_dir)
        svn = os.path.join(self.bin_dir, "svn")
        with open(svn, "w", encoding="utf-8") as fh:
            fh.write(_FAKE_SVN)
        os.chmod(svn, stat.S_IRWXU)
        with open(os.path.join(self.rec_dir, "info.xml"), "w", encoding="utf-8") as fh:
            fh.write(_INFO_XML)
        env_patch = mock.patch.dict(
            os.environ,
            {
                "PATH": self.bin_dir + os.pathsep + os.environ.get("PATH", ""),
                "AXROSS_FAKE_SVN_DIR": self.rec_dir,
            },
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        self.addCleanup(self._tmp.cleanup)

    def _recorded(self, kind: str, n: int = 0) -> str:
        path = os.path.join(self.rec_dir, f"{kind}{n}")
        if not os.path.exists(path):
            return ""
        with open(path, encoding="utf-8") as fh:
            return fh.read()

    def _connect(self, **kw):
        from core import svn_fs_client as svn_mod

        return svn_mod.SvnFsSession(url="https://svn.example.com/repo", **kw)

    def test_password_is_sent_on_stdin_not_in_argv(self) -> None:
        secret = "s3" + "cret-pw"
        sess = self._connect(username="alice", password=secret)
        self.addCleanup(sess.close)
        argv = self._recorded("argv").splitlines()
        self.assertNotIn(secret, argv)
        self.assertNotIn("--password", argv)
        self.assertIn("--password-from-stdin", argv)
        self.assertEqual(self._recorded("stdin"), secret + "\n")
        self.assertIn("--username", argv)
        self.assertIn("--non-interactive", argv)
        self.assertIn("--no-auth-cache", argv)

    def test_every_later_call_also_keeps_the_password_off_argv(self) -> None:
        secret = "an" + "other-pw"
        sess = self._connect(username="alice", password=secret)
        self.addCleanup(sess.close)
        # The listing parses the same fake output as an empty directory.
        sess.list_dir("/trunk")
        argv1 = self._recorded("argv", 1).splitlines()
        self.assertIn("ls", argv1)
        self.assertNotIn(secret, argv1)
        self.assertEqual(self._recorded("stdin", 1), secret + "\n")

    def test_url_embedded_password_also_goes_over_stdin(self) -> None:
        from core import svn_fs_client as svn_mod

        sess = svn_mod.SvnFsSession(url="https://bob:url%20pw@svn.example.com/repo")
        self.addCleanup(sess.close)
        argv_text = self._recorded("argv")
        self.assertNotIn("url pw", argv_text)
        self.assertEqual(self._recorded("stdin"), "url pw\n")

    def test_without_password_no_stdin_flag_is_passed(self) -> None:
        sess = self._connect(username="alice")
        self.addCleanup(sess.close)
        argv = self._recorded("argv").splitlines()
        self.assertNotIn("--password-from-stdin", argv)
        self.assertNotIn("--password", argv)
        self.assertEqual(self._recorded("stdin"), "")

    def test_old_client_without_the_option_fails_with_a_clear_message(self) -> None:
        with open(os.path.join(self.rec_dir, "fail_stderr"), "w", encoding="utf-8") as fh:
            fh.write("svn: invalid option: --password-from-stdin\n")
        with self.assertRaises(OSError) as ctx:
            self._connect(username="alice", password="pw-" + "x")
        self.assertIn("1.10", str(ctx.exception))
        # The secret never reached argv, not even on the failing call.
        self.assertNotIn("pw-x", self._recorded("argv"))

    def test_password_with_a_line_break_is_refused_rather_than_put_on_argv(self) -> None:
        # stdin carries a single line; a multi-line secret cannot be
        # passed safely, and falling back to argv would leak it.
        with self.assertRaises(OSError):
            self._connect(username="alice", password="line1\nline2")
        self.assertEqual(self._recorded("argv"), "")


if __name__ == "__main__":
    unittest.main()
