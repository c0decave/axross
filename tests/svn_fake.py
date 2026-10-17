"""A subprocess.Popen stand-in for the SVN tests, built on their fake
subprocess.run: ``svn cat`` streams through Popen
(core.svn_fs_client.SvnFsSession._run_capped), the other commands still
run through subprocess.run."""

from __future__ import annotations

import io


def popen_from_run(fake_run):
    """A Popen class whose process answers what *fake_run* returns."""

    class _Popen:
        def __init__(self, argv, **kwargs):
            result = fake_run(argv, **kwargs)
            self.args = argv
            self.returncode = None
            self._code = result.returncode
            self.stdout = io.BufferedReader(io.BytesIO(result.stdout or b""))
            self.stderr = io.BufferedReader(io.BytesIO(result.stderr or b""))
            self.stdin = io.BytesIO()

        def wait(self, timeout=None):
            self.returncode = self._code
            return self._code

        def poll(self):
            return self.returncode

        def kill(self):
            self.returncode = -9

    return _Popen
