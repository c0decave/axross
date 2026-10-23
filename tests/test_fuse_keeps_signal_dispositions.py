"""A FUSE unmount leaves the process's signal handling as it found it.

Reproduced 2026-10-22: libfuse's teardown sets SIGPIPE back to "default"
although axross (like every Python process) ignores it, and libfuse never
installed anything for it. From then on a write to a pipe or socket whose
reader is gone - a dead agent, analysis or voice worker, a dropped SSH
connection - killed axross silently with status 141 instead of raising
BrokenPipeError. It also killed whole pytest runs after the real-mount
test (each file passed alone). Measured: SIGPIPE ignored before mounting,
while mounted, and NOT after the unmount; SIGINT/SIGHUP/SIGTERM were back
to their old state. core.fuse_mount now saves the four dispositions in the
FUSE thread and restores them when the loop ends.

The mount runs in a child process, so a failing run cannot take the test
process down with it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT))
from core import fuse_mount as FM  # noqa: E402

_needs_fuse = pytest.mark.skipif(
    not (sys.platform.startswith("linux") and FM.FUSE_AVAILABLE and os.path.exists("/dev/fuse")
         and (shutil.which("fusermount3") or shutil.which("fusermount"))),
    reason="needs FUSE (fusepy, /dev/fuse, fusermount)",
)

_CHILD = textwrap.dedent("""
    import os, sys, tempfile, time
    sys.path.insert(0, {root!r})
    def state():
        d = {{}}
        for line in open("/proc/self/status"):
            if line.startswith(("SigIgn:", "SigCgt:")):
                k, v = line.split()
                d[k[:-1]] = int(v, 16)
        four = sum(1 << (n - 1) for n in (1, 2, 13, 15))  # HUP INT PIPE TERM
        return {{k: v & four for k, v in d.items()}}
    from core import fuse_mount as FM
    from core.local_fs import LocalFS
    before = state()
    src, mnt = tempfile.mkdtemp(), tempfile.mkdtemp()
    open(os.path.join(src, "a.txt"), "w").write("x")
    h = FM.mount(LocalFS(), mnt, root=src)
    for _ in range(100):
        if os.path.ismount(mnt):
            break
        time.sleep(0.05)
    if not os.path.ismount(mnt):
        print("NOMOUNT"); sys.exit(0)
    {action}
    for _ in range(100):
        if not os.path.ismount(mnt) and not h.is_alive():
            break
        time.sleep(0.05)
    after = state()
    print("SAME" if after == before else "CHANGED %r -> %r" % (before, after), flush=True)
    r, w = os.pipe()
    os.close(r)
    try:
        os.write(w, b"x")
        print("WROTE")
    except BrokenPipeError:
        print("BROKENPIPE")
""")


def _run(tmp_path, action: str) -> subprocess.CompletedProcess:
    script = tmp_path / "child.py"
    script.write_text(_CHILD.format(root=str(ROOT), action=action), encoding="utf-8")
    env = {**os.environ, "TMPDIR": str(tmp_path)}
    return subprocess.run([sys.executable, str(script)], capture_output=True, text=True,
                          timeout=120, env=env)


def _check(r: subprocess.CompletedProcess) -> None:
    if "NOMOUNT" in r.stdout:
        pytest.skip("FUSE mount did not come up")
    assert r.returncode == 0, f"child died with {r.returncode} (141 = SIGPIPE): {r.stdout}{r.stderr}"
    assert "SAME" in r.stdout, r.stdout
    assert "BROKENPIPE" in r.stdout, r.stdout


@_needs_fuse
def test_happy_an_unmount_keeps_sigpipe_ignored(tmp_path):
    _check(_run(tmp_path, "h.unmount()"))


@_needs_fuse
def test_sad_an_external_unmount_keeps_it_too(tmp_path):
    # The mount ends from outside (fusermount -u), not through axross.
    tool = shutil.which("fusermount3") or shutil.which("fusermount")
    _check(_run(tmp_path, f"import subprocess; subprocess.run([{tool!r}, '-u', mnt])"))


def test_edge_the_helper_restores_what_it_saved(tmp_path):
    # Without any FUSE: saving and restoring is a no-op on the dispositions.
    def masks():
        return [line for line in Path("/proc/self/status").read_text().splitlines()
                if line.startswith(("SigIgn:", "SigCgt:"))]

    before = masks()
    with FM.preserved_signal_dispositions():
        pass
    assert masks() == before
