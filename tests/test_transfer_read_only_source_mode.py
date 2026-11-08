"""Copying a 0400 or 0500 file works for a user who is not root.

``_precreate_private_temp`` created the temp file with the source's exact
mode, without the owner-write bit that ``core.atomic_io`` adds for this
case (``_OWNER_WRITE``). The ``open_write(temp, "wb")`` that follows then
got EACCES: F5 on an AWS-style ``key.pem`` (mode 0400) failed with
"Permission denied" for every user but root. The temp file is now created
with ``mode | 0o200``, written, and given the source's mode after.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from core.local_fs import LocalFS
from core.transfer_worker import TransferJob, TransferStatus, TransferWorker

ROOT = Path(__file__).resolve().parents[1]
KEY = b"stand-in for a key file\n"


class _NotRoot(LocalFS):
    """LocalFS that refuses to open a file for writing without its owner
    write bit, as the kernel does for a user without CAP_DAC_OVERRIDE (the
    tests may run as root). Records the mode of the file while data goes in."""

    def __init__(self) -> None:
        super().__init__()
        self.modes_while_writing: list[int] = []

    def open_write(self, path, append=False):
        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
        except FileNotFoundError:
            mode = None
        if mode is not None and not mode & stat.S_IWUSR:
            raise PermissionError(13, "Permission denied", path)
        f = super().open_write(path, append)
        self.modes_while_writing.append(stat.S_IMODE(os.stat(path).st_mode))
        return f


def _copy(tmp_path: Path, mode: int, dest_backend) -> tuple[TransferJob, Path]:
    src = tmp_path / "key.pem"
    src.write_bytes(KEY)
    src.chmod(mode)
    (tmp_path / "out").mkdir()
    dst = tmp_path / "out" / "key.pem"
    job = TransferJob(source_path=str(src), dest_path=str(dst), filename="key.pem",
                      total_bytes=len(KEY), source_mode=mode)
    job.source_backend = LocalFS()
    job.dest_backend = dest_backend
    TransferWorker()._process_job(job)
    return job, dst


@pytest.mark.parametrize("mode", [0o400, 0o500, 0o440])
def test_happy_a_file_without_owner_write_copies_with_its_mode(tmp_path, mode):
    job, dst = _copy(tmp_path, mode, _NotRoot())
    assert job.status == TransferStatus.DONE, job.error_message
    assert dst.read_bytes() == KEY
    assert stat.S_IMODE(dst.stat().st_mode) == mode
    assert os.listdir(dst.parent) == ["key.pem"]


def test_edge_the_temp_file_is_private_while_the_data_goes_in(tmp_path):
    backend = _NotRoot()
    job, dst = _copy(tmp_path, 0o400, backend)
    assert job.status == TransferStatus.DONE, job.error_message
    # When the data goes in (the last open), only the owner can read it.
    assert backend.modes_while_writing[-1] == 0o600
    assert stat.S_IMODE(dst.stat().st_mode) == 0o400


def test_happy_a_0600_file_keeps_its_mode_from_the_first_byte(tmp_path):
    backend = _NotRoot()
    job, dst = _copy(tmp_path, 0o600, backend)
    assert job.status == TransferStatus.DONE, job.error_message
    assert stat.S_IMODE(dst.stat().st_mode) == 0o600
    assert backend.modes_while_writing[-1] == 0o600


_SCRIPT = """
import os, sys
sys.path.insert(0, sys.argv[1])
from core.local_fs import LocalFS
from core.transfer_worker import TransferJob, TransferWorker
src, dst = sys.argv[2], sys.argv[3]
job = TransferJob(source_path=src, dest_path=dst, filename="key.pem",
                  total_bytes=os.path.getsize(src), source_mode=0o400)
job.source_backend = job.dest_backend = LocalFS()
TransferWorker()._process_job(job)
print(job.status.value, job.error_message)
"""


def test_sad_a_0400_file_copies_for_a_real_user_without_dac_override(tmp_path):
    """The real kernel check: as a non-root user directly, as root with
    CAP_DAC_OVERRIDE dropped (setpriv)."""
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        setpriv = shutil.which("setpriv")
        if setpriv is None:
            pytest.skip("root without setpriv: cannot drop CAP_DAC_OVERRIDE")
        prefix = [setpriv, "--inh-caps=-dac_override", "--bounding-set=-dac_override"]
    else:
        prefix = []
    src = tmp_path / "key.pem"
    src.write_bytes(KEY)
    src.chmod(0o400)
    (tmp_path / "out").mkdir()
    dst = tmp_path / "out" / "key.pem"
    result = subprocess.run(
        [*prefix, sys.executable, "-c", _SCRIPT, str(ROOT), str(src), str(dst)],
        capture_output=True, text=True, timeout=120,
    )
    if prefix and result.returncode != 0 and "setpriv" in result.stderr:
        pytest.skip(f"setpriv cannot drop the capability here: {result.stderr.strip()}")
    assert result.stdout.strip().startswith("done"), result.stdout + result.stderr
    assert dst.read_bytes() == KEY
    assert stat.S_IMODE(dst.stat().st_mode) == 0o400
