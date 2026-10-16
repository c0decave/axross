"""``SmbSession.shares_list`` keeps the password off the command line.

docs/SECURITY-REVIEW-2026-10.md C-5: the share listing ran
``smbclient -L //host -g -U user%password``. A process's argv is world
readable (``/proc/<pid>/cmdline``, ``ps``); smbclient's own man page says
its scrubbing of the process title "is after startup and so is subject to
a race". The password now travels in the child's ``PASSWD`` environment
variable (smbclient(1): "the tool will check the PASSWD environment
variable"), which only the same user (and root) can read.

Driven end to end through a stand-in ``smbclient`` executable that records
its argv and environment.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import textwrap
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

SC = pytest.importorskip("core.smb_client")

SECRET = "s3cr%t pass"


@pytest.fixture
def fake_smbclient(tmp_path, monkeypatch):
    record = tmp_path / "record.json"
    script = tmp_path / "bin" / "smbclient"
    script.parent.mkdir()
    script.write_text(
        textwrap.dedent(
            f"""\
            #!{sys.executable}
            import json, os, sys
            with open({str(record)!r}, "w") as fh:
                json.dump({{"argv": sys.argv[1:], "passwd": os.environ.get("PASSWD")}}, fh)
            print("Disk|public|Public share")
            print("IPC|IPC$|IPC Service")
            """
        )
    )
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{script.parent}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.delenv("PASSWD", raising=False)
    return lambda: json.loads(record.read_text())


def test_happy_password_is_not_in_argv(fake_smbclient):
    shares = SC.SmbSession.shares_list("fileserver", username="alice", password=SECRET)
    assert [s["name"] for s in shares] == ["public", "IPC$"]
    seen = fake_smbclient()
    assert not any(SECRET in a or "s3cr" in a for a in seen["argv"]), seen["argv"]
    assert seen["passwd"] == SECRET
    assert seen["argv"][-2:] == ["-U", "alice"]


def test_sad_username_with_percent_is_refused(fake_smbclient):
    # smbclient splits "-U user%pass" itself: a "%" in the user name would
    # put the rest of it on the command line as a password again.
    with pytest.raises(ValueError):
        SC.SmbSession.shares_list("fileserver", username="al%ice", password=SECRET)


def test_edge_anonymous_listing_sets_no_password(fake_smbclient):
    SC.SmbSession.shares_list("fileserver")
    seen = fake_smbclient()
    assert "-N" in seen["argv"]
    assert seen["passwd"] is None
