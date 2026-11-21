"""A batch of SFTP uploads is hashed with one remote command, not one per file.

Measured before: the integrity check after every upload ran its own
``sha256sum -- <file>`` on the server - an SSH channel, an exec and its
output per file; against a server that has sha256sum that cost more than
the upload of a small file itself. Now the temp files of a batch (up to
64) are hashed with one ``sha256sum -- f1 f2 ...`` (``checksum_many``),
every name quoted, the command line bounded and split when longer. Its
output is parsed strictly - a name with blanks, a newline, a backslash or
bytes that are no UTF-8 is found again (GNU marks escaped names with a
leading backslash) - and a file without a clear line is asked on its own,
as before. A server without sha256sum, or without commands, is asked once.
"""

from __future__ import annotations

import hashlib
import os
import sys
import time
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from core.exec_util import digests_from_sum_output  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

APP = QApplication.instance() or QApplication([])

#: Names a batch must find again in sha256sum's output.
ODD_NAMES = [
    "plain.txt",
    "with blank.txt",
    "two  blanks",
    "new\nline.txt",
    "back\\slash.txt",
    "cr\rreturn.txt",
    "-leading-dash",
    "quote's \"both\"",
    "$(touch pwned)`id`;x",
    "tab\tname",
    os.fsdecode(b"latin1-\xe9\xff.bin"),
    "unicode-é中.txt",
    "*star",
]


# -- the parser ----------------------------------------------------------------------------


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_happy_escaped_and_plain_lines_map_to_their_names():
    a, b, c = _digest(b"a"), _digest(b"b"), _digest(b"c")
    output = (f"{a}  /d/with blank\n".encode()
              + b"\\" + f"{b}  /d/new\\nline\\\\x\n".encode()
              + f"{c} */d/".encode() + b"\xff\xfe\n")
    names = [b"/d/with blank", b"/d/new\nline\\x", b"/d/\xff\xfe"]
    assert digests_from_sum_output(output, names, "sha256") == {
        b"/d/with blank": a, b"/d/new\nline\\x": b, b"/d/\xff\xfe": c}


def test_sad_garbled_or_ambiguous_lines_count_for_no_file():
    a, b = _digest(b"a"), _digest(b"b")
    names = [b"/d/a", b"/d/a\nb", b"/d/bad", b"/d/short", b"/d/odd", b"/d/missing"]
    output = b"".join([
        # busybox does not escape: "a\nb" comes as two lines, the first
        # claiming the name of another operand - neither may count
        f"{a}  /d/a\n".encode(), f"{b}  /d/a\n".encode(), b"b\n",
        b"\\" + f"{a}  /d/bad\\t\n".encode(),          # an escape GNU never writes
        f"{a[:-1]}  /d/short\n".encode(),              # a digest one digit short
        f"{'g' * 64}  /d/odd\n".encode(),              # no hex
        b"sha256sum: /d/missing: No such file or directory\n",
    ])
    assert digests_from_sum_output(output, names, "sha256") == {}


def test_edge_a_name_not_asked_for_is_ignored():
    a = _digest(b"a")
    out = f"{a}  /d/other\n{a}  /d/mine\n".encode()
    assert digests_from_sum_output(out, [b"/d/mine"], "sha256") == {b"/d/mine": a}


# -- against the test server ----------------------------------------------------------------


@pytest.fixture
def server(tmp_path, monkeypatch):
    from tests import sftp_testkit
    from core.profiles import ConnectionProfile
    from core.ssh_client import SSHSession

    home = tmp_path / "home"
    (home / ".ssh").mkdir(parents=True)
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    made = []

    def connect(**kwargs):
        with mock.patch("pathlib.Path.home", return_value=home):
            srv = sftp_testkit.SftpServer("/", commands=True, **kwargs)
            session = SSHSession(ConnectionProfile(
                name="t", protocol="sftp", host="127.0.0.1", port=srv.port, username="u"))
            session.connect(password="x", on_unknown_host=lambda _e: True)
        made.append((srv, session))
        return srv, session

    yield connect
    for srv, session in made:
        session.disconnect()
        srv.close()


def _odd_files(folder: Path, *, controls: bool = True) -> list[Path]:
    """The ODD_NAMES files in *folder*; without *controls* none with a
    control character (a copy refuses such a name: "name not usable")."""
    folder.mkdir(parents=True)
    paths = []
    for i, name in enumerate(ODD_NAMES):
        if not controls and any(ord(c) < 32 for c in name):
            continue
        path = folder / name
        path.write_bytes(f"content {i} of {name!r}".encode("utf-8", "surrogateescape"))
        paths.append(path)
    return paths


def test_happy_one_command_hashes_every_odd_name(server, tmp_path):
    srv, session = server()
    paths = _odd_files(tmp_path / "odd")
    got = session.checksum_many([str(p) for p in paths])
    assert got == {str(p): "sha256:" + _digest(p.read_bytes()) for p in paths}
    assert srv.stats["exec"] == 1
    assert not (tmp_path / "odd" / "pwned").exists() and not Path("pwned").exists()


def test_edge_a_long_batch_is_split_with_the_command_line_bounded(server, tmp_path):
    srv, session = server()
    paths = _odd_files(tmp_path / ("long-" + "n" * 120))
    session.CHECKSUM_COMMAND_MAX = 700
    got = session.checksum_many([str(p) for p in paths])
    assert len(got) == len(paths)
    assert srv.stats["exec"] > 1
    assert all(len(c) <= 700 for c in srv.commands_run), [len(c) for c in srv.commands_run]
    session.CHECKSUM_FILES_MAX = 4
    srv.commands_run.clear()
    assert len(session.checksum_many([str(p) for p in paths])) == len(paths)
    assert len(srv.commands_run) >= (len(paths) + 3) // 4


def _upload(session, src: Path, dst: Path):
    from core.transfer_manager import TransferManager

    mgr = TransferManager(max_parallel=1)
    done: dict = {}
    mgr.transfer_files_in_background(LocalFS(), session, [str(src)], str(dst),
                                     on_done=lambda jobs: done.setdefault("jobs", jobs))
    end = time.monotonic() + 60
    while time.monotonic() < end and ("jobs" not in done or mgr.unfinished()):
        APP.processEvents()
        time.sleep(0.005)
    APP.processEvents()
    mgr.shutdown()
    return done.get("jobs", [])


def _tree(root: Path, count: int) -> None:
    root.mkdir(parents=True)
    for i in range(count):
        (root / f"f{i:03}.txt").write_text(f"file {i}")


def test_happy_a_batch_of_uploads_is_checked_with_one_command(server, tmp_path):
    """100 small uploads: before, 100 remote commands; now one per batch of 64."""
    from core.transfer_worker import TransferStatus

    srv, session = server()
    _tree(tmp_path / "src" / "many", 100)
    (tmp_path / "dst").mkdir()
    jobs = _upload(session, tmp_path / "src" / "many", tmp_path / "dst")
    assert len(jobs) == 100
    assert all(j.status is TransferStatus.DONE and j.integrity_compared for j in jobs), \
        [(j.filename, j.status, j.error_message) for j in jobs if not j.integrity_compared][:3]
    assert srv.stats["exec"] == 2, srv.commands_run


def test_happy_odd_names_are_uploaded_and_checked_in_a_batch(server, tmp_path):
    from core.transfer_worker import TransferStatus

    from core.path_policy import transfer_leaf

    srv, session = server()
    paths = _odd_files(tmp_path / "src" / "odd", controls=False)
    (tmp_path / "dst").mkdir()
    jobs = _upload(session, tmp_path / "src" / "odd", tmp_path / "dst")
    assert {j.filename for j in jobs} == {p.name for p in paths}

    def usable(name: str) -> bool:
        try:
            transfer_leaf(LocalFS(), session, name)
            return True
        except ValueError:
            return False

    # A name the copy refuses on its own (a backslash: core.path_policy)
    # is a failed row before any batch; the rest is hashed in one go.
    paths = [p for p in paths if usable(p.name)]
    assert len(paths) >= 9
    jobs = [j for j in jobs if usable(j.filename)]
    for job in jobs:
        assert job.status is TransferStatus.DONE and job.integrity_compared, job.filename
    for p in paths:
        assert (tmp_path / "dst" / "odd" / p.name).read_bytes() == p.read_bytes()
    assert srv.stats["exec"] == 1


def test_sad_a_wrong_hash_fails_that_file_only(server, tmp_path):
    from core.ssh_client import SSHSession
    from core.transfer_worker import TransferStatus

    srv, session = server()
    _tree(tmp_path / "src" / "few", 5)
    (tmp_path / "dst").mkdir()
    real = SSHSession.checksum_many

    def one_corrupt(self, paths, algorithm="sha256"):
        got = real(self, paths, algorithm)
        for path in got:
            if "f002" in path:
                got[path] = "sha256:" + "0" * 64
        return got

    with mock.patch.object(SSHSession, "checksum_many", one_corrupt):
        jobs = {j.filename: j for j in _upload(session, tmp_path / "src" / "few",
                                               tmp_path / "dst")}
    bad = jobs.pop("f002.txt")
    assert bad.status is TransferStatus.ERROR and "Integrity FAIL" in bad.error_message
    assert not (tmp_path / "dst" / "few" / "f002.txt").exists()
    assert all(j.status is TransferStatus.DONE and j.integrity_compared for j in jobs.values())
    assert [p for p in (tmp_path / "dst").rglob("*") if ".part-" in p.name] == []


def test_sad_a_file_missing_from_the_answer_is_asked_on_its_own(server, tmp_path):
    from core.ssh_client import SSHSession
    from core.transfer_worker import TransferStatus

    srv, session = server()
    _tree(tmp_path / "src" / "few", 5)
    (tmp_path / "dst").mkdir()
    real = SSHSession.checksum_many

    def one_missing(self, paths, algorithm="sha256"):
        return {p: v for p, v in real(self, paths, algorithm).items() if "f003" not in p}

    with mock.patch.object(SSHSession, "checksum_many", one_missing):
        jobs = _upload(session, tmp_path / "src" / "few", tmp_path / "dst")
    assert all(j.status is TransferStatus.DONE and j.integrity_compared for j in jobs)
    assert srv.stats["exec"] == 2  # the batch, then that one file
    assert "f003" in srv.commands_run[-1].decode()


def test_edge_a_server_without_sha256sum_is_asked_once(server, tmp_path):
    from core.transfer_worker import TransferStatus

    srv, session = server(command_env={"PATH": "/nonexistent"})
    _tree(tmp_path / "src" / "many", 70)
    (tmp_path / "dst").mkdir()
    jobs = _upload(session, tmp_path / "src" / "many", tmp_path / "dst")
    assert all(j.status is TransferStatus.DONE for j in jobs)
    assert not any(j.integrity_compared for j in jobs)  # nothing to compare with
    assert srv.stats["exec"] == 1  # "missing" is remembered


def test_happy_sftp_to_sftp_hashes_both_sides_per_batch(server, tmp_path):
    from core.transfer_manager import TransferManager
    from core.transfer_worker import TransferDirection, TransferStatus

    srv, session = server()
    _tree(tmp_path / "src" / "many", 50)
    (tmp_path / "dst").mkdir()
    mgr = TransferManager(max_parallel=1)
    done: dict = {}
    mgr.transfer_files_in_background(session, session, [str(tmp_path / "src" / "many")],
                                     str(tmp_path / "dst"), TransferDirection.RELAY,
                                     on_done=lambda jobs: done.setdefault("jobs", jobs))
    end = time.monotonic() + 60
    while time.monotonic() < end and ("jobs" not in done or mgr.unfinished()):
        APP.processEvents()
        time.sleep(0.005)
    mgr.shutdown()
    assert all(j.status is TransferStatus.DONE and j.integrity_compared for j in done["jobs"])
    assert srv.stats["exec"] == 2  # the sources, then the uploads
