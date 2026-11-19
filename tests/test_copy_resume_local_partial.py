"""resumable_copy (MCP, scripting) into a local folder: its partial file
has a fixed name, so it is made O_EXCL and never through a symlink -
someone who could write the folder planted ``.<name>.axross-resume.part``
-> a victim file, the copy overwrote that file and put the link in place.
The copy gets the source's mode less the umask (a 0600 key arrived 0644),
and a resume appends only to this user's own partial."""
from __future__ import annotations

import os
import stat

import pytest

from core import copy_resume as CR
from core.local_fs import LocalFS
from core.path_policy import hidden_sibling_name


@pytest.fixture(autouse=True)
def _manifests(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_STATE_HOME", str(tmp_path / "state"))


def _src(tmp_path, mode=0o600, size=3 * CR.MIN_SEGMENT_SIZE):
    src = tmp_path / "id_key"
    src.write_bytes(os.urandom(size))
    os.chmod(src, mode)
    return src


def test_sad_a_planted_link_at_the_partial_name_is_not_followed(tmp_path):
    src = _src(tmp_path)
    out = tmp_path / "shared"
    out.mkdir()
    victim = tmp_path / "victim"
    victim.write_text("keep me")
    part = out / hidden_sibling_name("id_key", ".axross-resume.part")
    os.symlink(victim, part)
    report = CR.resumable_copy(LocalFS(), str(src), LocalFS(), str(out / "id_key"),
                               segment_size=CR.MIN_SEGMENT_SIZE)
    assert report.completed
    assert victim.read_text() == "keep me"
    dst = out / "id_key"
    assert not dst.is_symlink() and dst.read_bytes() == src.read_bytes()


def test_happy_the_copy_has_the_source_mode(tmp_path):
    src = _src(tmp_path, 0o600)
    old = os.umask(0o022)
    try:
        CR.resumable_copy(LocalFS(), str(src), LocalFS(), str(tmp_path / "copy"),
                          segment_size=CR.MIN_SEGMENT_SIZE)
    finally:
        os.umask(old)
    assert stat.S_IMODE(os.stat(tmp_path / "copy").st_mode) == 0o600


def test_sad_a_partial_swapped_for_a_link_before_the_resume_is_refused(tmp_path, monkeypatch):
    src = _src(tmp_path, 0o644)
    dst = tmp_path / "copy"
    calls = {"n": 0}
    real = CR._SourceReader.read

    def fail_once(self, offset, length):
        calls["n"] += 1
        if calls["n"] == 2:
            raise OSError("connection dropped")
        return real(self, offset, length)

    monkeypatch.setattr(CR._SourceReader, "read", fail_once)
    with pytest.raises(OSError):
        CR.resumable_copy(LocalFS(), str(src), LocalFS(), str(dst),
                          segment_size=CR.MIN_SEGMENT_SIZE)
    part = tmp_path / hidden_sibling_name("copy", ".axross-resume.part")
    victim = tmp_path / "victim"
    victim.write_bytes(part.read_bytes())  # same size and content: passes the checks
    part.unlink()
    os.symlink(victim, part)
    try:
        CR.resumable_copy(LocalFS(), str(src), LocalFS(), str(dst),
                          segment_size=CR.MIN_SEGMENT_SIZE)
    except PermissionError:
        assert not dst.exists()  # refused: the partial is not this user's file
    else:  # or started anew: the link removed, a new partial made
        assert not dst.is_symlink() and dst.read_bytes() == src.read_bytes()
    assert victim.stat().st_size == CR.MIN_SEGMENT_SIZE  # nothing appended to it
