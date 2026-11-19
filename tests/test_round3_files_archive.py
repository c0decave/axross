"""Review round 3 (files): archives. Each test names what was measured
before its fix."""

from __future__ import annotations

import gzip
import io
import os
import stat
import sys
import tarfile
import tempfile
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import archive as AR  # noqa: E402

posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX modes")


@pytest.fixture
def private_temp(tmp_path, monkeypatch):
    """tempfile's folder inside tmp_path: what an extraction leaves there is seen."""
    root = tmp_path / "tmp"
    root.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(root))
    yield root
    for dirpath, dirnames, _ in os.walk(tmp_path):
        for d in dirnames:
            try:
                os.chmod(os.path.join(dirpath, d), stat.S_IRWXU)
            except OSError:
                pass


def _rights_are_checked(base) -> bool:
    probe = os.path.join(str(base), "probe")
    os.mkdir(probe, 0o000)
    try:
        os.listdir(probe)
        return False
    except PermissionError:
        return True
    finally:
        os.chmod(probe, 0o700)
        os.rmdir(probe)


def _cancel_on_second_call(calls):
    def progress(done, total, name):
        calls.append((done, total))
        if len(calls) >= 2:
            raise AR.ExtractCancelled("stop")
    return progress


# -- 7z -------------------------------------------------------------------

py7zr = pytest.importorskip("py7zr")


@posix_only
def test_sad_a_7z_folder_stored_0000_is_extracted_whole(tmp_path, private_temp):
    """Measured before: py7zr closed the folder (0000), then set the time of
    the file inside - the extraction failed. Now every member is written by
    axross beneath the target, the stored modes applied at the end."""
    if not _rights_are_checked(tmp_path):
        pytest.skip("this process is let into every folder")
    src = tmp_path / "src"
    (src / "locked").mkdir(parents=True)
    (src / "inside.txt").write_text("inside")
    os.chmod(src / "locked", 0o000)
    archive = tmp_path / "a.7z"
    with py7zr.SevenZipFile(archive, "w") as zf:
        zf.write(src / "locked", "locked")
        zf.write(src / "inside.txt", "locked/inside.txt")
    os.chmod(src / "locked", 0o755)
    out = tmp_path / "out"
    assert AR.extract(str(archive), str(out)) == 1
    assert stat.S_IMODE(os.lstat(out / "locked").st_mode) == 0
    os.chmod(out / "locked", 0o700)
    assert (out / "locked" / "inside.txt").read_text() == "inside"
    assert os.listdir(private_temp) == []


@posix_only
def test_sad_a_7z_member_setuid_bit_is_not_extracted(tmp_path, private_temp):
    src = tmp_path / "tool"
    src.write_bytes(b"#!/bin/sh\n")
    os.chmod(src, 0o4755)
    archive = tmp_path / "a.7z"
    with py7zr.SevenZipFile(archive, "w") as zf:
        zf.write(src, "tool")
    out = tmp_path / "out"
    AR.extract(str(archive), str(out))
    assert not os.lstat(out / "tool").st_mode & (stat.S_ISUID | stat.S_ISGID)


def test_sad_cancel_stops_a_7z_while_its_data_is_written(tmp_path, private_temp, monkeypatch):
    """Measured before: the progress callback ran before and after py7zr's
    extraction only - Cancel waited for the whole archive."""
    monkeypatch.setattr(AR, "POLL_BYTES", 64 * 1024)
    archive = tmp_path / "a.7z"
    with py7zr.SevenZipFile(archive, "w") as zf:
        zf.writestr(os.urandom(1024 * 1024), "big.bin")
    calls: list = []
    out = tmp_path / "out"
    with pytest.raises(AR.ExtractCancelled):
        AR.extract(str(archive), str(out), progress=_cancel_on_second_call(calls))
    assert calls[-1] != (1, 1)  # stopped during the data, not after it
    assert not out.exists()
    assert os.listdir(private_temp) == []


def test_sad_a_damaged_7z_with_a_password_is_not_called_a_wrong_password(tmp_path):
    """Measured before: with a password given, any decoding error read
    "the password does not open the archive" - also for a 7z that needs no
    password, or one cut short before its encrypted part."""
    plain = tmp_path / "plain.7z"
    with py7zr.SevenZipFile(plain, "w") as zf:
        zf.writestr(os.urandom(4096), "a.bin")
    data = bytearray(plain.read_bytes())
    data[40] ^= 0xFF  # inside the packed stream
    plain.write_bytes(bytes(data))
    with pytest.raises(Exception) as info:
        AR.extract(str(plain), str(tmp_path / "out"), password="pw")
    assert not isinstance(info.value, AR.ArchivePasswordRequired)

    cut = tmp_path / "cut.7z"
    with py7zr.SevenZipFile(cut, "w", password="pw") as zf:
        zf.set_encrypted_header(True)
        zf.writestr(b"secret", "a.txt")
    cut.write_bytes(cut.read_bytes()[:20])
    with pytest.raises(Exception) as info:
        AR.extract(str(cut), str(tmp_path / "out2"), password="pw")
    assert not isinstance(info.value, AR.ArchivePasswordRequired)


def test_happy_a_wrong_7z_password_is_still_said(tmp_path):
    archive = tmp_path / "enc.7z"
    with py7zr.SevenZipFile(archive, "w", password="right") as zf:
        zf.set_encrypted_header(True)
        zf.writestr(b"secret", "a.txt")
    with pytest.raises(AR.ArchivePasswordRequired) as info:
        AR.extract(str(archive), str(tmp_path / "out"), password="wrong")
    assert info.value.wrong
    out = tmp_path / "ok"
    assert AR.extract(str(archive), str(out), password="right") == 1
    assert (out / "a.txt").read_bytes() == b"secret"


# -- single compressed file, RAR -------------------------------------------


def test_sad_cancel_stops_a_single_compressed_file(tmp_path, monkeypatch):
    monkeypatch.setattr(AR, "POLL_BYTES", 64 * 1024)
    archive = tmp_path / "big.bin.gz"
    archive.write_bytes(gzip.compress(os.urandom(1024 * 1024)))
    calls: list = []
    out = tmp_path / "out"
    with pytest.raises(AR.ExtractCancelled):
        AR.extract(str(archive), str(out), progress=_cancel_on_second_call(calls))
    assert calls[-1] != (1, 1)
    assert not out.exists()


class _RarInfo:
    def __init__(self, name, data=b"", is_dir=False):
        self.filename = name
        self.data = data
        self.file_size = len(data)
        self.compress_size = len(data)
        self._dir = is_dir
        self.host_os = 3
        self.mode = 0o40755 if is_dir else 0o100644
        self.date_time = (2020, 1, 1, 0, 0, 0)

    def is_dir(self):
        return self._dir

    def is_file(self):
        return not self._dir

    def is_symlink(self):
        return False


def _fake_rar(monkeypatch, infos):
    import types

    class RarFile:
        def __init__(self, _path):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def infolist(self):
            return list(infos)

        def open(self, info, pwd=None):
            return io.BytesIO(info.data)

    fake = types.ModuleType("rarfile")
    fake.RarFile = RarFile
    fake.RarCannotExec = type("RarCannotExec", (Exception,), {})
    fake.RarExecError = type("RarExecError", (Exception,), {})
    fake.RAR_OS_UNIX = 3
    monkeypatch.setattr(AR, "rarfile", fake)
    monkeypatch.setattr(AR, "RAR_AVAILABLE", True)


def test_sad_cancel_stops_a_rar_while_its_data_is_written(tmp_path, private_temp, monkeypatch):
    monkeypatch.setattr(AR, "POLL_BYTES", 64 * 1024)
    _fake_rar(monkeypatch, [_RarInfo("d", is_dir=True),
                            _RarInfo("d/big.bin", os.urandom(1024 * 1024))])
    archive = tmp_path / "a.rar"
    archive.write_bytes(b"stub")
    calls: list = []
    out = tmp_path / "out"
    with pytest.raises(AR.ExtractCancelled):
        AR.extract(str(archive), str(out), progress=_cancel_on_second_call(calls))
    assert calls[-1] != (1, 1)
    assert not out.exists()
    assert os.listdir(private_temp) == []


def test_happy_a_rar_is_written_beneath_the_target(tmp_path, private_temp, monkeypatch):
    _fake_rar(monkeypatch, [_RarInfo("d", is_dir=True), _RarInfo("d/a.txt", b"hello")])
    archive = tmp_path / "a.rar"
    archive.write_bytes(b"stub")
    out = tmp_path / "out"
    assert AR.extract(str(archive), str(out)) == 1
    assert (out / "d" / "a.txt").read_bytes() == b"hello"
    assert os.listdir(private_temp) == []


# -- ZIP and tar ------------------------------------------------------------


def test_sad_a_zip_folder_entry_ending_in_a_backslash_is_a_folder(tmp_path):
    """Measured before: "docs\\" (a Windows tool's folder entry) became an
    empty file "docs", and "docs\\a.txt" then failed the extraction."""
    archive = tmp_path / "win.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(zipfile.ZipInfo("docs\\"), b"")
        zf.writestr("docs\\a.txt", b"hello")
    out = tmp_path / "out"
    assert AR.extract(str(archive), str(out)) == 1
    assert (out / "docs").is_dir()
    assert (out / "docs" / "a.txt").read_bytes() == b"hello"
    entries = {e.name: e.is_dir for e in AR.list_archive(str(archive))}
    assert entries["docs\\"] is True


def test_sad_a_repeated_tar_member_takes_the_last_one(tmp_path):
    """Measured before: a tar that holds a file twice (an appended update,
    ``tar -r``) was refused whole. tar keeps the last one; so does axross."""
    archive = tmp_path / "upd.tar"
    with tarfile.open(archive, "w") as tf:
        for data in (b"old", b"new!"):
            info = tarfile.TarInfo("a.txt")
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))
        info = tarfile.TarInfo("b.txt")
        info.size = 1
        tf.addfile(info, io.BytesIO(b"b"))
    out = tmp_path / "out"
    assert AR.extract(str(archive), str(out)) == 2
    assert (out / "a.txt").read_bytes() == b"new!"
    out2 = tmp_path / "out2"
    AR.extract_members(str(archive), str(out2), ["a.txt"])
    assert (out2 / "a.txt").read_bytes() == b"new!"


@posix_only
def test_sad_extract_selected_folder_keeps_its_folders(tmp_path):
    """Measured before: Extract Selected on a folder handed over its files
    only - an empty subfolder was missing and the folders' stored modes
    were lost."""
    from PyQt6.QtWidgets import QApplication, QTreeView

    from ui.archive_pane import build_archive_tree, selected_member_names

    app = QApplication.instance() or QApplication([])  # noqa: F841 - kept alive
    archive = tmp_path / "a.tar"
    with tarfile.open(archive, "w") as tf:
        for name, mode in (("./d/", 0o700), ("./d/empty/", 0o750)):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = mode
            tf.addfile(info)
        info = tarfile.TarInfo("./d/a.txt")
        info.size = 1
        tf.addfile(info, io.BytesIO(b"a"))
    model = build_archive_tree(AR.list_archive(str(archive)))
    view = QTreeView()
    view.setModel(model)
    d = model.item(0, 0)
    sel = view.selectionModel()
    sel.select(d.index(), sel.SelectionFlag.ClearAndSelect | sel.SelectionFlag.Rows)
    members = selected_member_names(view)
    out = tmp_path / "out"
    AR.extract_members(str(archive), str(out), members)
    assert (out / "d" / "empty").is_dir()
    assert stat.S_IMODE(os.lstat(out / "d").st_mode) == 0o700 & ~_umask()
    assert (out / "d" / "a.txt").read_bytes() == b"a"


def _umask() -> int:
    old = os.umask(0)
    os.umask(old)
    return old


@pytest.mark.parametrize("name", ["CON", "nul.txt", "d/COM1.log", "Lpt9", "a.txt:secret",
                                  "trail.", "space "])
def test_sad_windows_names_are_refused_where_windows_rules_apply(tmp_path, monkeypatch, name):
    """Measured before: "NUL", "COM1.log" or "a.txt:stream" were handed to the
    file system - on Windows (or a share of it) the device or a hidden
    stream of another file, never the member."""
    archive = tmp_path / "w.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr(name, b"x")
    monkeypatch.setattr(AR, "windows_names_apply", lambda path: True)
    with pytest.raises(AR.UnsafeArchive, match="Windows"):
        AR.extract(str(archive), str(tmp_path / "out"))
    assert not (tmp_path / "out").exists()


def test_happy_windows_like_names_extract_where_windows_rules_do_not_apply(tmp_path, monkeypatch):
    archive = tmp_path / "w.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        zf.writestr("CONTRACT.txt", b"x")
        zf.writestr("console.log", b"y")
    monkeypatch.setattr(AR, "windows_names_apply", lambda path: True)
    assert AR.extract(str(archive), str(tmp_path / "out")) == 2


def test_happy_windows_rules_follow_the_target_file_system(monkeypatch):
    monkeypatch.setattr(AR.sys, "platform", "linux")
    from core import tmpfs_detect

    monkeypatch.setattr(tmpfs_detect, "fs_type", lambda path: "cifs")
    assert AR.windows_names_apply("/mnt/share/x")
    monkeypatch.setattr(tmpfs_detect, "fs_type", lambda path: "ext4")
    assert not AR.windows_names_apply("/home/x")
    monkeypatch.setattr(AR.sys, "platform", "win32")
    assert AR.windows_names_apply("C:/x")
