"""An encrypted archive opens with its password: a 7z (data, or data and
names encrypted) and ZIP members encrypted with ZipCrypto. Without the
password, or with a wrong one, ArchivePasswordRequired says which
(``wrong``) and nothing is left; the pane and the archive view ask for it
and try again. An AES ZIP member is named as such."""
from __future__ import annotations

import os
import struct
import sys
import zlib
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from core import archive as AR  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _crc_step(crc: int, byte: int) -> int:
    return ~zlib.crc32(bytes([byte]), ~crc & 0xFFFFFFFF) & 0xFFFFFFFF


def _zipcrypto(data: bytes, password: bytes, check: int) -> bytes:
    keys = [0x12345678, 0x23456789, 0x34567890]

    def update(c: int) -> None:
        keys[0] = _crc_step(keys[0], c)
        keys[1] = ((keys[1] + (keys[0] & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF
        keys[2] = _crc_step(keys[2], keys[1] >> 24)

    for c in password:
        update(c)
    out = bytearray()
    for p in bytes(range(11)) + bytes([check]) + data:
        t = (keys[2] | 2) & 0xFFFF
        out.append(p ^ (((t * (t ^ 1)) >> 8) & 0xFF))
        update(p)
    return bytes(out)


def _encrypted_zip(path: Path, members: dict[str, bytes], password: bytes,
                   method: int = 0) -> Path:
    """A ZIP of stored *members* encrypted with ZipCrypto (*method* 99
    marks them AES instead) - the standard library cannot write one."""
    local, central = bytearray(), bytearray()
    for name, data in members.items():
        crc = zlib.crc32(data)
        body = _zipcrypto(data, password, crc >> 24)
        raw = name.encode()
        hdr = struct.pack("<IHHHHHIIIHH", 0x04034B50, 20, 1, method, 0, 0x21, crc,
                          len(body), len(data), len(raw), 0)
        offset = len(local)
        local += hdr + raw + body
        central += struct.pack("<IHHHHHHIIIHHHHHII", 0x02014B50, 20, 20, 1, method, 0, 0x21,
                               crc, len(body), len(data), len(raw), 0, 0, 0, 0, 0,
                               offset) + raw
    eocd = struct.pack("<IHHHHIIH", 0x06054B50, 0, 0, len(members), len(members),
                       len(central), len(local), 0)
    path.write_bytes(bytes(local + central + eocd))
    return path


def _seven_zip(tmp_path, names_encrypted: bool) -> str:
    pytest.importorskip("py7zr")
    from core import packer as PK

    src = tmp_path / "src"
    src.mkdir()
    (src / "a.txt").write_text("secret")
    return PK.pack(LocalFS(), str(src), ["a.txt"], "x", PK.PackOptions(
        fmt="7z", password="pw", encrypt_names=names_encrypted)).path


# -- core -------------------------------------------------------------------


@pytest.mark.parametrize("names_encrypted", [False, True])
def test_a_7z_opens_with_its_password(tmp_path, names_encrypted):
    archive = _seven_zip(tmp_path, names_encrypted)
    assert AR.archive_needs_password(archive)
    out = tmp_path / "out"
    with pytest.raises(AR.ArchivePasswordRequired) as info:
        AR.extract(archive, str(out), password="wrong")
    assert info.value.wrong and not out.exists()
    assert [e.name for e in AR.list_archive(archive, password="pw")] == ["a.txt"]
    assert int(AR.extract(archive, str(out), password="pw")) == 1
    assert (out / "a.txt").read_text() == "secret"


def test_a_header_encrypted_7z_with_a_wrong_password_is_named_so(tmp_path):
    archive = _seven_zip(tmp_path, True)
    with pytest.raises(AR.ArchivePasswordRequired) as info:
        AR.list_archive(archive, password="wrong")
    assert info.value.wrong


def test_zipcrypto_members_open_with_the_password(tmp_path):
    archive = _encrypted_zip(tmp_path / "e.zip", {"a.txt": b"hello", "d/b.txt": b"world"},
                             b"pw")
    assert AR.archive_needs_password(str(archive))
    out = tmp_path / "out"
    with pytest.raises(AR.ArchivePasswordRequired) as info:
        AR.extract(str(archive), str(out))
    assert not info.value.wrong and not out.exists()
    with pytest.raises(AR.ArchivePasswordRequired) as info:
        AR.extract(str(archive), str(out), password="nope")
    assert info.value.wrong and not out.exists()
    assert int(AR.extract(str(archive), str(out), password="pw")) == 2
    assert (out / "d" / "b.txt").read_bytes() == b"world"
    part = tmp_path / "part"
    AR.extract_members(str(archive), str(part), ["a.txt"], password="pw")
    assert (part / "a.txt").read_bytes() == b"hello"


def test_an_aes_zip_member_is_named(tmp_path):
    archive = _encrypted_zip(tmp_path / "aes.zip", {"a.txt": b"x"}, b"pw", method=99)
    assert not AR.archive_needs_password(str(archive))
    with pytest.raises(OSError, match="AES"):
        AR.extract(str(archive), str(tmp_path / "out"), password="pw")


def test_a_plain_archive_needs_no_password(tmp_path):
    import zipfile

    with zipfile.ZipFile(tmp_path / "p.zip", "w") as zf:
        zf.writestr("a", "b")
    assert not AR.archive_needs_password(str(tmp_path / "p.zip"))


def test_the_password_is_not_logged(tmp_path, caplog):
    archive = _seven_zip(tmp_path, True)
    caplog.set_level("DEBUG")
    with pytest.raises(AR.ArchivePasswordRequired):
        AR.extract(archive, str(tmp_path / "o"), password="Hunter2-unique")
    assert "Hunter2-unique" not in caplog.text


# -- UI ---------------------------------------------------------------------


@pytest.fixture
def app():
    pytest.importorskip("PyQt6.QtWidgets")
    from PyQt6.QtWidgets import QApplication

    return QApplication.instance() or QApplication([])


def test_the_pane_asks_for_the_password_and_again_when_wrong(app, tmp_path):
    from PyQt6.QtWidgets import QMessageBox

    from models.file_item import FileItem
    from ui.file_pane import FilePaneWidget

    archive = _encrypted_zip(tmp_path / "e.zip", {"a.txt": b"hello"}, b"pw")
    answers = iter(["wrong", "pw"])
    asked = []

    def ask(_parent, name, *, wrong=False):
        asked.append((name, wrong))
        return next(answers)

    pane = FilePaneWidget(LocalFS())
    pane.navigate(str(tmp_path))
    try:
        with mock.patch("ui.archive_password.ask_archive_password", ask), \
                mock.patch.object(QMessageBox, "information"), \
                mock.patch.object(QMessageBox, "warning") as warned:
            pane._extract_archive(FileItem(name="e.zip", size=archive.stat().st_size))
    finally:
        pane.shutdown()
        pane.deleteLater()
    assert asked == [("e.zip", False), ("e.zip", True)]
    assert not warned.called
    assert (tmp_path / "e" / "a.txt").read_bytes() == b"hello"


def test_the_archive_view_lists_a_header_encrypted_7z_after_asking(app, tmp_path):
    from ui.archive_pane import ArchivePaneWidget

    archive = _seven_zip(tmp_path, True)
    got = []
    with mock.patch("ui.archive_password.ask_archive_password", lambda *a, **k: "pw"):
        pane = ArchivePaneWidget(archive)
        pane.password_entered.connect(got.append)
        # the constructor listed (and asked) before the signal was connected
    try:
        assert pane.load_error is None
        assert [e.name for e in pane._entries] == ["a.txt"]
    finally:
        pane.deleteLater()
