"""A path the FTP server does not have is reported missing, not as an empty file.

Measured against test.rebex.net and ftp.gnu.org (vsftpd): for a missing
path MLST, SIZE, MDTM and CWD all answered 550, yet ``stat()`` returned a
0-byte file dated 1970 - it ignored every refusal and had no way to say
"not there". vsftpd also answers NLST of a missing folder with an empty
listing (150/226), so ``list_dir()`` showed a typo'd path as an empty
folder. Now ``stat()`` raises FileNotFoundError when no probe finds the
path and the parent's listing does not name it; an empty fallback
listing is checked with CWD.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import ftp_client as FC  # noqa: E402
from tests.test_ftp_symlink_delete import _DirFtpServer  # noqa: E402


def _tree(tmp_path: Path) -> Path:
    root = tmp_path / "srv"
    (root / "pub" / "empty").mkdir(parents=True)
    (root / "pub" / "readme.txt").write_text("hello\n")
    return root


@pytest.fixture
def connect(tmp_path):
    made: list[tuple[_DirFtpServer, FC.FtpSession]] = []

    def make(**server_kw):
        srv = _DirFtpServer(_tree(tmp_path), **server_kw)
        s = FC.FtpSession("127.0.0.1", srv.port, "u", "p")
        made.append((srv, s))
        return srv, s

    yield make
    for srv, s in made:
        s.disconnect()
        srv.close()


# --- happy ----------------------------------------------------------------


@pytest.mark.parametrize("mlsd", ["none", "follow"])
def test_happy_stat_finds_a_file_and_a_folder(connect, mlsd):
    _srv, s = connect(mlsd=mlsd)
    f = s.stat("/pub/readme.txt")
    assert (f.name, f.size, f.is_dir) == ("readme.txt", 6, False)
    assert s.stat("/pub/empty").is_dir


def test_happy_an_existing_empty_folder_lists_empty(connect):
    _srv, s = connect(missing_listing="empty")
    assert s.list_dir("/pub/empty") == []


# --- sad ------------------------------------------------------------------


@pytest.mark.parametrize("mlsd", ["none", "follow"])
def test_sad_stat_of_a_missing_path_raises(connect, mlsd):
    _srv, s = connect(mlsd=mlsd)
    with pytest.raises(FileNotFoundError):
        s.stat("/pub/no-such-file")


def test_sad_a_missing_folder_is_not_listed_as_empty(connect):
    _srv, s = connect(missing_listing="empty")  # vsftpd
    with pytest.raises(FileNotFoundError):
        s.list_dir("/pub/no-such-folder")


# --- edge -----------------------------------------------------------------


def test_edge_a_file_whose_size_is_refused_is_still_found(connect):
    # SIZE refused (binary mode only) and no MDTM: only the parent's
    # listing can tell the file is there.
    _srv, s = connect(size=False, mdtm=False)
    f = s.stat("/pub/readme.txt")
    assert f.name == "readme.txt" and not f.is_dir


def test_edge_the_root_is_always_there(connect):
    _srv, s = connect()
    assert s.stat("/").is_dir
    assert os.path.basename("/") == ""  # the root has no parent to ask


# --- a name the server's encoding cannot carry ------------------------------
# Lab (pure-ftpd without UTF-8): uploading "Grüße ü 名前 space.txt" was
# refused as "target already exists". OPTS UTF8 was refused, so ftplib
# encodes commands as latin-1; "名前" raised UnicodeEncodeError - a
# ValueError - which exists() and stat() took for "a 213 reply ftplib
# cannot parse", i.e. the file is there.


def test_sad_a_name_latin1_cannot_carry_is_an_error_not_a_file(connect):
    _srv, s = connect(utf8=False)
    for call in (s.exists, s.stat):
        with pytest.raises(OSError, match="cannot be encoded") as err:
            call("/pub/名前.txt")
        assert not isinstance(err.value, FileNotFoundError)


def test_edge_a_latin1_name_still_works_without_utf8(connect, tmp_path):
    srv, s = connect(utf8=False)
    assert not s.exists("/pub/Grüße.txt")
    with pytest.raises(FileNotFoundError):
        s.stat("/pub/Grüße.txt")
