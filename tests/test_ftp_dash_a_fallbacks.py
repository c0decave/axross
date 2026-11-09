"""The ``LIST -a`` / ``NLST -a`` fallbacks of FTP listings without MLSD.

* A server that does not take the option may answer it with a 4xx:
  wu-ftpd and ProFTPD say "450 No files found" for the path "-a ..." that
  matches nothing. Only 5xx fell back to the plain command, so list_dir
  and exists() failed on such a server. A 4xx on the ``-a`` variant now
  falls back too (except 421, which closes the connection); a 4xx on the
  plain command is still raised.
* NLST -a was taken for "the server read -a as part of the path" as soon
  as one name began with "-a" - so one file named "-archive.tar" made
  the dot files vanish again. The plain NLST now decides: names it lists
  too are real entries and the ``-a`` answer stands.
"""

from __future__ import annotations

from ftplib import error_perm, error_temp

import pytest

from core import ftp_client as F
from core.ftp_client import FtpSession
from tests.test_backend_conformance import _FtpServer


def _site(tmp_path, **kw):
    root = tmp_path / "ftp"
    (root / "site").mkdir(parents=True)
    for name in (".htaccess", ".env", "index.html"):
        (root / "site" / name).write_bytes(b"x")
    srv = _FtpServer(root, mlsd=False, **kw)
    return root, srv, FtpSession("127.0.0.1", srv.port, "u", "p")


class _Ftp:
    """Answers NLST / LIST from a table: a list of lines or an exception."""

    def __init__(self, answers: dict) -> None:
        self.answers = answers
        self.asked: list[str] = []

    def _answer(self, command: str):
        self.asked.append(command)
        answer = self.answers[command]
        if isinstance(answer, BaseException):
            raise answer
        return list(answer)

    def nlst(self, arg: str):
        return self._answer(f"NLST {arg}")

    def retrlines(self, command: str, callback):
        for line in self._answer(command):
            callback(line)
        return "226 done"


# -- happy -------------------------------------------------------------------


def test_happy_a_server_answering_450_to_the_option_still_lists(tmp_path):
    _root, srv, s = _site(tmp_path, dash_a="450")
    try:
        # Without the option the server hides its dot files: only the rest.
        assert {i.name for i in s.list_dir("/site")} == {"index.html"}
        assert s.exists("/site/nope") is False
        assert s.exists("/site/index.html") is True
        assert "NLST /site" in srv.commands
    finally:
        s.close()
        srv.close()


def test_happy_a_file_named_dash_a_keeps_the_dot_files(tmp_path):
    root, srv, s = _site(tmp_path)
    (root / "site" / "-archive.tar").write_bytes(b"x")
    try:
        names = {i.name for i in s.list_dir("/site")}
        assert names == {".htaccess", ".env", "index.html", "-archive.tar"}
    finally:
        s.close()
        srv.close()


# -- sad ---------------------------------------------------------------------


def test_sad_the_option_read_as_part_of_the_path_gets_the_plain_names():
    ftp = _Ftp({
        "NLST -a /d": ["-a /d/x", "-a /d/y"],
        "NLST /d": ["x", "y"],
    })
    assert F._nlst_all(ftp, "/d") == ["x", "y"]


def test_sad_a_4xx_on_the_plain_command_is_still_raised():
    ftp = _Ftp({
        "NLST -a /d": error_temp("450 No files found"),
        "NLST /d": error_temp("450 No files found"),
    })
    with pytest.raises(error_temp):
        F._nlst_all(ftp, "/d")
    ftp = _Ftp({
        "LIST -a /d": error_temp("450 No files found"),
        "LIST /d": error_temp("451 local error"),
    })
    with pytest.raises(error_temp):
        F._list_lines_all(ftp, "/d")


def test_sad_unix_listing_falls_back_on_450_and_raises_a_plain_4xx():
    line = "-rw-r--r--   1 u  g   5 Jan  2  2024 a.txt"
    ftp = _Ftp({"LIST -a /d": error_temp("450 No files found"), "LIST /d": [line]})
    details = FtpSession._unix_listing(object.__new__(FtpSession), ftp, "/d")
    assert details and details[0].rest == "a.txt"
    ftp = _Ftp({"LIST -a /d": error_temp("450 No files found"),
                "LIST /d": error_temp("451 aborted")})
    with pytest.raises(error_temp):
        FtpSession._unix_listing(object.__new__(FtpSession), ftp, "/d")


# -- edge --------------------------------------------------------------------


@pytest.mark.parametrize("call", ["nlst", "list"])
def test_edge_421_on_the_option_is_not_masked(call):
    ftp = _Ftp({
        "NLST -a /d": error_temp("421 Timeout"),
        "LIST -a /d": error_temp("421 Timeout"),
        "NLST /d": ["x"],
        "LIST /d": ["x"],
    })
    with pytest.raises(error_temp, match="421"):
        if call == "nlst":
            F._nlst_all(ftp, "/d")
        else:
            F._list_lines_all(ftp, "/d")
    assert len(ftp.asked) == 1


def test_edge_dash_a_names_also_in_the_plain_listing_are_entries():
    ftp = _Ftp({
        "NLST -a /d": [".env", "-a", "-archive.tar", "x"],
        "NLST /d": ["-a", "-archive.tar", "x"],
    })
    assert F._nlst_all(ftp, "/d") == [".env", "-a", "-archive.tar", "x"]


def test_edge_a_5xx_on_the_option_still_falls_back():
    ftp = _Ftp({"NLST -a /d": error_perm("501 no options"), "NLST /d": ["x"]})
    assert F._nlst_all(ftp, "/d") == ["x"]
