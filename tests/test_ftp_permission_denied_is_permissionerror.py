"""A refusal the server words as one ("550 Permission denied", IIS's
"550 Access is denied.") is a PermissionError.

It was a plain OSError with the server's text, so the pane showed
"Cannot read /f: 550 Permission denied" and nothing could tell it from
any other failure; as a PermissionError the user reads "Permission denied
for /f. Your account has no rights to it there ..." (core.user_errors).
Driven against tests/ftp_fs_server.py, with MLSD and without.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ftp_fs_server import FtpFsServer  # noqa: E402

from core.ftp_client import FtpSession  # noqa: E402
from core.user_errors import describe  # noqa: E402


@pytest.fixture(params=["mlsd", "list"])
def denied(request, tmp_path):
    (tmp_path / "sec").mkdir()
    (tmp_path / "sec" / "x").write_bytes(b"1")
    (tmp_path / "f").write_bytes(b"1")
    features = None if request.param == "mlsd" else ()
    srv = FtpFsServer(str(tmp_path), **({} if features is None else {"features": features}))
    sess = FtpSession("127.0.0.1", srv.port, "u", "p")
    srv.denied = {b"/f", b"/sec"}
    yield sess
    sess.close()
    srv.close()


@pytest.mark.parametrize(
    "op, path",
    [
        ("read", "/f"),
        ("list", "/sec"),
        ("remove", "/f"),
        ("rename", "/f"),
        ("mkdir", "/sec/new"),
    ],
)
def test_refusal_is_permission_error(denied, op, path):
    calls = {
        "read": lambda: denied.open_read(path),
        "list": lambda: denied.list_dir(path),
        "remove": lambda: denied.remove(path),
        "rename": lambda: denied.rename(path, "/g"),
        "mkdir": lambda: denied.mkdir(path),
    }
    with pytest.raises(PermissionError) as info:
        calls[op]()
    assert describe(info.value).startswith(f"Permission denied for {path}.")


def test_missing_stays_file_not_found(denied):
    with pytest.raises(FileNotFoundError):
        denied.open_read("/nope")
