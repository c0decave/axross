"""Whether a server has MLSD comes from its FEAT reply, not from listing
the root folder at every login.

The login listed "/" with MLSD to find out: a root folder the account may
not read (a refusal) turned MLSD off for the whole session, so every
listing fell back to NLST + LIST and per-entry probes; a root with tens of
thousands of entries was transferred at every login. RFC 3659 7.8: a
server with MLSD names MLST in FEAT. Only a server that answers no FEAT is
still probed (in its login folder).
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from ftp_fs_server import FtpFsServer  # noqa: E402

from core.ftp_client import FtpSession  # noqa: E402


def _session(srv):
    return FtpSession("127.0.0.1", srv.port, "u", "p")


def test_feat_with_mlst_needs_no_listing_at_login(tmp_path):
    (tmp_path / "a").write_bytes(b"1")
    with FtpFsServer(str(tmp_path)) as srv:
        sess = _session(srv)
        try:
            assert sess._has_mlsd is True
            assert not any(c.startswith(("MLSD", "LIST", "NLST")) for c in srv.commands)
            assert [i.name for i in sess.list_dir("/")] == ["a"]
        finally:
            sess.close()


def test_unreadable_root_keeps_mlsd_for_other_folders(tmp_path):
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "f").write_bytes(b"1")
    import ftp_fs_server as FS

    real_mlsd = FS._Conn.do_MLSD

    def refuse_root(conn_self, arg):
        if arg in (b"", b"/", b"."):
            conn_self.send("550 Permission denied")
            return None
        return real_mlsd(conn_self, arg)

    with FtpFsServer(str(tmp_path)) as srv:
        FS._Conn.do_MLSD = refuse_root
        try:
            sess = _session(srv)
            try:
                assert sess._has_mlsd is True
                [item] = sess.list_dir("/sub")
                assert item.name == "f"
                assert any(c.startswith("MLSD /sub") for c in srv.commands)
            finally:
                sess.close()
        finally:
            FS._Conn.do_MLSD = real_mlsd


def test_feat_without_mlst_means_no_mlsd(tmp_path):
    (tmp_path / "a").write_bytes(b"1")
    with FtpFsServer(str(tmp_path), features=("SIZE", "MDTM")) as srv:
        sess = _session(srv)
        try:
            assert sess._has_mlsd is False
            assert not any(c.startswith("MLSD") for c in srv.commands)
            assert [i.name for i in sess.list_dir("/")] == ["a"]
        finally:
            sess.close()
