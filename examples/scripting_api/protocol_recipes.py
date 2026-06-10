"""Protocol-specific scripting recipes.

Some APIs require a live protocol session. The ``run()`` smoke uses
SQLite and small fakes where the API dispatch shape is the important
part; Docker-backed real sessions are in ``docker_protocol_smoke.py``.
"""

from __future__ import annotations

import io
import os
import tempfile
import urllib.request
from pathlib import Path

COVERS = (
    "open_url",
    "find_tftp_files",
    "slp_discover",
    "nntp_post",
    "git_push",
    "exec",
    "interactive_shell",
    "query",
    "tables",
    "imap_search",
    "imap_move",
    "imap_set_flags",
    "share",
    "ldap_search",
    "serve_s3",
    "serve_webdav",
)


class _ExecBackend:
    def exec(self, cmd, **_kwargs):
        from models.exec_result import ExecResult

        return ExecResult(0, f"ran: {cmd}\n".encode("utf-8"), b"")

    def interactive_shell(self, **_kwargs):
        return {"shell": "opened"}


class _CloudShareBackend:
    def presign(self, path, **_kwargs):
        return f"https://example.invalid/presigned{path}"


class _GitBackend:
    def __init__(self):
        self.pushed = []

    def flush_push(self, branch=None):
        self.pushed.append(branch)


class _TftpBackend:
    def find_files(self, wordlist=None, on_progress=None):
        names = list(wordlist or ["readme.txt"])
        if on_progress:
            for idx, name in enumerate(names, 1):
                on_progress(idx, len(names), name)
        return [name for name in names if name.endswith(".txt")]


class _NntpBackend:
    def __init__(self):
        self.article = b""

    def open_write(self, _path):
        backend = self

        class _Writer(io.BytesIO):
            def close(self):
                backend.article = self.getvalue()
                super().close()

        return _Writer()


class _ImapBackend:
    def __init__(self):
        self.flags = {}
        self.moves = []

    def search(self, criteria, *, mailbox="INBOX"):
        return [1] if criteria == "ALL" and mailbox == "INBOX" else []

    def set_flags(self, uid, flags, *, mailbox="INBOX", mode="set"):
        self.flags[(uid, mailbox)] = (mode, list(flags))

    def move(self, uid, src_mailbox, dst_mailbox):
        self.moves.append((uid, src_mailbox, dst_mailbox))


class _LdapBackend:
    def _path_to_dn(self, path):
        return path.strip("/")

    def search(
        self, base_dn, filter="(objectClass=*)", *, scope="subtree", attributes=None, limit=1000
    ):
        return [
            {
                "dn": f"cn=alice,{base_dn}",
                "attributes": {"cn": ["alice"], "mail": ["alice@example.invalid"]},
                "filter": filter,
                "scope": scope,
                "limit": limit,
                "requested": list(attributes or []),
            }
        ]


def slp_discovery_recipe(host: str = "10.99.0.43") -> dict:
    """Discover SLP services on a live target."""
    import axross

    return axross.slp_discover(host)


def imap_recipe(backend) -> list[int]:
    """Search, flag and move messages on an IMAP-like backend."""
    import axross

    uids = axross.imap_search(backend, "ALL", mailbox="INBOX")
    if uids:
        axross.imap_set_flags(backend, uids[0], ["\\Seen"], mode="add")
        axross.imap_move(backend, uids[0], "INBOX", "Archive")
    return uids


def run(base_dir: str | os.PathLike[str] | None = None) -> dict:
    """Run protocol dispatch examples that do not need external services."""
    import axross

    tmp_ctx = None
    if base_dir is None:
        tmp_ctx = tempfile.TemporaryDirectory()
        root = Path(tmp_ctx.name)
    else:
        root = Path(base_dir)
        root.mkdir(parents=True, exist_ok=True)

    try:
        db_path = root / "example.sqlite"
        db = axross.open_url(f"sqlite:///{db_path}")
        try:
            axross.query(db, "CREATE TABLE users(id INTEGER PRIMARY KEY, name TEXT)")
            axross.query(db, "INSERT INTO users(name) VALUES (?)", ("alice",))
            rows = axross.query(db, "SELECT name FROM users")
            assert rows == [{"name": "alice"}]
            assert "users" in axross.tables(db)
        finally:
            close = getattr(db, "close", None)
            if close:
                close()

        exec_result = axross.exec(_ExecBackend(), "id").check()
        shell = axross.interactive_shell(_ExecBackend())
        assert exec_result.stdout.startswith(b"ran:")
        assert shell["shell"] == "opened"

        assert axross.share(_CloudShareBackend(), "/report.txt").startswith("https://")
        git = _GitBackend()
        axross.git_push(git, branch="main")
        assert git.pushed == ["main"]

        assert axross.find_tftp_files(_TftpBackend(), wordlist=["readme.txt", "image.bin"])
        nntp = _NntpBackend()
        axross.nntp_post(nntp, "local.test", "Subject", "Body")
        assert b"Newsgroups: local.test" in nntp.article

        imap = _ImapBackend()
        assert imap_recipe(imap) == [1]
        assert imap.moves == [(1, "INBOX", "Archive")]

        ldap_rows = axross.ldap_search(
            _LdapBackend(),
            "ou=people,dc=example,dc=invalid",
            "(objectClass=inetOrgPerson)",
            attributes=["cn", "mail"],
        )
        assert ldap_rows[0]["dn"].startswith("cn=alice")

        ram = axross.ramfs()
        axross.write_text(ram, "/hello.txt", "hello reverse server")
        ram.mkdir("/bucket")
        axross.write_text(ram, "/bucket/hello.txt", "hello reverse server")
        webdav = axross.serve_webdav(ram, port=0, read_only=True)
        s3 = axross.serve_s3(ram, port=0, read_only=True)
        try:
            with urllib.request.urlopen(f"{webdav.base_url}/hello.txt", timeout=3) as resp:
                assert resp.read() == b"hello reverse server"
            # Minimum S3 path style: /bucket/key maps key under root.
            with urllib.request.urlopen(f"{s3.base_url}/bucket/hello.txt", timeout=3) as resp:
                assert resp.read() == b"hello reverse server"
        finally:
            webdav.shutdown()
            s3.shutdown()

        return {
            "sqlite_rows": len(rows),
            "imap_uids": 1,
            "ldap_rows": len(ldap_rows),
            "reverse_webdav": webdav.base_url,
            "reverse_s3": s3.base_url,
        }
    finally:
        if tmp_ctx is not None:
            tmp_ctx.cleanup()


if __name__ == "__main__":
    print(run())
