"""Find Files against a real remote: the podman lab's Samba (10.99.0.31,
tests/docker). Skipped when the lab is not reachable; run it inside
``podman unshare --rootless-netns``.

A remote folder is walked through ``list_dir``, content is read through
``open_read`` and an archive is copied to a private temp file before its
members are searched.
"""

from __future__ import annotations

import io
import socket
import sys
import uuid
import zipfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import file_search as FS  # noqa: E402
from core.search_federation import SearchQuery  # noqa: E402

LAB = ("10.99.0.31", 445)


def _lab_up() -> bool:
    try:
        with socket.create_connection(LAB, timeout=2):
            return True
    except OSError:
        return False


pytestmark = pytest.mark.skipif(
    not _lab_up(), reason="the lab's Samba (10.99.0.31) is not reachable"
)


@pytest.fixture
def share():
    from core import smb_client as M

    session = M.SmbSession(host=LAB[0], share="testshare", username="smbuser",
                           password="smb123", port=LAB[1])
    folder = f"/axross-find-{uuid.uuid4().hex[:8]}"
    session.mkdir(folder)
    session.mkdir(f"{folder}/sub")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("keys/wallet.dat", b"\0" * 32)
    for path, data in {
        f"{folder}/sub/vm.vmdk": b"KDMV" + b"\0" * 60,
        f"{folder}/notes.txt": b"first\nthe Secret Sauce recipe\n",
        f"{folder}/other.txt": b"nothing here\n",
        f"{folder}/pack.zip": buf.getvalue(),
    }.items():
        with session.open_write(path) as fh:
            fh.write(data)
    try:
        yield session, folder
    finally:
        try:
            session.remove(folder, recursive=True)
        finally:
            session.close()


def _paths(session, folder, **query) -> list[str]:
    hits = []
    FS.run_search([FS.SearchScope(session, folder)], SearchQuery(**query),
                  on_hit=lambda scope, hit: hits.append(hit.path))
    return sorted(p[len(folder):] for p in hits)


def test_live_smb_by_type_content_and_inside_an_archive(share) -> None:
    session, folder = share
    assert _paths(session, folder, categories=("disk_images",)) == ["/sub/vm.vmdk"]
    assert _paths(session, folder, contains="secret sauce") == ["/notes.txt"]
    assert _paths(session, folder, categories=("crypto_wallets",), search_archives=True) == [
        "/pack.zip!/keys/wallet.dat"
    ]
