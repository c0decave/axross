"""LocalFS, NFS and iSCSI copy() never land INSIDE an existing folder.

All three copied with ``shutil.copy2(src, dst)``, which puts *src* into
*dst* when *dst* is a folder (or a link to one) and reports success - the
bug the shell backends' ``cp`` had (tests/test_shell_copy_rename_into_
folder.py). ``copy(report.txt, Archive)`` then answered "done" while
Archive was still a folder and the copy sat at Archive/report.txt. The
reverse server's WebDAV COPY (Overwrite: T, the default) calls the
backend's copy() directly and answered 201 for it.
"""

from __future__ import annotations

import os
import urllib.error
import urllib.request

import pytest

from core.iscsi_client import IscsiSession
from core.local_fs import LocalFS
from core.nfs_client import NfsSession


def _local(root):
    return LocalFS(), str(root)


def _nfs(root):
    s = object.__new__(NfsSession)
    s._mount_point = str(root)
    return s, "/"


def _iscsi(root):
    s = object.__new__(IscsiSession)
    s._mount_point = str(root)
    return s, "/"


BACKENDS = [_local, _nfs, _iscsi]


@pytest.fixture(params=BACKENDS, ids=["local", "nfs", "iscsi"])
def disk(request, tmp_path):
    (tmp_path / "report.txt").write_text("data")
    (tmp_path / "old.txt").write_text("old")
    (tmp_path / "Archive").mkdir()
    backend, base = request.param(tmp_path)

    def p(name):
        return os.path.join(base, name) if base != "/" else "/" + name

    return backend, p, tmp_path


def test_happy_copy_onto_a_new_name_and_over_a_file(disk):
    b, p, root = disk
    b.copy(p("report.txt"), p("copy.txt"))
    assert (root / "copy.txt").read_text() == "data"
    b.copy(p("report.txt"), p("old.txt"))
    assert (root / "old.txt").read_text() == "data"


def test_sad_copy_onto_a_folder_fails_and_leaves_it_alone(disk):
    b, p, root = disk
    with pytest.raises(IsADirectoryError):
        b.copy(p("report.txt"), p("Archive"))
    assert os.listdir(root / "Archive") == []
    assert (root / "report.txt").read_text() == "data"


def test_edge_copy_onto_a_link_to_a_folder_fails_too(disk):
    b, p, root = disk
    os.symlink("Archive", root / "to-archive")
    with pytest.raises(IsADirectoryError):
        b.copy(p("report.txt"), p("to-archive"))
    assert os.listdir(root / "Archive") == []


def test_e2e_reverse_webdav_copy_onto_a_folder_is_no_201(tmp_path):
    """The real reverse server over LocalFS: COPY report.txt to the folder
    Archive answered 201 and left the copy inside Archive."""
    from core.reverse_serve import serve_webdav

    (tmp_path / "report.txt").write_text("data")
    (tmp_path / "Archive").mkdir()
    server = serve_webdav(
        LocalFS(), bind="127.0.0.1", port=0, auth_token=None, root_path=str(tmp_path)
    )
    try:
        base = server.base_url
        req = urllib.request.Request(
            f"{base}/report.txt", method="COPY",
            headers={"Destination": f"{base}/Archive"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
        except urllib.error.HTTPError as exc:
            status = exc.code
    finally:
        server.shutdown()
    assert status >= 400
    assert os.listdir(tmp_path / "Archive") == []
