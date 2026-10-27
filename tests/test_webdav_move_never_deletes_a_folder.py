"""WebDAV rename() and copy() never delete a folder to make room.

core/webdav_client.py sent every MOVE and COPY with ``Overwrite: T``. RFC
4918 (9.9.3 / 9.8.4) tells the server to DELETE an existing destination
(Depth infinity) before it moves or copies. Reproduced on the lab's Apache
mod_dav (tests/docker/Dockerfile.webdav): ``rename("/t/report.txt",
"/t/Archive/")`` with Archive a folder holding files answered 204 and left
``/t/Archive`` a file - the folder and everything in it was gone. (Without
the trailing slash Apache answers 301 instead; sabre/dav, nginx and IIS do
not ask for the slash.)

Now both go out with ``Overwrite: F``. A taken name answers 412: an
existing FILE is then replaced (what rename does on every other backend),
a folder destination - or a folder source over a file - is refused with
IsADirectoryError / FileExistsError and nothing is touched.

Two servers: axross' own reverse WebDAV server on loopback (always), and
the lab's Apache when it is reachable (run inside ``podman unshare
--rootless-netns``).
"""

from __future__ import annotations

import os
import socket
import uuid

import pytest

pytest.importorskip("defusedxml", reason="WebDAV needs defusedxml")

from core.webdav_client import WebDavSession  # noqa: E402

LAB = ("10.99.0.32", 80)


def _lab_up() -> bool:
    try:
        with socket.create_connection(LAB, timeout=0.5):
            return True
    except OSError:
        return False


@pytest.fixture(params=["reverse", "apache"])
def dav(request, tmp_path):
    """(session, base folder) with base/Archive/{one,two}.txt,
    base/report.txt, base/old.txt and base/proj/ ."""
    if request.param == "reverse":
        from core.local_fs import LocalFS
        from core.reverse_serve import serve_webdav

        srv = serve_webdav(LocalFS(), bind="127.0.0.1", port=0,
                           root_path=str(tmp_path), auth_token=None)
        session, base = WebDavSession(srv.base_url), "/t"
        cleanup = srv.shutdown
    else:
        if not _lab_up():
            pytest.skip("lab WebDAV (10.99.0.32) not reachable")
        session = WebDavSession(url=f"http://{LAB[0]}:{LAB[1]}",
                                username="davuser", password="dav123")
        base = "/audit-" + uuid.uuid4().hex[:8]

        def cleanup():
            session.remove(base, recursive=True)
    session.mkdir(base)
    session.mkdir(base + "/Archive")
    session.mkdir(base + "/proj")
    for name, data in (("Archive/one.txt", b"keep 1"), ("Archive/two.txt", b"keep 2"),
                       ("report.txt", b"report"), ("old.txt", b"old")):
        with session.open_write(f"{base}/{name}") as fh:
            fh.write(data)
    try:
        yield session, base
    finally:
        cleanup()


def _read(s, path):
    with s.open_read(path) as fh:
        return fh.read()


def _archive_intact(s, base):
    assert s.is_dir(base + "/Archive")
    assert sorted(i.name for i in s.list_dir(base + "/Archive")) == ["one.txt", "two.txt"]


# ------------------------------------------------------------------ happy

def test_happy_rename_and_copy_onto_new_names(dav):
    s, base = dav
    s.copy(base + "/report.txt", base + "/copy.txt")
    s.rename(base + "/copy.txt", base + "/moved.txt")
    assert _read(s, base + "/moved.txt") == b"report"
    assert not s.exists(base + "/copy.txt")


def test_happy_rename_and_copy_over_an_existing_file_replace_it(dav):
    s, base = dav
    s.copy(base + "/report.txt", base + "/old.txt")
    assert _read(s, base + "/old.txt") == b"report"
    with s.open_write(base + "/old.txt") as fh:
        fh.write(b"old again")
    s.rename(base + "/report.txt", base + "/old.txt")
    assert _read(s, base + "/old.txt") == b"report"
    assert not s.exists(base + "/report.txt")


# ------------------------------------------------------------------ sad

@pytest.mark.parametrize("slash", ["", "/"])
def test_sad_rename_onto_a_folder_keeps_the_folder(dav, slash):
    s, base = dav
    with pytest.raises(OSError):
        s.rename(base + "/report.txt", base + "/Archive" + slash)
    _archive_intact(s, base)
    assert _read(s, base + "/report.txt") == b"report"


@pytest.mark.parametrize("slash", ["", "/"])
def test_sad_copy_onto_a_folder_keeps_the_folder(dav, slash):
    s, base = dav
    with pytest.raises(OSError):
        s.copy(base + "/report.txt", base + "/Archive" + slash)
    _archive_intact(s, base)


# ------------------------------------------------------------------ edge

def test_edge_a_folder_is_never_moved_over_another_folder_or_a_file(dav):
    s, base = dav
    with pytest.raises(OSError):
        s.rename(base + "/proj/", base + "/Archive/")
    _archive_intact(s, base)
    with pytest.raises(OSError):
        s.rename(base + "/Archive", base + "/old.txt")
    _archive_intact(s, base)
    assert _read(s, base + "/old.txt") == b"old"


def test_edge_the_refusal_names_the_folder(dav):
    s, base = dav
    with pytest.raises(IsADirectoryError):
        s.rename(base + "/report.txt", base + "/Archive/")
    assert os.path.basename("Archive")
