"""reverse-serve keeps a client inside the served root with Windows paths.

The request path was split on "/" only and ``..`` refused, then joined
with the backend's own ``join`` - ``os.path.join``, i.e. ``ntpath.join``
on Windows. There ``/..%5C..%5CWindows%5Cwin.ini`` decodes to one
segment ``..\\..\\Windows\\win.ini`` that climbs out of the root, and a
segment with a drive (``/C:/Windows/win.ini``) replaces the root
altogether. Segments with a backslash or a drive are now refused, and
every joined path is checked to stay under the root in the backend's
own path flavour.

Windows is simulated with a backend whose join is ``ntpath.join`` and
whose separator is a backslash (what LocalFS is on Windows); the HTTP
server, the path parsing and the join check are the module's own code.
"""

from __future__ import annotations

import ntpath
import urllib.error
import urllib.request

import pytest

from core import reverse_serve as RS
from core.local_fs import LocalFS


class _WinBackend:
    """Records every path the server asks for; nothing exists."""

    def __init__(self):
        self.asked: list[str] = []

    def join(self, *parts):
        return ntpath.join(*parts)

    def separator(self):
        return "\\"

    def _miss(self, path, *a, **kw):
        self.asked.append(path)
        raise FileNotFoundError(path)

    stat = open_read = list_dir = remove = _miss

    def is_dir(self, path):
        self.asked.append(path)
        return False

    def exists(self, path):
        self.asked.append(path)
        return False


ESCAPES = [
    "/..%5C..%5CWindows%5Cwin.ini",
    "/docs/..%5C..%5C..%5Csecret.txt",
    "/C:/Windows/win.ini",
    "/c:%5CWindows%5Cwin.ini",
    "/%43:/Windows/win.ini",
    "/docs/D:evil.txt",
    "/%5C%5Cserver%5Cshare%5Cx",
]


@pytest.fixture
def win_dav():
    backend = _WinBackend()
    srv = RS.serve_webdav(backend, bind="127.0.0.1", port=0, root_path="/share", auth_token=None)
    try:
        yield srv, backend
    finally:
        srv.shutdown()


def _get(srv, path: str) -> int:
    try:
        with urllib.request.urlopen(f"{srv.base_url}{path}", timeout=10) as r:
            return r.status
    except urllib.error.HTTPError as exc:
        return exc.code


def _inside(path: str, root: str = "/share") -> bool:
    base = ntpath.normcase(ntpath.normpath(root))
    full = ntpath.normcase(ntpath.normpath(path))
    return full == base or full.startswith(base.rstrip("\\") + "\\")


# -- happy -------------------------------------------------------------------


def test_happy_a_plain_path_is_asked_for_under_the_root(win_dav):
    srv, backend = win_dav
    assert _get(srv, "/docs/a.txt") == 404
    assert backend.asked and all(_inside(p) for p in backend.asked), backend.asked


def test_happy_a_colon_inside_a_posix_name_is_still_served(tmp_path):
    (tmp_path / "12:30.log").write_bytes(b"log")
    srv = RS.serve_webdav(
        LocalFS(), bind="127.0.0.1", port=0, root_path=str(tmp_path), auth_token=None
    )
    try:
        with urllib.request.urlopen(f"{srv.base_url}/12:30.log", timeout=10) as r:
            assert r.read() == b"log"
    finally:
        srv.shutdown()


# -- sad ---------------------------------------------------------------------


@pytest.mark.parametrize("path", ESCAPES)
def test_sad_a_windows_escape_is_refused_before_the_backend_is_asked(win_dav, path):
    srv, backend = win_dav
    assert _get(srv, path) == 400
    assert backend.asked == [], backend.asked


@pytest.mark.parametrize("path", ["/bucket/..%5C..%5Cwin.ini", "/bucket/C:/win.ini", "/C:/x"])
def test_sad_the_s3_flavour_refuses_the_same_escapes(path):
    backend = _WinBackend()
    srv = RS.serve_s3(backend, bind="127.0.0.1", port=0, root_path="/share", auth_token=None)
    try:
        assert _get(srv, path) == 400
        assert backend.asked == [], backend.asked
    finally:
        srv.shutdown()


@pytest.mark.parametrize("path", ESCAPES)
def test_sad_normalize_key_refuses_backslash_and_drive_segments(path):
    with pytest.raises(PermissionError):
        RS._normalize_key(path)


def test_sad_the_join_check_catches_an_escape_that_reached_it():
    with pytest.raises(PermissionError):
        RS._rooted_join(_WinBackend(), "/share", "..\\..\\x")
    with pytest.raises(PermissionError):
        RS._rooted_join(_WinBackend(), "/share", "C:\\Windows")


# -- edge --------------------------------------------------------------------


def test_edge_the_root_itself_and_a_child_join_fine():
    assert RS._rooted_join(_WinBackend(), "/share") == "/share"
    assert _inside(RS._rooted_join(_WinBackend(), "/share", "a", "b.txt"))
    assert RS._rooted_join(LocalFS(), "/srv/x", "a:b.txt") == "/srv/x/a:b.txt"


def test_edge_a_trusted_windows_root_path_is_not_refused():
    # The operator's own root may carry a drive and backslashes.
    assert RS._normalize_root_path("C:\\Users\\alice\\share")


def test_edge_posix_root_slash_serves_every_path_below_it():
    assert RS._rooted_join(LocalFS(), "/", "etc", "hosts") == "/etc/hosts"
