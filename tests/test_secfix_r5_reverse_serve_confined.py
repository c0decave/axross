"""Reverse serve (LocalFS): a folder swapped for a symlink between the
check and the use does not lead out of the served root (security review
round 5).

Measured before: the handlers checked the path as a string
(``_rooted_join`` -> core.path_policy.confined_path) and then used it by
name. A token holder with a symlink to an outside folder in the served
tree (MOVE renames links) swapped a folder of a path for it between the
two, with two MOVEs in a loop: GET read ``outside/secret`` (race_dir, in
0.6 s), COPY overwrote it (race_copy) and DELETE removed it (race_delete).

Here the swap happens deterministically right after each path check
(core.path_policy.confined_path returns, then ``b/x`` becomes a link to
the outside folder). Every verb must refuse, never touch the outside
file. A link that stays inside the root keeps working.
"""

from __future__ import annotations

import http.client
import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import path_policy  # noqa: E402
from core import reverse_serve as RS  # noqa: E402
from core.confined_fs import FD_CONFINED  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

TOKEN = "r5-confined-" + "t" * 24
SECRET = b"OUTSIDE-SECRET"

pytestmark = pytest.mark.skipif(not FD_CONFINED, reason="descriptor-relative calls (POSIX)")


@pytest.fixture
def tree(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    (root / "b" / "x").mkdir(parents=True)
    (root / "b" / "d").mkdir()
    outside.mkdir()
    (root / "b" / "x" / "secret").write_bytes(b"inside")
    (root / "b" / "x" / "sub").mkdir()
    (root / "b" / "x" / "sub" / "f").write_bytes(b"in sub")
    (root / "b" / "d" / "f").write_bytes(b"in d")
    (outside / "secret").write_bytes(SECRET)
    (outside / "sub").mkdir()
    (outside / "sub" / "f").write_bytes(SECRET)
    return root, outside


@pytest.fixture
def swap_after_check(tree, monkeypatch):
    """After a check of a path below ``b/x`` passes, ``b/x`` is a link to
    the outside folder (what two MOVEs of the attacker do between check
    and use)."""
    root, outside = tree
    real = path_policy.confined_path
    x = root / "b" / "x"

    def checked_then_swapped(base, path, *, follow=True):
        out = real(base, path, follow=follow)
        if path.replace("\\", "/").startswith("b/x/") and not x.is_symlink():
            os.rename(x, root / "b" / "xreal")
            os.symlink(outside, x)
        return out

    monkeypatch.setattr(path_policy, "confined_path", checked_then_swapped)
    return root, outside


def _serve(kind, root):
    fn = RS.serve_s3 if kind == "s3" else RS.serve_webdav
    return fn(LocalFS(), bind="127.0.0.1", port=0, root_path=str(root), auth_token=TOKEN)


def _request(server, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    try:
        hdrs = {"Authorization": f"Bearer {TOKEN}", "Host": f"127.0.0.1:{server.port}"}
        hdrs.update(headers or {})
        conn.request(method, path, body=body, headers=hdrs)
        resp = conn.getresponse()
        return resp.status, resp.read()
    finally:
        conn.close()


@pytest.fixture
def dav(tree):
    server = _serve("webdav", tree[0])
    yield server
    server.shutdown()


# -- sad: the swap after the check ---------------------------------------------------------


def test_sad_get_through_a_folder_swapped_after_the_check_reads_nothing_outside(
        swap_after_check, dav):
    status, body = _request(dav, "GET", "/b/x/secret")
    assert SECRET not in body
    assert status in (400, 403, 404, 500)


def test_sad_put_through_a_swapped_folder_writes_nothing_outside(swap_after_check, dav):
    root, outside = swap_after_check
    status, _ = _request(dav, "PUT", "/b/x/secret", body=b"PWNED")
    assert (outside / "secret").read_bytes() == SECRET
    assert status >= 400


def test_sad_delete_through_a_swapped_folder_removes_nothing_outside(swap_after_check, dav):
    root, outside = swap_after_check
    status, _ = _request(dav, "DELETE", "/b/x/secret")
    assert (outside / "secret").read_bytes() == SECRET
    assert status >= 400


def test_sad_copy_onto_a_swapped_folder_writes_nothing_outside(swap_after_check, dav):
    root, outside = swap_after_check
    status, _ = _request(dav, "COPY", "/b/d/f", headers={"Destination": "/b/x/secret"})
    assert (outside / "secret").read_bytes() == SECRET
    assert status >= 400


def test_sad_copy_from_a_swapped_folder_copies_nothing_outside_in(swap_after_check, dav):
    root, outside = swap_after_check
    _request(dav, "COPY", "/b/x/secret", headers={"Destination": "/b/d/stolen"})
    stolen = root / "b" / "d" / "stolen"
    assert not stolen.exists() or stolen.read_bytes() != SECRET


def test_sad_move_into_a_swapped_folder_moves_nothing_out(swap_after_check, dav):
    root, outside = swap_after_check
    _request(dav, "MOVE", "/b/d/f", headers={"Destination": "/b/x/moved"})
    assert not (outside / "moved").exists()


def test_sad_mkcol_in_a_swapped_folder_creates_nothing_outside(swap_after_check, dav):
    root, outside = swap_after_check
    status, _ = _request(dav, "MKCOL", "/b/x/sub/newdir")
    assert not (outside / "sub" / "newdir").exists()
    assert status >= 400


def test_sad_propfind_of_a_swapped_folder_lists_nothing_outside(swap_after_check, dav):
    root, outside = swap_after_check
    (outside / "sub" / "only-outside.txt").write_bytes(b"x")
    status, body = _request(dav, "PROPFIND", "/b/x/sub/", headers={"Depth": "1"})
    assert b"only-outside" not in body


@pytest.mark.parametrize("kind", ["s3", "webdav"])
def test_sad_both_flavours_refuse_a_read_through_the_swap(swap_after_check, kind):
    root, _outside = swap_after_check
    server = _serve(kind, root)
    try:
        status, body = _request(server, "GET", "/b/x/sub/f")
        assert SECRET not in body and status >= 400
    finally:
        server.shutdown()


def test_sad_s3_put_through_a_swapped_folder_writes_nothing_outside(swap_after_check):
    root, outside = swap_after_check
    server = _serve("s3", root)
    try:
        status, _ = _request(server, "PUT", "/b/x/sub/f", body=b"PWNED",
                             headers={"Content-Length": "5"})
        assert (outside / "sub" / "f").read_bytes() == SECRET
        assert status >= 400
    finally:
        server.shutdown()


# -- happy: links inside the root, ordinary writes -----------------------------------------


def test_happy_a_folder_link_that_stays_inside_still_works(tree, dav):
    root, _outside = tree
    os.symlink(root / "b" / "d", root / "b" / "dlink")
    assert _request(dav, "GET", "/b/dlink/f") == (200, b"in d")
    status, _ = _request(dav, "PUT", "/b/dlink/new", body=b"via link")
    assert status == 201 and (root / "b" / "d" / "new").read_bytes() == b"via link"
    assert _request(dav, "GET", "/b/dlink/new") == (200, b"via link")
    status, _ = _request(dav, "DELETE", "/b/dlink/new")
    assert status == 204 and not (root / "b" / "d" / "new").exists()


def test_happy_put_replaces_a_file_and_keeps_its_mode(tree, dav):
    root, _outside = tree
    target = root / "b" / "d" / "f"
    target.chmod(0o640)
    status, _ = _request(dav, "PUT", "/b/d/f", body=b"new content")
    assert status == 201
    assert target.read_bytes() == b"new content"
    assert stat.S_IMODE(target.stat().st_mode) == 0o640
    assert [p.name for p in target.parent.iterdir()] == ["f"]  # no temp file left


def test_happy_move_renames_a_link_itself(tree, dav):
    root, outside = tree
    os.symlink(outside, root / "b" / "out")
    status, _ = _request(dav, "MOVE", "/b/out", headers={"Destination": "/b/renamed"})
    assert status == 201
    assert os.readlink(root / "b" / "renamed") == str(outside)
    assert (outside / "secret").read_bytes() == SECRET


def test_happy_the_backend_is_confined_to_the_served_root(tree):
    root, _outside = tree
    server = _serve("webdav", root)
    try:
        backend = server.httpd.RequestHandlerClass.config.backend
        assert isinstance(backend, RS._ServedTreeFS)
        assert backend.roots == (str(root),)
    finally:
        server.shutdown()


# -- edge -----------------------------------------------------------------------------------


def test_edge_a_patched_local_fs_keeps_the_string_checks(tree):
    """A LocalFS with an instance attribute is not the plain local file
    system: it is served as given (the string checks stay)."""
    root, _outside = tree
    backend = LocalFS()
    backend.marker = True
    assert RS._served_backend(backend, str(root)) is backend


def test_edge_a_link_swapped_in_at_the_target_of_a_put_is_refused(tree):
    """The last layer: a link that appears after the resolution is refused
    by the descriptor-relative store, never followed."""
    root, outside = tree
    fs = RS._ServedTreeFS(str(root))
    os.symlink(outside / "secret", root / "b" / "d" / "late")

    class Reader:
        def __init__(self):
            self.data = [b"PWNED"]

        def read(self, _n):
            return self.data.pop() if self.data else b""

    from core.confined_fs import ConfinedLocalFS

    with pytest.raises(PermissionError):
        ConfinedLocalFS.confined_atomic_write_stream(fs, str(root / "b" / "d" / "late"),
                                                     Reader())
    assert (outside / "secret").read_bytes() == SECRET
