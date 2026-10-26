"""Reverse serve end to end: every verb of the WebDAV and the S3 endpoint
over real HTTP, on LocalFS and on RamFS - what rclone, davfs2, Finder or
aws-cli see.

Before this file most verbs of the WebDAV side (HEAD, MKCOL, COPY, LOCK,
the HTML index, every refusal) and HEAD / the folder marker of the S3 side
ran in no test (core/reverse_serve.py: 73 % of its branches,
docs/TEST_COVERAGE_MATRIX.md of 2026-10-26).

Bugs found while writing it:

* WebDAV ``DELETE /`` answered 204 and removed the served root folder
  itself, with everything in it; ``MOVE /`` renamed it away. The S3 side
  refuses a DELETE without a key. Both are now refused with 403.
* A DELETE the backend refused (no permission) was reported as success by
  the S3 endpoint (204 - S3's answer for a key that does not exist) and as
  "not found" by WebDAV (404). A client such as rclone or restic then takes
  the object for gone while it is still there. Only a missing key is 204 /
  404 now; a refusal is 403, any other failure 500.
"""

from __future__ import annotations

import base64
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import reverse_serve  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402
from core.ram_fs import RamFsSession  # noqa: E402

TOKEN = "t0ken-for-the-matrix-tests"


class Tree:
    """One backend with a served root holding ``docs/a.txt`` (b"alpha")."""

    def __init__(self, kind: str, tmp_path: Path) -> None:
        self.kind = kind
        if kind == "localfs":
            self.backend = LocalFS()
            self.root = str(tmp_path / "served")
            os.makedirs(self.root)
        else:
            self.backend = RamFsSession(f"reverse-{id(self)}")
            self.root = "/served"
            self.backend.mkdir(self.root)
        self.backend.mkdir(self.path("docs"))
        self.write("docs/a.txt", b"alpha")

    def path(self, rel: str) -> str:
        return self.backend.join(self.root, *rel.split("/")) if rel else self.root

    def write(self, rel: str, data: bytes) -> None:
        with self.backend.open_write(self.path(rel)) as fh:
            fh.write(data)

    def read(self, rel: str) -> bytes:
        with self.backend.open_read(self.path(rel)) as fh:
            return fh.read()

    def exists(self, rel: str) -> bool:
        return self.backend.exists(self.path(rel))


@pytest.fixture(scope="module", params=["localfs", "ramfs"])
def _module_tree(request, tmp_path_factory):
    t = Tree(request.param, tmp_path_factory.mktemp("reverse"))
    yield t
    if request.param == "ramfs":
        t.backend.disconnect()


def _reset(t: Tree) -> None:
    """Back to just docs/a.txt - the servers live for the whole module (a
    server's shutdown waits half a second), the files do not. A root a
    test removed comes back, so one failure does not fail the rest."""
    if not t.backend.exists(t.root):
        t.backend.mkdir(t.root)
    if t.kind == "localfs":
        for child in Path(t.root).iterdir():
            if child.is_dir() and not child.is_symlink():
                child.chmod(0o700)
    for item in t.backend.list_dir(t.root):
        t.backend.remove(t.path(item.name), recursive=True)
    t.backend.mkdir(t.path("docs"))
    t.write("docs/a.txt", b"alpha")


@pytest.fixture
def tree(_module_tree):
    _reset(_module_tree)
    return _module_tree


def serve(tree, flavour: str, **kw):
    fn = reverse_serve.serve_webdav if flavour == "webdav" else reverse_serve.serve_s3
    kw.setdefault("auth_token", TOKEN)
    return fn(tree.backend, bind="127.0.0.1", port=0, root_path=tree.root, **kw)


@pytest.fixture(scope="module")
def _module_dav(_module_tree):
    srv = serve(_module_tree, "webdav")
    yield srv
    srv.shutdown()


@pytest.fixture(scope="module")
def _module_s3(_module_tree):
    srv = serve(_module_tree, "s3")
    yield srv
    srv.shutdown()


@pytest.fixture
def dav(_module_dav, tree):
    return _module_dav


@pytest.fixture
def s3(_module_s3, tree):
    return _module_s3


def http(srv, method, path, body=None, headers=None, token=TOKEN):
    """(status, headers, body) of one real request."""
    headers = dict(headers or {})
    if token is not None:
        headers.setdefault("Authorization", f"Bearer {token}")
    req = urllib.request.Request(srv.base_url + path, data=body, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.headers, resp.read()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.headers, exc.read()


def propfind_hrefs(body: bytes) -> list[str]:
    ns = {"d": "DAV:"}
    return [h.text for h in ET.fromstring(body).findall(".//d:href", ns)]


# ========================================================== WebDAV: happy
def test_happy_options_names_every_verb(dav):
    status, headers, _ = http(dav, "OPTIONS", "/")
    assert status == 200 and headers["DAV"] == "1, 2"
    for verb in ("GET", "PUT", "DELETE", "MKCOL", "PROPFIND", "COPY", "MOVE", "LOCK"):
        assert verb in headers["Allow"]


def test_happy_put_then_get_and_head_round_trip(dav, tree):
    assert http(dav, "PUT", "/docs/new.bin", body=b"\x00\x01payload")[0] == 201
    assert tree.read("docs/new.bin") == b"\x00\x01payload"
    status, headers, body = http(dav, "GET", "/docs/new.bin")
    assert (status, body) == (200, b"\x00\x01payload")
    status, headers, body = http(dav, "HEAD", "/docs/new.bin")
    assert status == 200 and body == b""
    assert headers["Content-Length"] == "9" and headers["Last-Modified"].endswith("GMT")


def test_happy_put_into_a_missing_folder_creates_it(dav, tree):
    assert http(dav, "PUT", "/deep/er/f.txt", body=b"x")[0] == 201
    assert tree.read("deep/er/f.txt") == b"x"


def test_happy_propfind_lists_a_folder_with_depth_1(dav):
    status, _, body = http(dav, "PROPFIND", "/docs", headers={"Depth": "1"})
    assert status == 207
    hrefs = propfind_hrefs(body)
    assert hrefs[0].rstrip("/").endswith("/docs") and any(h.endswith("/a.txt") for h in hrefs)


def test_happy_mkcol_copy_move_delete(dav, tree):
    assert http(dav, "MKCOL", "/archive")[0] == 201
    assert tree.backend.is_dir(tree.path("archive"))
    dest = {"Destination": f"{dav.base_url}/archive/a.txt"}
    assert http(dav, "COPY", "/docs/a.txt", headers=dest)[0] == 201
    assert tree.read("archive/a.txt") == b"alpha" and tree.exists("docs/a.txt")
    dest = {"Destination": f"{dav.base_url}/archive/moved.txt"}
    assert http(dav, "MOVE", "/docs/a.txt", headers=dest)[0] == 201
    assert tree.read("archive/moved.txt") == b"alpha" and not tree.exists("docs/a.txt")
    assert http(dav, "DELETE", "/archive")[0] == 204
    assert not tree.exists("archive")


def test_happy_lock_and_unlock_answer_like_a_dav_class_2_server(dav):
    status, headers, body = http(dav, "LOCK", "/docs/a.txt")
    assert status == 200 and headers["Lock-Token"].startswith("<opaquelocktoken:")
    assert headers["Lock-Token"].strip("<>") in body.decode()
    assert http(dav, "UNLOCK", "/docs/a.txt")[0] == 204


def test_happy_a_browser_gets_an_html_index(dav):
    status, headers, body = http(dav, "GET", "/docs")
    assert status == 200 and headers["Content-Type"].startswith("text/html")
    assert "<a href='a.txt'>a.txt</a>" in body.decode()


def test_happy_basic_auth_with_the_token_as_password_is_accepted(dav):
    basic = base64.b64encode(f"anyone:{TOKEN}".encode()).decode()
    status, _, body = http(dav, "GET", "/docs/a.txt", headers={"Authorization": f"Basic {basic}"})
    assert (status, body) == (200, b"alpha")


# ============================================================ WebDAV: sad
@pytest.mark.parametrize(
    "method",
    ["GET", "HEAD", "PUT", "DELETE", "MKCOL", "PROPFIND", "COPY", "MOVE", "LOCK", "UNLOCK"],
)
def test_sad_every_verb_without_the_token_is_401_and_changes_nothing(dav, tree, method):
    headers = {"Destination": f"{dav.base_url}/docs/b.txt"}
    status, resp_headers, _ = http(
        dav, method, "/docs/a.txt", body=b"evil", headers=headers, token="wrong-token-123456"
    )
    assert status == 401
    assert "Basic" in resp_headers.get("WWW-Authenticate", "")
    assert tree.read("docs/a.txt") == b"alpha" and not tree.exists("docs/b.txt")


@pytest.mark.parametrize("method", ["PUT", "DELETE", "MKCOL", "COPY", "MOVE", "LOCK"])
def test_sad_read_only_refuses_every_change(tree, method):
    srv = serve(tree, "webdav", read_only=True)
    try:
        headers = {"Destination": f"{srv.base_url}/docs/b.txt"}
        status, _, _ = http(srv, method, "/docs/a.txt", body=b"evil", headers=headers)
        assert status == 403
        assert http(srv, "GET", "/docs/a.txt")[2] == b"alpha"  # reading still works
    finally:
        srv.shutdown()
    assert tree.read("docs/a.txt") == b"alpha" and not tree.exists("docs/b.txt")


@pytest.mark.parametrize("method", ["GET", "HEAD", "PROPFIND", "DELETE"])
def test_sad_a_missing_path_is_404(dav, method):
    assert http(dav, method, "/docs/nope.txt")[0] == 404


def test_sad_mkcol_on_an_existing_folder_or_without_a_parent(dav):
    assert http(dav, "MKCOL", "/docs")[0] == 405
    assert http(dav, "MKCOL", "/no/parent")[0] == 409


def test_sad_copy_and_move_need_a_destination_inside_the_root(dav, tree):
    assert http(dav, "COPY", "/docs/a.txt")[0] == 400
    assert http(dav, "MOVE", "/docs/a.txt")[0] == 400
    out = {"Destination": f"{dav.base_url}/../escaped.txt"}
    assert http(dav, "MOVE", "/docs/a.txt", headers=out)[0] == 400
    assert tree.read("docs/a.txt") == b"alpha"


def test_sad_put_with_a_bad_content_length_is_400(dav, tree):
    status, _, _ = http(dav, "PUT", "/docs/a.txt", headers={"Content-Length": "-5"})
    assert status == 400 and tree.read("docs/a.txt") == b"alpha"


def test_sad_the_served_root_cannot_be_deleted_or_moved_away(dav, tree):
    assert http(dav, "DELETE", "/")[0] == 403
    dest = {"Destination": f"{dav.base_url}/docs/root-moved"}
    assert http(dav, "MOVE", "/", headers=dest)[0] == 403
    assert tree.backend.is_dir(tree.root) and tree.read("docs/a.txt") == b"alpha"


def test_sad_nothing_is_moved_or_copied_onto_the_served_root(dav, tree):
    dest = {"Destination": f"{dav.base_url}/"}
    assert http(dav, "MOVE", "/docs", headers=dest)[0] == 403
    assert http(dav, "COPY", "/docs/a.txt", headers=dest)[0] == 403
    assert tree.read("docs/a.txt") == b"alpha"


class _RefusingRemove:
    """The tree's backend, refusing to remove anything - a folder the user
    may not change, a share mounted read-only."""

    def __init__(self, backend) -> None:
        self._b = backend

    def __getattr__(self, name):
        return getattr(self._b, name)

    def remove(self, path, recursive=False):
        raise PermissionError(13, "Permission denied", path)


def test_sad_a_delete_the_backend_refuses_is_not_reported_as_done(tree):
    tree_backend = tree.backend
    tree.backend = _RefusingRemove(tree_backend)
    srv = serve(tree, "webdav")
    try:
        assert http(srv, "DELETE", "/docs/a.txt")[0] == 403
    finally:
        srv.shutdown()
        tree.backend = tree_backend
    assert tree.read("docs/a.txt") == b"alpha"


class _BlindExists(_RefusingRemove):
    """A backend that cannot say whether a path is there (a dropped
    connection) and refuses the remove as well."""

    def exists(self, path):
        raise OSError(5, "Input/output error", path)

    def remove(self, path, recursive=False):
        raise OSError(5, "Input/output error", path)


def test_sad_a_delete_whose_existence_check_fails_is_not_404(tree):
    """404 tells a client the file is gone (rclone, a sync): when the
    backend cannot even say whether it is there, the answer is an error."""
    tree_backend = tree.backend
    tree.backend = _BlindExists(tree_backend)
    srv = serve(tree, "webdav")
    try:
        assert http(srv, "DELETE", "/docs/a.txt")[0] == 500
    finally:
        srv.shutdown()
        tree.backend = tree_backend
    assert tree.read("docs/a.txt") == b"alpha"


def test_sad_e2e_a_delete_in_a_folder_without_write_permission(tmp_path):
    if os.geteuid() == 0:
        pytest.skip("root ignores the folder's permission bits")
    tree = Tree("localfs", tmp_path)
    locked = Path(tree.path("docs"))
    locked.chmod(0o500)
    try:
        for flavour, path in (("webdav", "/docs/a.txt"), ("s3", "/docs/a.txt")):
            srv = serve(tree, flavour)
            try:
                status, _, _ = http(srv, "DELETE", path)
            finally:
                srv.shutdown()
            assert status == 403, flavour
            assert (locked / "a.txt").read_bytes() == b"alpha"
    finally:
        locked.chmod(0o700)


# =========================================================== WebDAV: edge
def test_edge_propfind_depth_0_does_not_list_the_children(dav):
    status, _, body = http(dav, "PROPFIND", "/docs", headers={"Depth": "0"})
    assert status == 207 and len(propfind_hrefs(body)) == 1


def test_edge_propfind_depth_infinity_answers_like_depth_1(dav, tree):
    tree.backend.mkdir(tree.path("docs/sub"))
    tree.write("docs/sub/deep.txt", b"d")
    status, _, body = http(dav, "PROPFIND", "/docs", headers={"Depth": "infinity"})
    hrefs = propfind_hrefs(body)
    assert status == 207 and any(h.rstrip("/").endswith("/sub") for h in hrefs)
    assert not any(h.endswith("deep.txt") for h in hrefs)


def test_edge_an_empty_file_round_trips(dav, tree):
    assert http(dav, "PUT", "/docs/empty", body=b"")[0] == 201
    assert tree.read("docs/empty") == b""
    status, headers, body = http(dav, "GET", "/docs/empty")
    assert (status, body, headers["Content-Length"]) == (200, b"", "0")


def test_edge_unicode_and_spaces_in_names(dav, tree):
    name = "Übersicht%20Q3%20%E2%80%94%20final.txt"  # "Übersicht Q3 — final.txt"
    assert (
        http(dav, "PUT", "/docs/" + urllib.request.quote("Übersicht") + "%20Q3.txt", body=b"u")[0]
        == 201
    )
    assert tree.read("docs/Übersicht Q3.txt") == b"u"
    assert http(dav, "PUT", "/docs/" + name.replace("Ü", "%C3%9C"), body=b"v")[0] == 201
    assert tree.read("docs/Übersicht Q3 — final.txt") == b"v"
    status, _, body = http(dav, "PROPFIND", "/docs", headers={"Depth": "1"})
    assert any("%C3%9Cbersicht" in h or "Übersicht" in h for h in propfind_hrefs(body))


def test_edge_a_hostile_name_is_escaped_in_the_html_index(dav, tree):
    tree.write("docs/<script>alert(1)<'script>", b"x")
    body = http(dav, "GET", "/docs")[2].decode()
    assert "<script>" not in body and "&lt;script&gt;" in body
    assert "%3Cscript%3E" in body and "%27" in body  # quoted in the href


def test_edge_copy_onto_an_existing_file_replaces_it_unless_overwrite_is_f(dav, tree):
    tree.write("docs/b.txt", b"bravo")
    dest = {"Destination": f"{dav.base_url}/docs/b.txt"}
    assert http(dav, "COPY", "/docs/a.txt", headers={**dest, "Overwrite": "F"})[0] == 412
    assert tree.read("docs/b.txt") == b"bravo"
    assert http(dav, "COPY", "/docs/a.txt", headers=dest)[0] == 201
    assert tree.read("docs/b.txt") == b"alpha"


# ============================================================== S3 matrix
def test_happy_s3_head_of_the_service_a_bucket_and_an_object(s3):
    assert http(s3, "HEAD", "/")[0] == 200
    assert http(s3, "HEAD", "/docs")[0] == 200
    status, headers, _ = http(s3, "HEAD", "/docs/a.txt")
    assert status == 200 and headers["Content-Length"] == "5"


def test_happy_s3_put_get_list_delete(s3, tree):
    assert http(s3, "PUT", "/docs/k/obj.bin", body=b"objdata")[0] == 200
    assert tree.read("docs/k/obj.bin") == b"objdata"
    assert http(s3, "GET", "/docs/k/obj.bin")[2] == b"objdata"
    status, _, body = http(s3, "GET", "/docs?list-type=2&prefix=k/")
    assert status == 200 and b"<Key>k/obj.bin</Key>" in body
    assert b"<Name>docs</Name>" in http(s3, "GET", "/")[2]
    assert http(s3, "DELETE", "/docs/k/obj.bin")[0] == 204
    assert not tree.exists("docs/k/obj.bin")


def test_happy_s3_a_folder_marker_creates_a_folder(s3, tree):
    assert http(s3, "PUT", "/docs/newdir/", body=b"")[0] == 200
    assert tree.backend.is_dir(tree.path("docs/newdir"))


def test_sad_s3_a_missing_object_head_is_404_and_delete_is_204(s3):
    assert http(s3, "HEAD", "/docs/none")[0] == 404
    assert http(s3, "DELETE", "/docs/none")[0] == 204  # S3 semantics: idempotent


def test_sad_s3_delete_and_put_need_a_key(s3, tree):
    assert http(s3, "DELETE", "/")[0] == 400
    assert http(s3, "DELETE", "/docs")[0] == 400
    assert http(s3, "PUT", "/docs", body=b"x")[0] == 400
    assert tree.read("docs/a.txt") == b"alpha"


@pytest.mark.parametrize("method", ["PUT", "DELETE"])
def test_sad_s3_read_only_and_wrong_token_change_nothing(tree, method):
    srv = serve(tree, "s3", read_only=True)
    try:
        assert http(srv, method, "/docs/a.txt", body=b"evil")[0] == 403
        assert http(srv, method, "/docs/a.txt", body=b"evil", token="nope-nope-nope-nope")[0] == 403
    finally:
        srv.shutdown()
    assert tree.read("docs/a.txt") == b"alpha"


def test_sad_s3_a_delete_the_backend_refuses_is_403_not_204(tree):
    tree_backend = tree.backend
    tree.backend = _RefusingRemove(tree_backend)
    srv = serve(tree, "s3")
    try:
        status, _, body = http(srv, "DELETE", "/docs/a.txt")
    finally:
        srv.shutdown()
        tree.backend = tree_backend
    assert status == 403 and b"<Code>AccessDenied</Code>" in body
    assert tree.read("docs/a.txt") == b"alpha"


def test_edge_s3_traversal_in_the_key_is_refused(s3, tree):
    assert http(s3, "PUT", "/docs/..%2F..%2Fescape", body=b"x")[0] == 400
    assert http(s3, "GET", "/docs/%2e%2e/%2e%2e/etc")[0] in (400, 404)


def test_edge_s3_aws_signature_key_id_counts_as_the_token(s3):
    auth = f"AWS4-HMAC-SHA256 Credential={TOKEN}/20261026/us-east-1/s3/aws4_request, Signature=x"
    status, _, body = http(s3, "GET", "/docs/a.txt", headers={"Authorization": auth})
    assert (status, body) == (200, b"alpha")
