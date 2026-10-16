"""The newest features against real remotes in the docker protocol lab.

* Duplicate Finder: index an SFTP folder, plan a dedupe (dry run), run it
  (copies go to the SFTP trash and come back from it), and refuse a copy
  that changed after indexing.
* Metadata: read and remove the metadata of a JPEG on SFTP, S3 (MinIO)
  and WebDAV, in place (original kept in that connection's trash) and as
  a cleaned copy.
* Transfers: copy and move between two different remote backends through
  the transfer queue (TransferManager) and the scripting API.

Every test needs the lab (tests/docker/docker-compose.yml) and skips when
the service it talks to is not reachable, like the ``_<proto>_up()``
guards in tests/test_protocols.py. Each test works in a folder of its own
(uuid) and removes it afterwards.
"""

from __future__ import annotations

import hashlib
import os
import socket
import sys
import time
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from tests import metadata_testkit as K  # noqa: E402

SSH_HOST, SSH_PORT, SSH_USER, SSH_PASS = "10.99.0.10", 22, "alpha", "alpha123"
S3_HOST, S3_PORT = "10.99.0.33", 9000
S3_ENDPOINT = f"http://{S3_HOST}:{S3_PORT}"
S3_ACCESS_KEY, S3_SECRET_KEY, S3_BUCKET = "minioadmin", "minioadmin123", "testbucket"
WEBDAV_HOST, WEBDAV_PORT = "10.99.0.32", 80
WEBDAV_URL = f"http://{WEBDAV_HOST}:{WEBDAV_PORT}"
WEBDAV_USER, WEBDAV_PASS = "davuser", "dav123"


def _up(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


def _sftp_up() -> bool:
    return _up(SSH_HOST, SSH_PORT)


def _s3_up() -> bool:
    return _up(S3_HOST, S3_PORT)


def _webdav_up() -> bool:
    return _up(WEBDAV_HOST, WEBDAV_PORT)


requires_sftp = pytest.mark.skipif(not _sftp_up(), reason="ssh-alpha lab container not reachable")
requires_s3 = pytest.mark.skipif(not _s3_up(), reason="S3 / MinIO lab container not reachable")
requires_webdav = pytest.mark.skipif(
    not _webdav_up(), reason="WebDAV lab container not reachable"
)


# ---------------------------------------------------------------------------
# Connections and helpers
# ---------------------------------------------------------------------------


def _sftp():
    from core.profiles import ConnectionProfile
    from core.ssh_client import SSHSession

    profile = ConnectionProfile(
        name="lab-alpha",
        protocol="sftp",
        host=SSH_HOST,
        port=SSH_PORT,
        username=SSH_USER,
        auth_type="password",
    )
    session = SSHSession(profile)
    session.connect(password=SSH_PASS, on_unknown_host=lambda _err: True)
    return session


def _s3():
    from core.s3_client import S3Session

    return S3Session(
        bucket=S3_BUCKET,
        endpoint=S3_ENDPOINT,
        access_key=S3_ACCESS_KEY,
        secret_key=S3_SECRET_KEY,
        region="us-east-1",
    )


def _webdav():
    from core.webdav_client import WebDavSession

    return WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)


def _put(backend, path: str, data: bytes) -> str:
    with backend.open_write(path) as fh:
        fh.write(data)
    return path


def _get(backend, path: str) -> bytes:
    with backend.open_read(path) as fh:
        return fh.read()


def _rmtree(backend, path: str) -> None:
    try:
        if backend.exists(path):
            backend.remove(path, recursive=True)
    except OSError:
        pass


def _scratch(backend, base: str, label: str) -> str:
    folder = backend.join(base, f"axross-lab-{label}-{uuid.uuid4().hex[:10]}")
    backend.mkdir(folder)
    return folder


@pytest.fixture
def sftp():
    session = _sftp()
    try:
        yield session
    finally:
        session.disconnect()


@pytest.fixture
def s3():
    session = _s3()
    try:
        yield session
    finally:
        session.disconnect()


@pytest.fixture
def dav():
    session = _webdav()
    try:
        yield session
    finally:
        session.disconnect()


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    """Index, settings and journal of this test only."""
    from core import cas as CAS
    from core import open_limits as OL

    monkeypatch.setattr(CAS, "_DEFAULT_DB", tmp_path / "cas.sqlite")
    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setenv("AXROSS_OPERATION_JOURNAL", str(tmp_path / "ops.jsonl"))
    return tmp_path


# ---------------------------------------------------------------------------
# Duplicate Finder on SFTP
# ---------------------------------------------------------------------------


def _dupes_tree(sftp, root: str) -> dict[str, str]:
    """``keep`` (older, deeper path) and ``extra`` hold the same bytes,
    ``single`` is unique. The older copy sits on the LONGER path, so a
    survivor chosen by path instead of by time would be wrong."""
    sftp.mkdir(sftp.join(root, "archive"))
    keep = _put(sftp, sftp.join(root, "archive", "photo-original.bin"), b"same bytes\n" * 512)
    extra = _put(sftp, sftp.join(root, "p.bin"), b"same bytes\n" * 512)
    single = _put(sftp, sftp.join(root, "single.bin"), b"unique\n")
    now = time.time()
    sftp.sftp.utime(keep, (now - 86400, now - 86400))
    sftp.sftp.utime(extra, (now - 60, now - 60))
    return {"keep": keep, "extra": extra, "single": single}


@requires_sftp
def test_happy_sftp_dupes_index_and_dry_run_plan(sftp, isolated):
    import axross
    from core import cas as CAS

    root = _scratch(sftp, sftp.home(), "dupes")
    try:
        files = _dupes_tree(sftp, root)
        bid = CAS.backend_id_for(sftp)
        assert CAS.rebuild(sftp, root, backend_id=bid) == 3

        (scan,) = axross.duplicate_scans()
        assert (scan.root, scan.status, scan.backend_id) == (root, "complete", bid)
        groups = axross.duplicates(folder=root)
        assert [[e.path for e in g] for g in groups] == [[files["keep"], files["extra"]]]

        plan = axross.dedupe(folder=root, backends=[sftp])
        assert plan.dry_run is True
        assert [e.path for e in plan.keep] == [files["keep"]]
        assert [e.path for e in plan.trash] == [files["extra"]]
        assert "Dry run: 1 duplicate group(s), keep 1, trash 1" in plan.render()
        # A dry run touches nothing on the server.
        for path in files.values():
            assert sftp.exists(path), path
    finally:
        _rmtree(sftp, root)


@requires_sftp
def test_happy_sftp_dedupe_moves_the_copy_to_the_trash_and_back(sftp, isolated):
    import axross
    from core import cas as CAS
    from core import trash as T

    root = _scratch(sftp, sftp.home(), "dedupe")
    trash_root = sftp.join(root, ".axross-trash")
    try:
        files = _dupes_tree(sftp, root)
        CAS.rebuild(sftp, root, backend_id=CAS.backend_id_for(sftp))

        groups = CAS.duplicates(None, None, folder=root)
        result = CAS.dedupe(groups, {CAS.backend_id_for(sftp): sftp}, dry_run=False,
                            trash_root=trash_root)
        assert [e.path for e in result.removed] == [files["extra"]]
        assert (result.refused, result.failed) == ([], [])
        assert not sftp.exists(files["extra"])
        assert _get(sftp, files["keep"]) == b"same bytes\n" * 512

        (entry,) = T.list_trash(sftp, root=trash_root)
        assert entry.original_path == files["extra"]
        T.restore(sftp, entry.trash_id, root=trash_root)
        assert _get(sftp, files["extra"]) == b"same bytes\n" * 512
        # The index forgot the trashed copy: no duplicates left to plan.
        assert axross.duplicates(folder=root) == []
    finally:
        _rmtree(sftp, root)


@requires_sftp
def test_sad_sftp_dedupe_refuses_when_the_kept_copy_changed(sftp, isolated):
    from core import cas as CAS

    root = _scratch(sftp, sftp.home(), "dedupe-sad")
    try:
        files = _dupes_tree(sftp, root)
        bid = CAS.backend_id_for(sftp)
        CAS.rebuild(sftp, root, backend_id=bid)
        # After indexing, the survivor is rewritten: it no longer holds
        # the content, so removing the other copy would erase it.
        _put(sftp, files["keep"], b"edited after the scan\n")

        result = CAS.dedupe(CAS.duplicates(None, None, folder=root), {bid: sftp},
                            dry_run=False, trash_root=sftp.join(root, ".axross-trash"))
        assert result.removed == []
        assert [(e.path, why) for e, why in result.refused] == [
            (files["extra"], "no other verified copy would remain")
        ]
        assert _get(sftp, files["extra"]) == b"same bytes\n" * 512
    finally:
        _rmtree(sftp, root)


@requires_sftp
def test_edge_sftp_index_skips_symlinks_and_the_trash(sftp, isolated):
    from core import cas as CAS

    root = _scratch(sftp, sftp.home(), "dupes-edge")
    try:
        target = _put(sftp, sftp.join(root, "real.bin"), b"payload")
        sftp.symlink(target, sftp.join(root, "alias.bin"))
        sftp.mkdir(sftp.join(root, ".axross-trash"))
        _put(sftp, sftp.join(root, ".axross-trash", "old.bin"), b"payload")

        bid = CAS.backend_id_for(sftp)
        assert CAS.rebuild(sftp, root, backend_id=bid) == 1
        assert [e.path for e in CAS.list_for_backend(None, bid)] == [target]
        assert CAS.duplicates(None, None, folder=root) == []
    finally:
        _rmtree(sftp, root)


# ---------------------------------------------------------------------------
# Metadata read / remove on SFTP, S3 and WebDAV
# ---------------------------------------------------------------------------


def _metadata_round_trip(backend, folder: str) -> None:
    import axross
    from core import trash as T

    original = K.jpeg_bytes()
    path = _put(backend, backend.join(folder, "photo.jpg"), original)

    report = axross.metadata(backend, path)
    assert (report.kind, report.error) == ("image", "")
    assert report.removable > 0
    assert report.size == len(original)

    # Cleaned copy: the original is untouched, the copy carries no marker.
    (copy,) = axross.remove_metadata(backend, path, mode="copy")
    assert (copy.status, copy.error) == ("cleaned", "")
    assert copy.output == backend.join(folder, "photo.clean.jpg")
    assert _get(backend, path) == original
    assert K.MARK not in _get(backend, copy.output)

    # In place: the file is replaced, its original kept in the trash.
    (done,) = axross.remove_metadata(backend, path, mode="in_place")
    assert (done.status, done.error, done.output) == ("cleaned", "", path)
    cleaned = _get(backend, path)
    assert K.MARK not in cleaned
    assert hashlib.sha256(cleaned).hexdigest() == done.sha256
    assert axross.metadata(backend, path).removable == 0
    kept = [e for e in T.list_trash(backend) if e.trash_id == done.trash_id]
    assert [e.original_path for e in kept] == [path]
    T.discard(backend, done.trash_id)


@requires_sftp
def test_happy_sftp_metadata_read_and_remove(sftp, isolated):
    folder = _scratch(sftp, sftp.home(), "meta")
    try:
        _metadata_round_trip(sftp, folder)
    finally:
        _rmtree(sftp, folder)


@requires_s3
def test_happy_s3_metadata_read_and_remove(s3, isolated):
    folder = _scratch(s3, "/", "meta")
    try:
        _metadata_round_trip(s3, folder)
    finally:
        _rmtree(s3, folder)


@requires_webdav
def test_happy_webdav_metadata_read_and_remove(dav, isolated):
    folder = _scratch(dav, "/", "meta")
    try:
        _metadata_round_trip(dav, folder)
    finally:
        _rmtree(dav, folder)


@requires_sftp
def test_sad_sftp_metadata_of_missing_and_unsupported_files(sftp, isolated):
    import axross

    folder = _scratch(sftp, sftp.home(), "meta-sad")
    try:
        with pytest.raises(FileNotFoundError):
            axross.remove_metadata(sftp, sftp.join(folder, "absent.jpg"), mode="copy")
        text = _put(sftp, sftp.join(folder, "notes.txt"), b"plain text")
        assert axross.metadata(sftp, text).error == "not a supported file type"
        (result,) = axross.remove_metadata(sftp, text, mode="in_place")
        assert result.status == "unsupported"
        assert _get(sftp, text) == b"plain text"
        # A .jpg that is not a JPEG is reported, never "cleaned".
        fake = _put(sftp, sftp.join(folder, "fake.jpg"), b"not an image at all")
        (bad,) = axross.remove_metadata(sftp, fake, mode="in_place")
        assert bad.status == "error" and bad.error
        assert _get(sftp, fake) == b"not an image at all"
    finally:
        _rmtree(sftp, folder)


@requires_s3
def test_edge_s3_bare_jpeg_is_left_unchanged(s3, isolated):
    import axross

    folder = _scratch(s3, "/", "meta-edge")
    try:
        bare = K.jpeg_bytes(everything=False)
        path = _put(s3, s3.join(folder, "bare.jpg"), bare)
        (result,) = axross.remove_metadata(s3, path, mode="in_place")
        assert result.status == "unchanged"
        assert _get(s3, path) == bare
        assert not s3.exists(s3.join(folder, "bare.clean.jpg"))
    finally:
        _rmtree(s3, folder)


# ---------------------------------------------------------------------------
# Copy and move between two different remote backends
# ---------------------------------------------------------------------------


@pytest.fixture
def manager():
    pytest.importorskip("PyQt6")
    from PyQt6.QtWidgets import QApplication

    from core.transfer_manager import TransferManager

    app = QApplication.instance() or QApplication([])
    mgr = TransferManager()
    try:
        yield app, mgr
    finally:
        mgr.shutdown()


def _wait(app, jobs, timeout: float = 60.0) -> None:
    from core.transfer_worker import TransferStatus

    deadline = time.monotonic() + timeout
    while any(j.status in (TransferStatus.PENDING, TransferStatus.ACTIVE) for j in jobs):
        app.processEvents()
        if time.monotonic() > deadline:
            raise AssertionError(f"transfer did not finish: {[j.status for j in jobs]}")
        time.sleep(0.02)
    app.processEvents()


def _payload(size: int) -> bytes:
    return os.urandom(size)


@requires_sftp
@requires_s3
@requires_webdav
def test_happy_transfer_queue_copies_sftp_to_s3_and_moves_s3_to_webdav(
    sftp, s3, dav, manager, isolated
):
    from core.transfer_worker import TransferStatus

    app, mgr = manager
    src_dir = _scratch(sftp, sftp.home(), "xfer")
    s3_dir = _scratch(s3, "/", "xfer")
    dav_dir = _scratch(dav, "/", "xfer")
    data = _payload(3 * 1024 * 1024 + 17)  # several transfer chunks
    try:
        src = _put(sftp, sftp.join(src_dir, "blob.bin"), data)

        jobs = mgr.transfer_files(sftp, s3, [src], s3_dir)
        _wait(app, jobs)
        assert [(j.status, j.error_message) for j in jobs] == [(TransferStatus.DONE, "")]
        assert _get(s3, s3.join(s3_dir, "blob.bin")) == data
        assert sftp.exists(src)  # a copy keeps its source

        jobs = mgr.transfer_files(s3, dav, [s3.join(s3_dir, "blob.bin")], dav_dir, move=True)
        _wait(app, jobs)
        assert [(j.status, j.error_message) for j in jobs] == [(TransferStatus.DONE, "")]
        assert _get(dav, dav.join(dav_dir, "blob.bin")) == data
        assert not s3.exists(s3.join(s3_dir, "blob.bin"))  # a move removes it
    finally:
        _rmtree(sftp, src_dir)
        _rmtree(s3, s3_dir)
        _rmtree(dav, dav_dir)


@requires_sftp
@requires_webdav
def test_happy_scripting_copy_and_move_between_sftp_and_webdav(sftp, dav, isolated):
    import axross

    src_dir = _scratch(sftp, sftp.home(), "script-xfer")
    dav_dir = _scratch(dav, "/", "script-xfer")
    data = _payload(1024 * 1024 + 5)
    try:
        src = _put(sftp, sftp.join(src_dir, "a.bin"), data)
        copied = dav.join(dav_dir, "a-copy.bin")
        assert axross.copy(sftp, src, dav, copied) == len(data)
        assert _get(dav, copied) == data and sftp.exists(src)

        moved = dav.join(dav_dir, "a-moved.bin")
        assert axross.move(sftp, src, dav, moved) == len(data)
        assert _get(dav, moved) == data
        assert not sftp.exists(src)
    finally:
        _rmtree(sftp, src_dir)
        _rmtree(dav, dav_dir)


@requires_sftp
@requires_s3
def test_sad_cross_backend_move_onto_an_existing_file_keeps_both(sftp, s3, isolated):
    import axross

    src_dir = _scratch(sftp, sftp.home(), "xfer-sad")
    s3_dir = _scratch(s3, "/", "xfer-sad")
    try:
        src = _put(sftp, sftp.join(src_dir, "a.txt"), b"new")
        dst = _put(s3, s3.join(s3_dir, "a.txt"), b"old")
        with pytest.raises(FileExistsError):
            axross.move(sftp, src, s3, dst)
        assert _get(sftp, src) == b"new"
        assert _get(s3, dst) == b"old"
    finally:
        _rmtree(sftp, src_dir)
        _rmtree(s3, s3_dir)


@requires_sftp
@requires_s3
def test_sad_transfer_queue_reports_a_missing_source(sftp, s3, manager, isolated):
    from core.transfer_worker import TransferStatus

    app, mgr = manager
    s3_dir = _scratch(s3, "/", "xfer-missing")
    try:
        missing = sftp.join(sftp.home(), f"absent-{uuid.uuid4().hex}.bin")
        job = mgr.transfer_file(sftp, s3, missing, s3.join(s3_dir, "absent.bin"))
        _wait(app, [job])
        assert job.status == TransferStatus.ERROR and job.error_message
        assert not s3.exists(s3.join(s3_dir, "absent.bin"))
    finally:
        _rmtree(s3, s3_dir)


@requires_sftp
@requires_webdav
def test_edge_transfer_queue_moves_a_folder_tree_and_an_empty_file(sftp, dav, manager, isolated):
    from core.transfer_worker import TransferStatus

    app, mgr = manager
    src_dir = _scratch(sftp, sftp.home(), "xfer-tree")
    dav_dir = _scratch(dav, "/", "xfer-tree")
    try:
        tree = sftp.join(src_dir, "tree")
        sftp.mkdir(tree)
        sftp.mkdir(sftp.join(tree, "sub"))
        _put(sftp, sftp.join(tree, "empty.txt"), b"")
        _put(sftp, sftp.join(tree, "sub", "deep.txt"), b"deep\n")

        jobs = mgr.transfer_files(sftp, dav, [tree], dav_dir, move=True)
        _wait(app, jobs)
        assert {j.status for j in jobs} == {TransferStatus.DONE}, [j.error_message for j in jobs]
        assert _get(dav, dav.join(dav_dir, "tree", "empty.txt")) == b""
        assert _get(dav, dav.join(dav_dir, "tree", "sub", "deep.txt")) == b"deep\n"
        assert not sftp.exists(tree)
    finally:
        _rmtree(sftp, src_dir)
        _rmtree(dav, dav_dir)
