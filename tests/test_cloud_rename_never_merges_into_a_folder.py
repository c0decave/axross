"""S3 and Azure Blob rename() never merge into an existing folder.

Both rename by copy + delete, object by object. Measured on the lab's
MinIO (10.99.0.33) and Azurite (10.99.0.39), the twins of the rsync bug
(tests/test_rsync_rename_never_lands_inside.py):

* ``rename("/t/proj", "/t/Archive")`` with Archive an existing folder
  copied proj/p.txt over Archive/p.txt, deleted proj and returned - the
  old Archive/p.txt was gone.
* ``rename("/t/report.txt", "/t/Archive")`` wrote an object named
  "Archive" beside the folder "Archive/": the S3 listing then showed only
  the FILE Archive, the folder and everything in it vanished from view.

Now a folder destination is IsADirectoryError and a folder over a file
FileExistsError, before anything is copied or deleted.
"""

from __future__ import annotations

import os
import socket
import sys
import uuid
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))


# ------------------------------------------------------------------ offline

def _s3(tree):
    pytest.importorskip("boto3")
    from core.s3_client import S3Session

    s = object.__new__(S3Session)
    s._anonymous = False
    s._bucket = "b"
    s._s3 = mock.MagicMock()
    s.is_dir = lambda p: tree.get(p) is True
    s.exists = lambda p: p in tree
    s._object_beside_prefix = lambda key, path: False
    return s, s._s3


def _azure(tree):
    pytest.importorskip("azure.storage.blob")
    from core.azure_client import AzureBlobSession

    s = object.__new__(AzureBlobSession)
    s._container = mock.MagicMock()
    s.is_dir = lambda p: tree.get(p) is True
    s.exists = lambda p: p in tree
    s._blob_at = lambda key, path: None
    return s, s._container


TREE = {"/t/Archive": True, "/t/proj": True, "/t/report.txt": False, "/t/old.txt": False}
MAKERS = {"s3": _s3, "azure": _azure}


@pytest.mark.parametrize("kind", list(MAKERS))
@pytest.mark.parametrize("src", ["/t/report.txt", "/t/proj"])
def test_sad_rename_onto_a_folder_touches_nothing(kind, src):
    s, client = MAKERS[kind](TREE)
    with pytest.raises(IsADirectoryError):
        s.rename(src, "/t/Archive")
    assert client.method_calls == []


@pytest.mark.parametrize("kind", list(MAKERS))
def test_sad_a_folder_over_a_file_touches_nothing(kind):
    s, client = MAKERS[kind](TREE)
    with pytest.raises(FileExistsError):
        s.rename("/t/proj", "/t/old.txt")
    assert client.method_calls == []


@pytest.mark.parametrize("kind", list(MAKERS))
def test_edge_a_failed_destination_check_touches_nothing(kind):
    s, client = MAKERS[kind](TREE)

    def broken(path):
        if path == "/t/new":
            raise TimeoutError("check timed out")
        return TREE.get(path) is True

    s.is_dir = broken
    with pytest.raises(OSError):
        s.rename("/t/report.txt", "/t/new")
    assert client.method_calls == []


# ------------------------------------------------------------------ live (lab)

def _up(host, port):
    try:
        with socket.create_connection((host, port), timeout=0.5):
            return True
    except OSError:
        return False


@pytest.fixture(params=["s3", "azure"])
def lab(request):
    import test_protocols as TP

    if request.param == "s3":
        pytest.importorskip("boto3")
        if not _up(TP.S3_HOST, TP.S3_PORT):
            pytest.skip("lab MinIO not reachable")
        from core.s3_client import S3Session

        s = S3Session(bucket=TP.S3_BUCKET, region="us-east-1", access_key=TP.S3_ACCESS_KEY,
                      secret_key=TP.S3_SECRET_KEY, endpoint=TP.S3_ENDPOINT)
        try:
            s._s3.create_bucket(Bucket=TP.S3_BUCKET)
        except Exception:  # noqa: BLE001 - it exists already
            pass
    else:
        pytest.importorskip("azure.storage.blob")
        if not _up(TP.AZURITE_HOST, 10000):
            pytest.skip("lab Azurite not reachable")
        from azure.storage.blob import BlobServiceClient

        from core.azure_client import AzureBlobSession

        container = BlobServiceClient.from_connection_string(
            TP.AZURITE_CONNECTION_STRING).get_container_client(TP.AZURITE_CONTAINER)
        try:
            container.create_container()
        except Exception:  # noqa: BLE001 - it exists already
            pass
        s = AzureBlobSession(connection_string=TP.AZURITE_CONNECTION_STRING,
                             container=TP.AZURITE_CONTAINER)
    base = "/audit-" + uuid.uuid4().hex[:8]
    for name, data in (("Archive/p.txt", b"archived p"), ("Archive/one.txt", b"keep"),
                       ("proj/p.txt", b"p"), ("report.txt", b"report")):
        with s.open_write(f"{base}/{name}") as fh:
            fh.write(data)
    try:
        yield s, base
    finally:
        s.remove(base, recursive=True)


def _read(s, path):
    with s.open_read(path) as fh:
        return fh.read()


def test_e2e_lab_rename_onto_a_folder_keeps_both(lab):
    s, base = lab
    with pytest.raises(IsADirectoryError):
        s.rename(base + "/proj", base + "/Archive")
    with pytest.raises(IsADirectoryError):
        s.rename(base + "/report.txt", base + "/Archive")
    assert _read(s, base + "/Archive/p.txt") == b"archived p"
    assert _read(s, base + "/proj/p.txt") == b"p"
    assert sorted((i.name, i.is_dir) for i in s.list_dir(base)) == [
        ("Archive", True), ("proj", True), ("report.txt", False)]


def test_e2e_lab_rename_onto_free_names_still_works(lab):
    s, base = lab
    s.rename(base + "/report.txt", base + "/renamed.txt")
    s.rename(base + "/proj", base + "/project")
    assert _read(s, base + "/renamed.txt") == b"report"
    assert _read(s, base + "/project/p.txt") == b"p"
    assert not s.exists(base + "/proj") and not s.exists(base + "/report.txt")
    assert os.path.basename(base)
