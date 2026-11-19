"""Connecting to Azure Blob / Files: a container- or share-scoped SAS
connects, and a refused login, a missing container and a closed port say
what is wrong.

Measured against Azurite and tests/fake_azure_storage.py (the SDK talks
HTTP to it as to Azure):

* A container SAS ("Generate SAS" on a container in the portal) could not
  connect at all: the connect probe was Get Container Properties, which a
  service SAS may not call (403 AuthorizationPermissionMismatch), although
  it lists, reads and writes the container. Same for a share SAS and Get
  Share Properties.
* A wrong account key: "Permission denied for the item. Your account has no
  rights to it there; choose another place ..." - no word of the key.
* A missing container: "the item was not found. It may have been moved or
  deleted; refresh the folder ..."
* A closed port: "The connection was closed by the other side."
"""

from __future__ import annotations

import socket
import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))

pytest.importorskip("azure.storage.blob")
pytest.importorskip("azure.storage.fileshare")

from fake_azure_storage import FakeAzureStorage  # noqa: E402

from core.azure_client import AzureBlobSession, AzureFilesSession  # noqa: E402
from core.user_errors import describe  # noqa: E402


@pytest.fixture(autouse=True)
def _no_proxy_env(monkeypatch):
    for name in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy", "ALL_PROXY",
                 "all_proxy"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("NO_PROXY", "127.0.0.1")


@pytest.fixture
def azure():
    server = FakeAzureStorage()
    yield server
    server.close()


def test_happy_a_container_sas_connects_although_it_may_not_read_the_properties(azure):
    azure.answers["container_props"] = (403, "AuthorizationPermissionMismatch")
    session = AzureBlobSession(connection_string=azure.sas_connection_string(), container="ctr")
    assert session.list_dir("/") == []
    assert session.connected
    assert ("GET", "/devstoreaccount1/ctr", "container_list") in azure.requests


def test_happy_a_share_sas_connects_although_it_may_not_read_the_properties(azure):
    azure.answers["share_props"] = (403, "AuthorizationResourceTypeMismatch")
    session = AzureFilesSession(
        connection_string=azure.sas_connection_string("File"), share_name="share")
    assert session.connected
    assert any(op == "dir_list" for _m, _p, op in azure.requests)


def test_sad_a_sas_that_may_not_list_either_is_refused(azure):
    azure.answers["container_props"] = (403, "AuthorizationPermissionMismatch")
    azure.answers["container_list"] = (403, "AuthorizationPermissionMismatch")
    with pytest.raises(PermissionError):
        AzureBlobSession(connection_string=azure.sas_connection_string(), container="ctr")


@pytest.mark.parametrize("code", ["AuthenticationFailed", "AuthorizationFailure"])
def test_sad_a_wrong_key_says_to_check_the_key(azure, code):
    azure.answers["container_props"] = (403, code)
    with pytest.raises(PermissionError) as info:
        AzureBlobSession(connection_string=azure.key_connection_string(), container="ctr")
    text = describe(info.value)
    assert "account key" in text and "SAS" in text
    assert "the item" not in text


def test_sad_a_wrong_key_on_a_share_says_to_check_the_key(azure):
    azure.answers["share_props"] = (403, "AuthenticationFailed")
    with pytest.raises(PermissionError) as info:
        AzureFilesSession(connection_string=azure.key_connection_string("File"),
                          share_name="share")
    assert "account key" in describe(info.value)


def test_sad_a_missing_container_is_named(azure):
    azure.answers["container_props"] = (404, "ContainerNotFound")
    with pytest.raises(FileNotFoundError) as info:
        AzureBlobSession(connection_string=azure.key_connection_string(), container="photos")
    text = describe(info.value)
    assert "photos" in text and "does not exist" in text
    assert "refresh the folder" not in text


def test_sad_a_missing_share_is_named(azure):
    azure.answers["share_props"] = (404, "ShareNotFound")
    with pytest.raises(FileNotFoundError) as info:
        AzureFilesSession(connection_string=azure.key_connection_string("File"),
                          share_name="backups")
    text = describe(info.value)
    assert "backups" in text and "does not exist" in text


def test_sad_a_closed_port_is_a_refused_connection():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    cs = (f"DefaultEndpointsProtocol=http;AccountName=devstoreaccount1;AccountKey=a2V5;"
          f"BlobEndpoint=http://127.0.0.1:{port}/devstoreaccount1;")
    started = time.monotonic()
    with pytest.raises(ConnectionRefusedError) as info:
        AzureBlobSession(connection_string=cs, container="ctr")
    # Not the SDK's three retries 15 s, 18 s and 24 s apart (82 s measured).
    assert time.monotonic() - started < 15
    text = describe(info.value)
    assert "refused the connection" in text and "closed by the other side" not in text


def test_sad_a_dropped_server_is_not_connected_any_more(azure):
    session = AzureBlobSession(connection_string=azure.key_connection_string(), container="ctr")
    assert session.connected
    azure.close()
    started = time.monotonic()
    assert not session.connected
    assert time.monotonic() - started < 15  # 89 s with the SDK's retries
