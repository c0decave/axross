"""A public Azure Blob container opens without a key.

Microsoft's Open Datasets (account azureopendatastorage, container
nyctlc) allow anonymous read: an unsigned List Blobs answers. The
connection dialog accepts an account name alone, but AzureBlobSession
refused it: "Provide connection_string, or account_name with account_key
or sas_token". Now an account name without key or SAS connects
anonymously; a SAS URL cannot be signed without a key, and Azure Files
has no anonymous access.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import azure_client as AZ  # noqa: E402


class _Container:
    def get_container_properties(self):
        return {}


class _Service:
    made: list[dict] = []

    def __init__(self, account_url=None, credential="unset", **kw):
        _Service.made.append({"account_url": account_url, "credential": credential})

    def get_container_client(self, name):
        return _Container()


@pytest.fixture
def service(monkeypatch):
    _Service.made = []
    monkeypatch.setattr(AZ, "BlobServiceClient", _Service)
    return _Service.made


# --- happy ----------------------------------------------------------------


def test_happy_an_account_name_alone_connects_anonymously(service):
    AZ.AzureBlobSession(account_name="azureopendatastorage", container="nyctlc")
    assert service == [
        {"account_url": "https://azureopendatastorage.blob.core.windows.net", "credential": None}
    ]


def test_happy_a_key_still_signs(service):
    AZ.AzureBlobSession(account_name="acct", account_key="a2V5", container="c")
    assert service[0]["credential"] == {"account_name": "acct", "account_key": "a2V5"}


# --- sad ------------------------------------------------------------------


def test_sad_nothing_at_all_is_still_refused(service):
    with pytest.raises(ValueError):
        AZ.AzureBlobSession(container="c")


def test_sad_an_anonymous_session_cannot_sign_a_sas_url(service):
    s = AZ.AzureBlobSession(account_name="azureopendatastorage", container="nyctlc")
    with pytest.raises(OSError):
        s.sas_url("/x.parquet")


# --- edge -----------------------------------------------------------------


def test_edge_azure_files_has_no_anonymous_access():
    with pytest.raises(ValueError):
        AZ.AzureFilesSession(account_name="acct", share_name="s")
