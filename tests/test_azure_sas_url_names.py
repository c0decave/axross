"""Azure Blob sas_url() (review round 2): the blob name goes into the URL
quoted, at the account's own endpoint.

The name was pasted in as it is: "report #2.txt" ended the URL at the
"#", "a?b" put the signature after the wrong "?", and an account on
Azurite, a sovereign cloud or a custom domain got a link to
blob.core.windows.net.
"""

from __future__ import annotations

import sys
from pathlib import Path
from urllib.parse import unquote, urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

pytest.importorskip("azure.storage.blob")
from azure.storage.blob import BlobServiceClient  # noqa: E402

from core import azure_client as AZ  # noqa: E402

KEY = "a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5a2V5"


def _session(endpoint: str):
    s = object.__new__(AZ.AzureBlobSession)
    s._account_key = KEY
    s._service = BlobServiceClient(account_url=endpoint, credential={"account_name": "acct",
                                                                     "account_key": KEY})
    s._container_name = "box"
    s._container = s._service.get_container_client("box")
    return s


@pytest.mark.parametrize("name", ["report #2.txt", "a?b.txt", "100%.txt", "dir/x y.txt"])
def test_sad_name_is_quoted(name) -> None:
    url = _session("https://acct.blob.core.windows.net").sas_url("/" + name)
    parts = urlsplit(url)
    assert parts.fragment == ""
    assert unquote(parts.path) == "/box/" + name
    assert "sig=" in parts.query and "se=" in parts.query


def test_sad_the_accounts_own_endpoint() -> None:
    url = _session("http://127.0.0.1:10000/acct").sas_url("/f.txt")
    assert url.startswith("http://127.0.0.1:10000/acct/box/f.txt?")
