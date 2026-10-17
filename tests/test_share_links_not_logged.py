"""A created share link is returned, never written to the log.

Dropbox shared_link_create, OneDrive share and Google Drive share logged
the "anyone with the link" URL in full at INFO: whoever reads the log can
open the file. S3 presign and Azure sas_url already log only the
bucket/container and key. The log now names the path, not the link.
"""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from types import SimpleNamespace as NS
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

dropbox_exceptions = pytest.importorskip("dropbox.exceptions")
requests = pytest.importorskip("requests")

from requests_fuzz_adapter import mount  # noqa: E402

from core.dropbox_client import DropboxSession  # noqa: E402
from core.gdrive_client import GDriveSession  # noqa: E402
from core.onedrive_client import OneDriveSession  # noqa: E402

SECRET = "SECRETKEY"
DBX_URL = f"https://www.dropbox.com/scl/fi/ID/a.pdf?rlkey={SECRET}&dl=0"
OD_URL = f"https://1drv.ms/b/s!{SECRET}"
GD_URL = f"https://drive.google.com/file/d/{SECRET}/view?usp=sharing"


def _dropbox(create) -> DropboxSession:
    d = DropboxSession.__new__(DropboxSession)
    dbx = NS(
        sharing_create_shared_link_with_settings=create,
        sharing_list_shared_links=lambda path, direct_only: NS(links=[NS(url=DBX_URL)]),
    )
    d._ensure_connected = lambda: dbx
    return d


def _onedrive() -> OneDriveSession:
    o = OneDriveSession.__new__(OneDriveSession)
    o._http = requests.Session()
    mount(o._http, lambda r: (200, {}, json.dumps({"link": {"webUrl": OD_URL}}).encode()))
    o._access_token = "t"
    o._app = mock.Mock()
    o._app.get_accounts.return_value = [{"username": "u"}]
    o._app.acquire_token_silent.return_value = {"access_token": "t"}
    o._cache = mock.Mock(has_state_changed=False)
    o._drive_type, o._site_id, o._scopes = "personal", None, []
    return o


def _gdrive() -> GDriveSession:
    class Req:
        def __init__(self, answer):
            self.answer = answer

        def execute(self):
            return self.answer

    svc = NS(
        permissions=lambda: NS(create=lambda **kw: Req({"id": "P1"})),
        files=lambda: NS(get=lambda **kw: Req({"webViewLink": GD_URL})),
    )
    g = GDriveSession.__new__(GDriveSession)
    g._service = svc
    g._path_cache = {"/": "root", "/a.pdf": "F1"}
    return g


def _shared_logs(caplog) -> str:
    return "\n".join(r.getMessage() for r in caplog.records)


# -- happy -------------------------------------------------------------------


def test_happy_dropbox_link_is_returned_and_only_the_path_logged(caplog):
    caplog.set_level(logging.DEBUG)
    d = _dropbox(lambda p, settings: NS(url=DBX_URL))
    assert d.shared_link_create("/a.pdf") == DBX_URL
    text = _shared_logs(caplog)
    assert "/a.pdf" in text
    assert SECRET not in text


def test_happy_onedrive_link_is_returned_and_only_the_path_logged(caplog):
    caplog.set_level(logging.DEBUG)
    assert _onedrive().share("/a.pdf") == OD_URL
    text = _shared_logs(caplog)
    assert "/a.pdf" in text
    assert SECRET not in text


def test_happy_gdrive_link_is_returned_and_only_the_path_logged(caplog):
    caplog.set_level(logging.DEBUG)
    assert _gdrive().share("/a.pdf")["url"] == GD_URL
    text = _shared_logs(caplog)
    assert "/a.pdf" in text
    assert SECRET not in text


# -- sad ---------------------------------------------------------------------


def test_sad_dropbox_reused_existing_link_is_not_logged_either(caplog):
    caplog.set_level(logging.DEBUG)

    def already(p, settings):
        raise dropbox_exceptions.ApiError("rid", "shared_link_already_exists", None, None)

    assert _dropbox(already).shared_link_create("/a.pdf") == DBX_URL
    text = _shared_logs(caplog)
    assert "/a.pdf" in text
    assert SECRET not in text


# -- edge --------------------------------------------------------------------


def test_edge_the_link_is_absent_at_every_log_level(caplog):
    caplog.set_level(logging.DEBUG)
    _dropbox(lambda p, settings: NS(url=DBX_URL)).shared_link_create("/a.pdf")
    _onedrive().share("/a.pdf", password="pw", expires="2026-12-31T23:59:59Z")
    _gdrive().share("/a.pdf")
    assert all(SECRET not in r.getMessage() for r in caplog.records)
    assert all("pw" not in r.getMessage().split() for r in caplog.records)
