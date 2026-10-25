"""Where an OAuth sign-in's credentials come from, for the connection dialog.

axross ships no OAuth client of its own for these services: Google's
``drive`` scope is a restricted one (a public client needs Google's
verification), and Microsoft and Dropbox tie a client to an app the user
registers. Each guide says what to create where (the full walk-through is
OAUTH_SETUP.md) and that the sign-in itself happens in the browser when
the connection opens. Google lets the user download the client as a JSON
file: :func:`parse_google_client` takes the two values from it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

#: A Google client file is a few hundred bytes; anything far larger is no such file.
MAX_CLIENT_FILE_BYTES = 64 * 1024


@dataclass(frozen=True)
class Guide:
    console_url: str
    console_name: str
    steps: tuple[str, ...]
    sign_in: str


_BROWSER = ("Connecting opens the browser for the sign-in; the token is then kept "
            "for this connection and renewed by itself.")

GUIDES: dict[str, Guide] = {
    "gdrive": Guide(
        "https://console.cloud.google.com/apis/credentials",
        "Google Cloud Console",
        (
            "Create a project and enable the Google Drive API.",
            "Create an OAuth client ID of type Desktop app.",
            "OAuth consent screen: add the scope …/auth/drive and yourself as a test user.",
            "Enter Client ID and Client Secret - or download the client's JSON file and "
            "use Import Client JSON…",
        ),
        _BROWSER,
    ),
    "onedrive": Guide(
        "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
        "Azure Portal - App registrations",
        (
            "New registration; redirect URI: Public client/native, http://localhost.",
            "API permissions (Microsoft Graph, delegated): Files.ReadWrite.All, User.Read.",
            "Authentication: Allow public client flows = Yes.",
            "Enter the Application (client) ID; Tenant ID: common for a personal account.",
        ),
        _BROWSER,
    ),
    "sharepoint": Guide(
        "https://portal.azure.com/#view/Microsoft_AAD_RegisteredApps/ApplicationsListBlade",
        "Azure Portal - App registrations",
        (
            "New registration; redirect URI: Public client/native, http://localhost.",
            "API permissions (Microsoft Graph, delegated): Files.ReadWrite.All, "
            "Sites.ReadWrite.All, User.Read.",
            "Authentication: Allow public client flows = Yes.",
            "Enter the Application (client) ID, your tenant and the Site URL.",
        ),
        _BROWSER,
    ),
    "dropbox": Guide(
        "https://www.dropbox.com/developers/apps",
        "Dropbox App Console",
        (
            "Create app: Scoped access, Full Dropbox.",
            "Permissions: files.metadata.read/write, files.content.read/write, "
            "account_info.read - then Submit.",
            "Enter the App key (the secret is optional: axross signs in with PKCE).",
        ),
        "Connecting opens the browser for the sign-in; Dropbox then shows a code, "
        "which axross asks for in a window. The token is kept and renewed by itself.",
    ),
}


def parse_google_client(text: str) -> tuple[str, str]:
    """``(client_id, client_secret)`` from a Google client JSON file;
    ValueError with the reason when it is none or the wrong kind."""
    if len(text) > MAX_CLIENT_FILE_BYTES:
        raise ValueError("the file is too large to be a Google client file")
    try:
        data = json.loads(text)
    except ValueError:
        raise ValueError("the file is no JSON") from None
    if not isinstance(data, dict):
        raise ValueError("the file is no Google client file")
    if "installed" not in data and isinstance(data.get("web"), dict):
        raise ValueError("this is a Web application client - create one of type Desktop app")
    client = data.get("installed")
    if not isinstance(client, dict):
        raise ValueError("the file is no Google client file (no Desktop app client in it)")
    client_id, secret = client.get("client_id"), client.get("client_secret")
    if not isinstance(client_id, str) or not isinstance(secret, str) \
            or not client_id.strip() or not secret.strip():
        raise ValueError("the client file has no client ID and secret")
    return client_id.strip(), secret.strip()


__all__ = ["GUIDES", "Guide", "MAX_CLIENT_FILE_BYTES", "parse_google_client"]
