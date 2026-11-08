"""Two cloud profiles for two accounts never share one session.

Google Drive, Dropbox, OneDrive and SharePoint keep a token file per
profile NAME (connection_manager._profile_token_files), so the profile
name picks the signed-in account. The session key left the name out for
every protocol but ramfs: "Work" and "Personal" with the same app key /
client id and no host or username got the session of whichever connected
first, and the second profile's uploads and deletes went to the first
account. NNTP over TLS and plaintext NNTP to one host and port shared a
key too (``nntp_ssl`` was not part of it), so a TLS profile could reuse a
cleartext session.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core.connection_manager import ConnectionManager  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402


class _Fake:
    connected = True

    def __init__(self, who: str):
        self.who = who

    def close(self) -> None:
        pass

    def disconnect(self) -> None:
        pass


@pytest.fixture
def cm():
    manager = ConnectionManager()
    manager._create_session = lambda prof, *a, **k: _Fake(prof.name)
    return manager


CLOUD = [
    ("gdrive", "gdrive_client_id"),
    ("dropbox", "dropbox_app_key"),
    ("onedrive", "onedrive_client_id"),
    ("sharepoint", "onedrive_client_id"),
]


@pytest.mark.parametrize("proto, field", CLOUD, ids=[c[0] for c in CLOUD])
def test_sad_two_accounts_with_one_app_key_get_two_sessions(cm, proto, field):
    work = ConnectionProfile(name="Work", protocol=proto, **{field: "same-app"})
    home = ConnectionProfile(name="Personal", protocol=proto, **{field: "same-app"})
    a = cm.connect(work)
    b = cm.connect(home)
    assert a is not b
    assert (a.who, b.who) == ("Work", "Personal")


@pytest.mark.parametrize("proto, field", CLOUD, ids=[c[0] for c in CLOUD])
def test_happy_one_cloud_profile_reuses_its_own_session(cm, proto, field):
    profile = ConnectionProfile(name="Work", protocol=proto, **{field: "same-app"})
    assert cm.connect(profile) is cm.connect(profile)


def test_edge_network_profiles_to_one_server_still_share(cm):
    a = ConnectionProfile(name="one", protocol="sftp", host="h", username="u")
    b = ConnectionProfile(name="two", protocol="sftp", host="h", username="u")
    assert cm.connect(a) is cm.connect(b)


def test_sad_tls_nntp_never_reuses_a_plaintext_session(cm):
    plain = ConnectionProfile(name="p", protocol="nntp", host="news", port=119, nntp_ssl=False)
    tls = ConnectionProfile(name="t", protocol="nntp", host="news", port=119, nntp_ssl=True)
    assert cm.connect(plain) is not cm.connect(tls)
