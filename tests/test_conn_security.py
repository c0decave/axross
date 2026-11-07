"""core.conn_security: how a connection is protected - from a profile's
settings ("configured") and from the live connection objects ("negotiated":
a real in-memory TLS handshake, fakes of paramiko's Transport and of
smbprotocol's Session) - and the security_info() of the backends."""

from __future__ import annotations

import os
import ssl
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from fake_ircd import self_signed  # noqa: E402

from core import conn_security as CS  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402


def _profile(protocol, **fields):
    return ConnectionProfile(name="p", protocol=protocol, host="h.example", **fields)


def tls_pair(tmp_path, *, maximum=None):
    """A client SSLObject after a real handshake with a server in memory."""
    cert, key, _der = self_signed(tmp_path)
    server_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    server_ctx.load_cert_chain(cert, key)
    if maximum is not None:
        server_ctx.maximum_version = maximum
    client_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_ctx.load_verify_locations(cert)
    c_in, c_out, s_in, s_out = (ssl.MemoryBIO() for _ in range(4))
    client = client_ctx.wrap_bio(c_in, c_out, server_hostname="localhost")
    server = server_ctx.wrap_bio(s_in, s_out, server_side=True)
    for _ in range(10):
        for side in (client, server):
            try:
                side.do_handshake()
            except ssl.SSLWantReadError:
                pass
        s_in.write(c_out.read())
        c_in.write(s_out.read())
        if client.version() and server.version():
            try:
                client.do_handshake()
                break
            except ssl.SSLWantReadError:
                continue
    assert client.version()
    return client


# --- configured -------------------------------------------------------------------------------

@pytest.mark.parametrize("protocol, fields, level, words", [
    ("ftp", {}, CS.LEVEL_CLEARTEXT, "FTP - cleartext"),
    ("ftps", {}, CS.LEVEL_TLS, "certificate verified"),
    ("ftps", {"ftps_verify_tls": False}, CS.LEVEL_TLS_WEAK, "NOT verified"),
    ("sftp", {}, CS.LEVEL_ENCRYPTED, "SSH"),
    ("scp", {}, CS.LEVEL_ENCRYPTED, "SSH"),
    ("rsync", {"rsync_ssh": True}, CS.LEVEL_ENCRYPTED, "over SSH"),
    ("rsync", {}, CS.LEVEL_CLEARTEXT, "rsync://"),
    ("smb", {}, CS.LEVEL_SIGNED, "signing"),
    ("webdav", {"webdav_url": "https://dav.example/remote.php"}, CS.LEVEL_TLS, "HTTPS"),
    ("webdav", {"webdav_url": "http://dav.example/"}, CS.LEVEL_CLEARTEXT, "http://"),
    ("s3", {}, CS.LEVEL_TLS, "Amazon S3"),
    ("s3", {"s3_endpoint": "http://minio.local:9000"}, CS.LEVEL_CLEARTEXT, "http://"),
    ("s3", {"s3_endpoint": "minio.example"}, CS.LEVEL_TLS, "HTTPS"),
    ("nfs", {}, CS.LEVEL_CLEARTEXT, "AUTH_SYS"),
    ("iscsi", {}, CS.LEVEL_CLEARTEXT, "CHAP"),
    ("imap", {}, CS.LEVEL_TLS, "IMAP over TLS"),
    ("imap", {"imap_ssl": False}, CS.LEVEL_CLEARTEXT, "IMAP without TLS"),
    ("pop3", {"pop3_ssl": False}, CS.LEVEL_CLEARTEXT, "POP3"),
    ("azure_blob", {"azure_connection_string": "DefaultEndpointsProtocol=http;AccountName=a"},
     CS.LEVEL_CLEARTEXT, "http://"),
    ("azure_blob", {}, CS.LEVEL_TLS, "Azure"),
    ("gdrive", {}, CS.LEVEL_TLS, "Google Drive"),
    ("telnet", {}, CS.LEVEL_CLEARTEXT, "Telnet"),
    ("tftp", {}, CS.LEVEL_CLEARTEXT, "no login"),
    ("adb", {"adb_mode": "usb"}, CS.LEVEL_LOCAL, "USB"),
    ("adb", {}, CS.LEVEL_CLEARTEXT, "TCP"),
    ("ramfs", {}, CS.LEVEL_LOCAL, "memory"),
])
def test_happy_every_protocol_says_what_it_is_configured_for(protocol, fields, level, words):
    info = CS.from_profile(_profile(protocol, **fields))
    assert info.level == level and words in info.summary and info.negotiated is False


def test_happy_svn_follows_its_address():
    assert CS.from_profile(ConnectionProfile(protocol="svn", host="svn+ssh://h/r")).level == CS.LEVEL_ENCRYPTED
    assert CS.from_profile(ConnectionProfile(protocol="svn", host="svn://h/r")).level == CS.LEVEL_CLEARTEXT
    assert CS.from_profile(ConnectionProfile(protocol="svn", host="https://h/r")).level == CS.LEVEL_TLS


def test_edge_an_unknown_protocol_is_unknown_not_safe():
    info = CS.from_profile(SimpleNamespace(protocol="carrier-pigeon"))
    assert info.level == CS.LEVEL_UNKNOWN and "carrier-pigeon" in info.summary


def test_happy_the_weakest_wins_and_local_counts_as_strong():
    infos = [CS.LOCAL, CS.SecurityInfo(CS.LEVEL_TLS, "a"), CS.SecurityInfo(CS.LEVEL_SIGNED, "b")]
    assert CS.weakest(infos).level == CS.LEVEL_SIGNED
    assert CS.weakest(infos + [CS.SecurityInfo(CS.LEVEL_CLEARTEXT, "c")]).level == CS.LEVEL_CLEARTEXT
    assert CS.weakest([CS.LOCAL, CS.SecurityInfo(CS.LEVEL_E2E, "x")]).level == CS.LEVEL_E2E
    assert CS.weakest([]) is None


# --- negotiated -------------------------------------------------------------------------------

def test_happy_a_live_tls_connection_names_version_and_cipher(tmp_path):
    client = tls_pair(tmp_path)
    info = CS.tls_socket(client, verified=True, what="IMAP")
    assert info.level == CS.LEVEL_TLS and info.negotiated
    assert info.summary == f"IMAP: {CS.tls_version_text(client.version())}, certificate verified"
    assert info.details[0] == f"Cipher: {client.cipher()[0]}"


def test_sad_an_unchecked_certificate_is_weak(tmp_path):
    info = CS.tls_socket(tls_pair(tmp_path), verified=False)
    assert info.level == CS.LEVEL_TLS_WEAK and "NOT verified" in info.summary


def test_edge_a_socket_that_is_not_tls_gives_no_tls_answer():
    assert CS.tls_socket(object(), verified=True) is None
    assert CS.tls_version_text("TLSv1.3") == "TLS 1.3" and CS.tls_version_text(None) == "TLS"


def _transport(active=True, **over):
    key = SimpleNamespace(get_name=lambda: "ssh-ed25519")
    values = dict(remote_cipher="aes256-gcm@openssh.com", remote_mac="hmac-sha2-256",
                  kex_engine=SimpleNamespace(name="curve25519-sha256"), remote_version="SSH-2.0-OpenSSH_9.6")
    values.update(over)
    return SimpleNamespace(is_active=lambda: active, get_remote_server_key=lambda: key, **values)


def test_happy_ssh_names_its_cipher_key_exchange_and_host_key():
    info = CS.ssh_transport(_transport(), "SFTP over SSH")
    assert info.level == CS.LEVEL_ENCRYPTED and info.negotiated
    assert "aes256-gcm@openssh.com" in info.summary and "host key checked" in info.summary
    assert "Key exchange: curve25519-sha256" in info.details and "Host key: ssh-ed25519" in info.details
    assert not any(d.startswith("MAC") for d in info.details)   # an AEAD cipher has no separate MAC


def test_sad_a_closed_ssh_transport_falls_back_to_the_settings():
    assert CS.ssh_transport(_transport(active=False)) is None
    assert CS.ssh_transport(None) is None


def _smb(dialect=0x0311, encrypt=False, signing=True, cipher=0x0002, trees=None):
    connection = SimpleNamespace(dialect=dialect, cipher_id=cipher, require_signing=signing)
    return SimpleNamespace(connection=connection, encrypt_data=encrypt, signing_required=signing,
                           tree_connect_table=trees or {})


def test_happy_smb3_with_encryption_names_dialect_and_cipher():
    info = CS.smb_session(_smb(encrypt=True))
    assert info.level == CS.LEVEL_ENCRYPTED and info.summary == "SMB 3.1.1 with encryption (AES-128-GCM)"


def test_happy_smb3_signing_only_says_it_is_not_encrypted():
    info = CS.smb_session(_smb())
    assert info.level == CS.LEVEL_SIGNED and info.summary.startswith("SMB 3.1.1 signing only, not encrypted")


def test_edge_a_share_that_requires_encryption_counts():
    trees = {1: SimpleNamespace(share_name="\\\\srv\\Secret", encrypt_data=True)}
    assert CS.smb_session(_smb(trees=trees), "secret").level == CS.LEVEL_ENCRYPTED
    assert CS.smb_session(_smb(trees=trees), "public").level == CS.LEVEL_SIGNED


def test_sad_smb2_unsigned_is_cleartext_and_a_broken_session_is_none():
    info = CS.smb_session(_smb(dialect=0x0210, signing=False))
    assert info.level == CS.LEVEL_CLEARTEXT and info.summary.startswith("SMB 2.1 neither signed")
    assert CS.smb_session(SimpleNamespace()) is None
    assert CS.smb_session(None) is None


# --- the backends -------------------------------------------------------------------------------

def test_happy_smb_backend_reads_its_kept_session():
    from core.smb_client import SmbSession

    session = SmbSession.__new__(SmbSession)
    session._share = "data"
    assert session.security_info() is None          # not connected yet: the profile tells
    session._smb_session = _smb(encrypt=True)
    assert session.security_info().level == CS.LEVEL_ENCRYPTED


def test_happy_ftps_backend_reads_tls_and_the_data_channel(tmp_path):
    from core.ftp_client import FtpSession

    session = FtpSession.__new__(FtpSession)
    session._tls, session._verify_tls = True, True
    session._ftp = SimpleNamespace(sock=tls_pair(tmp_path), _prot_p=True)
    info = session.security_info()
    assert info.level == CS.LEVEL_TLS and info.summary.startswith("FTPS: TLS")
    assert "data channel protected (PROT P)" in info.details
    session._ftp._prot_p = False
    info = session.security_info()
    assert info.level == CS.LEVEL_TLS_WEAK and "data channel NOT protected" in info.summary


def test_sad_plain_ftp_backend_is_cleartext_and_offline_is_none():
    from core.ftp_client import FtpSession

    session = FtpSession.__new__(FtpSession)
    session._tls, session._verify_tls = False, True
    session._ftp = None
    assert session.security_info() is None
    session._ftp = SimpleNamespace(sock=object())
    assert session.security_info().level == CS.LEVEL_CLEARTEXT


def test_happy_sftp_backend_reads_its_transport():
    from core.ssh_client import SSHSession

    session = SSHSession.__new__(SSHSession)
    session._transport = _transport()
    assert session.security_info().summary.startswith("SFTP over SSH, encrypted")


def test_happy_of_backend_prefers_the_live_answer_then_the_profile_then_local():
    from core.local_fs import LocalFS

    live = SimpleNamespace(security_info=lambda: CS.SecurityInfo(CS.LEVEL_TLS, "live", True),
                           _axross_profile=_profile("ftp"))
    assert CS.of_backend(live).summary == "live"
    offline = SimpleNamespace(security_info=lambda: None, _axross_profile=_profile("ftp"))
    assert CS.of_backend(offline).level == CS.LEVEL_CLEARTEXT
    assert CS.of_backend(LocalFS()) is CS.LOCAL


def test_sad_a_failing_security_info_never_breaks_the_badge():
    def boom():
        raise RuntimeError("half closed")
    assert CS.of_backend(SimpleNamespace(security_info=boom, _axross_profile=_profile("sftp"))).level \
        == CS.LEVEL_ENCRYPTED
    assert CS.of_backend(SimpleNamespace()) is CS.UNKNOWN
    assert CS.of_backend(None) is CS.UNKNOWN
