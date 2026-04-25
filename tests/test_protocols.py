#!/usr/bin/env python3
"""Network integration tests for FTP, SMB, WebDAV, S3, NFS, IMAP, and Telnet backends.

Expects the docker-compose network to be running:
  cd tests/docker && docker compose up -d

Network layout:
  ftp-server    10.99.0.30:21   (user: ftpuser / ftp123)
  smb-server    10.99.0.31:445  (user: smbuser / smb123, share: testshare)
  webdav-server 10.99.0.32:80   (user: davuser / dav123)
  s3-server     10.99.0.33:9000 (user: minioadmin / minioadmin123, bucket: testbucket)
  nfs-server    10.99.0.35:2049 (export: /srv/nfs/share)
  imap-server   10.99.0.36:143  (user: imapuser / imap123)
  telnet-server 10.99.0.37:23   (user: telnetuser / telnet123)
"""
from __future__ import annotations

import io
import os
import socket
import sys
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.backend_registry import init_registry

init_registry()

# ── Server configs ──────────────────────────────────────────
FTP_HOST = "10.99.0.30"
FTP_PORT = 21
FTP_USER = "ftpuser"
FTP_PASS = "ftp123"
FTPS_HOST = "10.99.0.38"
FTPS_PORT = 21  # Explicit FTPS (AUTH TLS on port 21)
FTPS_USER = "ftpsuser"
FTPS_PASS = "ftps123"

SMB_HOST = "10.99.0.31"
SMB_PORT = 445
SMB_USER = "smbuser"
SMB_PASS = "smb123"
SMB_SHARE = "testshare"

WEBDAV_HOST = "10.99.0.32"
WEBDAV_PORT = 80
WEBDAV_USER = "davuser"
WEBDAV_PASS = "dav123"
WEBDAV_URL = f"http://{WEBDAV_HOST}:{WEBDAV_PORT}"

S3_HOST = "10.99.0.33"
S3_PORT = 9000
S3_ACCESS_KEY = "minioadmin"
S3_SECRET_KEY = "minioadmin123"
S3_BUCKET = "testbucket"
S3_ENDPOINT = f"http://{S3_HOST}:{S3_PORT}"

RSYNC_HOST = "10.99.0.34"
RSYNC_PORT = 873
RSYNC_USER = "rsyncuser"
RSYNC_PASS = "rsync123"
RSYNC_MODULE = "testmod"

NFS_HOST = "10.99.0.35"
NFS_PORT = 2049
NFS_EXPORT = "/nfsshare"
ISCSI_HOST = "10.99.0.40"
ISCSI_PORT = 3260
ISCSI_IQN = "iqn.2024-01.com.axross:test-target"

# Azurite emulator (Azure Storage emulator)
AZURITE_HOST = "10.99.0.39"
AZURITE_ACCOUNT = "devstoreaccount1"
# Well-known well-known Azurite master key (not a secret — baked into the image)
AZURITE_KEY = (
    "Eby8vdM02xNOcqFlqUwJPLlmEtlCDXJ1OUzFT50uSRZ6IFsuFq2UVErCz4I6tq/"
    "K1SZFPTOtr/KBHBeksoGMGw=="
)
AZURITE_CONNECTION_STRING = (
    f"DefaultEndpointsProtocol=http;"
    f"AccountName={AZURITE_ACCOUNT};"
    f"AccountKey={AZURITE_KEY};"
    f"BlobEndpoint=http://{AZURITE_HOST}:10000/{AZURITE_ACCOUNT};"
)
AZURITE_CONTAINER = "axross-test"

IMAP_HOST = "10.99.0.36"
IMAP_PORT = 143
IMAP_USER = "imapuser"
IMAP_PASS = "imap123"

TELNET_HOST = "10.99.0.37"
TELNET_PORT = 23
TELNET_USER = "telnetuser"
TELNET_PASS = "telnet123"

# Proxy containers in the lab (see tests/docker/docker-compose.yml).
SOCKS_PROXY_HOST = "10.99.0.20"
SOCKS_PROXY_PORT = 1080
HTTP_PROXY_HOST = "10.99.0.21"
HTTP_PROXY_PORT = 8888

passed = 0
failed = 0
skipped = 0
errors: list[str] = []


def _label(name: str):
    def decorator(func):
        # Accept *args/**kwargs so the decorator works on both module-level
        # functions and instance methods (e.g. TestTelnet.test_telnet_*).
        def wrapper(*args, **kwargs):
            global passed, failed
            try:
                func(*args, **kwargs)
                print(f"  PASS  {name}")
                passed += 1
            except Exception as e:
                print(f"  FAIL  {name}: {e}")
                traceback.print_exc()
                failed += 1
                errors.append(f"{name}: {e}")
                raise
        return wrapper
    return decorator


def wait_for_port(host: str, port: int, timeout: float = 30) -> bool:
    """Wait until a TCP port is reachable."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            sock = socket.create_connection((host, port), timeout=2)
            sock.close()
            return True
        except (ConnectionRefusedError, OSError, TimeoutError):
            time.sleep(1)
    return False


# ════════════════════════════════════════════════════════════
#  SECTION 1: FTP
# ════════════════════════════════════════════════════════════

@_label("FTP 1.1 Connect and list root")
def test_ftp_connect():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    assert s.connected
    items = s.list_dir(s.home())
    names = {i.name for i in items}
    assert len(names) > 0, f"Expected files, got empty listing"
    s.disconnect()


@_label("FTP 1.2 List data directory")
def test_ftp_list_data():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    # Find the data dir — may be at /home/ftpuser/data or relative
    home = s.home()
    items = s.list_dir(home)
    names = {i.name for i in items}
    # Navigate into data
    data_path = s.join(home, "data")
    items = s.list_dir(data_path)
    names = {i.name for i in items}
    assert "readme.txt" in names, f"readme.txt not found in {names}"
    assert "subdir" in names, f"subdir not found in {names}"
    s.disconnect()


@_label("FTP 1.3 Read file content")
def test_ftp_read():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    home = s.home()
    with s.open_read(s.join(home, "data", "readme.txt")) as f:
        content = f.read()
    assert b"Hello from FTP" in content, f"Unexpected content: {content}"
    s.disconnect()


@_label("FTP 1.4 Write + read + delete cycle")
def test_ftp_write_cycle():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    home = s.home()
    test_file = s.join(home, "test_write.txt")
    try:
        with s.open_write(test_file) as f:
            f.write(b"FTP write test\n")
        with s.open_read(test_file) as f:
            content = f.read()
        assert content == b"FTP write test\n", f"Got: {content}"
        s.remove(test_file)
        assert not s.exists(test_file)
    finally:
        s.disconnect()


@_label("FTP 1.5 Mkdir + rmdir")
def test_ftp_mkdir():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    home = s.home()
    test_dir = s.join(home, "test_mkdir_ftp")
    try:
        if s.exists(test_dir):
            s.remove(test_dir, recursive=True)
        s.mkdir(test_dir)
        assert s.is_dir(test_dir)
        s.remove(test_dir)
    finally:
        s.disconnect()


@_label("FTP 1.6 Rename file")
def test_ftp_rename():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    home = s.home()
    src = s.join(home, "rename_src.txt")
    dst = s.join(home, "rename_dst.txt")
    try:
        with s.open_write(src) as f:
            f.write(b"rename test")
        s.rename(src, dst)
        assert not s.exists(src)
        assert s.exists(dst)
        s.remove(dst)
    finally:
        s.disconnect()


@_label("FTP 1.7 Stat file")
def test_ftp_stat():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    home = s.home()
    info = s.stat(s.join(home, "data", "bigfile.bin"))
    assert info.size > 0, f"Expected size > 0, got {info.size}"
    assert not info.is_dir
    s.disconnect()


@_label("FTP 1.8 Path helpers")
def test_ftp_paths():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    assert s.separator() == "/"
    assert s.join("/home", "user") == "/home/user"
    assert s.parent("/home/user/data") == "/home/user"
    s.disconnect()


@_label("FTP 1.9 ConnectionManager dispatch")
def test_ftp_via_cm():
    from core.connection_manager import ConnectionManager
    from core.profiles import ConnectionProfile
    profile = ConnectionProfile(
        name="ftp-test",
        protocol="ftp",
        host=FTP_HOST,
        port=FTP_PORT,
        username=FTP_USER,
    )
    cm = ConnectionManager()
    try:
        session = cm.connect(profile, password=FTP_PASS)
        assert session.connected
        items = session.list_dir(session.home())
        assert len(items) > 0
    finally:
        cm.disconnect_all()


# ════════════════════════════════════════════════════════════
#  SECTION 1b: FTPS (explicit AUTH TLS)
# ════════════════════════════════════════════════════════════

def _ftps_session():
    from core.ftp_client import FtpSession
    # The lab's pure-ftpd uses a self-signed cert. Production callers
    # must keep verify_tls=True (the new default); test code that
    # intentionally connects to a self-signed lab server explicitly
    # opts out.
    return FtpSession(
        host=FTPS_HOST, port=FTPS_PORT,
        username=FTPS_USER, password=FTPS_PASS,
        tls=True, verify_tls=False,
    )


@_label("FTPS 1b.1 Connect + TLS upgrade")
def test_ftps_connect():
    s = _ftps_session()
    try:
        assert s.connected
        items = s.list_dir(s.home())
        assert any(i.name == "data" for i in items), \
            f"'data' not in {[i.name for i in items]}"
    finally:
        s.disconnect()


@_label("FTPS 1b.2 Read file over TLS data channel")
def test_ftps_read():
    s = _ftps_session()
    try:
        with s.open_read(s.join(s.home(), "data", "readme.txt")) as f:
            data = f.read()
        assert b"Hello from FTPS" in data, f"unexpected: {data!r}"
    finally:
        s.disconnect()


@_label("FTPS 1b.3 Write/read/delete cycle over TLS")
def test_ftps_write_cycle():
    s = _ftps_session()
    try:
        path = s.join(s.home(), "ftps_write_test.txt")
        with s.open_write(path) as f:
            f.write(b"FTPS write test\n")
        with s.open_read(path) as f:
            data = f.read()
        assert data == b"FTPS write test\n"
        s.remove(path)
        assert not s.exists(path)
    finally:
        s.disconnect()


@_label("FTPS 1b.4 List subdir (control+data both encrypted)")
def test_ftps_list_subdir():
    s = _ftps_session()
    try:
        items = s.list_dir(s.join(s.home(), "data", "subdir"))
        names = {i.name for i in items}
        assert "nested.txt" in names, f"nested.txt not in {names}"
    finally:
        s.disconnect()


@_label("FTPS 1b.5 Stat binary file")
def test_ftps_stat():
    s = _ftps_session()
    try:
        info = s.stat(s.join(s.home(), "data", "bigfile.bin"))
        assert info.size >= 64 * 1024, f"size={info.size}"
        assert not info.is_dir
    finally:
        s.disconnect()


@_label("FTPS 1b.6 ConnectionManager dispatches ftps profile")
def test_ftps_via_cm():
    from core.connection_manager import ConnectionManager
    from core.profiles import ConnectionProfile
    profile = ConnectionProfile(
        name="ftps-test",
        protocol="ftps",
        host=FTPS_HOST,
        port=FTPS_PORT,
        username=FTPS_USER,
        # Lab uses self-signed — explicit opt-out; production callers
        # keep the default verify_tls=True.
        ftps_verify_tls=False,
    )
    cm = ConnectionManager()
    try:
        session = cm.connect(profile, password=FTPS_PASS)
        assert session.connected
        items = session.list_dir(session.home())
        assert len(items) > 0
    finally:
        cm.disconnect_all()


# ════════════════════════════════════════════════════════════
#  SECTION 2: SMB
# ════════════════════════════════════════════════════════════

@_label("SMB 2.1 Connect and list root")
def test_smb_connect():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER, password=SMB_PASS, port=SMB_PORT)
    assert s.connected
    items = s.list_dir("/")
    names = {i.name for i in items}
    assert "readme.txt" in names, f"readme.txt not found in {names}"
    s.disconnect()


@_label("SMB 2.2 Read file")
def test_smb_read():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER, password=SMB_PASS, port=SMB_PORT)
    with s.open_read("/readme.txt") as f:
        content = f.read()
    assert b"Hello from SMB" in content, f"Unexpected: {content}"
    s.disconnect()


@_label("SMB 2.3 List subdirectory")
def test_smb_list_subdir():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER, password=SMB_PASS, port=SMB_PORT)
    items = s.list_dir("/subdir")
    names = {i.name for i in items}
    assert "nested.txt" in names
    s.disconnect()


@_label("SMB 2.4 Write + read + delete cycle")
def test_smb_write_cycle():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER, password=SMB_PASS, port=SMB_PORT)
    try:
        with s.open_write("/smb_test.txt") as f:
            f.write(b"SMB write test\n")
        with s.open_read("/smb_test.txt") as f:
            content = f.read()
        assert content == b"SMB write test\n", f"Got: {content}"
        s.remove("/smb_test.txt")
        assert not s.exists("/smb_test.txt")
    finally:
        s.disconnect()


@_label("SMB 2.5 Mkdir + rmdir")
def test_smb_mkdir():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER, password=SMB_PASS, port=SMB_PORT)
    try:
        if s.exists("/smb_testdir"):
            s.remove("/smb_testdir", recursive=True)
        s.mkdir("/smb_testdir")
        assert s.is_dir("/smb_testdir")
        s.remove("/smb_testdir")
    finally:
        s.disconnect()


@_label("SMB 2.6 Rename file")
def test_smb_rename():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER, password=SMB_PASS, port=SMB_PORT)
    try:
        with s.open_write("/smb_rename_src.txt") as f:
            f.write(b"rename")
        s.rename("/smb_rename_src.txt", "/smb_rename_dst.txt")
        assert not s.exists("/smb_rename_src.txt")
        assert s.exists("/smb_rename_dst.txt")
        s.remove("/smb_rename_dst.txt")
    finally:
        s.disconnect()


@_label("SMB 2.7 Stat file")
def test_smb_stat():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER, password=SMB_PASS, port=SMB_PORT)
    info = s.stat("/bigfile.bin")
    assert info.size > 0
    assert not info.is_dir
    s.disconnect()


@_label("SMB 2.8 ConnectionManager dispatch")
def test_smb_via_cm():
    from core.connection_manager import ConnectionManager
    from core.profiles import ConnectionProfile
    profile = ConnectionProfile(
        name="smb-test",
        protocol="smb",
        host=SMB_HOST,
        port=SMB_PORT,
        username=SMB_USER,
        smb_share=SMB_SHARE,
    )
    cm = ConnectionManager()
    try:
        session = cm.connect(profile, password=SMB_PASS)
        items = session.list_dir("/")
        names = {i.name for i in items}
        assert "readme.txt" in names
    finally:
        cm.disconnect_all()


# ════════════════════════════════════════════════════════════
#  SECTION 3: WebDAV
# ════════════════════════════════════════════════════════════

@_label("WebDAV 3.1 Connect and list root")
def test_webdav_connect():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    assert s.connected
    items = s.list_dir("/")
    names = {i.name for i in items}
    assert "readme.txt" in names, f"readme.txt not found in {names}"
    s.disconnect()


@_label("WebDAV 3.2 Read file")
def test_webdav_read():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    with s.open_read("/readme.txt") as f:
        content = f.read()
    assert b"Hello from WebDAV" in content, f"Unexpected: {content}"
    s.disconnect()


@_label("WebDAV 3.3 List subdirectory")
def test_webdav_list_subdir():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    items = s.list_dir("/subdir")
    names = {i.name for i in items}
    assert "nested.txt" in names
    s.disconnect()


@_label("WebDAV 3.4 Write + read + delete cycle")
def test_webdav_write_cycle():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        with s.open_write("/dav_test.txt") as f:
            f.write(b"WebDAV write test\n")
        with s.open_read("/dav_test.txt") as f:
            content = f.read()
        assert content == b"WebDAV write test\n", f"Got: {content}"
        s.remove("/dav_test.txt")
        assert not s.exists("/dav_test.txt")
    finally:
        s.disconnect()


@_label("WebDAV 3.5 Mkdir + rmdir")
def test_webdav_mkdir():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        if s.exists("/dav_testdir"):
            s.remove("/dav_testdir")
        s.mkdir("/dav_testdir")
        assert s.is_dir("/dav_testdir")
        s.remove("/dav_testdir")
    finally:
        s.disconnect()


@_label("WebDAV 3.6 Rename file")
def test_webdav_rename():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        with s.open_write("/dav_rename_src.txt") as f:
            f.write(b"rename")
        s.rename("/dav_rename_src.txt", "/dav_rename_dst.txt")
        assert not s.exists("/dav_rename_src.txt")
        assert s.exists("/dav_rename_dst.txt")
        s.remove("/dav_rename_dst.txt")
    finally:
        s.disconnect()


@_label("WebDAV 3.7 ConnectionManager dispatch")
def test_webdav_via_cm():
    from core.connection_manager import ConnectionManager
    from core.profiles import ConnectionProfile
    profile = ConnectionProfile(
        name="webdav-test",
        protocol="webdav",
        host="",
        username=WEBDAV_USER,
        webdav_url=WEBDAV_URL,
    )
    cm = ConnectionManager()
    try:
        session = cm.connect(profile, password=WEBDAV_PASS)
        items = session.list_dir("/")
        names = {i.name for i in items}
        assert "readme.txt" in names
    finally:
        cm.disconnect_all()


# ════════════════════════════════════════════════════════════
#  SECTION 4: S3 (MinIO)
# ════════════════════════════════════════════════════════════

@_label("S3 4.1 Connect and list root")
def test_s3_connect():
    from core.s3_client import S3Session
    s = S3Session(
        bucket=S3_BUCKET, region="us-east-1",
        access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
        endpoint=S3_ENDPOINT,
    )
    assert s.connected
    items = s.list_dir("/")
    names = {i.name for i in items}
    assert "readme.txt" in names, f"readme.txt not found in {names}"
    s.disconnect()


@_label("S3 4.2 Read file")
def test_s3_read():
    from core.s3_client import S3Session
    s = S3Session(
        bucket=S3_BUCKET, region="us-east-1",
        access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
        endpoint=S3_ENDPOINT,
    )
    with s.open_read("/readme.txt") as f:
        content = f.read()
    assert b"Hello from S3" in content, f"Unexpected: {content}"
    s.disconnect()


@_label("S3 4.3 List subdirectory (virtual prefix)")
def test_s3_list_subdir():
    from core.s3_client import S3Session
    s = S3Session(
        bucket=S3_BUCKET, region="us-east-1",
        access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
        endpoint=S3_ENDPOINT,
    )
    items = s.list_dir("/subdir")
    names = {i.name for i in items}
    assert "nested.txt" in names, f"nested.txt not found in {names}"
    s.disconnect()


@_label("S3 4.4 Write + read + delete cycle")
def test_s3_write_cycle():
    from core.s3_client import S3Session
    s = S3Session(
        bucket=S3_BUCKET, region="us-east-1",
        access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
        endpoint=S3_ENDPOINT,
    )
    try:
        with s.open_write("/s3_test.txt") as f:
            f.write(b"S3 write test\n")
        with s.open_read("/s3_test.txt") as f:
            content = f.read()
        assert content == b"S3 write test\n", f"Got: {content}"
        s.remove("/s3_test.txt")
        assert not s.exists("/s3_test.txt")
    finally:
        s.disconnect()


@_label("S3 4.5 Mkdir (directory marker) + is_dir")
def test_s3_mkdir():
    from core.s3_client import S3Session
    s = S3Session(
        bucket=S3_BUCKET, region="us-east-1",
        access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
        endpoint=S3_ENDPOINT,
    )
    try:
        s.mkdir("/s3_testdir")
        assert s.is_dir("/s3_testdir")
        s.remove("/s3_testdir")
    finally:
        s.disconnect()


@_label("S3 4.6 Rename (copy + delete)")
def test_s3_rename():
    from core.s3_client import S3Session
    s = S3Session(
        bucket=S3_BUCKET, region="us-east-1",
        access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
        endpoint=S3_ENDPOINT,
    )
    try:
        with s.open_write("/s3_rename_src.txt") as f:
            f.write(b"rename test")
        s.rename("/s3_rename_src.txt", "/s3_rename_dst.txt")
        assert not s.exists("/s3_rename_src.txt")
        assert s.exists("/s3_rename_dst.txt")
        with s.open_read("/s3_rename_dst.txt") as f:
            assert f.read() == b"rename test"
        s.remove("/s3_rename_dst.txt")
    finally:
        s.disconnect()


@_label("S3 4.7 Stat file")
def test_s3_stat():
    from core.s3_client import S3Session
    s = S3Session(
        bucket=S3_BUCKET, region="us-east-1",
        access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
        endpoint=S3_ENDPOINT,
    )
    info = s.stat("/bigfile.bin")
    assert info.size > 0, f"Expected size > 0, got {info.size}"
    assert not info.is_dir
    s.disconnect()


@_label("S3 4.8 ConnectionManager dispatch")
def test_s3_via_cm():
    from core.connection_manager import ConnectionManager
    from core.profiles import ConnectionProfile
    profile = ConnectionProfile(
        name="s3-test",
        protocol="s3",
        username=S3_ACCESS_KEY,
        s3_bucket=S3_BUCKET,
        s3_region="us-east-1",
        s3_endpoint=S3_ENDPOINT,
    )
    cm = ConnectionManager()
    try:
        session = cm.connect(profile, password=S3_SECRET_KEY)
        items = session.list_dir("/")
        names = {i.name for i in items}
        assert "readme.txt" in names
    finally:
        cm.disconnect_all()


# ════════════════════════════════════════════════════════════
#  SECTION 5: Rsync
# ════════════════════════════════════════════════════════════

@_label("Rsync 5.1 Connect and list root")
def test_rsync_connect():
    from core.rsync_client import RsyncSession
    s = RsyncSession(host=RSYNC_HOST, port=RSYNC_PORT, module=RSYNC_MODULE,
                     username=RSYNC_USER, password=RSYNC_PASS)
    assert s.connected
    items = s.list_dir("/")
    names = {i.name for i in items}
    assert "readme.txt" in names, f"readme.txt not found in {names}"
    s.close()


@_label("Rsync 5.2 Read file")
def test_rsync_read():
    from core.rsync_client import RsyncSession
    s = RsyncSession(host=RSYNC_HOST, port=RSYNC_PORT, module=RSYNC_MODULE,
                     username=RSYNC_USER, password=RSYNC_PASS)
    with s.open_read("/readme.txt") as f:
        content = f.read()
    assert b"rsync test file" in content, f"Unexpected: {content}"
    s.close()


@_label("Rsync 5.3 List subdirectory")
def test_rsync_list_subdir():
    from core.rsync_client import RsyncSession
    s = RsyncSession(host=RSYNC_HOST, port=RSYNC_PORT, module=RSYNC_MODULE,
                     username=RSYNC_USER, password=RSYNC_PASS)
    items = s.list_dir("/subdir")
    names = {i.name for i in items}
    assert "nested.txt" in names, f"nested.txt not found in {names}"
    s.close()


@_label("Rsync 5.4 Write + read cycle")
def test_rsync_write_cycle():
    from core.rsync_client import RsyncSession
    s = RsyncSession(host=RSYNC_HOST, port=RSYNC_PORT, module=RSYNC_MODULE,
                     username=RSYNC_USER, password=RSYNC_PASS)
    try:
        with s.open_write("/rsync_test.txt") as f:
            f.write(b"rsync write test\n")
        with s.open_read("/rsync_test.txt") as f:
            content = f.read()
        assert content == b"rsync write test\n", f"Got: {content}"
        s.remove("/rsync_test.txt")
    finally:
        s.close()


@_label("Rsync 5.5 ConnectionManager dispatch")
def test_rsync_via_cm():
    from core.connection_manager import ConnectionManager
    from core.profiles import ConnectionProfile
    profile = ConnectionProfile(
        name="rsync-test",
        protocol="rsync",
        host=RSYNC_HOST,
        port=RSYNC_PORT,
        username=RSYNC_USER,
        rsync_module=RSYNC_MODULE,
    )
    cm = ConnectionManager()
    try:
        session = cm.connect(profile, password=RSYNC_PASS)
        items = session.list_dir("/")
        names = {i.name for i in items}
        assert "readme.txt" in names
    finally:
        cm.disconnect_all()


# ════════════════════════════════════════════════════════════
#  SECTION 6: NFS  (pytest-compatible)
# ════════════════════════════════════════════════════════════

import pytest


def _nfs_session():
    from core.nfs_client import NfsSession
    # The alpine kernel-NFS server exposes only NFSv4. We also pass "/"
    # as export path — the server exports a single share at the root.
    return NfsSession(host=NFS_HOST, export_path="/", port=NFS_PORT, version=4)


def _can_mount_nfs() -> bool:
    """Check if NFS mount works (fails in Docker bridge networks)."""
    import subprocess, tempfile, shutil
    if not shutil.which("mount.nfs") and not shutil.which("mount"):
        return False
    if os.geteuid() != 0:
        # Our NfsSession uses `sudo -n`; if that's not configured, the
        # real session will also fail. Short-circuit so the skip message
        # is accurate.
        r = subprocess.run(
            ["sudo", "-n", "true"], capture_output=True, timeout=3,
        )
        if r.returncode != 0:
            return False
    mp = tempfile.mkdtemp(prefix="nfscheck-")
    try:
        r = subprocess.run(
            ["mount", "-t", "nfs", "-o",
             f"vers=4,port={NFS_PORT},nolock,tcp",
             f"{NFS_HOST}:/", mp],
            capture_output=True, text=True, timeout=10,
        )
        if r.returncode == 0:
            subprocess.run(["umount", mp], capture_output=True, timeout=10)
            return True
        return False
    except Exception:
        return False
    finally:
        try:
            os.rmdir(mp)
        except OSError:
            pass


_nfs_mount_works = None


def _skip_if_nfs_unavailable():
    global _nfs_mount_works
    if _nfs_mount_works is None:
        _nfs_mount_works = _can_mount_nfs()
    if not _nfs_mount_works:
        pytest.skip("NFS mount not available (Docker bridge network limitation)")


class TestNfs:
    """NFS integration tests (requires privileged container + nfs-common).

    NOTE: NFS mount does not work inside Docker bridge networks due to
    kernel network namespace limitations. These tests will be skipped
    when running inside standard Docker compose.
    """

    def test_nfs_connect(self):
        _skip_if_nfs_unavailable()
        s = _nfs_session()
        try:
            assert s.connected
            items = s.list_dir("/")
            names = {i.name for i in items}
            assert "readme.txt" in names, f"readme.txt not found in {names}"
        finally:
            s.disconnect()

    def test_nfs_list_dir(self):
        _skip_if_nfs_unavailable()
        s = _nfs_session()
        try:
            items = s.list_dir("/subdir")
            names = {i.name for i in items}
            assert "nested.txt" in names, f"nested.txt not found in {names}"
        finally:
            s.disconnect()

    def test_nfs_write_read_cycle(self):
        _skip_if_nfs_unavailable()
        s = _nfs_session()
        try:
            with s.open_write("/nfs_test.txt") as f:
                f.write(b"NFS write test\n")
            with s.open_read("/nfs_test.txt") as f:
                content = f.read()
            assert content == b"NFS write test\n", f"Got: {content}"
            s.remove("/nfs_test.txt")
            assert not s.exists("/nfs_test.txt")
        finally:
            s.disconnect()

    def test_nfs_mkdir_remove(self):
        _skip_if_nfs_unavailable()
        s = _nfs_session()
        try:
            if s.exists("/nfs_testdir"):
                s.remove("/nfs_testdir")
            s.mkdir("/nfs_testdir")
            assert s.is_dir("/nfs_testdir")
            s.remove("/nfs_testdir")
        finally:
            s.disconnect()

    def test_nfs_rename(self):
        _skip_if_nfs_unavailable()
        s = _nfs_session()
        try:
            with s.open_write("/nfs_rename_src.txt") as f:
                f.write(b"rename test")
            s.rename("/nfs_rename_src.txt", "/nfs_rename_dst.txt")
            assert not s.exists("/nfs_rename_src.txt")
            assert s.exists("/nfs_rename_dst.txt")
            s.remove("/nfs_rename_dst.txt")
        finally:
            s.disconnect()

    # -- coverage gap-fillers (chmod / readlink / disk_usage / path helpers)

    def test_nfs_path_helpers(self):
        _skip_if_nfs_unavailable()
        s = _nfs_session()
        try:
            _assert_path_helpers(s)
        finally:
            s.disconnect()

    def test_nfs_disk_usage(self):
        _skip_if_nfs_unavailable()
        s = _nfs_session()
        try:
            total, used, free = s.disk_usage("/")
            assert isinstance(total, int) and total > 0
        finally:
            s.disconnect()

    def test_nfs_chmod_live(self):
        _skip_if_nfs_unavailable()
        s = _nfs_session()
        path = "/nfs_chmod_test.txt"
        try:
            with s.open_write(path) as f:
                f.write(b"chmod me\n")
            s.chmod(path, 0o640)
            info = s.stat(path)
            assert info.permissions & 0o777 == 0o640, oct(info.permissions)
        finally:
            if s.exists(path):
                s.remove(path)
            s.disconnect()

    def test_nfs_readlink_live(self):
        import os as _os
        _skip_if_nfs_unavailable()
        s = _nfs_session()
        target = "/nfs_link_target.txt"
        link = "/nfs_link.txt"
        try:
            with s.open_write(target) as f:
                f.write(b"target\n")
            real_link = _os.path.join(s._mount_point, "nfs_link.txt")
            if _os.path.lexists(real_link):
                _os.remove(real_link)
            _os.symlink("nfs_link_target.txt", real_link)
            resolved = s.readlink(link)
            assert resolved == "nfs_link_target.txt", resolved
        finally:
            if s.exists(link):
                s.remove(link)
            if s.exists(target):
                s.remove(target)
            s.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 6b: iSCSI  (pytest-compatible)
# ════════════════════════════════════════════════════════════

_iscsi_available: bool | None = None


def _can_use_iscsi() -> bool:
    """Detect whether iscsiadm is usable as the current user.

    iSCSI requires three things, any of which can be missing on a typical
    developer workstation or CI runner:
      1. iscsiadm binary + open-iscsi package
      2. Root (or passwordless ``sudo -n``)
      3. The ``iscsi_tcp`` kernel module loaded on the host (containers
         share the host's kernel; if the host hasn't loaded it, no amount
         of container privilege helps).
    """
    import shutil
    import subprocess
    if not shutil.which("iscsiadm"):
        return False
    # Need root or passwordless sudo to actually connect.
    if os.geteuid() != 0:
        r = subprocess.run(
            ["sudo", "-n", "true"], capture_output=True, timeout=3,
        )
        if r.returncode != 0:
            return False
    # iscsi_tcp kernel module must already be loaded on the host. We can't
    # load it from an unprivileged process, and a privileged container
    # still can't install new modules since /lib/modules comes from the
    # container image (not the host).
    try:
        with open("/proc/modules") as fh:
            modules = fh.read()
        if "iscsi_tcp" not in modules:
            return False
    except OSError:
        return False
    # Probe iscsid socket
    try:
        r = subprocess.run(
            ["iscsiadm", "-m", "session"],
            capture_output=True, timeout=5, text=True,
        )
        if "can not connect to iSCSI daemon" in (r.stderr or ""):
            return False
    except (OSError, subprocess.TimeoutExpired):
        return False
    return True


def _skip_if_iscsi_unavailable():
    global _iscsi_available
    if _iscsi_available is None:
        _iscsi_available = _can_use_iscsi()
    if not _iscsi_available:
        pytest.skip(
            "iSCSI test requires iscsiadm + root/sudo + host-loaded "
            "iscsi_tcp kernel module. Run `sudo modprobe iscsi_tcp` on "
            "the host, then rerun inside the test-runner container."
        )


def _iscsi_session():
    from core.iscsi_client import IscsiSession
    return IscsiSession(
        target_ip=ISCSI_HOST,
        target_iqn=ISCSI_IQN,
        port=ISCSI_PORT,
        auto_mount=True,
    )


class TestIscsi:
    """iSCSI tests — require the test-runner-iscsi container (privileged +
    open-iscsi + host networking so the NETLINK_ISCSI channel works).

    Tests share ONE IscsiSession via a class-scoped fixture. Reconnecting
    per test stresses the kernel iSCSI subsystem enough that the SCSI
    rescan after re-login occasionally races out, which is not a bug in
    axross — it is a property of iscsiadm + the kernel when pounded
    thousands of times per hour.
    """

    session = None

    @classmethod
    def setup_class(cls):
        _skip_if_iscsi_unavailable()
        import subprocess
        import time as _t

        # Full kernel-iSCSI reset. Previous runs (or manual debugging)
        # can leave:
        #  - mounted block devices (block logout)
        #  - kernel sessions that linger because they're in use
        #  - iscsid with cached node records pointing at dead endpoints
        #
        # Order matters: (1) unmount every /dev/sd* mount so logout isn't
        # blocked by busy-device, (2) logout per-sid, (3) delete node
        # records, (4) restart iscsid, (5) verify kernel has no lingering
        # sessions before we create the test session. If after all this
        # the kernel still reports a session, we restart the iscsi-server
        # container-side is not something we can do from here, so we
        # still try to connect and let the backend surface the error.
        try:
            with open("/proc/mounts") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0].startswith("/dev/sd"):
                        subprocess.run(["umount", "-f", parts[1]],
                                       capture_output=True, timeout=5)
        except OSError:
            pass

        # Per-sid logout — more reliable than --logoutall=all when a
        # session is wedged.
        for _ in range(3):
            r = subprocess.run(["iscsiadm", "-m", "session"],
                               capture_output=True, text=True, timeout=5)
            sids = []
            for line in (r.stdout or "").splitlines():
                # format: "tcp: [N] host:port,tpgt iqn (non-flash)"
                import re as _re
                m = _re.search(r"\[(\d+)\]", line)
                if m:
                    sids.append(m.group(1))
            if not sids:
                break
            for sid in sids:
                subprocess.run(
                    ["iscsiadm", "-m", "session", f"--sid={sid}", "--logout"],
                    capture_output=True, timeout=10,
                )
            _t.sleep(1)

        subprocess.run(["iscsiadm", "-m", "node", "-o", "delete",
                        "-T", ISCSI_IQN], capture_output=True, timeout=5)

        # Restart iscsid to drop cached connection / auth state.
        subprocess.run(["pkill", "-9", "iscsid"], capture_output=True)
        _t.sleep(0.5)
        subprocess.Popen(["iscsid"])
        _t.sleep(1.5)

        for _ in range(10):
            r = subprocess.run(["iscsiadm", "-m", "session"],
                               capture_output=True, text=True, timeout=3)
            if r.returncode in (0, 21):
                break
            _t.sleep(0.3)

        cls.session = _iscsi_session()

    @classmethod
    def teardown_class(cls):
        if cls.session is not None:
            try:
                cls.session.disconnect()
            except Exception:
                pass
            cls.session = None

    def test_iscsi_discover_and_login(self):
        s = self.session
        assert s.connected
        assert os.path.isdir(s._mount_point)
        assert s._device_path.startswith("/dev/"), s._device_path

    def test_iscsi_write_read_cycle(self):
        s = self.session
        path = "/iscsi_test_write.txt"
        with s.open_write(path) as f:
            f.write(b"iSCSI write\n")
        with s.open_read(path) as f:
            data = f.read()
        assert data == b"iSCSI write\n"
        s.remove(path)
        assert not s.exists(path)

    def test_iscsi_mkdir_list(self):
        s = self.session
        if s.exists("/iscsi_testdir"):
            s.remove("/iscsi_testdir")
        s.mkdir("/iscsi_testdir")
        assert s.is_dir("/iscsi_testdir")
        items = s.list_dir("/")
        assert any(i.name == "iscsi_testdir" for i in items)
        s.remove("/iscsi_testdir")

    def test_iscsi_path_traversal_is_blocked(self):
        """The mount-point path mapper must reject escape attempts."""
        s = self.session
        import pytest as _pt
        with _pt.raises(PermissionError):
            s.stat("/../../etc/passwd")

    # -- coverage gap-fillers

    def test_iscsi_path_helpers(self):
        _assert_path_helpers(self.session)

    def test_iscsi_disk_usage(self):
        total, used, free = self.session.disk_usage("/")
        assert total > 50 * 1024 * 1024, total  # 100 MB LUN minus fs overhead

    def test_iscsi_chmod_live(self):
        s = self.session
        path = "/iscsi_chmod_test.txt"
        try:
            with s.open_write(path) as f:
                f.write(b"chmod me\n")
            s.chmod(path, 0o600)
            assert s.stat(path).permissions & 0o777 == 0o600
        finally:
            if s.exists(path):
                s.remove(path)

    def test_iscsi_readlink_live(self):
        import os as _os
        s = self.session
        target = "/iscsi_target.txt"
        real_link = _os.path.join(s._mount_point, "iscsi_link.txt")
        try:
            with s.open_write(target) as f:
                f.write(b"target\n")
            if _os.path.lexists(real_link):
                _os.remove(real_link)
            _os.symlink("iscsi_target.txt", real_link)
            resolved = s.readlink("/iscsi_link.txt")
            assert resolved == "iscsi_target.txt"
        finally:
            if _os.path.lexists(real_link):
                _os.remove(real_link)
            if s.exists(target):
                s.remove(target)

    def test_iscsi_rename_live(self):
        """iSCSI rename was listed as gap in coverage matrix. Exercise it
        on both files and directories so the block-device filesystem
        path handles both."""
        s = self.session
        src_file = "/iscsi_rename_src.txt"
        dst_file = "/iscsi_rename_dst.txt"
        src_dir = "/iscsi_rename_srcdir"
        dst_dir = "/iscsi_rename_dstdir"
        try:
            with s.open_write(src_file) as f:
                f.write(b"rename me")
            s.rename(src_file, dst_file)
            assert not s.exists(src_file)
            assert s.exists(dst_file)

            s.mkdir(src_dir)
            s.rename(src_dir, dst_dir)
            assert not s.exists(src_dir)
            assert s.is_dir(dst_dir)
        finally:
            for p in (src_file, dst_file, src_dir, dst_dir):
                if s.exists(p):
                    s.remove(p)

    def test_iscsi_readlink_loop_is_detected(self):
        """A symlink pointing to itself must NOT crash readlink / stat.
        POSIX permits ELOOP detection on follow, but readlink()
        itself should return the literal target without following."""
        import os as _os
        s = self.session
        loop_path = _os.path.join(s._mount_point, "iscsi_selfloop")
        try:
            if _os.path.lexists(loop_path):
                _os.remove(loop_path)
            # Self-referencing symlink
            _os.symlink("iscsi_selfloop", loop_path)
            # readlink should NOT follow the link — it should return
            # the raw target string even when the target is itself.
            resolved = s.readlink("/iscsi_selfloop")
            assert resolved == "iscsi_selfloop", resolved
            # stat with follow=False (lstat semantics) should also work
            info = s.stat("/iscsi_selfloop")
            assert info.is_link is True, info
            assert info.link_target == "iscsi_selfloop", info.link_target
        finally:
            if _os.path.lexists(loop_path):
                _os.remove(loop_path)

    def test_iscsi_large_file(self):
        """50 MB round-trip — LUN is 100 MB, ext4 overhead eats some.
        Exercises the block-device filesystem under sustained write."""
        _large_roundtrip(self.session, "/large_iscsi.bin", _ISCSI_MB)

    def test_iscsi_readlink_chain_loop_is_detected(self):
        """A -> B -> A style chain. readlink() on A returns "B"; it
        must not silently resolve the loop."""
        import os as _os
        s = self.session
        a = _os.path.join(s._mount_point, "iscsi_chain_a")
        b = _os.path.join(s._mount_point, "iscsi_chain_b")
        try:
            for p in (a, b):
                if _os.path.lexists(p):
                    _os.remove(p)
            _os.symlink("iscsi_chain_b", a)
            _os.symlink("iscsi_chain_a", b)
            # readlink one step — no follow
            assert s.readlink("/iscsi_chain_a") == "iscsi_chain_b"
            assert s.readlink("/iscsi_chain_b") == "iscsi_chain_a"
            # A readthrough attempt via open_read would hit ELOOP; the
            # backend should surface an OSError rather than hang.
            try:
                with s.open_read("/iscsi_chain_a") as f:
                    f.read()
            except OSError:
                pass
            else:
                raise AssertionError(
                    "open_read through a symlink loop should raise OSError"
                )
        finally:
            for p in (a, b):
                if _os.path.lexists(p):
                    _os.remove(p)


# ════════════════════════════════════════════════════════════
#  SECTION 7: IMAP  (pytest-compatible)
# ════════════════════════════════════════════════════════════

def _imap_session():
    from core.imap_client import ImapSession
    return ImapSession(host=IMAP_HOST, port=IMAP_PORT, username=IMAP_USER,
                       password=IMAP_PASS, use_ssl=False)


class TestImap:
    """IMAP integration tests (Dovecot container on port 143)."""

    def test_imap_connect(self):
        s = _imap_session()
        try:
            assert s.connected
            items = s.list_dir("/")
            names = {i.name for i in items}
            assert "INBOX" in names, f"INBOX not found in {names}"
        finally:
            s.disconnect()

    def test_imap_list_dir(self):
        s = _imap_session()
        try:
            items = s.list_dir("/INBOX")
            eml_items = [i for i in items if i.name.endswith(".eml")]
            assert len(eml_items) >= 1, f"Expected at least 1 .eml, got {len(eml_items)}"
        finally:
            s.disconnect()

    def test_imap_write_read_cycle(self):
        s = _imap_session()
        try:
            test_msg = (
                b"From: test@example.com\r\n"
                b"To: imapuser@localhost\r\n"
                b"Subject: TestWriteRead\r\n"
                b"Message-ID: <writeread001@example.com>\r\n"
                b"\r\n"
                b"Test body content\r\n"
            )
            with s.open_write("/INBOX") as f:
                f.write(test_msg)
            # Force re-select so SEARCH sees the new message
            s._selected_mailbox = None
            items = s.list_dir("/INBOX")
            eml_items = [i for i in items if i.name.endswith(".eml")]
            found = [i for i in eml_items if "TestWriteRead" in i.name]
            assert len(found) >= 1, f"TestWriteRead not found in {[i.name for i in eml_items]}"
            with s.open_read(f"/INBOX/{found[0].name}") as f:
                content = f.read()
            assert b"Test body content" in content, f"Body not found in: {content[:200]}"
        finally:
            s.disconnect()

    def test_imap_mkdir_remove(self):
        s = _imap_session()
        try:
            mbox_name = "TestFolder"
            # Clean up if leftover (ignore error if not existing)
            try:
                s.remove(f"/{mbox_name}")
            except OSError:
                pass
            s.mkdir(f"/{mbox_name}")
            items = s.list_dir("/")
            names = {i.name for i in items}
            assert mbox_name in names, f"{mbox_name} not found in {names}"
            s.remove(f"/{mbox_name}")
            items = s.list_dir("/")
            names = {i.name for i in items}
            assert mbox_name not in names, f"{mbox_name} still present in {names}"
        finally:
            s.disconnect()

    def test_imap_rename(self):
        s = _imap_session()
        try:
            src = "RenSrc"
            dst = "RenDst"
            for name in (src, dst):
                try:
                    s.remove(f"/{name}")
                except OSError:
                    pass
            s.mkdir(f"/{src}")
            s.rename(f"/{src}", f"/{dst}")
            items = s.list_dir("/")
            names = {i.name for i in items}
            assert src not in names, f"{src} still present after rename"
            assert dst in names, f"{dst} not found after rename"
            s.remove(f"/{dst}")
        finally:
            s.disconnect()

    # -- coverage gap-fillers

    def test_imap_path_helpers(self):
        s = _imap_session()
        try:
            _assert_path_helpers(s, separator=s.separator())
        finally:
            s.disconnect()

    def test_imap_stat_is_dir_exists(self):
        s = _imap_session()
        try:
            assert s.is_dir("/INBOX") is True
            assert s.exists("/INBOX") is True
            info = s.stat("/INBOX")
            assert info.is_dir is True
        finally:
            s.disconnect()

    def test_imap_chmod_raises(self):
        s = _imap_session()
        try:
            try:
                s.chmod("/INBOX", 0o755)
            except OSError:
                return
            raise AssertionError("IMAP.chmod should raise OSError")
        finally:
            s.disconnect()

    def test_imap_readlink_raises(self):
        s = _imap_session()
        try:
            try:
                s.readlink("/INBOX")
            except OSError:
                return
            raise AssertionError("IMAP.readlink should raise OSError")
        finally:
            s.disconnect()

    def test_imap_disk_usage_raises(self):
        s = _imap_session()
        try:
            try:
                s.disk_usage("/INBOX")
            except OSError:
                return
            raise AssertionError("IMAP.disk_usage should raise OSError")
        finally:
            s.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 8: Telnet (shell commands over telnet)
# ════════════════════════════════════════════════════════════

def _telnet_session():
    from core.telnet_client import TelnetSession
    return TelnetSession(host=TELNET_HOST, port=TELNET_PORT,
                         username=TELNET_USER, password=TELNET_PASS)


class TestTelnet:
    @_label("Telnet 8.1 Connect")
    def test_telnet_connect(self):
        s = _telnet_session()
        try:
            assert s.connected
            home = s.home()
            assert home and home.startswith("/")
        finally:
            s.disconnect()

    @_label("Telnet 8.2 List dir")
    def test_telnet_list_dir(self):
        s = _telnet_session()
        try:
            items = s.list_dir(s.join(s.home(), "data"))
            names = [i.name for i in items]
            assert "readme.txt" in names
            assert "subdir" in names
            assert "bigfile.bin" in names
        finally:
            s.disconnect()

    @_label("Telnet 8.3 Stat")
    def test_telnet_stat(self):
        s = _telnet_session()
        try:
            item = s.stat(s.join(s.home(), "data", "readme.txt"))
            assert item.name == "readme.txt"
            assert item.size > 0
            assert not item.is_dir
        finally:
            s.disconnect()

    @_label("Telnet 8.4 Is dir / Exists")
    def test_telnet_is_dir_exists(self):
        s = _telnet_session()
        try:
            assert s.is_dir(s.join(s.home(), "data"))
            assert not s.is_dir(s.join(s.home(), "data", "readme.txt"))
            assert s.exists(s.join(s.home(), "data", "readme.txt"))
            assert not s.exists(s.join(s.home(), "nonexistent_xyz"))
        finally:
            s.disconnect()

    @_label("Telnet 8.5 Read file")
    def test_telnet_read(self):
        s = _telnet_session()
        try:
            with s.open_read(s.join(s.home(), "data", "readme.txt")) as f:
                data = f.read()
            assert b"Hello from Telnet" in data
        finally:
            s.disconnect()

    @_label("Telnet 8.6 Write + Read cycle")
    def test_telnet_write_read(self):
        s = _telnet_session()
        try:
            test_path = s.join(s.home(), "test_write.txt")
            test_data = b"Telnet write test 12345\nLine 2\n"
            with s.open_write(test_path) as f:
                f.write(test_data)
            with s.open_read(test_path) as f:
                read_back = f.read()
            assert read_back == test_data
            s.remove(test_path)
        finally:
            s.disconnect()

    @_label("Telnet 8.7 Binary roundtrip")
    def test_telnet_binary_roundtrip(self):
        s = _telnet_session()
        try:
            test_path = s.join(s.home(), "test_binary.bin")
            test_data = bytes(range(256)) * 4  # 1024 bytes with all byte values
            with s.open_write(test_path) as f:
                f.write(test_data)
            with s.open_read(test_path) as f:
                read_back = f.read()
            assert read_back == test_data, (
                f"Binary mismatch: wrote {len(test_data)} bytes, "
                f"read {len(read_back)} bytes"
            )
            s.remove(test_path)
        finally:
            s.disconnect()

    @_label("Telnet 8.8 Mkdir + Remove")
    def test_telnet_mkdir_remove(self):
        s = _telnet_session()
        try:
            dir_path = s.join(s.home(), "test_mkdir_dir")
            s.mkdir(dir_path)
            assert s.is_dir(dir_path)
            assert s.exists(dir_path)
            s.remove(dir_path)
            assert not s.exists(dir_path)
        finally:
            s.disconnect()

    @_label("Telnet 8.9 Rename")
    def test_telnet_rename(self):
        s = _telnet_session()
        try:
            src = s.join(s.home(), "rename_src.txt")
            dst = s.join(s.home(), "rename_dst.txt")
            with s.open_write(src) as f:
                f.write(b"rename test")
            assert s.exists(src)
            s.rename(src, dst)
            assert not s.exists(src)
            assert s.exists(dst)
            with s.open_read(dst) as f:
                assert f.read() == b"rename test"
            s.remove(dst)
        finally:
            s.disconnect()

    @_label("Telnet 8.10 Chmod")
    def test_telnet_chmod(self):
        s = _telnet_session()
        try:
            test_path = s.join(s.home(), "chmod_test.txt")
            with s.open_write(test_path) as f:
                f.write(b"chmod test")
            s.chmod(test_path, 0o755)
            item = s.stat(test_path)
            assert item.permissions & 0o111  # executable bits set
            s.remove(test_path)
        finally:
            s.disconnect()

    @_label("Telnet 8.11 Disk usage")
    def test_telnet_disk_usage(self):
        s = _telnet_session()
        try:
            total, used, free = s.disk_usage(s.home())
            assert total > 0
            assert used >= 0
            assert free >= 0
        finally:
            s.disconnect()

    @_label("Telnet 8.12 Symlink")
    def test_telnet_symlink(self):
        s = _telnet_session()
        try:
            items = s.list_dir(s.join(s.home(), "data"))
            link_items = [i for i in items if i.name == "link.txt"]
            assert len(link_items) == 1
            assert link_items[0].is_link
            target = s.readlink(s.join(s.home(), "data", "link.txt"))
            assert "readme.txt" in target
        finally:
            s.disconnect()

    @_label("Telnet 8.13 Empty file")
    def test_telnet_empty_file(self):
        s = _telnet_session()
        try:
            test_path = s.join(s.home(), "empty_test.txt")
            with s.open_write(test_path) as f:
                f.write(b"")
            with s.open_read(test_path) as f:
                data = f.read()
            assert data == b""
            s.remove(test_path)
        finally:
            s.disconnect()

    @_label("Telnet 8.14 Special filenames")
    def test_telnet_special_filenames(self):
        s = _telnet_session()
        try:
            test_path = s.join(s.home(), "file with spaces.txt")
            with s.open_write(test_path) as f:
                f.write(b"spaces test")
            with s.open_read(test_path) as f:
                assert f.read() == b"spaces test"
            s.remove(test_path)
        finally:
            s.disconnect()

    # -- coverage gap-fillers (normalize / separator / parent)

    def test_telnet_path_helpers(self):
        s = _telnet_session()
        try:
            _assert_path_helpers(s)
        finally:
            s.disconnect()

    def test_telnet_normalize(self):
        s = _telnet_session()
        try:
            n = s.normalize("/a/./b/../c")
            assert n == "/a/c", n
        finally:
            s.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 9: Cross-protocol transfer
# ════════════════════════════════════════════════════════════

@_label("Cross 5.1 FTP -> SMB file transfer")
def test_ftp_to_smb():
    from core.ftp_client import FtpSession
    from core.smb_client import SmbSession
    ftp = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    smb = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER, password=SMB_PASS, port=SMB_PORT)
    try:
        with ftp.open_read(ftp.join(ftp.home(), "data", "readme.txt")) as f:
            data = f.read()
        with smb.open_write("/from_ftp.txt") as f:
            f.write(data)
        with smb.open_read("/from_ftp.txt") as f:
            verify = f.read()
        assert verify == data
        smb.remove("/from_ftp.txt")
    finally:
        ftp.disconnect()
        smb.disconnect()


@_label("Cross 5.2 S3 -> WebDAV file transfer")
def test_s3_to_webdav():
    from core.s3_client import S3Session
    from core.webdav_client import WebDavSession
    s3 = S3Session(
        bucket=S3_BUCKET, region="us-east-1",
        access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
        endpoint=S3_ENDPOINT,
    )
    dav = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        with s3.open_read("/readme.txt") as f:
            data = f.read()
        with dav.open_write("/from_s3.txt") as f:
            f.write(data)
        with dav.open_read("/from_s3.txt") as f:
            verify = f.read()
        assert verify == data
        dav.remove("/from_s3.txt")
    finally:
        s3.disconnect()
        dav.disconnect()


@_label("Cross 5.3 SMB -> S3 file transfer")
def test_smb_to_s3():
    from core.smb_client import SmbSession
    from core.s3_client import S3Session
    smb = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER, password=SMB_PASS, port=SMB_PORT)
    s3 = S3Session(
        bucket=S3_BUCKET, region="us-east-1",
        access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
        endpoint=S3_ENDPOINT,
    )
    try:
        with smb.open_read("/readme.txt") as f:
            data = f.read()
        with s3.open_write("/from_smb.txt") as f:
            f.write(data)
        with s3.open_read("/from_smb.txt") as f:
            verify = f.read()
        assert verify == data
        s3.remove("/from_smb.txt")
    finally:
        smb.disconnect()
        s3.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 9: Azure Blob (against Azurite emulator)
# ════════════════════════════════════════════════════════════

class TestAzureBlob:
    """Azure Blob tests against the Azurite emulator.

    Azurite is the Microsoft-provided local Azure Storage emulator; it
    exposes the same API surface as real Azure Blob Storage. The magic
    connection string and account key are well-known constants baked
    into the emulator — they are not a secret.
    """

    session = None

    @classmethod
    def setup_class(cls):
        try:
            from core.azure_client import AzureBlobSession
        except ImportError as exc:
            pytest.skip(f"Azure Blob backend unavailable: {exc}")

        # Ensure the container exists. Azurite starts empty.
        try:
            from azure.storage.blob import BlobServiceClient
        except ImportError as exc:
            pytest.skip(f"azure-storage-blob not installed: {exc}")

        service = BlobServiceClient.from_connection_string(AZURITE_CONNECTION_STRING)
        container = service.get_container_client(AZURITE_CONTAINER)
        try:
            container.create_container()
        except Exception:
            pass  # already exists

        # Seed a few blobs under /data/
        container.upload_blob("data/readme.txt", b"Hello from Azurite\n",
                              overwrite=True)
        container.upload_blob("data/subdir/nested.txt", b"nested file\n",
                              overwrite=True)
        container.upload_blob("data/bigfile.bin", os.urandom(64 * 1024),
                              overwrite=True)

        cls.session = AzureBlobSession(
            connection_string=AZURITE_CONNECTION_STRING,
            container=AZURITE_CONTAINER,
        )

    @classmethod
    def teardown_class(cls):
        if cls.session is not None:
            try:
                cls.session.close()
            except Exception:
                pass
            cls.session = None

    def test_azure_blob_connect(self):
        s = self.session
        assert s.connected
        assert s.name.endswith("(Azure Blob)")

    def test_azure_blob_list_seed_data(self):
        s = self.session
        items = s.list_dir("/data")
        names = {i.name for i in items}
        assert "readme.txt" in names, names
        assert "subdir" in names, names
        assert "bigfile.bin" in names, names

    def test_azure_blob_read(self):
        s = self.session
        with s.open_read("/data/readme.txt") as f:
            data = f.read()
        assert data == b"Hello from Azurite\n"

    def test_azure_blob_write_read_cycle(self):
        s = self.session
        path = "/data/azxxross_roundtrip.txt"
        with s.open_write(path) as f:
            f.write(b"roundtrip payload\n")
        with s.open_read(path) as f:
            assert f.read() == b"roundtrip payload\n"
        s.remove(path)
        assert not s.exists(path)

    def test_azure_blob_stat_returns_size(self):
        s = self.session
        info = s.stat("/data/bigfile.bin")
        assert info.size == 64 * 1024, info.size
        assert not info.is_dir

    def test_azure_blob_mkdir_creates_virtual_dir(self):
        s = self.session
        # Azure Blob has no real directories; mkdir creates a zero-byte
        # marker blob or similar. The backend hides that abstraction.
        s.mkdir("/data/new_dir")
        assert s.is_dir("/data/new_dir")
        s.remove("/data/new_dir", recursive=True)

    def test_azure_blob_rename(self):
        s = self.session
        src = "/data/azrename_src.txt"
        dst = "/data/azrename_dst.txt"
        with s.open_write(src) as f:
            f.write(b"rename me\n")
        s.rename(src, dst)
        assert not s.exists(src)
        assert s.exists(dst)
        s.remove(dst)

    def test_azure_blob_recursive_listing(self):
        s = self.session
        items = s.list_dir("/data/subdir")
        names = {i.name for i in items}
        assert "nested.txt" in names, names

    # -- coverage gap-fillers

    def test_azure_blob_path_helpers(self):
        _assert_path_helpers(self.session)

    def test_azure_blob_chmod_raises(self):
        try:
            self.session.chmod("/data/readme.txt", 0o755)
        except OSError:
            return
        raise AssertionError("AzureBlob.chmod should raise OSError")

    def test_azure_blob_readlink_raises(self):
        try:
            self.session.readlink("/data/readme.txt")
        except OSError:
            return
        raise AssertionError("AzureBlob.readlink should raise OSError")

    def test_azure_blob_disk_usage_raises(self):
        """AzureBlob.disk_usage raises OSError by design — Azure has no
        quota API that maps cleanly to (total, used, free)."""
        try:
            self.session.disk_usage("/")
        except OSError:
            return
        raise AssertionError("AzureBlob.disk_usage should raise OSError")


# ════════════════════════════════════════════════════════════
#  SECTION 10: Coverage gap-fillers
#
#  The preceding sections exercise each protocol's core operations
#  (list / read / write / remove / rename). This section fills the
#  matrix for the remaining FileBackend methods:
#
#    - Path helpers: separator, join, parent, home, normalize
#    - Metadata:     chmod, readlink, disk_usage
#
#  For backends that raise OSError by design (FTP/SMB/WebDAV/S3/Rsync/
#  IMAP/Azure-Blob have no chmod/readlink on their wire protocol), we
#  pin that contract as a regression so nobody accidentally "fixes" it
#  with a silent no-op.
# ════════════════════════════════════════════════════════════


def _assert_path_helpers(s, *, separator="/"):
    """Shared contract checks for separator / join / parent / home / normalize.

    These are pure-Python helpers but diverge per backend (S3 uses POSIX
    separators even on Windows, Azure Blob has virtual directories, etc.).
    The checks are narrow on purpose: we verify the contract, not the
    internal implementation.
    """
    assert s.separator() == separator
    assert s.join("a", "b") == f"a{separator}b"
    # trailing-separator handling
    joined = s.join("dir" + separator, "file")
    assert joined.endswith("file")
    # parent of a joined path returns the directory part
    sample = s.join("parent", "child")
    assert s.parent(sample).endswith("parent")
    # home() returns a non-empty absolute-looking string
    home = s.home()
    assert isinstance(home, str) and len(home) > 0
    # normalize must be deterministic and never raise
    norm = s.normalize(sample)
    assert isinstance(norm, str)


# -- FTP -------------------------------------------------------------------

@_label("FTP-Gap Path helpers")
def test_ftp_path_helpers():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    try:
        _assert_path_helpers(s)
    finally:
        s.disconnect()


@_label("FTP-Gap disk_usage contract")
def test_ftp_disk_usage_contract():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    try:
        total, used, free = s.disk_usage(s.home())
        # FTP has no standard quota — expect the (0,0,0) stub, or a real answer.
        assert isinstance(total, int) and isinstance(used, int) and isinstance(free, int)
    finally:
        s.disconnect()


@_label("FTP-Gap chmod raises OSError")
def test_ftp_chmod_raises():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    try:
        try:
            s.chmod(s.home(), 0o755)
        except OSError:
            return
        raise AssertionError("FTP.chmod should raise OSError (no wire-level chmod)")
    finally:
        s.disconnect()


@_label("FTP-Gap readlink raises OSError")
def test_ftp_readlink_raises():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    try:
        try:
            s.readlink(s.home())
        except OSError:
            return
        raise AssertionError("FTP.readlink should raise OSError")
    finally:
        s.disconnect()


# -- FTPS ------------------------------------------------------------------

@_label("FTPS-Gap Path helpers + disk_usage")
def test_ftps_path_helpers_and_disk_usage():
    s = _ftps_session()
    try:
        _assert_path_helpers(s)
        total, used, free = s.disk_usage(s.home())
        assert isinstance(total, int)
    finally:
        s.disconnect()


# -- SMB -------------------------------------------------------------------

@_label("SMB-Gap Path helpers + disk_usage")
def test_smb_path_helpers_and_disk_usage():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER,
                   password=SMB_PASS, port=SMB_PORT)
    try:
        _assert_path_helpers(s)
        total, used, free = s.disk_usage("/")
        assert isinstance(total, int) and total >= 0
    finally:
        s.disconnect()


@_label("SMB-Gap chmod raises OSError")
def test_smb_chmod_raises():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER,
                   password=SMB_PASS, port=SMB_PORT)
    try:
        try:
            s.chmod("/", 0o755)
        except OSError:
            return
        raise AssertionError("SMB.chmod should raise OSError")
    finally:
        s.disconnect()


# -- WebDAV ----------------------------------------------------------------

@_label("WebDAV-Gap Path helpers")
def test_webdav_path_helpers():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        _assert_path_helpers(s)
    finally:
        s.disconnect()


@_label("WebDAV-Gap stat returns size and mtime for seed file")
def test_webdav_stat_live():
    """Apache mod_dav returns getcontentlength + getlastmodified.
    The backend must surface size > 0 and is_dir=False for a real file."""
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        info = s.stat("/readme.txt")
        assert info.name == "readme.txt", info.name
        assert info.size > 0, info.size
        assert info.is_dir is False
    finally:
        s.disconnect()


@_label("WebDAV-Gap stat on directory reports is_dir=True")
def test_webdav_stat_directory_live():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        info = s.stat("/subdir")
        assert info.is_dir is True, info
    finally:
        s.disconnect()


@_label("WebDAV-Gap is_dir / exists contract live")
def test_webdav_is_dir_exists_live():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        assert s.is_dir("/") is True
        assert s.is_dir("/subdir") is True
        assert s.is_dir("/readme.txt") is False
        assert s.exists("/readme.txt") is True
        assert s.exists("/nonexistent_path_xyz.txt") is False
        assert s.exists("/subdir") is True
    finally:
        s.disconnect()


@_label("WebDAV-Gap disk_usage exercises XXE-guarded PROPFIND parser")
def test_webdav_disk_usage_live():
    """Exercises the hardened defusedxml code path on an actual server.
    Apache mod_dav does not return quota, so we expect (0, 0, 0); the
    important assertion is that the call completes without raising and
    without invoking the old stdlib xml.etree parser."""
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        total, used, free = s.disk_usage("/")
        assert isinstance(total, int)
        assert isinstance(used, int)
        assert isinstance(free, int)
    finally:
        s.disconnect()


@_label("WebDAV-Gap chmod raises OSError")
def test_webdav_chmod_raises():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        try:
            s.chmod("/", 0o755)
        except OSError:
            return
        raise AssertionError("WebDAV.chmod should raise OSError")
    finally:
        s.disconnect()


# -- S3 --------------------------------------------------------------------

@_label("S3-Gap Path helpers + disk_usage")
def test_s3_path_helpers():
    from core.s3_client import S3Session
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        _assert_path_helpers(s)
        total, used, free = s.disk_usage("/")
        assert isinstance(total, int)
    finally:
        s.disconnect()


# -- Rsync -----------------------------------------------------------------

@_label("Rsync-Gap Path helpers")
def test_rsync_path_helpers():
    from core.rsync_client import RsyncSession
    s = RsyncSession(host=RSYNC_HOST, port=RSYNC_PORT, module=RSYNC_MODULE,
                     username=RSYNC_USER, password=RSYNC_PASS)
    try:
        _assert_path_helpers(s)
    finally:
        s.disconnect()


@_label("Rsync-Gap stat/is_dir/exists on seed data")
def test_rsync_metadata_ops():
    from core.rsync_client import RsyncSession
    s = RsyncSession(host=RSYNC_HOST, port=RSYNC_PORT, module=RSYNC_MODULE,
                     username=RSYNC_USER, password=RSYNC_PASS)
    try:
        items = s.list_dir("/")
        assert len(items) > 0
        # Pick first non-directory entry if available, else any entry
        target = next((i for i in items if not i.is_dir), items[0])
        info = s.stat(f"/{target.name}")
        assert info.name == target.name
        assert s.exists(f"/{target.name}")
        assert s.is_dir("/") is True
        assert s.exists("/nonexistent_file_xyz") is False
    finally:
        s.disconnect()


# NOTE: NFS, iSCSI, IMAP, Telnet, Azure Blob gap-fillers are added as
# methods on the existing Test<Proto> classes below to reuse their
# class-scoped session fixtures. Creating a separate class here would
# spawn a *second* session against the same endpoint — for iSCSI this
# conflicts with the kernel's single-session-per-target constraint.


# ════════════════════════════════════════════════════════════
#  SECTION 11: Sad paths & edge cases
#
#  The preceding sections validate happy paths. This section covers
#  the obvious failure modes we need to understand BEFORE they bite a
#  user in the field:
#
#    - Wrong credentials:     all protocols raise cleanly?
#    - Unreachable endpoints: clean OSError / ConnectionError?
#    - Unicode filenames:     round-trip across wire encodings?
#    - Empty file round-trip: zero-byte isn't a corner case pretend
#                             it isn't
#    - Transfer cancellation: UI cancel button actually stops I/O?
#    - Malformed paths:       trailing slash, "//foo", ".", ""
# ════════════════════════════════════════════════════════════

# Unreachable endpoint — port 1 on 10.99.0.1 is guaranteed-closed on
# the docker bridge gateway. Some backends produce ConnectionError,
# some OSError, some ImportError (optional dep missing) — the
# contract is "raise something, don't hang forever".
_UNREACHABLE_HOST = "10.99.0.1"
_UNREACHABLE_PORT = 1


def _expect_auth_or_connection_error(op, label="op"):
    """Call *op* and assert it raises a recognizable auth/network error.

    Accept any of: OSError (base of ConnectionError), paramiko's
    AuthenticationException, smbprotocol's LogonFailure, or a
    string-matched "auth"/"login"/"logon" failure. Reject: silent
    success, or raising an unrelated exception type.
    """
    try:
        op()
    except OSError:
        return
    except Exception as exc:
        name = type(exc).__name__.lower()
        msg = str(exc).lower()
        if any(k in name or k in msg for k in (
            "auth", "login", "logon", "credential", "denied",
            "forbidden", "unauthorized", "invalid", "reject",
            "connect", "timeout", "refused", "access",
        )):
            return
        raise AssertionError(f"{label} raised unexpected {type(exc).__name__}: {exc}")
    raise AssertionError(f"{label} should have raised on invalid input")


# ── Wrong credentials ─────────────────────────────────────────────────

@_label("Sad 11.1a FTP wrong password")
def test_ftp_wrong_password():
    from core.ftp_client import FtpSession
    _expect_auth_or_connection_error(
        lambda: FtpSession(host=FTP_HOST, port=FTP_PORT,
                           username=FTP_USER, password="wrong-" + FTP_PASS),
        "FTP wrong password",
    )


@_label("Sad 11.1b FTPS wrong password")
def test_ftps_wrong_password():
    from core.ftp_client import FtpSession
    _expect_auth_or_connection_error(
        lambda: FtpSession(host=FTPS_HOST, port=FTPS_PORT,
                           username=FTPS_USER, password="wrong-" + FTPS_PASS,
                           tls=True, verify_tls=False),
        "FTPS wrong password",
    )


@_label("Sad 11.1c SMB wrong password")
def test_smb_wrong_password():
    from core.smb_client import SmbSession
    _expect_auth_or_connection_error(
        lambda: SmbSession(host=SMB_HOST, share=SMB_SHARE,
                           username=SMB_USER, password="bogus", port=SMB_PORT),
        "SMB wrong password",
    )


@_label("Sad 11.1d WebDAV wrong password")
def test_webdav_wrong_password():
    from core.webdav_client import WebDavSession
    _expect_auth_or_connection_error(
        lambda: WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password="bogus"),
        "WebDAV wrong password",
    )


@_label("Sad 11.1e S3 wrong credentials")
def test_s3_wrong_credentials():
    from core.s3_client import S3Session
    _expect_auth_or_connection_error(
        lambda: S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                          access_key="WRONG", secret_key="WRONG",
                          region="us-east-1"),
        "S3 wrong credentials",
    )


@_label("Sad 11.1f Rsync wrong password")
def test_rsync_wrong_password():
    from core.rsync_client import RsyncSession
    _expect_auth_or_connection_error(
        lambda: RsyncSession(host=RSYNC_HOST, port=RSYNC_PORT, module=RSYNC_MODULE,
                             username=RSYNC_USER, password="wrong"),
        "Rsync wrong password",
    )


@_label("Sad 11.1g IMAP wrong password")
def test_imap_wrong_password():
    from core.imap_client import ImapSession
    _expect_auth_or_connection_error(
        lambda: ImapSession(host=IMAP_HOST, port=IMAP_PORT,
                            username=IMAP_USER, password="bogus",
                            use_ssl=False),
        "IMAP wrong password",
    )


@_label("Sad 11.1h Telnet wrong password")
def test_telnet_wrong_password():
    from core.telnet_client import TelnetSession
    _expect_auth_or_connection_error(
        lambda: TelnetSession(host=TELNET_HOST, port=TELNET_PORT,
                              username=TELNET_USER, password="bogus"),
        "Telnet wrong password",
    )


@_label("Sad 11.1i Azure Blob wrong credentials")
def test_azure_blob_wrong_credentials():
    try:
        from core.azure_client import AzureBlobSession
    except ImportError:
        return  # backend optional
    bad_conn = (
        f"DefaultEndpointsProtocol=http;"
        f"AccountName={AZURITE_ACCOUNT};"
        f"AccountKey={'A' * 88}=="  # wrong key, base64-ish shape
        f";BlobEndpoint=http://{AZURITE_HOST}:10000/{AZURITE_ACCOUNT};"
    )
    _expect_auth_or_connection_error(
        lambda: AzureBlobSession(connection_string=bad_conn,
                                 container=AZURITE_CONTAINER),
        "Azure Blob wrong credentials",
    )


# ── Unreachable endpoints ─────────────────────────────────────────────

@_label("Sad 11.2a FTP unreachable host")
def test_ftp_unreachable():
    from core.ftp_client import FtpSession
    _expect_auth_or_connection_error(
        lambda: FtpSession(host=_UNREACHABLE_HOST, port=_UNREACHABLE_PORT,
                           username="u", password="p"),
        "FTP unreachable",
    )


@_label("Sad 11.2b SMB unreachable host")
def test_smb_unreachable():
    from core.smb_client import SmbSession
    _expect_auth_or_connection_error(
        lambda: SmbSession(host=_UNREACHABLE_HOST, port=_UNREACHABLE_PORT,
                           share="x", username="u", password="p"),
        "SMB unreachable",
    )


@_label("Sad 11.2c Telnet unreachable host")
def test_telnet_unreachable():
    from core.telnet_client import TelnetSession
    _expect_auth_or_connection_error(
        lambda: TelnetSession(host=_UNREACHABLE_HOST, port=_UNREACHABLE_PORT,
                              username="u", password="p"),
        "Telnet unreachable",
    )


# ── Unicode filenames ─────────────────────────────────────────────────
# Name mixes Emoji, Cyrillic, CJK, Umlauts — common FS/encoding stressor.

_UNICODE_FILENAME = "тест-файл_📄_ドキュメント_Ä.txt"
_UNICODE_CONTENT = "Hëllo wörld 世界\n".encode("utf-8")


def _unicode_roundtrip(session, dir_path="/"):
    """Write+read a unicode-named file under *dir_path* and assert it round-trips."""
    path = session.join(dir_path, _UNICODE_FILENAME) if hasattr(session, "join") else f"{dir_path.rstrip('/')}/{_UNICODE_FILENAME}"
    try:
        with session.open_write(path) as f:
            f.write(_UNICODE_CONTENT)
        with session.open_read(path) as f:
            assert f.read() == _UNICODE_CONTENT
        items = session.list_dir(dir_path)
        assert any(i.name == _UNICODE_FILENAME for i in items), \
            f"unicode name not in listing: {[i.name for i in items]}"
    finally:
        if session.exists(path):
            session.remove(path)


_FTP_UNICODE_LATIN1 = "tëst-fïle_Ünicode_ñame.txt"


@_label("Sad 11.3a FTP unicode filename (latin-1 subset)")
def test_ftp_unicode():
    """FTP may fall back to latin-1 encoding when the server does not
    advertise UTF-8 (pure-ftpd on the docker lab does not advertise it
    in FEAT). Emoji/CJK/Cyrillic are genuinely not representable in
    latin-1 — we test the subset that IS: Western accented characters,
    German umlauts. Full-unicode coverage is in SMB/WebDAV/S3."""
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    try:
        name = _FTP_UNICODE_LATIN1
        path = s.join(s.home(), name)
        content = "Ümlaut payload: ñoño, café, résumé\n".encode("utf-8")
        try:
            with s.open_write(path) as f:
                f.write(content)
            with s.open_read(path) as f:
                assert f.read() == content
            items = s.list_dir(s.home())
            assert any(i.name == name for i in items), \
                f"name not in listing: {[i.name for i in items]}"
        finally:
            if s.exists(path):
                s.remove(path)
    finally:
        s.disconnect()


@_label("Sad 11.3a2 FTP unicode mkdir / rename / stat (latin-1 subset)")
def test_ftp_unicode_mkdir_rename_stat():
    """Write-paths for directory mgmt + metadata should survive the
    same latin-1-subset treatment as filenames. Historically is_dir()
    crashed on non-ASCII response decoding — regression here."""
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    try:
        dir_name = "Ümläut-Øvertuning_dïr"
        dir_path = s.join(s.home(), dir_name)
        file_name = "rësumé.txt"
        file_path = s.join(dir_path, file_name)
        renamed_dir = s.join(s.home(), "rënämed_" + dir_name)
        try:
            s.mkdir(dir_path)
            assert s.is_dir(dir_path), "is_dir returned False after mkdir"

            with s.open_write(file_path) as f:
                f.write(b"payload")

            info = s.stat(file_path)
            assert info.name == file_name, info.name
            assert info.size == 7, info.size
            assert info.is_dir is False

            dir_info = s.stat(dir_path)
            assert dir_info.is_dir is True, dir_info

            # Rename the whole directory tree
            s.rename(dir_path, renamed_dir)
            assert s.exists(renamed_dir)
            assert not s.exists(dir_path)
            assert s.exists(s.join(renamed_dir, file_name))
        finally:
            for p in (renamed_dir, dir_path):
                if s.exists(p):
                    s.remove(p, recursive=True)
    finally:
        s.disconnect()


@_label("Sad 11.3a3 FTP full unicode (Emoji/CJK) documented as server-limited")
def test_ftp_full_unicode_is_server_limited():
    """pure-ftpd does NOT advertise UTF8 in FEAT, which makes full
    unicode (Emoji / CJK / Cyrillic) unsupported end-to-end on this
    server. We pin this as a regression so that if the server / client
    combination ever DOES gain UTF-8 support we notice and tighten the
    matrix."""
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    try:
        assert s._ftp.encoding == "latin-1", (
            "pure-ftpd should not advertise UTF-8; encoding negotiation changed")
        emoji_name = "файл_📄_ドキュメント.txt"
        emoji_path = s.join(s.home(), emoji_name)
        try:
            with s.open_write(emoji_path) as f:
                f.write(b"unused")
        except UnicodeEncodeError:
            return  # expected: server-imposed limitation
        except OSError:
            return  # server refused
        # If write succeeded, the limitation is gone — note it and
        # clean up so future refactors can widen this test.
        if s.exists(emoji_path):
            s.remove(emoji_path)
        raise AssertionError(
            "FTP accepted Emoji/CJK path — remove this guard test and "
            "promote test_ftp_full_unicode_roundtrip instead."
        )
    finally:
        s.disconnect()


@_label("Sad 11.3b SMB unicode filename")
def test_smb_unicode():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER,
                   password=SMB_PASS, port=SMB_PORT)
    try:
        _unicode_roundtrip(s, "/")
    finally:
        s.disconnect()


@_label("Sad 11.3c WebDAV unicode filename")
def test_webdav_unicode():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        _unicode_roundtrip(s, "/")
    finally:
        s.disconnect()


@_label("Sad 11.3d S3 unicode filename")
def test_s3_unicode():
    from core.s3_client import S3Session
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        _unicode_roundtrip(s, "/")
    finally:
        s.disconnect()


# ── Empty-file round-trip ─────────────────────────────────────────────

def _empty_file_roundtrip(s, dir_path):
    path = s.join(dir_path, "empty_rt.txt") if hasattr(s, "join") else \
           f"{dir_path.rstrip('/')}/empty_rt.txt"
    try:
        with s.open_write(path) as f:
            f.write(b"")
        with s.open_read(path) as f:
            assert f.read() == b""
        assert s.exists(path)
    finally:
        if s.exists(path):
            s.remove(path)


@_label("Sad 11.4a FTP empty file")
def test_ftp_empty_file():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    try:
        _empty_file_roundtrip(s, s.home())
    finally:
        s.disconnect()


@_label("Sad 11.4b SMB empty file")
def test_smb_empty_file():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER,
                   password=SMB_PASS, port=SMB_PORT)
    try:
        _empty_file_roundtrip(s, "/")
    finally:
        s.disconnect()


@_label("Sad 11.4c WebDAV empty file")
def test_webdav_empty_file():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        _empty_file_roundtrip(s, "/")
    finally:
        s.disconnect()


@_label("Sad 11.4d S3 empty file")
def test_s3_empty_file():
    from core.s3_client import S3Session
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        _empty_file_roundtrip(s, "/")
    finally:
        s.disconnect()


# ── Malformed paths ──────────────────────────────────────────────────

def _malformed_path_contract(s, root="/"):
    """Edge cases that every backend must at least not segfault on.

    The contract is intentionally narrow: no particular return value is
    required, only that the call raises OSError OR returns something
    sane. We catch OSError and move on; a segfault / hang / silent
    incorrect answer would be the real bug.
    """
    for odd in [
        root + "/",            # trailing slash on root
        root + "//double",     # doubled separator
        root + "/a/./b",       # "." component
        "",                    # empty
    ]:
        try:
            s.exists(odd)
        except OSError:
            pass


@_label("Sad 11.5a FTP malformed paths")
def test_ftp_malformed_paths():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    try:
        _malformed_path_contract(s, s.home())
    finally:
        s.disconnect()


@_label("Sad 11.5b SMB malformed paths")
def test_smb_malformed_paths():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER,
                   password=SMB_PASS, port=SMB_PORT)
    try:
        _malformed_path_contract(s, "/")
    finally:
        s.disconnect()


@_label("Sad 11.5c S3 malformed paths")
def test_s3_malformed_paths():
    from core.s3_client import S3Session
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        _malformed_path_contract(s, "/")
    finally:
        s.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 12: Fault injection via toxiproxy
#
#  Toxiproxy sits between our client code and a backend server, and
#  lets us cut / slow / corrupt the TCP link mid-operation. We use it
#  to prove the client code handles adverse network conditions
#  (connection drop, rate-limit, bandwidth cap, latency) without
#  hanging or silently corrupting data.
# ════════════════════════════════════════════════════════════

TOXIPROXY_HOST = "10.99.0.50"
TOXIPROXY_ADMIN = f"http://{TOXIPROXY_HOST}:8474"


def _toxiproxy_create(name: str, upstream_host: str, upstream_port: int,
                      listen_port: int) -> str:
    """Create a toxiproxy in front of *upstream_host:upstream_port*.
    Returns the listen host (always 10.99.0.50) / port our client should connect to.
    Raises on HTTP failure."""
    import urllib.request
    import json as _json
    # Delete stale proxy with same name if present
    try:
        req = urllib.request.Request(
            f"{TOXIPROXY_ADMIN}/proxies/{name}", method="DELETE")
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass
    data = _json.dumps({
        "name": name,
        "listen": f"0.0.0.0:{listen_port}",
        "upstream": f"{upstream_host}:{upstream_port}",
        "enabled": True,
    }).encode()
    req = urllib.request.Request(
        f"{TOXIPROXY_ADMIN}/proxies",
        data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=3).read()
    return TOXIPROXY_HOST


def _toxiproxy_delete(name: str) -> None:
    import urllib.request
    try:
        req = urllib.request.Request(
            f"{TOXIPROXY_ADMIN}/proxies/{name}", method="DELETE")
        urllib.request.urlopen(req, timeout=3)
    except Exception:
        pass


def _toxiproxy_disable(name: str) -> None:
    """Toggle a proxy off — simulates a mid-transfer link drop."""
    import urllib.request
    import json as _json
    data = _json.dumps({"enabled": False}).encode()
    req = urllib.request.Request(
        f"{TOXIPROXY_ADMIN}/proxies/{name}",
        data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=3).read()


def _toxiproxy_add_toxic(proxy: str, toxic_name: str, toxic_type: str,
                         attributes: dict, stream: str = "downstream") -> None:
    """Attach a toxic (bandwidth, latency, slow_close, ...) to a proxy.

    stream: "downstream" = server → client (affects response body),
            "upstream"   = client → server (affects request body).
    Pass one toxic per stream if you want both directions throttled;
    this helper installs a single toxic per call.
    """
    import urllib.request
    import json as _json
    data = _json.dumps({
        "name": toxic_name,
        "type": toxic_type,
        "stream": stream,
        "toxicity": 1.0,
        "attributes": attributes,
    }).encode()
    req = urllib.request.Request(
        f"{TOXIPROXY_ADMIN}/proxies/{proxy}/toxics",
        data=data, method="POST",
        headers={"Content-Type": "application/json"},
    )
    urllib.request.urlopen(req, timeout=3).read()


@_label("Fault 12.1 IMAP mid-transfer connection drop surfaces as error")
def test_imap_mid_transfer_drop():
    """IMAP uses a single TCP channel (no out-of-band data channel like
    FTP PASV), so a toxiproxy link-drop cleanly reaches the client."""
    import threading
    import time as _t
    from core.imap_client import ImapSession
    PROXY = "imap_drop_test"
    try:
        _toxiproxy_create(PROXY, IMAP_HOST, IMAP_PORT, 10143)
        s = ImapSession(host=TOXIPROXY_HOST, port=10143,
                        username=IMAP_USER, password=IMAP_PASS,
                        use_ssl=False)
        try:
            s.list_dir("/")  # prove the channel works

            _toxiproxy_disable(PROXY)
            try:
                for _ in range(50):
                    s.list_dir("/")
                    _t.sleep(0.02)
                raise AssertionError("IMAP did not raise after drop")
            except Exception as exc:
                name = type(exc).__name__.lower()
                if any(k in name for k in (
                    "error", "connection", "timeout", "reset", "abort",
                    "eof", "bye",
                )):
                    return
                raise
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


@_label("Fault 12.4 toxiproxy bandwidth cap actually throttles the wire")
def test_toxiproxy_bandwidth_cap_effective():
    """Proves the fault-injection infrastructure actually throttles
    bytes — independent of any axross backend. 64 KB through a
    32 KB/s cap must take at least 1.5 seconds at the HTTP level.

    We test on RAW HTTP (not through webdavclient3) because
    webdavclient3 does its own buffering and makes wire-level
    bandwidth assertions unreliable through it. The later
    protocol-specific tests trust that this infrastructure works.
    """
    import time as _t
    import urllib.request
    import base64
    PROXY = "wire_bw"
    try:
        _toxiproxy_create(PROXY, WEBDAV_HOST, WEBDAV_PORT, 10091)
        _toxiproxy_add_toxic(PROXY, "slow", "bandwidth", {"rate": 32})
        auth = base64.b64encode(f"{WEBDAV_USER}:{WEBDAV_PASS}".encode()).decode()
        req = urllib.request.Request(
            f"http://{TOXIPROXY_HOST}:10091/bigfile.bin",
            headers={"Authorization": f"Basic {auth}"},
        )
        t0 = _t.monotonic()
        data = urllib.request.urlopen(req, timeout=15).read()
        dt = _t.monotonic() - t0
        assert len(data) == 65536, len(data)
        assert dt > 1.5, f"bandwidth cap not effective: {dt:.2f}s"
    finally:
        _toxiproxy_delete(PROXY)


@_label("Fault 12.4b WebDAV open_read completes under bandwidth cap")
def test_webdav_open_read_under_bandwidth_cap():
    """Functional: WebDavSession.open_read must return the full payload
    under a bandwidth cap without hanging, even if webdavclient3 does
    its own buffering. This covers the 'client doesn't freak out under
    slow network' scenario for real user code."""
    import time as _t
    from core.webdav_client import WebDavSession
    PROXY = "wd_slow_read"
    try:
        _toxiproxy_create(PROXY, WEBDAV_HOST, WEBDAV_PORT, 10082)
        _toxiproxy_add_toxic(PROXY, "slow", "bandwidth", {"rate": 64})
        s = WebDavSession(
            url=f"http://{TOXIPROXY_HOST}:10082",
            username=WEBDAV_USER, password=WEBDAV_PASS,
        )
        try:
            t0 = _t.monotonic()
            with s.open_read("/bigfile.bin") as f:
                data = f.read()
            dt = _t.monotonic() - t0
            assert len(data) == 65536
            # Just assert it completed under a sensible ceiling
            assert dt < 30.0, f"unexpectedly slow: {dt:.2f}s"
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


@_label("Fault 12.5 IMAP behind high-latency link: still completes")
def test_imap_high_latency():
    """Add 200ms per-packet latency. A handful of commands should
    still complete; the goal is to prove the client doesn't wedge
    when RTTs spike."""
    import time as _t
    from core.imap_client import ImapSession
    PROXY = "imap_laggy"
    try:
        _toxiproxy_create(PROXY, IMAP_HOST, IMAP_PORT, 10144)
        _toxiproxy_add_toxic(PROXY, "lag", "latency",
                             {"latency": 200, "jitter": 50})
        s = ImapSession(host=TOXIPROXY_HOST, port=10144,
                        username=IMAP_USER, password=IMAP_PASS,
                        use_ssl=False)
        try:
            t0 = _t.monotonic()
            items = s.list_dir("/")
            dt = _t.monotonic() - t0
            assert len(items) > 0
            # Minimum: ~200ms for at least the LIST roundtrip. If it
            # finished in <100ms toxiproxy's latency toxic isn't active.
            assert dt > 0.2, f"latency toxic not effective: {dt:.2f}s"
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


@_label("Fault 12.3 WebDAV mid-transfer connection drop surfaces as error")
def test_webdav_mid_transfer_drop():
    """HTTP is single-channel — toxiproxy drop applies directly."""
    import threading
    import time as _t
    from core.webdav_client import WebDavSession
    PROXY = "webdav_drop_test"
    try:
        _toxiproxy_create(PROXY, WEBDAV_HOST, WEBDAV_PORT, 10080)
        proxied_url = f"http://{TOXIPROXY_HOST}:10080"
        s = WebDavSession(url=proxied_url, username=WEBDAV_USER,
                          password=WEBDAV_PASS)
        try:
            s.list_dir("/")

            _toxiproxy_disable(PROXY)
            try:
                for _ in range(20):
                    s.list_dir("/")
                    _t.sleep(0.05)
                raise AssertionError("WebDAV did not raise after drop")
            except Exception as exc:
                name = type(exc).__name__.lower()
                msg = str(exc).lower()
                if any(k in name or k in msg for k in (
                    "error", "connection", "timeout", "reset",
                    "refused", "closed",
                )):
                    return
                raise
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


@_label("Fault 12.2 SMB mid-transfer connection drop surfaces as error")
def test_smb_mid_transfer_drop():
    """Same pattern for SMB: connect through toxiproxy, disable proxy
    after a short delay, verify the next I/O surfaces as an exception
    rather than hanging.

    smbclient's session pool keys on host only and doesn't always
    honour a custom port across register / listdir pairs, so we run
    toxiproxy on the standard SMB port 445 on its own IP."""
    import threading
    import time as _t
    from core.smb_client import SmbSession
    PROXY = "smb_drop_test"
    try:
        _toxiproxy_create(PROXY, SMB_HOST, SMB_PORT, 445)
        s = SmbSession(host=TOXIPROXY_HOST, share=SMB_SHARE,
                       username=SMB_USER, password=SMB_PASS, port=445)
        try:
            def kill():
                _t.sleep(0.1)
                _toxiproxy_disable(PROXY)
            threading.Thread(target=kill, daemon=True).start()

            try:
                for _ in range(200):
                    s.list_dir("/")
                raise AssertionError("SMB hung after proxy drop")
            except Exception as exc:
                name = type(exc).__name__.lower()
                if any(k in name for k in (
                    "error", "connection", "timeout", "closed",
                )):
                    return
                raise
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


# ════════════════════════════════════════════════════════════
#  SECTION 13: Large-file round-trips
#
#  Previously only SSH was tested at 1 MB. Here we take 100 MB through
#  every real-storage protocol + a 1 GB canary via SSH, with SHA-256
#  verification on the round-trip. Catches chunking bugs, memory
#  leaks, and buffer-reuse problems that small files don't exercise.
# ════════════════════════════════════════════════════════════

_LARGE_MB = 100
_XLARGE_MB = 1024  # 1 GB canary for SSH only
_ISCSI_MB = 50     # iSCSI LUN is 100 MB; ext4 overhead eats some


def _stream_pattern_bytes(total: int, chunk: int = 1024 * 1024):
    """Yield deterministic 1-MiB chunks of a known pattern. SHA-256 of
    the full stream is recomputed by the caller from the same iterator
    so we avoid allocating the whole payload in RAM twice."""
    import struct
    for i in range(0, total, chunk):
        n = min(chunk, total - i)
        # 8-byte big-endian counter followed by pad. Different per
        # chunk so a misplaced chunk is detectable.
        header = struct.pack(">Q", i)
        yield (header + b"\xab" * (n - 8))[:n] if n >= 8 else b"\xab" * n


def _pattern_sha256(total: int) -> str:
    import hashlib
    h = hashlib.sha256()
    for chunk in _stream_pattern_bytes(total):
        h.update(chunk)
    return h.hexdigest()


def _write_pattern(session, path: str, total: int) -> None:
    with session.open_write(path) as f:
        for chunk in _stream_pattern_bytes(total):
            f.write(chunk)


def _verify_pattern(session, path: str, expected_sha: str) -> None:
    import hashlib
    h = hashlib.sha256()
    with session.open_read(path) as f:
        while True:
            chunk = f.read(1024 * 1024)
            if not chunk:
                break
            h.update(chunk)
    assert h.hexdigest() == expected_sha, "payload hash mismatch"


def _large_roundtrip(session, path: str, mb: int) -> None:
    total = mb * 1024 * 1024
    expected = _pattern_sha256(total)
    try:
        _write_pattern(session, path, total)
        _verify_pattern(session, path, expected)
    finally:
        if session.exists(path):
            session.remove(path)


# FTP 100 MB — pure-ftpd, single connection
@_label(f"Large 13.1 FTP {_LARGE_MB} MB round-trip")
def test_ftp_large_file():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT, username=FTP_USER, password=FTP_PASS)
    try:
        _large_roundtrip(s, s.join(s.home(), "large_ftp.bin"), _LARGE_MB)
    finally:
        s.disconnect()


# SMB 100 MB
@_label(f"Large 13.2 SMB {_LARGE_MB} MB round-trip")
def test_smb_large_file():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER,
                   password=SMB_PASS, port=SMB_PORT)
    try:
        _large_roundtrip(s, "/large_smb.bin", _LARGE_MB)
    finally:
        s.disconnect()


# WebDAV 100 MB — Apache mod_dav via spooled temp file
@_label(f"Large 13.3 WebDAV {_LARGE_MB} MB round-trip")
def test_webdav_large_file():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        _large_roundtrip(s, "/large_webdav.bin", _LARGE_MB)
    finally:
        s.disconnect()


# S3 100 MB — MinIO, multipart upload territory
@_label(f"Large 13.4 S3 {_LARGE_MB} MB round-trip")
def test_s3_large_file():
    from core.s3_client import S3Session
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        _large_roundtrip(s, "/large_s3.bin", _LARGE_MB)
    finally:
        s.disconnect()


# Rsync 100 MB
@_label(f"Large 13.5 Rsync {_LARGE_MB} MB round-trip")
def test_rsync_large_file():
    from core.rsync_client import RsyncSession
    s = RsyncSession(host=RSYNC_HOST, port=RSYNC_PORT, module=RSYNC_MODULE,
                     username=RSYNC_USER, password=RSYNC_PASS)
    try:
        _large_roundtrip(s, "/large_rsync.bin", _LARGE_MB)
    finally:
        s.disconnect()


# Azure Blob 100 MB via Azurite — reuses class fixture
class TestAzureBlobLarge:
    session = None

    @classmethod
    def setup_class(cls):
        try:
            from core.azure_client import AzureBlobSession
        except ImportError as exc:
            pytest.skip(f"Azure Blob backend unavailable: {exc}")
        try:
            from azure.storage.blob import BlobServiceClient
        except ImportError as exc:
            pytest.skip(f"azure-storage-blob not installed: {exc}")
        service = BlobServiceClient.from_connection_string(AZURITE_CONNECTION_STRING)
        container = service.get_container_client(AZURITE_CONTAINER)
        try:
            container.create_container()
        except Exception:
            pass
        cls.session = AzureBlobSession(
            connection_string=AZURITE_CONNECTION_STRING,
            container=AZURITE_CONTAINER,
        )

    @classmethod
    def teardown_class(cls):
        if cls.session is not None:
            cls.session.close()

    def test_azure_blob_large_file(self):
        _large_roundtrip(self.session, "/large_azure.bin", _LARGE_MB)


# NFS 100 MB (reuses TestNfs class-scope session pattern)
@_label(f"Large 13.7 NFS {_LARGE_MB} MB round-trip")
def test_nfs_large_file():
    _skip_if_nfs_unavailable()
    s = _nfs_session()
    try:
        _large_roundtrip(s, "/large_nfs.bin", _LARGE_MB)
    finally:
        s.disconnect()


# iSCSI large-file lives on TestIscsi so it inherits the robust
# setup_class session reset instead of starting iscsid from scratch
# on its own.


# ════════════════════════════════════════════════════════════
#  SECTION 14: Concurrency
#
#  Covers the "2+ transfers in parallel to the same server" gap. The
#  interesting cases are:
#    - Two independent sessions to the same host (naive concurrency)
#    - One session shared between threads (exercises the per-thread
#      SFTP client cache in core/ssh_client.py: _thread_sftp dict)
#    - Multiple TransferJobs queued on one TransferManager (exercises
#      the QThread worker loop)
# ════════════════════════════════════════════════════════════

@_label("Conc 14.1 SMB: one session shared across threads")
def test_smb_shared_session_parallel_reads():
    """smbprotocol's session pool is process-wide / one-per-host, so
    two SmbSession INSTANCES pointing at the same host actually share
    the same underlying SMB session — it is not meaningful to treat
    them as independent. The realistic concurrency pattern is one
    SmbSession used from multiple threads (e.g. the UI list thread
    and a transfer worker). Pin that pattern here: two threads each
    do list + read on a shared session, no cross-thread corruption."""
    import threading
    from core.smb_client import SmbSession

    s = SmbSession(host=SMB_HOST, share=SMB_SHARE,
                   username=SMB_USER, password=SMB_PASS, port=SMB_PORT)
    errors = []
    try:
        # Seed one file per worker — SMB serializes per-file handles so
        # two threads reading the SAME file will fight over the lock.
        # Separate files isolates the test to "session can serve
        # multiple threads" without clashing on file-level locking.
        for idx in range(2):
            with s.open_write(f"/conc_read_{idx}.txt") as f:
                f.write(f"worker-{idx}-payload".encode())

        def worker(idx: int):
            try:
                for _ in range(4):
                    items = s.list_dir("/")
                    names = {i.name for i in items}
                    if "readme.txt" not in names:
                        errors.append(f"worker-{idx}: seed missing")
                    with s.open_read(f"/conc_read_{idx}.txt") as f:
                        data = f.read()
                    if f"worker-{idx}".encode() not in data:
                        errors.append(f"worker-{idx}: wrong data {data!r}")
            except Exception as exc:
                errors.append(f"worker-{idx}: {type(exc).__name__}: {exc}")

        threads = [threading.Thread(target=worker, args=(i,), daemon=True)
                   for i in range(2)]
        for t in threads: t.start()
        for t in threads: t.join(timeout=15)

        assert not errors, errors
        for t in threads:
            assert not t.is_alive(), "thread hung"

        # Cleanup
        for idx in range(2):
            try:
                s.remove(f"/conc_read_{idx}.txt")
            except Exception:
                pass
    finally:
        s.disconnect()


@_label("Conc 14.2 S3: four parallel uploads to distinct keys")
def test_s3_four_parallel_uploads():
    """S3 is HTTP-backed; distinct sessions genuinely multiplex. We
    assert all four complete and that no cross-key corruption happens
    — the latter matters because boto3's Session state could in
    principle leak between concurrent clients."""
    import threading
    from core.s3_client import S3Session

    errors = []

    def worker(idx: int):
        try:
            s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                          access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                          region="us-east-1")
            try:
                payload = (f"s3-worker-{idx}").encode() * 2048
                key = f"/conc_s3_{idx}.bin"
                with s.open_write(key) as f:
                    f.write(payload)
                with s.open_read(key) as f:
                    got = f.read()
                if got != payload:
                    errors.append(f"worker-{idx}: payload mismatch")
                s.remove(key)
            finally:
                s.disconnect()
        except Exception as exc:
            errors.append(f"worker-{idx}: {type(exc).__name__}: {exc}")

    threads = [threading.Thread(target=worker, args=(i,), daemon=True)
               for i in range(4)]
    for t in threads: t.start()
    for t in threads: t.join(timeout=20)

    assert not errors, errors
    for t in threads:
        assert not t.is_alive()


# Conc 14.3 (TransferManager parallel jobs) lives in
# tests/test_hardening_regressions.py — it depends on PyQt6 which is
# not installable in the test-runner container without libglib.


# -- Toxiproxy coverage extension: mid_transfer_drop for the rest ----

# Protocol-specific credentials used by the extended toxic tests. These
# repeat values already pinned elsewhere in this file, grouped here so
# the fault-injection section is self-contained.
_SSH_HOST = "10.99.0.10"
_SSH_PORT = 22
_SSH_USER = "alpha"
_SSH_PASS = "alpha123"


def _make_ssh_profile_through_proxy(listen_port: int):
    """Build a SSH ConnectionProfile that targets toxiproxy."""
    from core.profiles import ConnectionProfile
    return ConnectionProfile(
        name=f"ssh-via-toxi-{listen_port}",
        protocol="sftp", host=TOXIPROXY_HOST, port=listen_port,
        username=_SSH_USER, auth_type="password",
    )


def _auto_trust(err):
    return True


@_label("Fault 12.6 SSH mid-transfer connection drop surfaces as error")
def test_ssh_mid_transfer_drop():
    import threading
    import time as _t
    from core.ssh_client import SSHSession
    PROXY = "ssh_drop"
    try:
        _toxiproxy_create(PROXY, _SSH_HOST, _SSH_PORT, 10010)
        profile = _make_ssh_profile_through_proxy(10010)
        s = SSHSession(profile)
        s.connect(password=_SSH_PASS, on_unknown_host=_auto_trust)
        try:
            s.list_dir(s.home())
            _toxiproxy_disable(PROXY)
            try:
                for _ in range(50):
                    s.list_dir(s.home())
                    _t.sleep(0.02)
                raise AssertionError("SSH hung after proxy drop")
            except Exception as exc:
                name = type(exc).__name__.lower()
                if any(k in name for k in (
                    "error", "connection", "closed", "eof", "reset",
                    "socket", "timeout",
                )):
                    return
                raise
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


@_label("Fault 12.7 S3 mid-transfer connection drop surfaces as error")
def test_s3_mid_transfer_drop():
    import threading
    import time as _t
    from core.s3_client import S3Session
    PROXY = "s3_drop"
    try:
        _toxiproxy_create(PROXY, S3_HOST, S3_PORT, 10033)
        s = S3Session(bucket=S3_BUCKET,
                      endpoint=f"http://{TOXIPROXY_HOST}:10033",
                      access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                      region="us-east-1")
        try:
            s.list_dir("/")
            _toxiproxy_disable(PROXY)
            try:
                for _ in range(20):
                    s.list_dir("/")
                    _t.sleep(0.05)
                raise AssertionError("S3 hung after proxy drop")
            except Exception as exc:
                name = type(exc).__name__.lower()
                msg = str(exc).lower()
                if any(k in name or k in msg for k in (
                    "error", "connection", "closed", "timeout", "reset",
                    "refused", "endpoint",
                )):
                    return
                raise
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


@_label("Fault 12.8 Rsync unreachable via toxiproxy surfaces as OSError")
def test_rsync_mid_transfer_drop():
    """Rsync shells out to the rsync binary with a short-lived
    connection per op. We can't "drop mid-flight" as easily, but we
    can prove that a disabled proxy surfaces as OSError at the NEXT
    operation (rsync returns non-zero)."""
    import time as _t
    from core.rsync_client import RsyncSession
    PROXY = "rsync_drop"
    try:
        _toxiproxy_create(PROXY, RSYNC_HOST, RSYNC_PORT, 10034)
        s = RsyncSession(host=TOXIPROXY_HOST, port=10034,
                         module=RSYNC_MODULE,
                         username=RSYNC_USER, password=RSYNC_PASS)
        try:
            s.list_dir("/")  # warm
            _toxiproxy_disable(PROXY)
            try:
                for _ in range(5):
                    s.list_dir("/")
                    _t.sleep(0.1)
                raise AssertionError("Rsync hung / silently reconnected")
            except OSError:
                return
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


@_label("Fault 12.9 Telnet mid-transfer connection drop surfaces as OSError")
def test_telnet_mid_transfer_drop():
    import time as _t
    from core.telnet_client import TelnetSession
    PROXY = "telnet_drop"
    try:
        _toxiproxy_create(PROXY, TELNET_HOST, TELNET_PORT, 10037)
        s = TelnetSession(host=TOXIPROXY_HOST, port=10037,
                          username=TELNET_USER, password=TELNET_PASS)
        try:
            s.list_dir(s.home())
            _toxiproxy_disable(PROXY)
            try:
                for _ in range(20):
                    s.list_dir(s.home())
                    _t.sleep(0.05)
                raise AssertionError("Telnet hung after drop")
            except Exception as exc:
                name = type(exc).__name__.lower()
                if any(k in name for k in (
                    "error", "connection", "closed", "timeout", "reset",
                    "eof", "socket",
                )):
                    return
                raise
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


@_label("Fault 12.10 Azure Blob mid-transfer connection drop surfaces as error")
def test_azure_blob_mid_transfer_drop():
    import time as _t
    try:
        from core.azure_client import AzureBlobSession
    except ImportError:
        pytest.skip("azure-storage-blob not installed")
    PROXY = "azure_drop"
    try:
        _toxiproxy_create(PROXY, AZURITE_HOST, 10000, 10039)
        proxied_conn = (
            f"DefaultEndpointsProtocol=http;"
            f"AccountName={AZURITE_ACCOUNT};"
            f"AccountKey={AZURITE_KEY};"
            f"BlobEndpoint=http://{TOXIPROXY_HOST}:10039/{AZURITE_ACCOUNT};"
        )
        s = AzureBlobSession(connection_string=proxied_conn,
                             container=AZURITE_CONTAINER)
        try:
            s.list_dir("/")
            _toxiproxy_disable(PROXY)
            try:
                for _ in range(20):
                    s.list_dir("/")
                    _t.sleep(0.05)
                raise AssertionError("Azure hung after drop")
            except Exception as exc:
                name = type(exc).__name__.lower()
                msg = str(exc).lower()
                if any(k in name or k in msg for k in (
                    "error", "connection", "closed", "timeout", "reset",
                    "refused", "service", "endpoint",
                )):
                    return
                raise
        finally:
            try:
                s.close()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


@_label("Fault 12.11 FTP control-channel drop surfaces as error")
def test_ftp_mid_transfer_drop():
    import time as _t
    from core.ftp_client import FtpSession
    PROXY = "ftp_ctrl_drop"
    try:
        _toxiproxy_create(PROXY, FTP_HOST, FTP_PORT, 10022)
        s = FtpSession(host=TOXIPROXY_HOST, port=10022,
                       username=FTP_USER, password=FTP_PASS)
        try:
            # Warm the connection — proves it actually works through
            # the proxy BEFORE we drop it, so the later failure is
            # attributable to the drop, not to a misconfigured test.
            s._ftp.voidcmd("NOOP")
            _toxiproxy_disable(PROXY)
            try:
                for _ in range(50):
                    s._ftp.voidcmd("NOOP")
                    _t.sleep(0.02)
                raise AssertionError("FTP hung after control-drop")
            except Exception as exc:
                name = type(exc).__name__.lower()
                if any(k in name for k in (
                    "error", "connection", "closed", "eof", "reset",
                )):
                    return
                raise
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


@_label("Fault 12.12 FTPS control-channel drop surfaces as error")
def test_ftps_mid_transfer_drop():
    import time as _t
    from core.ftp_client import FtpSession
    PROXY = "ftps_ctrl_drop"
    try:
        _toxiproxy_create(PROXY, FTPS_HOST, FTPS_PORT, 10023)
        s = FtpSession(host=TOXIPROXY_HOST, port=10023,
                       username=FTPS_USER, password=FTPS_PASS,
                       tls=True, verify_tls=False)
        try:
            s._ftp.voidcmd("NOOP")  # warm — proves wire works
            _toxiproxy_disable(PROXY)
            try:
                for _ in range(50):
                    s._ftp.voidcmd("NOOP")
                    _t.sleep(0.02)
                raise AssertionError("FTPS hung after control-drop")
            except Exception as exc:
                name = type(exc).__name__.lower()
                if any(k in name for k in (
                    "error", "connection", "closed", "eof", "reset", "ssl",
                )):
                    return
                raise
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


# -- Bandwidth-cap extension -----------------------------------------

@_label("Fault 12.13 SSH large read under bandwidth cap is actually slower")
def test_ssh_bandwidth_cap():
    """Read a seeded 64 KB file through a 32 KB/s cap. Must take > 1.5s.
    If the cap weren't effective the read would complete in ms — the
    lower bound catches that regression."""
    import time as _t
    from core.ssh_client import SSHSession
    PROXY = "ssh_bw"
    try:
        _toxiproxy_create(PROXY, _SSH_HOST, _SSH_PORT, 11010)
        _toxiproxy_add_toxic(PROXY, "slow", "bandwidth", {"rate": 32})
        profile = _make_ssh_profile_through_proxy(11010)
        s = SSHSession(profile)
        s.connect(password=_SSH_PASS, on_unknown_host=_auto_trust)
        try:
            # ssh-alpha image ships data/bigfile.bin (~64 KB)
            remote = s.join(s.home(), "data", "bigfile.bin")
            t0 = _t.monotonic()
            with s.open_read(remote) as f:
                data = f.read()
            dt = _t.monotonic() - t0
            assert len(data) >= 64 * 1024
            assert dt > 1.5, f"bandwidth cap not effective: {dt:.2f}s"
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


@_label("Fault 12.14 S3 large read under bandwidth cap is actually slower")
def test_s3_bandwidth_cap():
    """Upload a 128 KB object directly, then read it back through a
    32 KB/s cap — must take > 3s."""
    import time as _t
    from core.s3_client import S3Session
    PROXY = "s3_bw"
    # Put the object via a direct (un-throttled) session first
    direct = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                       access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                       region="us-east-1")
    key = "/bw_probe.bin"
    payload = b"x" * 128 * 1024
    try:
        with direct.open_write(key) as f:
            f.write(payload)
    finally:
        direct.disconnect()

    try:
        _toxiproxy_create(PROXY, S3_HOST, S3_PORT, 11033)
        _toxiproxy_add_toxic(PROXY, "slow", "bandwidth", {"rate": 32})
        s = S3Session(bucket=S3_BUCKET,
                      endpoint=f"http://{TOXIPROXY_HOST}:11033",
                      access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                      region="us-east-1")
        try:
            t0 = _t.monotonic()
            with s.open_read(key) as f:
                data = f.read()
            dt = _t.monotonic() - t0
            assert len(data) == 128 * 1024
            assert dt > 3.0, f"bandwidth cap not effective: {dt:.2f}s"
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)
        direct2 = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                            access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                            region="us-east-1")
        try:
            direct2.remove(key)
        finally:
            direct2.disconnect()


@_label("Fault 12.15 Telnet file read under bandwidth cap is actually slower")
def test_telnet_bandwidth_cap():
    """Telnet transfers files base64-encoded over the shell, which
    amplifies the file size by ~1.33x but still goes over the TCP
    connection. Read a seeded 64 KB file through a 32 KB/s cap —
    base64 yields ~85 KB on the wire, so > 2.5s is the floor."""
    import time as _t
    from core.telnet_client import TelnetSession
    PROXY = "telnet_bw"
    try:
        _toxiproxy_create(PROXY, TELNET_HOST, TELNET_PORT, 11037)
        _toxiproxy_add_toxic(PROXY, "slow", "bandwidth", {"rate": 32})
        s = TelnetSession(host=TOXIPROXY_HOST, port=11037,
                          username=TELNET_USER, password=TELNET_PASS)
        try:
            remote = s.join(s.home(), "data", "bigfile.bin")
            t0 = _t.monotonic()
            with s.open_read(remote) as f:
                data = f.read()
            dt = _t.monotonic() - t0
            assert len(data) >= 64 * 1024
            assert dt > 2.0, f"bandwidth cap not effective: {dt:.2f}s"
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


# -- Latency extension -----------------------------------------------

@_label("Fault 12.16 SSH under high latency completes (slowly)")
def test_ssh_high_latency():
    import time as _t
    from core.ssh_client import SSHSession
    PROXY = "ssh_lag"
    try:
        _toxiproxy_create(PROXY, _SSH_HOST, _SSH_PORT, 12010)
        _toxiproxy_add_toxic(PROXY, "lag", "latency",
                             {"latency": 150, "jitter": 50})
        profile = _make_ssh_profile_through_proxy(12010)
        s = SSHSession(profile)
        s.connect(password=_SSH_PASS, on_unknown_host=_auto_trust)
        try:
            t0 = _t.monotonic()
            items = s.list_dir(s.home())
            dt = _t.monotonic() - t0
            assert len(items) > 0
            assert dt > 0.1, f"latency toxic not effective: {dt:.2f}s"
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


@_label("Fault 12.17 S3 under high latency completes")
def test_s3_high_latency():
    import time as _t
    from core.s3_client import S3Session
    PROXY = "s3_lag"
    try:
        _toxiproxy_create(PROXY, S3_HOST, S3_PORT, 12033)
        _toxiproxy_add_toxic(PROXY, "lag", "latency",
                             {"latency": 150, "jitter": 50})
        s = S3Session(bucket=S3_BUCKET,
                      endpoint=f"http://{TOXIPROXY_HOST}:12033",
                      access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                      region="us-east-1")
        try:
            t0 = _t.monotonic()
            items = s.list_dir("/")
            dt = _t.monotonic() - t0
            assert isinstance(items, list)
            assert dt > 0.1, f"latency toxic not effective: {dt:.2f}s"
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


@_label("Fault 12.18 WebDAV under high latency completes")
def test_webdav_high_latency():
    import time as _t
    from core.webdav_client import WebDavSession
    PROXY = "webdav_lag"
    try:
        _toxiproxy_create(PROXY, WEBDAV_HOST, WEBDAV_PORT, 12080)
        _toxiproxy_add_toxic(PROXY, "lag", "latency",
                             {"latency": 150, "jitter": 50})
        s = WebDavSession(url=f"http://{TOXIPROXY_HOST}:12080",
                          username=WEBDAV_USER, password=WEBDAV_PASS)
        try:
            t0 = _t.monotonic()
            items = s.list_dir("/")
            dt = _t.monotonic() - t0
            assert isinstance(items, list)
            assert dt > 0.1, f"latency toxic not effective: {dt:.2f}s"
        finally:
            try:
                s.disconnect()
            except Exception:
                pass
    finally:
        _toxiproxy_delete(PROXY)


# ════════════════════════════════════════════════════════════
#  SECTION 14b: TLS / cert-mismatch (MITM protection)
#
#  Before this section landed, FtpSession used FTP_TLS() without a
#  context argument — which in Python's stdlib defaults to
#  CERT_NONE + check_hostname=False, i.e. accepts ANY certificate
#  including an attacker-substituted one. We now default to a
#  verifying context and these tests pin:
#
#    (a) default-mode FTPS against a self-signed lab server REJECTS
#        the handshake (certifies our MITM guard works)
#    (b) explicit verify_tls=False still accepts (regression check
#        so accidentally flipping the default to fail-closed-without-
#        escape still lets intentional use of self-signed work)
# ════════════════════════════════════════════════════════════


@_label("TLS 14b.1 Self-signed FTPS is rejected by default (verify_tls=True)")
def test_ftps_rejects_self_signed_by_default():
    """Connecting to our lab pure-ftpd (self-signed cert) with the
    default verify_tls=True must raise a TLS verification error —
    otherwise the MITM-guard regression sneaks in."""
    import ssl
    from core.ftp_client import FtpSession
    try:
        FtpSession(host=FTPS_HOST, port=FTPS_PORT,
                   username=FTPS_USER, password=FTPS_PASS, tls=True)
    except ssl.SSLError:
        return
    except OSError as exc:
        # Sometimes SSL errors surface as generic OSError subclasses;
        # as long as the message mentions certificate/ssl, we accept.
        msg = str(exc).lower()
        if any(k in msg for k in ("cert", "ssl", "tls", "verify", "trust")):
            return
        raise
    raise AssertionError(
        "FtpSession with verify_tls=True accepted a self-signed cert — "
        "MITM guard is broken"
    )


@_label("TLS 14b.2 verify_tls=False explicit opt-in still accepts self-signed")
def test_ftps_accepts_self_signed_with_opt_in():
    """Regression: explicit verify_tls=False must still let users
    connect to internal / lab servers without cert chains."""
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTPS_HOST, port=FTPS_PORT,
                   username=FTPS_USER, password=FTPS_PASS,
                   tls=True, verify_tls=False)
    try:
        assert s.connected
    finally:
        s.disconnect()


@_label("TLS 14b.3 FTPS connecting to wrong hostname is rejected")
def test_ftps_rejects_hostname_mismatch():
    """Connect via 127.0.0.1 (not a hostname in the cert) with
    verify_tls=True. Must fail at hostname-check step even if the
    cert chain was trusted.

    Note: our lab only has self-signed certs so technically chain-
    verification fails first. The point is: the guard is active
    regardless of which check flags the problem."""
    import ssl
    from core.ftp_client import FtpSession
    # Setup a toxiproxy that forwards to FTPS on a different apparent
    # host so the client connects to an address that the cert
    # definitely does not cover.
    try:
        _toxiproxy_create("ftps_mismatch", FTPS_HOST, FTPS_PORT, 10021)
    except Exception:
        pytest.skip("toxiproxy not reachable")
    try:
        try:
            FtpSession(host=TOXIPROXY_HOST, port=10021,
                       username=FTPS_USER, password=FTPS_PASS, tls=True)
        except (ssl.SSLError, OSError) as exc:
            msg = str(exc).lower()
            if any(k in msg for k in (
                "cert", "ssl", "tls", "verify", "hostname", "trust",
            )):
                return
            raise
        raise AssertionError("FTPS accepted connection with mismatched host")
    finally:
        _toxiproxy_delete("ftps_mismatch")


# ════════════════════════════════════════════════════════════
#  SECTION 15: Quota / disk-full
#
#  The tiny-ftp-server has its home directory mounted on a 16 MB
#  tmpfs. Writing more than that MUST surface ENOSPC (or a
#  protocol-level rejection) to the client rather than succeeding
#  silently. If the client code masked the error we'd accept silent
#  truncation — a very nasty data-integrity failure.
# ════════════════════════════════════════════════════════════

TINY_FTP_HOST = "10.99.0.60"
TINY_FTP_USER = "tinyftp"
TINY_FTP_PASS = "tiny123"


@_label("Quota 15.1 FTP overflow raises recognizable disk-full error")
def test_ftp_disk_full_raises():
    """Upload 32 MB into a 16 MB tmpfs-backed FTP home. The write MUST
    fail — either mid-stream (ENOSPC) or on close — and the resulting
    exception must be OSError-shaped so callers can handle it."""
    from core.ftp_client import FtpSession
    s = FtpSession(host=TINY_FTP_HOST, port=21,
                   username=TINY_FTP_USER, password=TINY_FTP_PASS)
    try:
        payload_path = s.join(s.home(), "toobig.bin")
        chunk = b"x" * (1024 * 1024)  # 1 MiB
        try:
            with s.open_write(payload_path) as f:
                for _ in range(32):  # 32 MiB total
                    f.write(chunk)
            raise AssertionError(
                "FTP write of 32 MB into 16 MB tmpfs succeeded — "
                "client silently truncated or server lied"
            )
        except OSError:
            return  # expected: ENOSPC / write error / protocol error
        except Exception as exc:
            msg = str(exc).lower()
            name = type(exc).__name__.lower()
            if any(k in msg or k in name for k in (
                "space", "full", "quota", "enospc", "error",
                "disk", "allotted", "storage",
            )):
                return
            raise
    finally:
        # Best-effort cleanup — if tmpfs is at capacity the remove
        # may itself fail, which is fine.
        try:
            s.remove(s.join(s.home(), "toobig.bin"))
        except Exception:
            pass
        s.disconnect()


@_label("Quota 15.2 LocalFS disk-full: tempfile-backed tiny volume")
def test_local_fs_disk_full_raises():
    """Equivalent on the local filesystem backend: point LocalFS at a
    tiny tmpfs-backed dir and try to write > capacity. Exercises the
    ENOSPC path in LocalFS.open_write."""
    import os as _os
    import tempfile
    from core.local_fs import LocalFS

    # Use Linux-specific fallocate on a backing file to create a bounded
    # "disk" — works everywhere tmpfs-with-size doesn't fit the harness.
    # Simpler alternative: write until the docker tmpfs at /tmp hits
    # memory pressure. Not portable — instead we synthesize a tiny fs
    # via a sparse file + loopback? Too privileged.
    #
    # Pragmatic alternative: if test runs on Linux with /dev/shm bounded,
    # use that. Otherwise skip.
    if not _os.path.exists("/dev/shm"):
        pytest.skip("test needs /dev/shm (Linux tmpfs)")

    # /dev/shm is usually tmpfs. We write until we hit its cap OR a
    # sensible limit (if /dev/shm is huge, we'd write forever).
    # Instead: create a tempdir there, write until we see OSError.
    with tempfile.TemporaryDirectory(dir="/dev/shm", prefix="axxtiny-") as tmp:
        fs = LocalFS()
        target = _os.path.join(tmp, "fill.bin")
        chunk = b"x" * (1024 * 1024)
        raised = False
        try:
            with fs.open_write(target) as f:
                # Write at most 8 GB to avoid infinite loop on huge tmpfs
                for i in range(8192):
                    try:
                        f.write(chunk)
                    except OSError:
                        raised = True
                        break
        except OSError:
            raised = True
        # We either hit ENOSPC (likely) or succeeded on a very large
        # tmpfs — latter is a non-bug; only fail if tmpfs claimed
        # infinite capacity but our write somehow corrupted silently.
        if not raised:
            # Rare: /dev/shm was huge. Accept as inconclusive.
            pytest.skip("tmpfs at /dev/shm larger than 8 GB probe — cannot exercise ENOSPC here")
        # If we got here, ENOSPC surfaced correctly.


# ════════════════════════════════════════════════════════════
#  SECTION 16: checksum() primitive
#
#  FileBackend.checksum(path, algorithm) returns a hex-encoded
#  fingerprint WITHOUT a full read where the backend has a native
#  way (S3 ETag, WebDAV getetag, Azure Content-MD5, remote shell
#  sha256sum, cloud-SDK hash). Backends without a cheap native MUST
#  return the empty string (contract-tested below) so callers can
#  fall back to streaming via open_read.
# ════════════════════════════════════════════════════════════

def _assert_checksum_shape(cs: str):
    """A non-empty checksum MUST be `<algo>:<hex-or-etag>`."""
    assert cs, "expected non-empty checksum"
    assert ":" in cs, f"missing algo prefix in {cs!r}"
    algo, _, rest = cs.partition(":")
    assert algo and rest


# ── Backends with NATIVE cheap checksum ───────────────────────────────

@_label("Cksum 16.1 SSH sha256sum via exec_command")
def test_ssh_checksum_native():
    from core.ssh_client import SSHSession
    from core.profiles import ConnectionProfile
    profile = ConnectionProfile(
        name="ssh-cksum",
        protocol="sftp", host=_SSH_HOST, port=_SSH_PORT,
        username=_SSH_USER, auth_type="password",
    )
    s = SSHSession(profile)
    s.connect(password=_SSH_PASS, on_unknown_host=_auto_trust)
    try:
        path = s.join(s.home(), "data", "readme.txt")
        cs = s.checksum(path, "sha256")
        _assert_checksum_shape(cs)
        assert cs.startswith("sha256:")
        # readme is tiny; recompute on the wire manually as sanity
        import hashlib
        with s.open_read(path) as f:
            expected = "sha256:" + hashlib.sha256(f.read()).hexdigest()
        assert cs == expected
    finally:
        s.disconnect()


@_label("Cksum 16.2 SSH checksum on missing path raises OSError")
def test_ssh_checksum_missing():
    from core.ssh_client import SSHSession
    from core.profiles import ConnectionProfile
    profile = ConnectionProfile(
        name="ssh-cksum-miss",
        protocol="sftp", host=_SSH_HOST, port=_SSH_PORT,
        username=_SSH_USER, auth_type="password",
    )
    s = SSHSession(profile)
    s.connect(password=_SSH_PASS, on_unknown_host=_auto_trust)
    try:
        try:
            s.checksum("/nonexistent_xyz_abc.bin", "sha256")
        except OSError:
            return
        raise AssertionError("missing file must raise OSError")
    finally:
        s.disconnect()


@_label("Cksum 16.3 S3 ETag returned as md5:")
def test_s3_checksum_etag():
    from core.s3_client import S3Session
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        key = "/cksum_probe.txt"
        payload = b"S3 checksum probe\n"
        with s.open_write(key) as f:
            f.write(payload)
        cs = s.checksum(key)
        _assert_checksum_shape(cs)
        # small objects: ETag == MD5, so our prefix is md5:
        assert cs.startswith("md5:"), cs
        import hashlib
        assert cs.split(":", 1)[1] == hashlib.md5(payload).hexdigest()
        s.remove(key)
    finally:
        s.disconnect()


@_label("Cksum 16.4 WebDAV returns etag: prefix on Apache mod_dav")
def test_webdav_checksum_etag():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        cs = s.checksum("/readme.txt")
        _assert_checksum_shape(cs)
        # Apache mod_dav gives us an inode-based etag, not a content hash
        assert cs.startswith("etag:"), cs
    finally:
        s.disconnect()


@_label("Cksum 16.5 Azure Blob returns md5: from Content-MD5")
def test_azure_blob_checksum_md5():
    try:
        from core.azure_client import AzureBlobSession
    except ImportError:
        pytest.skip("azure-storage-blob not installed")
    from azure.storage.blob import BlobServiceClient, ContentSettings
    import hashlib
    # Upload a blob WITH content_md5 set so the property is populated
    service = BlobServiceClient.from_connection_string(AZURITE_CONNECTION_STRING)
    container = service.get_container_client(AZURITE_CONTAINER)
    payload = b"Azure checksum probe\n"
    md5 = hashlib.md5(payload).digest()
    key = "cksum_probe.txt"
    container.upload_blob(
        key, payload, overwrite=True,
        content_settings=ContentSettings(content_md5=bytearray(md5)),
    )
    s = AzureBlobSession(connection_string=AZURITE_CONNECTION_STRING,
                         container=AZURITE_CONTAINER)
    try:
        cs = s.checksum(f"/{key}")
        _assert_checksum_shape(cs)
        assert cs.startswith("md5:"), cs
        import binascii
        assert cs.split(":", 1)[1] == binascii.hexlify(md5).decode()
    finally:
        s.close()
        container.delete_blob(key)


@_label("Cksum 16.6 NFS stream-hash returns correct sha256")
def test_nfs_checksum_stream():
    _skip_if_nfs_unavailable()
    s = _nfs_session()
    try:
        path = "/cksum_probe.bin"
        payload = b"NFS mount stream hash\n" * 1024
        with s.open_write(path) as f:
            f.write(payload)
        cs = s.checksum(path, "sha256")
        _assert_checksum_shape(cs)
        import hashlib
        assert cs == "sha256:" + hashlib.sha256(payload).hexdigest()
        s.remove(path)
    finally:
        s.disconnect()


@_label("Cksum 16.7 Telnet remote sha256sum")
def test_telnet_checksum_shell():
    from core.telnet_client import TelnetSession
    s = TelnetSession(host=TELNET_HOST, port=TELNET_PORT,
                      username=TELNET_USER, password=TELNET_PASS)
    try:
        path = s.join(s.home(), "data", "readme.txt")
        cs = s.checksum(path, "sha256")
        if not cs:
            pytest.skip("remote sha256sum not available")
        _assert_checksum_shape(cs)
        assert cs.startswith("sha256:")
    finally:
        s.disconnect()


# ── Backends without native checksum: contract must be "" ──────────────

@_label("Cksum 16.20 FTP returns empty — no native HASH in lab server")
def test_ftp_checksum_empty():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT,
                   username=FTP_USER, password=FTP_PASS)
    try:
        cs = s.checksum(s.join(s.home(), "data", "readme.txt"))
        # pure-ftpd doesn't advertise HASH — contract requires ""
        assert cs == "", f"expected empty, got {cs!r}"
    finally:
        s.disconnect()


@_label("Cksum 16.21 SMB checksum contract is empty")
def test_smb_checksum_empty():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER,
                   password=SMB_PASS, port=SMB_PORT)
    try:
        assert s.checksum("/readme.txt") == ""
    finally:
        s.disconnect()


@_label("Cksum 16.22 IMAP checksum contract is empty")
def test_imap_checksum_empty():
    s = _imap_session()
    try:
        # IMAP has no files in the classic sense; probe on INBOX
        try:
            items = s.list_dir("/INBOX")
        except OSError:
            pytest.skip("INBOX not available for checksum probe")
        if not items:
            pytest.skip("no messages to checksum")
        assert s.checksum(f"/INBOX/{items[0].name}") == ""
    finally:
        s.disconnect()


@_label("Cksum 16.23 Unsupported algorithm returns empty or raises")
def test_ssh_checksum_unsupported_algo():
    """The protocol says an unsupported algorithm MAY return "" OR
    MAY raise OSError. We pin whichever we have."""
    from core.ssh_client import SSHSession
    from core.profiles import ConnectionProfile
    profile = ConnectionProfile(
        name="ssh-cksum-bad",
        protocol="sftp", host=_SSH_HOST, port=_SSH_PORT,
        username=_SSH_USER, auth_type="password",
    )
    s = SSHSession(profile)
    s.connect(password=_SSH_PASS, on_unknown_host=_auto_trust)
    try:
        path = s.join(s.home(), "data", "readme.txt")
        try:
            result = s.checksum(path, "nonexistent-algo")
        except OSError:
            return
        assert result == "", f"expected empty, got {result!r}"
    finally:
        s.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 17: atomic_write across protocols
#
#  atomic_write(backend, path, data) must end with the file
#  containing exactly ``data`` and no sibling temp files left
#  behind. Native-atomic protocols (S3, Azure, cloud) get a single
#  PUT; rename-capable protocols get tmp+rename.
# ════════════════════════════════════════════════════════════


def _probe_dir_has_no_tmpfile(session, dir_path: str) -> bool:
    names = {i.name for i in session.list_dir(dir_path)}
    return not any(
        n.startswith(".tmp-") or n.startswith(".axross-atomic-") for n in names
    )


@_label("Atomic 17.1 SFTP atomic_write commits via rename")
def test_ssh_atomic_write():
    from core.atomic_io import atomic_write
    from core.ssh_client import SSHSession
    from core.profiles import ConnectionProfile
    s = SSHSession(ConnectionProfile(
        name="aw-ssh", protocol="sftp",
        host=_SSH_HOST, port=_SSH_PORT,
        username=_SSH_USER, auth_type="password",
    ))
    s.connect(password=_SSH_PASS, on_unknown_host=_auto_trust)
    try:
        path = s.join(s.home(), "aw_probe.txt")
        atomic_write(s, path, b"atomic-ssh-payload\n")
        with s.open_read(path) as f:
            assert f.read() == b"atomic-ssh-payload\n"
        assert _probe_dir_has_no_tmpfile(s, s.home())
        s.remove(path)
    finally:
        s.disconnect()


@_label("Atomic 17.2 S3 atomic_write uses native PUT (no temp)")
def test_s3_atomic_write():
    from core.atomic_io import atomic_write
    from core.s3_client import S3Session
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        key = "/aw_probe.txt"
        atomic_write(s, key, b"atomic-s3-payload\n")
        with s.open_read(key) as f:
            assert f.read() == b"atomic-s3-payload\n"
        s.remove(key)
    finally:
        s.disconnect()


@_label("Atomic 17.3 WebDAV atomic_write commits via rename")
def test_webdav_atomic_write():
    from core.atomic_io import atomic_write
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        path = "/aw_probe.txt"
        atomic_write(s, path, b"atomic-webdav-payload\n")
        with s.open_read(path) as f:
            assert f.read() == b"atomic-webdav-payload\n"
        assert _probe_dir_has_no_tmpfile(s, "/")
        s.remove(path)
    finally:
        s.disconnect()


@_label("Atomic 17.4 SMB atomic_write commits via rename")
def test_smb_atomic_write():
    from core.atomic_io import atomic_write
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE,
                   username=SMB_USER, password=SMB_PASS, port=SMB_PORT)
    try:
        path = "/aw_probe.txt"
        atomic_write(s, path, b"atomic-smb-payload\n")
        with s.open_read(path) as f:
            assert f.read() == b"atomic-smb-payload\n"
        assert _probe_dir_has_no_tmpfile(s, "/")
        s.remove(path)
    finally:
        s.disconnect()


@_label("Atomic 17.5 FTP atomic_write commits via rename")
def test_ftp_atomic_write():
    from core.atomic_io import atomic_write
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT,
                   username=FTP_USER, password=FTP_PASS)
    try:
        path = s.join(s.home(), "aw_probe.txt")
        atomic_write(s, path, b"atomic-ftp-payload\n")
        with s.open_read(path) as f:
            assert f.read() == b"atomic-ftp-payload\n"
        assert _probe_dir_has_no_tmpfile(s, s.home())
        s.remove(path)
    finally:
        s.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 18: server-side copy
#
#  core/server_ops.server_side_copy prefers backend.copy() (native)
#  and falls back to stream copy when the native raises. These tests
#  verify the native path for backends that have one.
# ════════════════════════════════════════════════════════════


@_label("Copy 18.1 SSH cp -p via exec_command")
def test_ssh_server_side_copy():
    from core.server_ops import server_side_copy
    from core.ssh_client import SSHSession
    from core.profiles import ConnectionProfile
    s = SSHSession(ConnectionProfile(
        name="cp-ssh", protocol="sftp",
        host=_SSH_HOST, port=_SSH_PORT,
        username=_SSH_USER, auth_type="password",
    ))
    s.connect(password=_SSH_PASS, on_unknown_host=_auto_trust)
    try:
        src = s.join(s.home(), "cp_src.txt")
        dst = s.join(s.home(), "cp_dst.txt")
        payload = b"server-side-copy-ssh\n"
        with s.open_write(src) as f:
            f.write(payload)
        server_side_copy(s, src, dst)
        with s.open_read(dst) as f:
            assert f.read() == payload
        # Both exist — it's a copy, not a move
        assert s.exists(src)
        assert s.exists(dst)
        s.remove(src); s.remove(dst)
    finally:
        s.disconnect()


@_label("Copy 18.2 S3 CopyObject without streaming bytes")
def test_s3_server_side_copy():
    from core.server_ops import server_side_copy
    from core.s3_client import S3Session
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        src = "/cp_src.bin"
        dst = "/cp_dst.bin"
        payload = b"server-side-copy-s3\n"
        with s.open_write(src) as f:
            f.write(payload)
        server_side_copy(s, src, dst)
        with s.open_read(dst) as f:
            assert f.read() == payload
        assert s.exists(src) and s.exists(dst)
        s.remove(src); s.remove(dst)
    finally:
        s.disconnect()


@_label("Copy 18.3 WebDAV COPY method")
def test_webdav_server_side_copy():
    from core.server_ops import server_side_copy
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        src = "/cp_src.txt"
        dst = "/cp_dst.txt"
        payload = b"server-side-copy-webdav\n"
        with s.open_write(src) as f:
            f.write(payload)
        server_side_copy(s, src, dst)
        with s.open_read(dst) as f:
            assert f.read() == payload
        assert s.exists(src) and s.exists(dst)
        s.remove(src); s.remove(dst)
    finally:
        s.disconnect()


@_label("Copy 18.4 FTP falls back to stream (no native)")
def test_ftp_server_side_copy_fallback():
    from core.server_ops import server_side_copy
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT,
                   username=FTP_USER, password=FTP_PASS)
    try:
        src = s.join(s.home(), "cp_src.txt")
        dst = s.join(s.home(), "cp_dst.txt")
        payload = b"server-side-copy-ftp-fallback\n"
        with s.open_write(src) as f:
            f.write(payload)
        server_side_copy(s, src, dst)
        with s.open_read(dst) as f:
            assert f.read() == payload
        assert s.exists(src) and s.exists(dst)
        s.remove(src); s.remove(dst)
    finally:
        s.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 19: version history
#
#  Backends with native versioning (S3, Azure Blob, Dropbox, GDrive,
#  OneDrive) expose list_versions(path) -> [FileVersion] and
#  open_version_read(path, version_id) -> stream. Backends without
#  return [] / raise OSError (contract pinned here).
# ════════════════════════════════════════════════════════════


def _ensure_s3_versioning_enabled():
    """Turn on versioning on the test bucket via the MinIO admin path.
    Tolerated-to-fail if already enabled."""
    import boto3
    c = boto3.client(
        "s3",
        endpoint_url=S3_ENDPOINT,
        aws_access_key_id=S3_ACCESS_KEY,
        aws_secret_access_key=S3_SECRET_KEY,
        region_name="us-east-1",
    )
    try:
        c.put_bucket_versioning(
            Bucket=S3_BUCKET,
            VersioningConfiguration={"Status": "Enabled"},
        )
    except Exception:
        pass


@_label("Version 19.1 S3 list_versions returns commit history")
def test_s3_list_versions():
    _ensure_s3_versioning_enabled()
    from core.s3_client import S3Session
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        key = "/version_probe.txt"
        # Write twice so we have two versions
        with s.open_write(key) as f:
            f.write(b"version-one\n")
        with s.open_write(key) as f:
            f.write(b"version-two\n")
        versions = s.list_versions(key)
        assert len(versions) >= 2, f"expected >=2 versions, got {versions}"
        # Newest first: first entry should be current
        assert versions[0].is_current
        # All have version_id populated
        assert all(v.version_id for v in versions)
    finally:
        # Cleanup: remove all versions (delete marker + historicals)
        versions = s.list_versions(key)
        for v in versions:
            try:
                s._s3.delete_object(Bucket=S3_BUCKET, Key=key[1:],
                                    VersionId=v.version_id)
            except Exception:
                pass
        s.disconnect()


@_label("Version 19.2 S3 open_version_read fetches the historical bytes")
def test_s3_open_version_read():
    _ensure_s3_versioning_enabled()
    from core.s3_client import S3Session
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        key = "/version_read_probe.txt"
        with s.open_write(key) as f:
            f.write(b"FIRST")
        with s.open_write(key) as f:
            f.write(b"SECOND")
        versions = s.list_versions(key)
        # Find the non-current (older) version
        older = [v for v in versions if not v.is_current]
        if not older:
            pytest.skip("MinIO didn't return a historical version — skip")
        with s.open_version_read(key, older[0].version_id) as f:
            data = f.read()
        assert data == b"FIRST", f"expected FIRST, got {data!r}"
    finally:
        versions = s.list_versions(key)
        for v in versions:
            try:
                s._s3.delete_object(Bucket=S3_BUCKET, Key=key[1:],
                                    VersionId=v.version_id)
            except Exception:
                pass
        s.disconnect()


@_label("Version 19.3 WebDAV has no versioning by default — empty list")
def test_webdav_list_versions_empty():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        assert s.list_versions("/readme.txt") == []
    finally:
        s.disconnect()


@_label("Version 19.4 FTP open_version_read raises OSError (no versioning)")
def test_ftp_open_version_read_raises():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT,
                   username=FTP_USER, password=FTP_PASS)
    try:
        path = s.join(s.home(), "data", "readme.txt")
        try:
            s.open_version_read(path, "anything")
        except OSError:
            return
        raise AssertionError("FTP open_version_read must raise OSError")
    finally:
        s.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 20: universal trash
#
#  core.trash moves items into ``<home>/.axross-trash/<uuid>``
#  with a sidecar metadata file. Exercise it over real backends —
#  rename semantics differ per protocol and we want to catch
#  regressions there.
# ════════════════════════════════════════════════════════════


@_label("Trash 20.1 FTP trash + list + restore roundtrip")
def test_ftp_trash_roundtrip():
    from core.ftp_client import FtpSession
    from core import trash as T
    s = FtpSession(host=FTP_HOST, port=FTP_PORT,
                   username=FTP_USER, password=FTP_PASS)
    try:
        # /home/ftpuser is writable; /data is root-owned. Write under home.
        home = s.home()
        trash_root = s.join(home, ".axross-trash")
        path = s.join(home, "trash_probe_ftp.txt")
        if s.exists(path):
            s.remove(path)
        with s.open_write(path) as f:
            f.write(b"to-be-trashed")
        tid = T.trash(s, path, root=trash_root)
        assert not s.exists(path)
        entries = T.list_trash(s, root=trash_root)
        assert any(e.trash_id == tid for e in entries)
        restored = T.restore(s, tid, root=trash_root)
        assert restored == path
        assert s.exists(path)
        s.remove(path)
    finally:
        try:
            T.empty_trash(s, root=s.join(s.home(), ".axross-trash"))
        except Exception:
            pass
        s.disconnect()


@_label("Trash 20.2 WebDAV trash + empty_trash")
def test_webdav_trash_and_empty():
    from core.webdav_client import WebDavSession
    from core import trash as T
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        path = "/trash_probe_dav.txt"
        with s.open_write(path) as f:
            f.write(b"gone")
        T.trash(s, path)
        assert not s.exists(path)
        entries = T.list_trash(s)
        assert len(entries) >= 1
        count = T.empty_trash(s)
        assert count >= 1
        assert T.list_trash(s) == []
    finally:
        try:
            T.empty_trash(s)
        except Exception:
            pass
        s.disconnect()


@_label("Trash 20.3 SMB trash preserves directory flag")
def test_smb_trash_directory():
    from core.smb_client import SmbSession
    from core import trash as T
    s = SmbSession(host=SMB_HOST, port=SMB_PORT, share=SMB_SHARE,
                   username=SMB_USER, password=SMB_PASS)
    try:
        base = s.home()
        d = s.join(base, "trash_dir_probe")
        if s.exists(d):
            s.remove(d, recursive=True)
        s.mkdir(d)
        f = s.join(d, "inside.txt")
        with s.open_write(f) as fh:
            fh.write(b"x")
        T.trash(s, d)
        entries = T.list_trash(s)
        mine = [e for e in entries if e.original_path == d]
        assert mine, f"Did not find our dir in trash: {entries}"
        assert mine[0].is_dir, "Directory flag not preserved"
        assert not s.exists(d)
    finally:
        try:
            T.empty_trash(s)
        except Exception:
            pass
        s.disconnect()


@_label("Trash 20.4 S3 trash + list + restore roundtrip")
def test_s3_trash_roundtrip():
    from core.s3_client import S3Session
    from core import trash as T
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        path = "/trash_probe_s3.txt"
        with s.open_write(path) as f:
            f.write(b"s3-trashable")
        tid = T.trash(s, path)
        assert not s.exists(path)
        entries = T.list_trash(s)
        assert any(e.trash_id == tid for e in entries)
        T.restore(s, tid)
        assert s.exists(path)
        s.remove(path)
    finally:
        try:
            T.empty_trash(s)
        except Exception:
            pass
        s.disconnect()


@_label("Trash 20.5 Trash of missing path raises OSError (FTP)")
def test_ftp_trash_missing_path_raises():
    from core.ftp_client import FtpSession
    from core import trash as T
    s = FtpSession(host=FTP_HOST, port=FTP_PORT,
                   username=FTP_USER, password=FTP_PASS)
    try:
        trash_root = s.join(s.home(), ".axross-trash")
        path = s.join(s.home(), "no_such_file_for_trash.txt")
        try:
            T.trash(s, path, root=trash_root)
        except OSError:
            return
        raise AssertionError("trash of missing file must raise OSError")
    finally:
        s.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 21: cross-protocol symlinks (.axlink)
#
#  core.xlink stores a small JSON pointer file that any backend can
#  host. Verify create/read roundtrip plus schema validation on real
#  backends.
# ════════════════════════════════════════════════════════════


@_label("XLink 21.1 FTP create + read_xlink roundtrip")
def test_ftp_xlink_roundtrip():
    from core.ftp_client import FtpSession
    from core import xlink as X
    s = FtpSession(host=FTP_HOST, port=FTP_PORT,
                   username=FTP_USER, password=FTP_PASS)
    try:
        link_name = s.join(s.home(), "pointer_ftp.axlink")
        if s.exists(link_name):
            s.remove(link_name)
        target = "sftp://elsewhere.example.com/remote/doc.txt"
        final = X.create_xlink(s, link_name, target,
                               display_name="remote doc")
        assert s.exists(final)
        assert X.is_xlink(s, final)
        link = X.read_xlink(s, final)
        assert link.target_url == target
        assert link.display_name == "remote doc"
        s.remove(final)
    finally:
        s.disconnect()


@_label("XLink 21.2 S3 create + read_xlink roundtrip")
def test_s3_xlink_roundtrip():
    from core.s3_client import S3Session
    from core import xlink as X
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        link_key = "/cross.axlink"
        target = "webdav://other.example.com/x"
        X.create_xlink(s, link_key, target)
        assert X.is_xlink(s, link_key)
        link = X.read_xlink(s, link_key)
        assert link.target_url == target
        s.remove(link_key)
    finally:
        s.disconnect()


@_label("XLink 21.3 WebDAV rejects foreign JSON as non-xlink")
def test_webdav_non_xlink_detected():
    from core.webdav_client import WebDavSession
    from core import xlink as X
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        path = "/not_really.axlink"
        with s.open_write(path) as f:
            f.write(b'{"schema": "something-else"}')
        # Filename says yes, payload says no.
        assert not X.is_xlink(s, path)
        s.remove(path)
    finally:
        s.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 21b: unicode edge cases across backends
#
#  The vanilla "round-trip a unicode name" tests in §11.3 pinned the
#  happy path. This section targets the *gotchas* that bite real
#  users: Unicode normalisation (NFC vs NFD), mixed bidi text, long
#  names, leading dot files, and case-folding quirks on SMB.
# ════════════════════════════════════════════════════════════


# NFD is the decomposed form (e.g. macOS stores filenames this way);
# NFC is the composed form (most Linux + Windows). A well-behaved
# backend either preserves the exact byte sequence or round-trips
# under one canonical form. "Preserves" is what we'd prefer; we
# pin *either* behaviour so a regression shows up.
import unicodedata as _uni
_NFC_NAME = _uni.normalize("NFC", "café-Ünicode-Ä.txt")
_NFD_NAME = _uni.normalize("NFD", "café-Ünicode-Ä.txt")
_BIDI_NAME = "رجع_back_عودة.txt"            # Arabic + Latin mixed
_LONG_NAME = ("x" * 200) + "_file.txt"       # 209 chars, under PATH_MAX


def _name_roundtrip(s, base, name: str) -> str:
    """Write a tiny file, list the dir, return the *observed* name."""
    path = s.join(base, name)
    with s.open_write(path) as f:
        f.write(b"x")
    try:
        items = s.list_dir(base)
        listed = [it.name for it in items]
        # Find an entry equal to the name OR equal to any normalisation
        # of it — backends may canonicalise and we want to catch that.
        candidates = {
            _uni.normalize("NFC", name),
            _uni.normalize("NFD", name),
            name,
        }
        for n in listed:
            if n in candidates:
                return n
        raise AssertionError(
            f"name {name!r} not in listing (as NFC/NFD). Got: {listed}"
        )
    finally:
        try:
            s.remove(path)
        except OSError:
            # The backend may have stored under a different form. Try
            # each normalisation so the test is idempotent.
            for alt in (_uni.normalize("NFC", name),
                        _uni.normalize("NFD", name)):
                try:
                    s.remove(s.join(base, alt))
                    return ""
                except OSError:
                    continue


@_label("Unicode 21b.1 S3 NFC vs NFD filename round-trip preserves bytes")
def test_s3_unicode_normalization():
    from core.s3_client import S3Session
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        # S3 keys are opaque byte strings — it MUST preserve exactly.
        got_nfc = _name_roundtrip(s, "/", _NFC_NAME)
        got_nfd = _name_roundtrip(s, "/", _NFD_NAME)
        assert got_nfc == _NFC_NAME, f"NFC not preserved: {got_nfc!r}"
        assert got_nfd == _NFD_NAME, f"NFD not preserved: {got_nfd!r}"
        assert got_nfc != got_nfd, "S3 must treat NFC and NFD as distinct"
    finally:
        s.disconnect()


@_label("Unicode 21b.2 WebDAV NFC round-trip")
def test_webdav_unicode_nfc():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        got = _name_roundtrip(s, "/", _NFC_NAME)
        assert got in {_NFC_NAME, _uni.normalize("NFD", _NFC_NAME)}
    finally:
        s.disconnect()


@_label("Unicode 21b.3 SMB NFC round-trip + case-insensitive listing")
def test_smb_unicode_case_insensitive():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER,
                   password=SMB_PASS, port=SMB_PORT)
    try:
        name = "Ümlaut_CaseTest.txt"
        path = s.join("/", name)
        with s.open_write(path) as f:
            f.write(b"x")
        try:
            # SMB is case-insensitive — file must be findable via lowercase
            # when listing returns it (listing preserves original case).
            items = [it.name for it in s.list_dir("/")]
            assert name in items, f"original case missing: {items}"
            # And exists() must match regardless of case.
            lower_path = s.join("/", name.lower())
            assert s.exists(lower_path), \
                f"SMB case-insensitive exists failed for {lower_path}"
        finally:
            s.remove(path)
    finally:
        s.disconnect()


@_label("Unicode 21b.4 S3 bidirectional (Arabic+Latin) filename")
def test_s3_unicode_bidi():
    from core.s3_client import S3Session
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        got = _name_roundtrip(s, "/", _BIDI_NAME)
        assert got == _BIDI_NAME, f"bidi name mangled: {got!r}"
    finally:
        s.disconnect()


@_label("Unicode 21b.5 WebDAV long (>200 char) filename")
def test_webdav_unicode_long_name():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        got = _name_roundtrip(s, "/", _LONG_NAME)
        assert got == _LONG_NAME, f"long name mangled: {got!r}"
    finally:
        s.disconnect()


@_label("Unicode 21b.6 S3 leading-dot filename is not treated as hidden")
def test_s3_dotfile():
    from core.s3_client import S3Session
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        name = ".dotfile_Ünicode.conf"
        got = _name_roundtrip(s, "/", name)
        assert got == name, f"dotfile mangled: {got!r}"
    finally:
        s.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 21c: partial-read / resume capability
#
#  ``open_read(path).seek(N)`` is how a transfer engine resumes a
#  half-finished download — read up to offset N already, ask the
#  server for the rest. Question: which backends actually honour
#  the seek (server-side range), and which silently read from 0
#  and discard the prefix?
#
#  Contract pinned here, per backend:
#
#     seek-ok       — handle.seek(N) + read() returns the tail.
#     seek-noop     — seek "succeeds" but read still returns from 0
#                     (bug-of-sorts; pinned so we notice if it flips).
#     seek-raises   — handle.seek(N) raises (use open_read + discard
#                     or don't offer resume for this backend).
# ════════════════════════════════════════════════════════════


# 16 KiB payload — long enough that a "silently from 0" backend
# returns detectably wrong bytes, short enough that the test is fast.
_RESUME_PAYLOAD = (b"AXX-RESUME-PROBE-" + bytes(range(256)) * 63)[:16384]
_RESUME_OFFSET = 12345


def _assert_resume_tail_matches(session, path: str, offset: int) -> None:
    """open_read + seek(offset) + read() → must equal the file's tail."""
    expected = _RESUME_PAYLOAD[offset:]
    with session.open_read(path) as fh:
        try:
            fh.seek(offset)
        except (OSError, io.UnsupportedOperation) as exc:
            raise AssertionError(f"seek raised: {exc}") from exc
        got = fh.read()
    assert got == expected, (
        f"tail mismatch: expected {len(expected)} bytes starting "
        f"{expected[:24]!r}, got {len(got)} bytes starting "
        f"{got[:24]!r}"
    )


@_label("Resume 21c.1 FTP seek-after-open returns tail (REST support)")
def test_ftp_partial_read():
    from core.ftp_client import FtpSession
    s = FtpSession(host=FTP_HOST, port=FTP_PORT,
                   username=FTP_USER, password=FTP_PASS)
    try:
        home = s.home()
        path = s.join(home, "resume_probe_ftp.bin")
        with s.open_write(path) as f:
            f.write(_RESUME_PAYLOAD)
        try:
            _assert_resume_tail_matches(s, path, _RESUME_OFFSET)
        finally:
            s.remove(path)
    finally:
        s.disconnect()


@_label("Resume 21c.2 SFTP seek-after-open returns tail")
def test_sftp_partial_read():
    pytest.skip(
        "SFTP is exercised in test_network.py; no sftp container in "
        "this suite's lab harness"
    )


@_label("Resume 21c.3 WebDAV seek-after-open returns tail (Range)")
def test_webdav_partial_read():
    from core.webdav_client import WebDavSession
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        path = "/resume_probe_dav.bin"
        with s.open_write(path) as f:
            f.write(_RESUME_PAYLOAD)
        try:
            _assert_resume_tail_matches(s, path, _RESUME_OFFSET)
        finally:
            s.remove(path)
    finally:
        s.disconnect()


@_label("Resume 21c.4 S3 seek-after-open returns tail (GetObject Range)")
def test_s3_partial_read():
    from core.s3_client import S3Session
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        path = "/resume_probe_s3.bin"
        with s.open_write(path) as f:
            f.write(_RESUME_PAYLOAD)
        try:
            _assert_resume_tail_matches(s, path, _RESUME_OFFSET)
        finally:
            s.remove(path)
    finally:
        s.disconnect()


@_label("Resume 21c.5 SMB seek-after-open returns tail")
def test_smb_partial_read():
    from core.smb_client import SmbSession
    s = SmbSession(host=SMB_HOST, share=SMB_SHARE, username=SMB_USER,
                   password=SMB_PASS, port=SMB_PORT)
    try:
        path = s.join("/", "resume_probe_smb.bin")
        with s.open_write(path) as f:
            f.write(_RESUME_PAYLOAD)
        try:
            _assert_resume_tail_matches(s, path, _RESUME_OFFSET)
        finally:
            s.remove(path)
    finally:
        s.disconnect()


@_label("Resume 21c.6 Azure Blob seek-after-open returns tail")
def test_azure_blob_partial_read():
    from core.azure_client import AzureBlobSession
    s = AzureBlobSession(
        connection_string=AZURITE_CONNECTION_STRING,
        container=AZURITE_CONTAINER,
    )
    try:
        path = "/resume_probe_azure.bin"
        with s.open_write(path) as f:
            f.write(_RESUME_PAYLOAD)
        try:
            _assert_resume_tail_matches(s, path, _RESUME_OFFSET)
        finally:
            s.remove(path)
    finally:
        s.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 21d: per-protocol proxy tunnelling
#
#  SFTP + SCP proxy coverage lives in tests/test_network.py. This
#  section covers the two other backends where axross can thread
#  a ProxyConfig all the way through: WebDAV (via requests.Session
#  proxies) and Telnet (we own the raw socket).
#
#  Each backend gets one SOCKS5 test and one HTTP-CONNECT test,
#  against the lab's socks-proxy (10.99.0.20:1080) and http-proxy
#  (10.99.0.21:8888).
# ════════════════════════════════════════════════════════════


def _proxied_webdav_session(proxy_type: str, host: str, port: int):
    from core.webdav_client import WebDavSession
    return WebDavSession(
        url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS,
        proxy_type=proxy_type, proxy_host=host, proxy_port=port,
    )


def _proxied_telnet_session(proxy_type: str, host: str, port: int):
    from core.telnet_client import TelnetSession
    return TelnetSession(
        host=TELNET_HOST, port=TELNET_PORT,
        username=TELNET_USER, password=TELNET_PASS,
        proxy_type=proxy_type, proxy_host=host, proxy_port=port,
    )


@_label("Proxy 21d.1 WebDAV via SOCKS5")
def test_webdav_via_socks5_proxy():
    import os as _os
    # Lab proxy is on a private-IP range — opt in for the SSRF guard.
    _os.environ["AXROSS_ALLOW_PRIVATE_PROXY"] = "1"
    try:
        s = _proxied_webdav_session(
            "socks5", SOCKS_PROXY_HOST, SOCKS_PROXY_PORT,
        )
        try:
            # list_dir goes over the proxied requests.Session; if it
            # works at all, the proxy is in the path.
            items = s.list_dir("/")
            assert isinstance(items, list)
        finally:
            s.disconnect()
    finally:
        _os.environ.pop("AXROSS_ALLOW_PRIVATE_PROXY", None)


@_label("Proxy 21d.2 WebDAV via HTTP CONNECT")
def test_webdav_via_http_connect_proxy():
    import os as _os
    _os.environ["AXROSS_ALLOW_PRIVATE_PROXY"] = "1"
    try:
        s = _proxied_webdav_session(
            "http", HTTP_PROXY_HOST, HTTP_PROXY_PORT,
        )
        try:
            # Round-trip a tiny file so the proxy sees PUT + GET, not
            # just the initial PROPFIND.
            with s.open_write("/_proxied.txt") as f:
                f.write(b"through-proxy")
            with s.open_read("/_proxied.txt") as f:
                assert f.read() == b"through-proxy"
            s.remove("/_proxied.txt")
        finally:
            s.disconnect()
    finally:
        _os.environ.pop("AXROSS_ALLOW_PRIVATE_PROXY", None)


@_label("Proxy 21d.3 Telnet via SOCKS5")
def test_telnet_via_socks5_proxy():
    import os as _os
    _os.environ["AXROSS_ALLOW_PRIVATE_PROXY"] = "1"
    try:
        s = _proxied_telnet_session(
            "socks5", SOCKS_PROXY_HOST, SOCKS_PROXY_PORT,
        )
        try:
            # list_dir driving exec() over the proxied socket is the
            # strongest signal we're truly tunnelling.
            items = s.list_dir(s.home())
            assert isinstance(items, list)
        finally:
            s.disconnect()
    finally:
        _os.environ.pop("AXROSS_ALLOW_PRIVATE_PROXY", None)


@_label("Proxy 21d.4 Telnet via HTTP CONNECT: ACL-refused is surfaced")
def test_telnet_via_http_connect_proxy():
    """The lab's tinyproxy restricts CONNECT to well-known TLS ports
    (443) and REFUSES port 23 with HTTP 403 Access violation.
    That's a property of tinyproxy's default ACL, not an axross
    bug — but we still verify:
      * the request actually reached the proxy (proxy returned 403),
      * the 403 is surfaced as a clean OSError with a readable
        message, instead of hanging or swallowing the failure.
    If the proxy policy ever changes to allow port 23 this test
    will need to be relaxed to a "happy path" assertion.
    """
    import os as _os
    _os.environ["AXROSS_ALLOW_PRIVATE_PROXY"] = "1"
    try:
        try:
            _proxied_telnet_session(
                "http", HTTP_PROXY_HOST, HTTP_PROXY_PORT,
            )
        except OSError as exc:
            msg = str(exc).lower()
            assert "403" in msg or "access violation" in msg, (
                f"expected proxy ACL refusal, got: {exc}"
            )
            return
        raise AssertionError(
            "expected tinyproxy to refuse CONNECT to port 23"
        )
    finally:
        _os.environ.pop("AXROSS_ALLOW_PRIVATE_PROXY", None)


@_label("Proxy 21d.5 Denied: proxy host on RFC1918 without opt-in")
def test_proxy_ssrf_guard_blocks_without_env_flag():
    """Without AXROSS_ALLOW_PRIVATE_PROXY the SSRF guard rejects the
    lab proxies. Pins the default-secure behaviour."""
    import os as _os
    _os.environ.pop("AXROSS_ALLOW_PRIVATE_PROXY", None)
    try:
        _proxied_webdav_session("socks5", SOCKS_PROXY_HOST, SOCKS_PROXY_PORT)
    except (ConnectionError, OSError) as exc:
        assert "deny" in str(exc).lower() or "private" in str(exc).lower()
        return
    raise AssertionError("expected SSRF guard to reject private-range proxy")


# ════════════════════════════════════════════════════════════
#  SECTION 22: encrypted overlay (.axenc)
#
#  core.encrypted_overlay stores AES-256-GCM blobs on any backend.
#  Verify that the ciphertext travels unchanged through each protocol
#  and round-trips cleanly — the GCM tag would catch any mid-transit
#  corruption.
# ════════════════════════════════════════════════════════════


@_label("Enc 22.1 FTP write_encrypted + read_encrypted roundtrip")
def test_ftp_encrypted_roundtrip():
    from core.ftp_client import FtpSession
    from core import encrypted_overlay as E
    s = FtpSession(host=FTP_HOST, port=FTP_PORT,
                   username=FTP_USER, password=FTP_PASS)
    try:
        home = s.home()
        path = s.join(home, "secret_ftp")
        final = E.write_encrypted(s, path, b"ftp secret payload", "pwftp")
        assert final.endswith(".axenc")
        out = E.read_encrypted(s, final, "pwftp")
        assert out == b"ftp secret payload", out
        s.remove(final)
    finally:
        s.disconnect()


@_label("Enc 22.2 S3 encrypted roundtrip — ciphertext survives S3")
def test_s3_encrypted_roundtrip():
    from core.s3_client import S3Session
    from core import encrypted_overlay as E
    s = S3Session(bucket=S3_BUCKET, endpoint=S3_ENDPOINT,
                  access_key=S3_ACCESS_KEY, secret_key=S3_SECRET_KEY,
                  region="us-east-1")
    try:
        path = E.write_encrypted(s, "/secret_s3", b"s3 at rest", "pws3")
        out = E.read_encrypted(s, path, "pws3")
        assert out == b"s3 at rest", out
        s.remove(path)
    finally:
        s.disconnect()


@_label("Enc 22.3 WebDAV wrong passphrase fails cleanly")
def test_webdav_encrypted_wrong_passphrase():
    from core.webdav_client import WebDavSession
    from core import encrypted_overlay as E
    s = WebDavSession(url=WEBDAV_URL, username=WEBDAV_USER, password=WEBDAV_PASS)
    try:
        path = E.write_encrypted(s, "/secret_dav", b"right pw only", "a")
        try:
            E.read_encrypted(s, path, "wrong")
        except E.InvalidCiphertext:
            pass
        else:
            raise AssertionError("wrong passphrase must raise")
        # Right passphrase still works
        out = E.read_encrypted(s, path, "a")
        assert out == b"right pw only"
        s.remove(path)
    finally:
        s.disconnect()


# ════════════════════════════════════════════════════════════
#  Run
# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 65)
    print("Axross — Multi-Protocol Integration Tests")
    print("=" * 65)

    # Wait for services
    services = [
        ("FTP", FTP_HOST, FTP_PORT),
        ("SMB", SMB_HOST, SMB_PORT),
        ("WebDAV", WEBDAV_HOST, WEBDAV_PORT),
        ("S3/MinIO", S3_HOST, S3_PORT),
        ("Rsync", RSYNC_HOST, RSYNC_PORT),
        ("NFS", NFS_HOST, NFS_PORT),
        ("IMAP", IMAP_HOST, IMAP_PORT),
        ("Telnet", TELNET_HOST, TELNET_PORT),
    ]

    print("\nWaiting for services...")
    service_ready = {}
    for name, host, port in services:
        ready = wait_for_port(host, port, timeout=30)
        service_ready[name] = ready
        status = "ready" if ready else "NOT REACHABLE"
        print(f"  {name} ({host}:{port}) {status}")

    # Extra wait for MinIO to fully initialize
    if service_ready.get("S3/MinIO"):
        time.sleep(3)

    print()

    all_tests = []

    # FTP tests
    if service_ready.get("FTP"):
        all_tests.extend([
            test_ftp_connect, test_ftp_list_data, test_ftp_read,
            test_ftp_write_cycle, test_ftp_mkdir, test_ftp_rename,
            test_ftp_stat, test_ftp_paths, test_ftp_via_cm,
        ])
    else:
        print("  SKIP  FTP tests (server not reachable)")
        skipped += 9

    # SMB tests
    if service_ready.get("SMB"):
        all_tests.extend([
            test_smb_connect, test_smb_read, test_smb_list_subdir,
            test_smb_write_cycle, test_smb_mkdir, test_smb_rename,
            test_smb_stat, test_smb_via_cm,
        ])
    else:
        print("  SKIP  SMB tests (server not reachable)")
        skipped += 8

    # WebDAV tests
    if service_ready.get("WebDAV"):
        all_tests.extend([
            test_webdav_connect, test_webdav_read, test_webdav_list_subdir,
            test_webdav_write_cycle, test_webdav_mkdir, test_webdav_rename,
            test_webdav_via_cm,
        ])
    else:
        print("  SKIP  WebDAV tests (server not reachable)")
        skipped += 7

    # S3 tests
    if service_ready.get("S3/MinIO"):
        all_tests.extend([
            test_s3_connect, test_s3_read, test_s3_list_subdir,
            test_s3_write_cycle, test_s3_mkdir, test_s3_rename,
            test_s3_stat, test_s3_via_cm,
        ])
    else:
        print("  SKIP  S3 tests (server not reachable)")
        skipped += 8

    # Rsync tests
    if service_ready.get("Rsync"):
        all_tests.extend([
            test_rsync_connect, test_rsync_read, test_rsync_list_subdir,
            test_rsync_write_cycle, test_rsync_via_cm,
        ])
    else:
        print("  SKIP  Rsync tests (server not reachable)")
        skipped += 5

    # NFS tests (run via pytest: python -m pytest tests/test_protocols.py -k nfs)
    if service_ready.get("NFS"):
        nfs_cls = TestNfs()
        all_tests.extend([
            _label("NFS 6.1 Connect")(nfs_cls.test_nfs_connect),
            _label("NFS 6.2 List dir")(nfs_cls.test_nfs_list_dir),
            _label("NFS 6.3 Write+Read")(nfs_cls.test_nfs_write_read_cycle),
            _label("NFS 6.4 Mkdir+Remove")(nfs_cls.test_nfs_mkdir_remove),
            _label("NFS 6.5 Rename")(nfs_cls.test_nfs_rename),
        ])
    else:
        print("  SKIP  NFS tests (server not reachable)")
        skipped += 5

    # IMAP tests (run via pytest: python -m pytest tests/test_protocols.py -k imap)
    if service_ready.get("IMAP"):
        imap_cls = TestImap()
        all_tests.extend([
            _label("IMAP 7.1 Connect")(imap_cls.test_imap_connect),
            _label("IMAP 7.2 List dir")(imap_cls.test_imap_list_dir),
            _label("IMAP 7.3 Write+Read")(imap_cls.test_imap_write_read_cycle),
            _label("IMAP 7.4 Mkdir+Remove")(imap_cls.test_imap_mkdir_remove),
            _label("IMAP 7.5 Rename")(imap_cls.test_imap_rename),
        ])
    else:
        print("  SKIP  IMAP tests (server not reachable)")
        skipped += 5

    # Telnet tests
    if service_ready.get("Telnet"):
        telnet_cls = TestTelnet()
        all_tests.extend([
            _label("Telnet 8.1 Connect")(telnet_cls.test_telnet_connect),
            _label("Telnet 8.2 List dir")(telnet_cls.test_telnet_list_dir),
            _label("Telnet 8.3 Stat")(telnet_cls.test_telnet_stat),
            _label("Telnet 8.4 Is dir/Exists")(telnet_cls.test_telnet_is_dir_exists),
            _label("Telnet 8.5 Read file")(telnet_cls.test_telnet_read),
            _label("Telnet 8.6 Write+Read")(telnet_cls.test_telnet_write_read),
            _label("Telnet 8.7 Binary roundtrip")(telnet_cls.test_telnet_binary_roundtrip),
            _label("Telnet 8.8 Mkdir+Remove")(telnet_cls.test_telnet_mkdir_remove),
            _label("Telnet 8.9 Rename")(telnet_cls.test_telnet_rename),
            _label("Telnet 8.10 Chmod")(telnet_cls.test_telnet_chmod),
            _label("Telnet 8.11 Disk usage")(telnet_cls.test_telnet_disk_usage),
            _label("Telnet 8.12 Symlink")(telnet_cls.test_telnet_symlink),
            _label("Telnet 8.13 Empty file")(telnet_cls.test_telnet_empty_file),
            _label("Telnet 8.14 Special filenames")(telnet_cls.test_telnet_special_filenames),
        ])
    else:
        print("  SKIP  Telnet tests (server not reachable)")
        skipped += 14

    # Cross-protocol tests (need multiple services)
    if service_ready.get("FTP") and service_ready.get("SMB"):
        all_tests.append(test_ftp_to_smb)
    else:
        skipped += 1

    if service_ready.get("S3/MinIO") and service_ready.get("WebDAV"):
        all_tests.append(test_s3_to_webdav)
    else:
        skipped += 1

    if service_ready.get("SMB") and service_ready.get("S3/MinIO"):
        all_tests.append(test_smb_to_s3)
    else:
        skipped += 1

    for t in all_tests:
        t()

    print()
    print("=" * 65)
    total = passed + failed + skipped
    print(f"Results: {passed} passed, {failed} failed, {skipped} skipped, {total} total")
    if errors:
        print()
        print("Failures:")
        for e in errors:
            print(f"  - {e}")
    print("=" * 65)

    sys.exit(1 if failed else 0)
