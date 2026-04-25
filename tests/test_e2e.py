#!/usr/bin/env python3
"""End-to-end tests against a Docker SSH/SFTP server.

Prerequisites:
  docker run -d --name sftp-test -p 2223:22 sftp-test-server

Server has:
  - user: testuser / password: testpass123
  - /home/testuser/data/readme.txt
  - /home/testuser/data/bigfile.bin (5MB)
  - /home/testuser/data/subdir/nested.txt
  - /home/testuser/data/link_to_readme (symlink)
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import traceback

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.backend import FileBackend
from core.connection_manager import ConnectionManager
from core.local_fs import LocalFS
from core.profiles import ConnectionProfile, ProfileManager
from core.proxy import ProxyConfig, create_direct_socket
from core.ssh_client import SSHSession
from core.transfer_worker import TransferDirection, TransferJob, TransferStatus
from models.file_item import FileItem

HOST = "127.0.0.1"
PORT = 2223
USER = "testuser"
PASS = "testpass123"

passed = 0
failed = 0
errors: list[str] = []


def _label(name: str):
    """Decorator for test functions."""
    def decorator(func):
        def wrapper():
            global passed, failed
            try:
                func()
                print(f"  PASS  {name}")
                passed += 1
            except Exception as e:
                print(f"  FAIL  {name}: {e}")
                traceback.print_exc()
                failed += 1
                errors.append(f"{name}: {e}")
        return wrapper
    return decorator


def make_profile(**overrides) -> ConnectionProfile:
    defaults = dict(
        name="test",
        host=HOST,
        port=PORT,
        username=USER,
        auth_type="password",
    )
    defaults.update(overrides)
    return ConnectionProfile(**defaults)


# ============================================================
# 1. Direct socket connection
# ============================================================
@_label("Direct socket connects to SSH server (IPv4)")
def test_direct_socket():
    sock = create_direct_socket(HOST, PORT, timeout=5)
    banner = sock.recv(256)
    assert b"SSH" in banner, f"Expected SSH banner, got: {banner}"
    sock.close()


# ============================================================
# 2. SSH Session — password auth
# ============================================================
@_label("SSHSession connects with password auth")
def test_ssh_password():
    profile = make_profile()
    session = SSHSession(profile)
    session.connect(password=PASS)
    assert session.connected
    session.disconnect()
    assert not session.connected


# ============================================================
# 3. SSH Session — wrong password
# ============================================================
@_label("SSHSession rejects wrong password")
def test_ssh_wrong_password():
    profile = make_profile()
    session = SSHSession(profile)
    try:
        session.connect(password="wrongpass")
        session.disconnect()
        assert False, "Should have raised"
    except Exception:
        pass  # Expected


# ============================================================
# 4. FileBackend protocol check
# ============================================================
@_label("SSHSession implements FileBackend protocol")
def test_backend_protocol():
    assert isinstance(SSHSession(make_profile()), FileBackend)


# ============================================================
# 5. SFTP list_dir
# ============================================================
@_label("SFTP list_dir returns files")
def test_list_dir():
    profile = make_profile()
    session = SSHSession(profile)
    session.connect(password=PASS)
    try:
        items = session.list_dir(session.home())
        names = {i.name for i in items}
        assert "data" in names or ".ssh" in names, f"Unexpected listing: {names}"
        # Check data dir
        data_items = session.list_dir(session.join(session.home(), "data"))
        data_names = {i.name for i in data_items}
        assert "readme.txt" in data_names, f"readme.txt not found in: {data_names}"
        assert "bigfile.bin" in data_names, f"bigfile.bin not found in: {data_names}"
        assert "subdir" in data_names, f"subdir not found in: {data_names}"
    finally:
        session.disconnect()


# ============================================================
# 6. SFTP stat
# ============================================================
@_label("SFTP stat returns correct info")
def test_stat():
    profile = make_profile()
    session = SSHSession(profile)
    session.connect(password=PASS)
    try:
        readme_path = session.join(session.home(), "data", "readme.txt")
        item = session.stat(readme_path)
        assert item.name == "readme.txt"
        assert item.size > 0
        assert not item.is_dir
    finally:
        session.disconnect()


# ============================================================
# 7. SFTP is_dir / exists
# ============================================================
@_label("SFTP is_dir and exists work correctly")
def test_is_dir_exists():
    profile = make_profile()
    session = SSHSession(profile)
    session.connect(password=PASS)
    try:
        home = session.home()
        assert session.exists(home)
        assert session.is_dir(home)
        readme = session.join(home, "data", "readme.txt")
        assert session.exists(readme)
        assert not session.is_dir(readme)
        assert not session.exists(session.join(home, "nonexistent_file_xyz"))
    finally:
        session.disconnect()


# ============================================================
# 8. SFTP mkdir + rmdir
# ============================================================
@_label("SFTP mkdir and remove work")
def test_mkdir_remove():
    profile = make_profile()
    session = SSHSession(profile)
    session.connect(password=PASS)
    try:
        test_dir = session.join(session.home(), "test_mkdir_dir")
        if session.exists(test_dir):
            session.remove(test_dir)
        session.mkdir(test_dir)
        assert session.exists(test_dir)
        assert session.is_dir(test_dir)
        session.remove(test_dir)
        assert not session.exists(test_dir)
    finally:
        session.disconnect()


# ============================================================
# 9. SFTP rename
# ============================================================
@_label("SFTP rename works")
def test_rename():
    profile = make_profile()
    session = SSHSession(profile)
    session.connect(password=PASS)
    try:
        src = session.join(session.home(), "rename_test_src.txt")
        dst = session.join(session.home(), "rename_test_dst.txt")
        # Create file
        with session.open_write(src) as f:
            f.write(b"rename test")
        assert session.exists(src)
        session.rename(src, dst)
        assert not session.exists(src)
        assert session.exists(dst)
        # Cleanup
        session.remove(dst)
    finally:
        session.disconnect()


# ============================================================
# 10. SFTP open_read / open_write
# ============================================================
@_label("SFTP read and write files")
def test_read_write():
    profile = make_profile()
    session = SSHSession(profile)
    session.connect(password=PASS)
    try:
        test_file = session.join(session.home(), "rw_test.txt")
        content = b"Hello SFTP write test!\nLine 2."

        # Write
        with session.open_write(test_file) as f:
            f.write(content)

        # Read back
        with session.open_read(test_file) as f:
            read_back = f.read()

        assert read_back == content, f"Content mismatch: {read_back!r} != {content!r}"

        # Cleanup
        session.remove(test_file)
    finally:
        session.disconnect()


# ============================================================
# 11. SFTP recursive remove
# ============================================================
@_label("SFTP recursive directory removal")
def test_recursive_remove():
    profile = make_profile()
    session = SSHSession(profile)
    session.connect(password=PASS)
    try:
        base = session.join(session.home(), "rmtree_test")
        sub = session.join(base, "sub")
        session.mkdir(base)
        session.mkdir(sub)
        with session.open_write(session.join(base, "file1.txt")) as f:
            f.write(b"f1")
        with session.open_write(session.join(sub, "file2.txt")) as f:
            f.write(b"f2")

        assert session.exists(base)
        session.remove(base, recursive=True)
        assert not session.exists(base)
    finally:
        session.disconnect()


# ============================================================
# 12. SFTP normalize / join / parent / separator
# ============================================================
@_label("SFTP path operations")
def test_path_ops():
    profile = make_profile()
    session = SSHSession(profile)
    session.connect(password=PASS)
    try:
        assert session.separator() == "/"
        joined = session.join("/home", "testuser", "data")
        assert joined == "/home/testuser/data"
        parent = session.parent("/home/testuser/data")
        assert parent == "/home/testuser"
        normalized = session.normalize(".")
        assert normalized.startswith("/")
    finally:
        session.disconnect()


# ============================================================
# 13. SFTP home directory
# ============================================================
@_label("SFTP home returns correct directory")
def test_home():
    profile = make_profile()
    session = SSHSession(profile)
    session.connect(password=PASS)
    try:
        home = session.home()
        assert "/testuser" in home, f"Expected /testuser in home: {home}"
    finally:
        session.disconnect()


# ============================================================
# 14. Connection Manager — reuses sessions
# ============================================================
@_label("ConnectionManager reuses sessions for same host")
def test_connection_manager_reuse():
    cm = ConnectionManager()
    profile = make_profile()
    try:
        s1 = cm.connect(profile, password=PASS)
        s2 = cm.connect(profile, password=PASS)
        assert s1 is s2, "Should reuse same session"
        cm.release(profile)
        assert s1.connected, "Should still be connected (one ref left)"
        cm.release(profile)
        assert not s1.connected, "Should be disconnected (no refs)"
    finally:
        cm.disconnect_all()


# ============================================================
# 15. Connection Manager — disconnect all
# ============================================================
@_label("ConnectionManager disconnect_all closes everything")
def test_connection_manager_disconnect_all():
    cm = ConnectionManager()
    p1 = make_profile(name="test1")
    p2 = make_profile(name="test2", port=PORT)
    try:
        s1 = cm.connect(p1, password=PASS)
        s2 = cm.connect(p2, password=PASS)
        assert s1.connected
        cm.disconnect_all()
        assert not s1.connected
    finally:
        cm.disconnect_all()


# ============================================================
# 16. Profile Manager
# ============================================================
@_label("ProfileManager saves and loads profiles")
def test_profile_manager():
    import json
    pm = ProfileManager()
    p = make_profile(name="docker-test-profile")
    pm.add(p)

    # Reload
    pm2 = ProfileManager()
    loaded = pm2.get("docker-test-profile")
    assert loaded is not None
    assert loaded.host == HOST
    assert loaded.port == PORT
    assert loaded.username == USER

    # Cleanup
    pm2.remove("docker-test-profile")


# ============================================================
# 17. Transfer: download file via backends
# ============================================================
@_label("File download via open_read/open_write")
def test_download_file():
    profile = make_profile()
    session = SSHSession(profile)
    session.connect(password=PASS)
    local = LocalFS()
    try:
        remote_path = session.join(session.home(), "data", "readme.txt")
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
            local_path = tmp.name

        # Download
        with session.open_read(remote_path) as src:
            content = src.read()
        with local.open_write(local_path) as dst:
            dst.write(content)

        # Verify
        with local.open_read(local_path) as f:
            downloaded = f.read()
        assert downloaded == content
        assert b"Hello from SFTP server" in downloaded
    finally:
        os.unlink(local_path)
        session.disconnect()


# ============================================================
# 18. Transfer: upload file via backends
# ============================================================
@_label("File upload via open_read/open_write")
def test_upload_file():
    profile = make_profile()
    session = SSHSession(profile)
    session.connect(password=PASS)
    local = LocalFS()
    try:
        content = b"Upload test content from local\n" * 100

        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
            tmp.write(content)
            local_path = tmp.name

        remote_path = session.join(session.home(), "uploaded_test.txt")

        # Upload
        with local.open_read(local_path) as src:
            data = src.read()
        with session.open_write(remote_path) as dst:
            dst.write(data)

        # Verify on remote
        with session.open_read(remote_path) as f:
            remote_content = f.read()
        assert remote_content == content

        # Cleanup
        session.remove(remote_path)
    finally:
        os.unlink(local_path)
        session.disconnect()


# ============================================================
# 19. Transfer large file (5MB bigfile.bin)
# ============================================================
@_label("Download 5MB file via chunked read")
def test_large_file_download():
    profile = make_profile()
    session = SSHSession(profile)
    session.connect(password=PASS)
    try:
        remote_path = session.join(session.home(), "data", "bigfile.bin")
        stat = session.stat(remote_path)
        assert stat.size >= 5 * 1024 * 1024, f"Expected >=5MB, got {stat.size}"

        with tempfile.NamedTemporaryFile(delete=False, suffix=".bin") as tmp:
            local_path = tmp.name

        # Chunked download
        transferred = 0
        with session.open_read(remote_path) as src:
            with open(local_path, "wb") as dst:
                while True:
                    chunk = src.read(64 * 1024)
                    if not chunk:
                        break
                    dst.write(chunk)
                    transferred += len(chunk)

        assert transferred == stat.size, f"Size mismatch: {transferred} != {stat.size}"
        local_size = os.path.getsize(local_path)
        assert local_size == stat.size
    finally:
        os.unlink(local_path)
        session.disconnect()


# ============================================================
# 20. FileItem properties
# ============================================================
@_label("FileItem size_human and mode_str")
def test_file_item_display():
    fi = FileItem(name="test.txt", size=1536, permissions=0o644, is_dir=False)
    assert fi.size_human == "1.5 KB"
    assert fi.mode_str == "-rw-r--r--"

    fi_dir = FileItem(name="docs", size=0, permissions=0o755, is_dir=True)
    assert fi_dir.size_human == ""
    assert fi_dir.mode_str == "drwxr-xr-x"

    fi_link = FileItem(name="link", size=10, permissions=0o777, is_dir=False, is_link=True)
    assert fi_link.type_char == "l"


# ============================================================
# 21. LocalFS backend
# ============================================================
@_label("LocalFS list_dir, stat, mkdir, remove")
def test_local_fs():
    fs = LocalFS()
    assert isinstance(fs, FileBackend)

    items = fs.list_dir("/tmp")
    assert len(items) >= 0

    with tempfile.TemporaryDirectory() as tmpdir:
        test_dir = os.path.join(tmpdir, "test_subdir")
        fs.mkdir(test_dir)
        assert fs.exists(test_dir)
        assert fs.is_dir(test_dir)

        test_file = os.path.join(test_dir, "hello.txt")
        with fs.open_write(test_file) as f:
            f.write(b"hello")
        assert fs.exists(test_file)

        item = fs.stat(test_file)
        assert item.name == "hello.txt"
        assert item.size == 5

        with fs.open_read(test_file) as f:
            assert f.read() == b"hello"

        fs.remove(test_file)
        assert not fs.exists(test_file)

        fs.remove(test_dir)
        assert not fs.exists(test_dir)


# ============================================================
# 22. Symlink handling
# ============================================================
@_label("SFTP handles symlinks correctly")
def test_symlinks():
    profile = make_profile()
    session = SSHSession(profile)
    session.connect(password=PASS)
    try:
        data_items = session.list_dir(session.join(session.home(), "data"))
        link_items = [i for i in data_items if i.name == "link_to_readme"]
        assert len(link_items) == 1, f"link_to_readme not found in listing"
        link = link_items[0]
        assert link.is_link, "Should be a symlink"
    finally:
        session.disconnect()


# ============================================================
# 23. Multiple SFTP channels on same transport
# ============================================================
@_label("Multiple SFTP channels on same transport")
def test_multi_channel():
    profile = make_profile()
    session = SSHSession(profile)
    session.connect(password=PASS)
    try:
        # Open additional channel
        sftp2 = session.open_sftp_channel()
        assert sftp2 is not None

        # Both channels work independently
        items1 = session.list_dir(session.home())
        items2 = sftp2.listdir(session.home())
        assert len(items1) > 0
        assert len(items2) > 0

        sftp2.close()
    finally:
        session.disconnect()


# ============================================================
# 24. SSHSession name property
# ============================================================
@_label("SSHSession.name returns user@host format")
def test_session_name():
    profile = make_profile()
    session = SSHSession(profile)
    assert session.name == f"{USER}@{HOST}"


# ============================================================
# 25. ProxyConfig
# ============================================================
@_label("ProxyConfig enabled flag works correctly")
def test_proxy_config():
    pc_none = ProxyConfig(proxy_type="none")
    assert not pc_none.enabled

    pc_socks = ProxyConfig(proxy_type="socks5", host="proxy.local", port=1080)
    assert pc_socks.enabled

    pc_no_host = ProxyConfig(proxy_type="socks5", host="", port=1080)
    assert not pc_no_host.enabled


# ============================================================
# Run all tests
# ============================================================
if __name__ == "__main__":
    print("=" * 60)
    print("Axross — End-to-End Tests")
    print(f"Server: {USER}@{HOST}:{PORT}")
    print("=" * 60)
    print()

    tests = [
        test_direct_socket,
        test_ssh_password,
        test_ssh_wrong_password,
        test_backend_protocol,
        test_list_dir,
        test_stat,
        test_is_dir_exists,
        test_mkdir_remove,
        test_rename,
        test_read_write,
        test_recursive_remove,
        test_path_ops,
        test_home,
        test_connection_manager_reuse,
        test_connection_manager_disconnect_all,
        test_profile_manager,
        test_download_file,
        test_upload_file,
        test_large_file_download,
        test_file_item_display,
        test_local_fs,
        test_symlinks,
        test_multi_channel,
        test_session_name,
        test_proxy_config,
    ]

    for t in tests:
        t()

    print()
    print("=" * 60)
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    if errors:
        print()
        print("Failures:")
        for e in errors:
            print(f"  - {e}")
    print("=" * 60)

    sys.exit(1 if failed else 0)
