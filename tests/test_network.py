#!/usr/bin/env python3
"""Network integration tests against Docker SSH/SFTP/Proxy infrastructure.

Expects the docker-compose network to be running:
  cd tests/docker && docker compose up -d

Network layout:
  ssh-alpha   10.99.0.10:22  (user: alpha / alpha123)
  ssh-beta    10.99.0.11:22  (user: beta  / beta123)
  ssh-gamma   10.99.0.12:22  (user: gamma / gamma123)
  socks-proxy 10.99.0.20:1080 (SOCKS5, no auth)
  http-proxy  10.99.0.21:8888 (HTTP CONNECT)
  test-runner 10.99.0.100     (this script)
"""
from __future__ import annotations

import os
import sys
import tempfile
import time
import traceback

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.backend import FileBackend
from core.connection_manager import ConnectionManager
from core.local_fs import LocalFS
from core.profiles import ConnectionProfile
from core.proxy import ProxyConfig, create_direct_socket, create_proxy_socket
from core.ssh_client import SSHSession, UnknownHostKeyError

# ── Server configs ──────────────────────────────────────────
SERVERS = {
    "alpha": {"host": "10.99.0.10", "port": 22, "user": "alpha", "pass": "alpha123"},
    "beta":  {"host": "10.99.0.11", "port": 22, "user": "beta",  "pass": "beta123"},
    "gamma": {"host": "10.99.0.12", "port": 22, "user": "gamma", "pass": "gamma123"},
}
SOCKS_HOST = "10.99.0.20"
SOCKS_PORT = 1080
HTTP_PROXY_HOST = "10.99.0.21"
HTTP_PROXY_PORT = 8888

passed = 0
failed = 0
errors: list[str] = []


def _label(name: str):
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


def make_profile(server: str, **overrides) -> ConnectionProfile:
    s = SERVERS[server]
    defaults = dict(
        name=server,
        host=s["host"],
        port=s["port"],
        username=s["user"],
        auth_type="password",
    )
    defaults.update(overrides)
    return ConnectionProfile(**defaults)


def auto_trust(error: UnknownHostKeyError) -> bool:
    """Auto-accept unknown host keys for testing."""
    return True


def connect_session(server: str, **overrides) -> SSHSession:
    s = SERVERS[server]
    profile = make_profile(server, **overrides)
    session = SSHSession(profile)
    session.connect(password=s["pass"], on_unknown_host=auto_trust)
    return session


# ════════════════════════════════════════════════════════════
#  SECTION 1: Direct connections to multiple servers
# ════════════════════════════════════════════════════════════

@_label("1.1 Direct connect to ssh-alpha")
def test_direct_alpha():
    s = connect_session("alpha")
    assert s.connected
    items = s.list_dir(s.home())
    names = {i.name for i in items}
    assert "data" in names
    with s.open_read(s.join(s.home(), "hostname.txt")) as f:
        hostname = f.read().decode().strip()
    assert hostname == "alpha", f"Expected 'alpha', got '{hostname}'"
    s.disconnect()

@_label("1.2 Direct connect to ssh-beta")
def test_direct_beta():
    s = connect_session("beta")
    with s.open_read(s.join(s.home(), "hostname.txt")) as f:
        hostname = f.read().decode().strip()
    assert hostname == "beta"
    s.disconnect()

@_label("1.3 Direct connect to ssh-gamma")
def test_direct_gamma():
    s = connect_session("gamma")
    with s.open_read(s.join(s.home(), "hostname.txt")) as f:
        hostname = f.read().decode().strip()
    assert hostname == "gamma"
    s.disconnect()

@_label("1.4 Wrong password rejected")
def test_wrong_password():
    profile = make_profile("alpha")
    session = SSHSession(profile)
    try:
        session.connect(password="wrong", on_unknown_host=auto_trust)
        session.disconnect()
        raise AssertionError("Should have raised")
    except Exception as e:
        assert "Authentication" in str(type(e).__name__) or "auth" in str(e).lower()

@_label("1.5 Multiple servers simultaneously")
def test_multi_server_simultaneous():
    sessions = []
    for name in ("alpha", "beta", "gamma"):
        s = connect_session(name)
        sessions.append((name, s))
    # All connected, read hostname from each
    for name, s in sessions:
        with s.open_read(s.join(s.home(), "hostname.txt")) as f:
            assert f.read().decode().strip() == name
    for _, s in sessions:
        s.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 2: SFTP operations across servers
# ════════════════════════════════════════════════════════════

@_label("2.1 SFTP list_dir on all servers")
def test_list_dir_all():
    for name in SERVERS:
        s = connect_session(name)
        items = s.list_dir(s.join(s.home(), "data"))
        names = {i.name for i in items}
        assert "readme.txt" in names, f"{name}: readme.txt missing"
        assert "bigfile.bin" in names, f"{name}: bigfile.bin missing"
        assert "subdir" in names, f"{name}: subdir missing"
        s.disconnect()

@_label("2.2 SFTP stat returns correct permissions")
def test_stat_permissions():
    s = connect_session("alpha")
    cfg = s.stat(s.join(s.home(), "data", "config.yml"))
    assert cfg.permissions & 0o777 == 0o600, f"Expected 600, got {oct(cfg.permissions & 0o777)}"
    s.disconnect()

@_label("2.3 SFTP mkdir + write + read + remove cycle")
def test_crud_cycle():
    s = connect_session("beta")
    base = s.join(s.home(), "test_crud")
    try:
        if s.exists(base):
            s.remove(base, recursive=True)
        s.mkdir(base)
        test_file = s.join(base, "test.txt")
        with s.open_write(test_file) as f:
            f.write(b"CRUD test content\n")
        with s.open_read(test_file) as f:
            content = f.read()
        assert content == b"CRUD test content\n"
        s.remove(base, recursive=True)
        assert not s.exists(base)
    finally:
        s.disconnect()

@_label("2.4 SFTP rename across directories")
def test_rename_across_dirs():
    s = connect_session("gamma")
    dir_a = s.join(s.home(), "rename_a")
    dir_b = s.join(s.home(), "rename_b")
    try:
        for d in (dir_a, dir_b):
            if s.exists(d):
                s.remove(d, recursive=True)
            s.mkdir(d)
        src = s.join(dir_a, "moved.txt")
        dst = s.join(dir_b, "moved.txt")
        with s.open_write(src) as f:
            f.write(b"moving")
        s.rename(src, dst)
        assert not s.exists(src)
        assert s.exists(dst)
    finally:
        for d in (dir_a, dir_b):
            try:
                s.remove(d, recursive=True)
            except OSError:
                pass
        s.disconnect()

@_label("2.5 SFTP recursive directory tree")
def test_recursive_tree():
    s = connect_session("alpha")
    base = s.join(s.home(), "deep_tree")
    try:
        if s.exists(base):
            s.remove(base, recursive=True)
        # Build 3-level tree
        for depth in range(3):
            path = base
            for i in range(depth + 1):
                path = s.join(path, f"level{i}")
            s.mkdir(path)
            with s.open_write(s.join(path, f"file{depth}.txt")) as f:
                f.write(f"depth {depth}\n".encode())
        # Verify
        assert s.is_dir(s.join(base, "level0", "level0", "level1"))
        # Remove all
        s.remove(base, recursive=True)
        assert not s.exists(base)
    finally:
        s.disconnect()

@_label("2.6 Symlink detection")
def test_symlinks():
    s = connect_session("alpha")
    items = s.list_dir(s.join(s.home(), "data"))
    links = [i for i in items if i.name == "link_to_readme"]
    assert len(links) == 1
    assert links[0].is_link
    s.disconnect()

@_label("2.7 Large file (2MB) transfer integrity")
def test_large_file_integrity():
    s = connect_session("beta")
    remote_path = s.join(s.home(), "data", "bigfile.bin")
    stat = s.stat(remote_path)
    assert stat.size >= 2 * 1024 * 1024

    chunks = []
    with s.open_read(remote_path) as f:
        while True:
            chunk = f.read(64 * 1024)
            if not chunk:
                break
            chunks.append(chunk)
    downloaded = b"".join(chunks)
    assert len(downloaded) == stat.size
    s.disconnect()


@_label("2.8 Large-file canary: 1 GB SSH round-trip + SHA-256")
def test_ssh_1gb_canary():
    """Memory-leak / chunking sniff test: push 1 GB through SFTP,
    pull it back, verify SHA-256. Catches buffer-reuse and chunk-
    boundary bugs that a 2 MB test never exercises.

    Runs against beta to avoid interfering with other SSH tests that
    assume clean state on alpha. The test streams data — if memory
    use blew up to 1 GB per direction, the container OOMs."""
    import hashlib
    import struct
    TOTAL = 1 * 1024 * 1024 * 1024
    CHUNK = 1 * 1024 * 1024

    def pattern(n: int):
        for i in range(0, n, CHUNK):
            sz = min(CHUNK, n - i)
            yield (struct.pack(">Q", i) + b"\xab" * (sz - 8))[:sz]

    expected = hashlib.sha256()
    for c in pattern(TOTAL):
        expected.update(c)

    s = connect_session("beta")
    remote_path = s.join(s.home(), "data", "canary_1gb.bin")
    try:
        with s.open_write(remote_path) as f:
            for c in pattern(TOTAL):
                f.write(c)

        actual = hashlib.sha256()
        with s.open_read(remote_path) as f:
            while True:
                chunk = f.read(CHUNK)
                if not chunk:
                    break
                actual.update(chunk)
        assert actual.hexdigest() == expected.hexdigest(), "1GB round-trip hash mismatch"
    finally:
        if s.exists(remote_path):
            s.remove(remote_path)
        s.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 3: SOCKS5 proxy
# ════════════════════════════════════════════════════════════

@_label("3.1 SOCKS5 proxy to ssh-alpha")
def test_socks5_alpha():
    profile = make_profile(
        "alpha",
        proxy_type="socks5",
        proxy_host=SOCKS_HOST,
        proxy_port=SOCKS_PORT,
    )
    session = SSHSession(profile)
    session.connect(password=SERVERS["alpha"]["pass"], on_unknown_host=auto_trust)
    with session.open_read(session.join(session.home(), "hostname.txt")) as f:
        assert f.read().decode().strip() == "alpha"
    session.disconnect()

@_label("3.2 SOCKS5 proxy to ssh-beta")
def test_socks5_beta():
    profile = make_profile(
        "beta",
        proxy_type="socks5",
        proxy_host=SOCKS_HOST,
        proxy_port=SOCKS_PORT,
    )
    session = SSHSession(profile)
    session.connect(password=SERVERS["beta"]["pass"], on_unknown_host=auto_trust)
    items = session.list_dir(session.join(session.home(), "data"))
    names = {i.name for i in items}
    assert "readme.txt" in names
    session.disconnect()

@_label("3.3 SOCKS5 proxy — file operations work")
def test_socks5_file_ops():
    profile = make_profile(
        "gamma",
        proxy_type="socks5",
        proxy_host=SOCKS_HOST,
        proxy_port=SOCKS_PORT,
    )
    session = SSHSession(profile)
    session.connect(password=SERVERS["gamma"]["pass"], on_unknown_host=auto_trust)
    test_dir = session.join(session.home(), "socks_test")
    try:
        if session.exists(test_dir):
            session.remove(test_dir, recursive=True)
        session.mkdir(test_dir)
        test_file = session.join(test_dir, "proxy_test.txt")
        with session.open_write(test_file) as f:
            f.write(b"Written through SOCKS5 proxy")
        with session.open_read(test_file) as f:
            assert f.read() == b"Written through SOCKS5 proxy"
        session.remove(test_dir, recursive=True)
    finally:
        session.disconnect()

@_label("3.4 SOCKS5 proxy — raw socket creation")
def test_socks5_raw_socket():
    proxy = ProxyConfig(
        proxy_type="socks5",
        host=SOCKS_HOST,
        port=SOCKS_PORT,
    )
    sock = create_proxy_socket(proxy, SERVERS["alpha"]["host"], 22, timeout=10)
    banner = sock.recv(256)
    assert b"SSH" in banner
    sock.close()


# ════════════════════════════════════════════════════════════
#  SECTION 4: HTTP CONNECT proxy
# ════════════════════════════════════════════════════════════

@_label("4.1 HTTP CONNECT proxy to ssh-alpha")
def test_http_proxy_alpha():
    profile = make_profile(
        "alpha",
        proxy_type="http",
        proxy_host=HTTP_PROXY_HOST,
        proxy_port=HTTP_PROXY_PORT,
    )
    session = SSHSession(profile)
    session.connect(password=SERVERS["alpha"]["pass"], on_unknown_host=auto_trust)
    with session.open_read(session.join(session.home(), "hostname.txt")) as f:
        assert f.read().decode().strip() == "alpha"
    session.disconnect()

@_label("4.2 HTTP CONNECT proxy to ssh-gamma")
def test_http_proxy_gamma():
    profile = make_profile(
        "gamma",
        proxy_type="http",
        proxy_host=HTTP_PROXY_HOST,
        proxy_port=HTTP_PROXY_PORT,
    )
    session = SSHSession(profile)
    session.connect(password=SERVERS["gamma"]["pass"], on_unknown_host=auto_trust)
    items = session.list_dir(session.home())
    names = {i.name for i in items}
    assert "data" in names
    session.disconnect()

@_label("4.3 HTTP CONNECT proxy — file write/read")
def test_http_proxy_file_ops():
    profile = make_profile(
        "beta",
        proxy_type="http",
        proxy_host=HTTP_PROXY_HOST,
        proxy_port=HTTP_PROXY_PORT,
    )
    session = SSHSession(profile)
    session.connect(password=SERVERS["beta"]["pass"], on_unknown_host=auto_trust)
    test_file = session.join(session.home(), "http_proxy_test.txt")
    try:
        with session.open_write(test_file) as f:
            f.write(b"Written through HTTP CONNECT proxy")
        with session.open_read(test_file) as f:
            assert f.read() == b"Written through HTTP CONNECT proxy"
        session.remove(test_file)
    finally:
        session.disconnect()

@_label("4.4 HTTP CONNECT raw socket creation")
def test_http_proxy_raw_socket():
    proxy = ProxyConfig(
        proxy_type="http",
        host=HTTP_PROXY_HOST,
        port=HTTP_PROXY_PORT,
    )
    sock = create_proxy_socket(proxy, SERVERS["beta"]["host"], 22, timeout=10)
    banner = sock.recv(256)
    assert b"SSH" in banner
    sock.close()


# ════════════════════════════════════════════════════════════
#  SECTION 5: ConnectionManager
# ════════════════════════════════════════════════════════════

@_label("5.1 ConnectionManager reuses sessions")
def test_cm_reuse():
    cm = ConnectionManager()
    p = make_profile("alpha")
    try:
        s1 = cm.connect(p, password=SERVERS["alpha"]["pass"], on_unknown_host=auto_trust)
        s2 = cm.connect(p, password=SERVERS["alpha"]["pass"], on_unknown_host=auto_trust)
        assert s1 is s2
    finally:
        cm.disconnect_all()

@_label("5.2 ConnectionManager manages multiple servers")
def test_cm_multi_server():
    cm = ConnectionManager()
    profiles = {name: make_profile(name) for name in SERVERS}
    sessions = {}
    try:
        for name, p in profiles.items():
            sessions[name] = cm.connect(p, password=SERVERS[name]["pass"], on_unknown_host=auto_trust)
        # All should be different sessions
        session_ids = {id(s) for s in sessions.values()}
        assert len(session_ids) == 3
        # All connected
        for s in sessions.values():
            assert s.connected
    finally:
        cm.disconnect_all()
    # All disconnected
    for s in sessions.values():
        assert not s.connected

@_label("5.3 ConnectionManager ref counting")
def test_cm_refcount():
    cm = ConnectionManager()
    p = make_profile("beta")
    try:
        s = cm.connect(p, password=SERVERS["beta"]["pass"], on_unknown_host=auto_trust)
        _ = cm.connect(p, password=SERVERS["beta"]["pass"])  # reuse, ref=2
        cm.release(p)  # ref=1
        assert s.connected
        cm.release(p)  # ref=0, disconnects
        assert not s.connected
    finally:
        cm.disconnect_all()


# ════════════════════════════════════════════════════════════
#  SECTION 6: Cross-server transfer simulation
# ════════════════════════════════════════════════════════════

@_label("6.1 Transfer file between two remote servers (via local relay)")
def test_cross_server_transfer():
    s_alpha = connect_session("alpha")
    s_beta = connect_session("beta")
    try:
        # Read from alpha
        src_path = s_alpha.join(s_alpha.home(), "data", "readme.txt")
        with s_alpha.open_read(src_path) as f:
            content = f.read()

        # Write to beta
        dst_path = s_beta.join(s_beta.home(), "from_alpha.txt")
        with s_beta.open_write(dst_path) as f:
            f.write(content)

        # Verify on beta
        with s_beta.open_read(dst_path) as f:
            verify = f.read()
        assert verify == content
        assert b"alpha" in verify

        s_beta.remove(dst_path)
    finally:
        s_alpha.disconnect()
        s_beta.disconnect()

@_label("6.2 Transfer file through SOCKS5 proxy between servers")
def test_cross_server_via_socks():
    p_alpha = make_profile(
        "alpha",
        proxy_type="socks5",
        proxy_host=SOCKS_HOST,
        proxy_port=SOCKS_PORT,
    )
    p_gamma = make_profile(
        "gamma",
        proxy_type="socks5",
        proxy_host=SOCKS_HOST,
        proxy_port=SOCKS_PORT,
    )
    s_alpha = SSHSession(p_alpha)
    s_alpha.connect(password=SERVERS["alpha"]["pass"], on_unknown_host=auto_trust)
    s_gamma = SSHSession(p_gamma)
    s_gamma.connect(password=SERVERS["gamma"]["pass"], on_unknown_host=auto_trust)
    try:
        with s_alpha.open_read(s_alpha.join(s_alpha.home(), "data", "readme.txt")) as f:
            data = f.read()
        dst = s_gamma.join(s_gamma.home(), "from_alpha_via_socks.txt")
        with s_gamma.open_write(dst) as f:
            f.write(data)
        with s_gamma.open_read(dst) as f:
            assert f.read() == data
        s_gamma.remove(dst)
    finally:
        s_alpha.disconnect()
        s_gamma.disconnect()

@_label("6.3 Large file transfer between servers")
def test_large_cross_transfer():
    s_beta = connect_session("beta")
    s_gamma = connect_session("gamma")
    try:
        src = s_beta.join(s_beta.home(), "data", "bigfile.bin")
        stat = s_beta.stat(src)
        dst = s_gamma.join(s_gamma.home(), "bigfile_copy.bin")

        # Chunked transfer
        transferred = 0
        with s_beta.open_read(src) as reader:
            with s_gamma.open_write(dst) as writer:
                while True:
                    chunk = reader.read(64 * 1024)
                    if not chunk:
                        break
                    writer.write(chunk)
                    transferred += len(chunk)

        assert transferred == stat.size
        dst_stat = s_gamma.stat(dst)
        assert dst_stat.size == stat.size
        s_gamma.remove(dst)
    finally:
        s_beta.disconnect()
        s_gamma.disconnect()


# ════════════════════════════════════════════════════════════
#  SECTION 7: Host key verification
# ════════════════════════════════════════════════════════════

@_label("7.1 Unknown host key triggers callback")
def test_unknown_host_callback():
    import tempfile
    profile = make_profile("alpha")
    session = SSHSession(profile)
    # Use a temp known_hosts so the key is definitely unknown
    session._known_hosts_path = __import__("pathlib").Path(
        tempfile.mktemp(suffix="_known_hosts")
    )

    callback_called = False
    def on_unknown(error):
        nonlocal callback_called
        callback_called = True
        assert error.host
        assert error.key_type
        assert error.fingerprint_sha256
        return True

    session.connect(password=SERVERS["alpha"]["pass"], on_unknown_host=on_unknown)
    assert callback_called
    session.disconnect()
    # Clean up temp file
    try:
        session._known_hosts_path.unlink()
    except OSError:
        pass

@_label("7.2 Host key is persisted after trust")
def test_host_key_persistence():
    import tempfile
    from pathlib import Path

    tmp_known = Path(tempfile.mktemp(suffix="_known_hosts"))

    # First connection — trust the key
    profile = make_profile("beta")
    session1 = SSHSession(profile)
    session1._known_hosts_path = tmp_known
    session1.connect(password=SERVERS["beta"]["pass"], on_unknown_host=lambda e: True)
    session1.disconnect()

    # File should exist now
    assert tmp_known.exists()

    # Second connection — should NOT call the callback
    session2 = SSHSession(profile)
    session2._known_hosts_path = tmp_known
    callback_called = False
    def should_not_be_called(error):
        nonlocal callback_called
        callback_called = True
        return True

    session2.connect(password=SERVERS["beta"]["pass"], on_unknown_host=should_not_be_called)
    assert not callback_called, "Callback should not be called for known host"
    session2.disconnect()

    try:
        tmp_known.unlink()
    except OSError:
        pass


# ════════════════════════════════════════════════════════════
#  SECTION 8: Edge cases
# ════════════════════════════════════════════════════════════

@_label("8.1 Multi-channel on same transport")
def test_multi_channel():
    s = connect_session("alpha")
    try:
        sftp2 = s.open_sftp_channel()
        # Both work
        items1 = s.list_dir(s.home())
        items2 = sftp2.listdir(s.home())
        assert len(items1) > 0
        assert len(items2) > 0
        sftp2.close()
    finally:
        s.disconnect()

@_label("8.2 Empty directory listing")
def test_empty_dir():
    s = connect_session("alpha")
    items = s.list_dir(s.join(s.home(), "data", "emptydir"))
    assert len(items) == 0
    s.disconnect()

@_label("8.3 Path operations")
def test_path_ops():
    s = connect_session("alpha")
    assert s.separator() == "/"
    assert s.join("/home", "alpha") == "/home/alpha"
    assert s.parent("/home/alpha/data") == "/home/alpha"
    assert s.parent("/") == "/"
    norm = s.normalize(".")
    assert norm.startswith("/")
    s.disconnect()

@_label("8.4 Reconnect after disconnect")
def test_reconnect():
    s = connect_session("gamma")
    assert s.connected
    s.disconnect()
    assert not s.connected
    # Reconnect
    s.connect(password=SERVERS["gamma"]["pass"], on_unknown_host=auto_trust)
    assert s.connected
    items = s.list_dir(s.home())
    assert len(items) > 0
    s.disconnect()


# ════════════════════════════════════════════════════════════
#  Run
# ════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("=" * 65)
    print("Axross — Network Integration Tests")
    print("=" * 65)

    # Wait for services to be ready
    print("\nWaiting for services...")
    for name, cfg in SERVERS.items():
        for attempt in range(30):
            try:
                sock = create_direct_socket(cfg["host"], cfg["port"], timeout=2)
                banner = sock.recv(256)
                sock.close()
                if b"SSH" in banner:
                    print(f"  {name} ({cfg['host']}:{cfg['port']}) ready")
                    break
            except Exception:
                if attempt == 29:
                    print(f"  {name} NOT REACHABLE — skipping")
                time.sleep(1)

    print()

    all_tests = [
        # Section 1: Direct connections
        test_direct_alpha,
        test_direct_beta,
        test_direct_gamma,
        test_wrong_password,
        test_multi_server_simultaneous,
        # Section 2: SFTP operations
        test_list_dir_all,
        test_stat_permissions,
        test_crud_cycle,
        test_rename_across_dirs,
        test_recursive_tree,
        test_symlinks,
        test_large_file_integrity,
        # Section 3: SOCKS5
        test_socks5_alpha,
        test_socks5_beta,
        test_socks5_file_ops,
        test_socks5_raw_socket,
        # Section 4: HTTP CONNECT
        test_http_proxy_alpha,
        test_http_proxy_gamma,
        test_http_proxy_file_ops,
        test_http_proxy_raw_socket,
        # Section 5: ConnectionManager
        test_cm_reuse,
        test_cm_multi_server,
        test_cm_refcount,
        # Section 6: Cross-server
        test_cross_server_transfer,
        test_cross_server_via_socks,
        test_large_cross_transfer,
        # Section 7: Host key verification
        test_unknown_host_callback,
        test_host_key_persistence,
        # Section 8: Edge cases
        test_multi_channel,
        test_empty_dir,
        test_path_ops,
        test_reconnect,
    ]

    for t in all_tests:
        t()

    print()
    print("=" * 65)
    print(f"Results: {passed} passed, {failed} failed, {passed + failed} total")
    if errors:
        print()
        print("Failures:")
        for e in errors:
            print(f"  - {e}")
    print("=" * 65)

    sys.exit(1 if failed else 0)
