"""Through a proxy the proxy resolves the server's name - never this computer.

Before:

* SFTP and SCP with *IP Version* IPv4 or IPv6 resolved the host name on this
  computer even through a SOCKS5 (or HTTP) proxy and sent the proxy an
  address: a DNS query around the proxy, and a name only the proxy's
  network knows failed. The combination is refused now with what to do
  instead (Automatic, or the server's address of that version).
* rsync through a SOCKS4 proxy ran ``nc -X 4``: OpenBSD nc has no SOCKS4a
  and resolved the rsync host locally. nc now dials the loopback shim,
  which speaks SOCKS4a upstream (the proxy resolves the name) as every
  other backend does.
"""

from __future__ import annotations

import socket
import sys
from pathlib import Path
from unittest import mock

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import proxy as P  # noqa: E402
from core import rsync_client as R  # noqa: E402
from core.profiles import ConnectionProfile  # noqa: E402


@pytest.fixture(autouse=True)
def _loopback_proxy_allowed(monkeypatch):
    """The fakes stand in for a proxy on loopback (deny-listed by default)."""
    monkeypatch.setattr(P, "_assert_proxy_host_not_private", lambda *_a, **_k: None)


def _no_target_lookup(monkeypatch, target="files.internal"):
    real = socket.getaddrinfo
    asked: list = []

    def lookup(host, *a, **kw):
        asked.append(host)
        if host == target:
            pytest.fail(f"{target} was resolved on this computer")
        return real(host, *a, **kw)

    monkeypatch.setattr(P.socket, "getaddrinfo", lookup)
    return asked


@pytest.mark.parametrize("kind", ["socks5", "socks4", "http"])
@pytest.mark.parametrize("family", [socket.AF_INET, socket.AF_INET6])
def test_sad_a_forced_ip_version_with_a_host_name_is_refused(kind, family, monkeypatch):
    _no_target_lookup(monkeypatch)
    with pytest.raises(ConnectionError, match="IP Version .* Automatic"):
        P.create_proxy_socket(P.ProxyConfig(kind, "127.0.0.1", 1080), "files.internal", 22,
                              timeout=2, family=family)


def test_sad_an_address_of_the_other_version_is_refused():
    with pytest.raises(ConnectionError, match="no IPv6 address"):
        P.create_proxy_socket(P.ProxyConfig("socks5", "127.0.0.1", 1080), "192.0.2.7", 22,
                              timeout=2, family=socket.AF_INET6)


def test_happy_an_address_of_that_version_goes_through_the_proxy(monkeypatch):
    seen = {}

    class FakeSocks:
        SOCKS4, SOCKS5 = 1, 2

        class socksocket:  # noqa: N801 - as PySocks names it
            def __init__(self, *a):
                pass

            def settimeout(self, t):
                pass

            def set_proxy(self, *a, **kw):
                seen["rdns"] = kw.get("rdns")

            def connect(self, addr):
                seen["addr"] = addr

    monkeypatch.setitem(sys.modules, "socks", FakeSocks)
    P.create_proxy_socket(P.ProxyConfig("socks5", "127.0.0.1", 1080), "192.0.2.7", 22,
                          timeout=2, family=socket.AF_INET)
    assert seen["addr"] == ("192.0.2.7", 22)


def test_happy_automatic_keeps_the_name_for_the_proxy(monkeypatch):
    _no_target_lookup(monkeypatch)
    seen = {}

    class FakeSocks:
        SOCKS4, SOCKS5 = 1, 2

        class socksocket:  # noqa: N801
            def __init__(self, *a):
                pass

            def settimeout(self, t):
                pass

            def set_proxy(self, *a, **kw):
                seen["rdns"] = kw.get("rdns")

            def connect(self, addr):
                seen["addr"] = addr

    monkeypatch.setitem(sys.modules, "socks", FakeSocks)
    P.create_proxy_socket(P.ProxyConfig("socks5", "127.0.0.1", 1080), "files.internal", 22,
                          timeout=2)
    assert seen == {"rdns": True, "addr": ("files.internal", 22)}


@pytest.mark.parametrize("session_class", ["SSHSession", "SCPSession"])
def test_sad_sftp_and_scp_with_ipv4_through_socks5_are_refused(session_class, monkeypatch):
    from core.connection_manager import _session_class

    _no_target_lookup(monkeypatch)
    profile = ConnectionProfile(name="p", protocol="sftp", host="files.internal", port=22,
                                username="u", address_family="ipv4", proxy_type="socks5",
                                proxy_host="127.0.0.1", proxy_port=1080)
    session = _session_class(session_class)(profile)
    with pytest.raises(OSError, match="IP Version IPv4"):
        session.connect(password="pw")


# --- rsync over SOCKS4 -----------------------------------------------------------------------------

@pytest.fixture
def openbsd_nc(monkeypatch):
    monkeypatch.setattr(R, "_resolve_nc_with_proxy_support", lambda: "/usr/bin/nc.openbsd")
    monkeypatch.setattr(R, "_nc_supports_proxy_username", lambda _nc: True)


@pytest.mark.parametrize("build", [
    lambda proxy: R._build_rsync_connect_prog(proxy, 873),
    lambda proxy: R._build_ssh_proxy_command(proxy),
], ids=["daemon", "ssh"])
def test_sad_rsync_over_socks4_never_runs_nc_with_local_resolution(build, openbsd_nc):
    shim = mock.Mock(host="127.0.0.1", port=41235)
    P._register_shim_port(shim.port, True)
    try:
        with mock.patch("core.proxy_http.shim_for", return_value=shim) as shim_for:
            cmd = build(P.ProxyConfig("socks4", "proxy.example", 1080))
    finally:
        P._register_shim_port(shim.port, False)
    assert "-X 4" not in cmd
    assert "-X connect" in cmd and "127.0.0.1:41235" in cmd
    assert shim_for.call_args.args[0].proxy_type == "socks4"


def test_happy_the_shim_dials_socks4a_for_a_name(monkeypatch):
    """What the shim does upstream: SOCKS4 with the name (rdns = SOCKS4a)."""
    _no_target_lookup(monkeypatch)
    seen = {}

    class FakeSocks:
        SOCKS4, SOCKS5 = 1, 2

        class socksocket:  # noqa: N801
            def __init__(self, *a):
                pass

            def settimeout(self, t):
                pass

            def set_proxy(self, kind, *a, **kw):
                seen.update(kind=kind, rdns=kw.get("rdns"))

            def connect(self, addr):
                seen["addr"] = addr

    monkeypatch.setitem(sys.modules, "socks", FakeSocks)
    P.create_proxy_socket(P.ProxyConfig("socks4", "127.0.0.1", 1080), "files.internal", 873,
                          timeout=2)
    assert seen == {"kind": 1, "rdns": True, "addr": ("files.internal", 873)}


# --- rsync through a proxy: the host goes into a shell command -------------------------------------

@pytest.mark.parametrize("host", ["x;touch /tmp/p", "x$(id)", "x`id`", "a|b", "-oProxyCommand=sh"])
@pytest.mark.parametrize("ssh_mode", [False, True], ids=["daemon", "ssh"])
def test_sad_an_rsync_host_with_shell_syntax_is_refused_through_a_proxy(host, ssh_mode, monkeypatch):
    """rsync runs RSYNC_CONNECT_PROG with sh -c after putting the host in for
    %H (ssh its ProxyCommand with %h), unquoted: such a host ran a command
    on this computer."""
    monkeypatch.setattr(R.RsyncSession, "_probe_connection",
                        lambda self: pytest.fail("rsync was started"))
    monkeypatch.setattr(R.shutil, "which", lambda _n: "/usr/bin/rsync")
    with pytest.raises(OSError):
        R.RsyncSession(host=host, module="m", ssh_mode=ssh_mode, proxy_type="socks5",
                       proxy_host="proxy.example", proxy_port=1080)


def test_happy_a_plain_rsync_host_goes_on_through_a_proxy(monkeypatch):
    probed = []
    monkeypatch.setattr(R.RsyncSession, "_probe_connection", lambda self: probed.append(1))
    monkeypatch.setattr(R.shutil, "which", lambda _n: "/usr/bin/rsync")
    R.RsyncSession(host="files.example", module="m", proxy_type="socks5",
                   proxy_host="proxy.example", proxy_port=1080)
    R.RsyncSession(host="2001:db8::1", module="m", proxy_type="socks5",
                   proxy_host="proxy.example", proxy_port=1080)
    assert probed == [1, 1]
