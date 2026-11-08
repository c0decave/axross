"""sift in a bubblewrap sandbox: the analysed file's folder, read-only, and
the network of the LLM profile's host, nothing else.

Reported: sift (core.analysis_worker) ran as a plain child process with
the user's rights - a parser bug in a hostile file reached the whole home
folder and the network. Decided: by default the analysis child runs in
bubblewrap with

* the system's libraries and the Python running axross, read-only,
* the folder of the analysed file, read-only (a remote file: the private
  temp folder of its copy),
* sift's cache folder, read-write (its results, 0700),
* no network of its own. With an LLM profile, its ``host:port`` alone is
  reachable: the child resolves that name to a loopback listener whose
  connections go through a Unix socket to axross, which opens the TCP
  connection after checking the host (:class:`SocketRelay`). TLS still
  names and verifies the real host - only the route is axross.

Without bubblewrap (not installed, user namespaces switched off) the
analysis runs as before, unsandboxed, after a warning (decided: warn, do
not refuse).
"""

from __future__ import annotations

import functools
import logging
import os
import shutil
import socket
import subprocess
import tempfile
import threading
from urllib.parse import urlsplit

from core.subprocess_env import clean_child_env

log = logging.getLogger(__name__)

#: Where the relay socket appears inside the sandbox.
RELAY_SOCKET_INSIDE = "/run/axross-relay/relay.sock"
#: Environment of the child: the allowed "host:port" entries, comma-separated.
ENV_HOSTS = "AXROSS_SIFT_HOSTS"
#: Environment of the child: the relay socket.
ENV_SOCKET = "AXROSS_SIFT_RELAY"
#: Bytes per read when pumping a relayed connection.
CHUNK = 64 * 1024
#: Seconds to open the real TCP connection.
CONNECT_TIMEOUT = 15.0
#: Longest "host:port" line a relayed connection may start with.
MAX_HEADER = 300
#: The resolver as the process started with it: the relay never resolves
#: through a bridge's redirection (install_child_bridge) back into itself.
_REAL_GETADDRINFO = socket.getaddrinfo


def _connect(host: str, port: int) -> socket.socket:
    """``socket.create_connection`` through :data:`_REAL_GETADDRINFO`."""
    error: OSError | None = None
    for family, kind, proto, _name, address in _REAL_GETADDRINFO(host, port, 0,
                                                                  socket.SOCK_STREAM):
        sock = socket.socket(family, kind, proto)
        try:
            sock.settimeout(CONNECT_TIMEOUT)
            sock.connect(address)
            sock.settimeout(None)
            return sock
        except OSError as exc:
            error = exc
            sock.close()
    raise error or OSError(f"cannot resolve {host}")


@functools.lru_cache(maxsize=1)
def bwrap_usable() -> bool:
    """bubblewrap is installed and can make a sandbox here (user namespaces
    may be switched off, or axross itself runs in a container)."""
    if not shutil.which("bwrap"):
        return False
    try:
        done = subprocess.run(
            ["bwrap", "--unshare-all", "--die-with-parent", "--ro-bind", "/", "/", "true"],
            capture_output=True, timeout=15, env=clean_child_env(),
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


def llm_host(llm: dict | None) -> tuple[str, int] | None:
    """``(host, port)`` of the profile's endpoint, or None (no LLM, no
    endpoint, a scheme other than http/https)."""
    if not llm:
        return None
    endpoint = str(llm.get("endpoint") or "").strip()
    if not endpoint:
        return None
    parts = urlsplit(endpoint if "://" in endpoint else f"http://{endpoint}")
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    try:
        port = parts.port or (443 if parts.scheme == "https" else 80)
    except ValueError:
        return None
    return parts.hostname.lower(), int(port)


def bwrap_command(inner: list[str], *, folder: str, cache_dir: str | None,
                  relay_dir: str | None, env: dict[str, str]) -> list[str]:
    """The bubblewrap command around *inner* (the analysis child)."""
    from core import agent_sandbox as AS

    mounts, pythonpath = AS._python_paths()
    argv = ["bwrap", "--die-with-parent", "--new-session", "--unshare-all",
            "--cap-drop", "ALL", "--clearenv",
            "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
            "--setenv", "HOME", "/tmp",
            "--setenv", "LANG", "C.UTF-8",
            "--setenv", "PYTHONDONTWRITEBYTECODE", "1",
            "--setenv", "PYTHONNOUSERSITE", "1",
            "--setenv", "PYTHONPATH", os.pathsep.join(pythonpath),
            "--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp"]
    for key, value in sorted(env.items()):
        argv += ["--setenv", key, value]
    # TLS needs the certificate store; the name resolution files are not
    # mounted (no network to resolve on: the relay's names come first).
    tls = ("/etc/ssl", "/etc/ca-certificates", "/etc/pki") if relay_dir else ()
    for path in (*AS._SYSTEM_PATHS, *tls):
        if os.path.islink(path):
            argv += ["--symlink", os.readlink(path), path]
        elif os.path.exists(path):
            argv += ["--ro-bind", path, path]
    for path in mounts:
        argv += ["--ro-bind", path, path]
    argv += ["--ro-bind", folder, folder]
    if cache_dir:
        argv += ["--bind", cache_dir, cache_dir]
    if relay_dir:
        argv += ["--ro-bind", relay_dir, os.path.dirname(RELAY_SOCKET_INSIDE)]
    argv += ["--chdir", "/tmp", "--", *inner]
    return argv


class SocketRelay:
    """axross's side: a Unix socket in a private folder. Each connection
    names ``host:port`` on its first line; an allowed one is joined to a
    TCP connection axross opens, anything else is closed."""

    def __init__(self, allowed: set[tuple[str, int]]) -> None:
        self.allowed = set(allowed)
        self.folder = tempfile.mkdtemp(prefix="axross-sift-relay-")
        os.chmod(self.folder, 0o700)
        self.path = os.path.join(self.folder, os.path.basename(RELAY_SOCKET_INSIDE))
        self._listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._listener.bind(self.path)
        self._listener.listen(16)
        self._closed = False
        threading.Thread(target=self._accept, daemon=True, name="sift-relay").start()

    def _accept(self) -> None:
        while not self._closed:
            try:
                conn, _ = self._listener.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True,
                             name="sift-relay-conn").start()

    def _serve(self, conn: socket.socket) -> None:
        try:
            header = b""
            while not header.endswith(b"\n"):
                piece = conn.recv(1)
                if not piece or len(header) > MAX_HEADER:
                    conn.close()
                    return
                header += piece
            host, _, port_text = header.decode("ascii", "replace").strip().rpartition(":")
            key = (host.strip("[]").lower(), int(port_text) if port_text.isdigit() else -1)
            if key not in self.allowed:
                log.warning("sift sandbox: refused a connection to %s:%s", *key)
                conn.close()
                return
            remote = _connect(*key)
        except OSError as exc:
            log.warning("sift sandbox: relay connection failed: %s", exc)
            conn.close()
            return
        _join(conn, remote)

    def close(self) -> None:
        self._closed = True
        # close() alone does not wake the accept() blocked on it (Linux):
        # one sift-relay thread was left behind per worker restart.
        try:
            self._listener.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self._listener.close()
        except OSError:
            pass
        shutil.rmtree(self.folder, ignore_errors=True)


def _join(a: socket.socket, b: socket.socket) -> None:
    def pump(src: socket.socket, dst: socket.socket) -> None:
        try:
            while True:
                data = src.recv(CHUNK)
                if not data:
                    break
                dst.sendall(data)
        except OSError:
            pass
        for sock in (src, dst):
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    t = threading.Thread(target=pump, args=(b, a), daemon=True)
    t.start()
    pump(a, b)
    t.join(timeout=5)
    a.close()
    b.close()


def install_child_bridge(environ=os.environ) -> dict[tuple[str, int], int]:
    """In the sandboxed child: a loopback listener per allowed host, each
    connection forwarded to the relay socket, and the host names resolved
    to the listeners. Returns the mapping (empty without a relay)."""
    path = environ.get(ENV_SOCKET)
    hosts = [h for h in (environ.get(ENV_HOSTS) or "").split(",") if h]
    if not path or not hosts:
        return {}
    from core.agent_net import _port_number, parse_hosts

    mapping: dict[tuple[str, int], int] = {}
    for host, port in parse_hosts(hosts):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        mapping[(host, port)] = listener.getsockname()[1]

        def accept(listener=listener, host=host, port=port) -> None:
            while True:
                try:
                    conn, _ = listener.accept()
                except OSError:
                    return
                threading.Thread(target=forward, args=(conn, host, port), daemon=True).start()

        threading.Thread(target=accept, daemon=True).start()

    def forward(conn: socket.socket, host: str, port: int) -> None:
        relay = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            relay.connect(path)
            relay.sendall(f"{host}:{port}\n".encode("ascii"))
        except OSError:
            conn.close()
            relay.close()
            return
        _join(conn, relay)

    original = socket.getaddrinfo

    def getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):  # noqa: A002
        key = (str(host).lower() if host is not None else "", _port_number(port))
        local = mapping.get(key)
        if local is not None:
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "",
                     ("127.0.0.1", local))]
        return original(host, port, family, type, proto, flags)

    socket.getaddrinfo = getaddrinfo
    return mapping


__all__ = ["ENV_HOSTS", "ENV_SOCKET", "RELAY_SOCKET_INSIDE", "SocketRelay", "bwrap_command",
           "bwrap_usable", "install_child_bridge", "llm_host"]
