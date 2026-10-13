"""Disposable proxy lab (podman): real proxy servers in front of services
that the host cannot reach any other way.

    python -m tests.proxy_lab up      # build images, start, print the map
    python -m tests.proxy_lab down    # remove containers and network

Topology -- one user network ``axproxy-lab``:

* ``axproxy-squid``  Basic + NTLM-handshake HTTP proxy (3128), TLS proxy
  (3129, ``https_port``), open HTTP proxy (3130)
* ``axproxy-dante``  SOCKS4/5 without auth (1080), SOCKS5 user/pass (1081)
* ``axproxy-targets`` ssh.lab / ftp.lab / http.lab / redis.lab -- no
  published ports and names the host cannot resolve, so a connection that
  does not go through a proxy cannot succeed.

Only proxy ports are published, on 127.0.0.1. Everything is prefixed
``axproxy-`` and nothing else on the host's podman is touched.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path

LAB_DIR = Path(__file__).resolve().parent / "docker" / "proxy-lab"
NETWORK = "axproxy-lab"
PREFIX = "axproxy-"

PROXY_USER = "labproxy"
PROXY_PASSWORD = "labproxy-pass"
DANTE_USER = "proxyuser"
DANTE_PASSWORD = "proxypass"
TARGET_USER = "labuser"
TARGET_PASSWORD = "labpass123"

# container -> (image Dockerfile, published container ports)
_CONTAINERS = {
    "squid": ("Dockerfile.squid", (3128, 3129, 3130)),
    "dante": ("Dockerfile.dante", (1080, 1081)),
    "targets": ("Dockerfile.targets", ()),
}
_TARGET_ALIASES = ("ssh.lab", "ftp.lab", "http.lab", "redis.lab")


class LabError(RuntimeError):
    pass


def podman_available() -> bool:
    return shutil.which("podman") is not None


def _podman(*args: str, check: bool = True, timeout: float = 900) -> subprocess.CompletedProcess:
    proc = subprocess.run(
        ["podman", *args], capture_output=True, text=True, timeout=timeout, check=False
    )
    if check and proc.returncode != 0:
        raise LabError(f"podman {' '.join(args[:3])} failed: {(proc.stderr or proc.stdout)[-600:]}")
    return proc


@dataclass
class ProxyLab:
    """Handle on a running lab; ``ports`` maps a proxy name to a host port."""

    ports: dict[str, int] = field(default_factory=dict)
    ca_file: str = ""
    workdir: Path | None = None

    # -- addresses the tests use ---------------------------------------
    host = "127.0.0.1"

    def proxy(self, name: str) -> dict:
        """Keyword arguments for a ConnectionProfile / backend ctor."""
        kinds = {
            "socks5": ("socks5", "", ""),
            "socks4": ("socks4", "", ""),
            "socks5-auth": ("socks5", DANTE_USER, DANTE_PASSWORD),
            "http": ("http", "", ""),
            "http-basic": ("http+basic", PROXY_USER, PROXY_PASSWORD),
            "https-basic": ("https+basic", PROXY_USER, PROXY_PASSWORD),
            "http-ntlm": ("http+ntlm", "LAB\\" + PROXY_USER, PROXY_PASSWORD),
        }
        kind, user, password = kinds[name]
        return {
            "proxy_type": kind,
            "proxy_host": self.host,
            "proxy_port": self.ports[name],
            "proxy_username": user,
            "proxy_password": password,
        }

    def target_ip(self) -> str:
        """Address of the targets container on the lab network (only
        meaningful inside it; used for SOCKS4, which has no host names)."""
        fmt = '{{(index .NetworkSettings.Networks "%s").IPAddress}}' % NETWORK
        return _podman("inspect", f"{PREFIX}targets", "--format", fmt).stdout.strip()

    # -- lifecycle --------------------------------------------------------
    @classmethod
    def up(cls, *, rebuild: bool = False) -> "ProxyLab":
        if not podman_available():
            raise LabError("podman is not installed")
        from tests.proxy_http_testkit import TestPki

        workdir = Path(tempfile.mkdtemp(prefix="axproxy-lab-"))
        pki = TestPki()
        crt, key = pki.issue("127.0.0.1", "localhost", "axproxy-squid")
        certs = workdir / "certs"
        certs.mkdir()
        shutil.copy(crt, certs / "proxy.crt")
        shutil.copy(key, certs / "proxy.key")
        for f in certs.iterdir():
            f.chmod(0o644)
        certs.chmod(0o755)

        cls.down(quiet=True)
        _podman("network", "create", NETWORK)
        for name, (dockerfile, _ports) in _CONTAINERS.items():
            image = f"localhost/{PREFIX}{name}:lab"
            if rebuild or _podman("image", "exists", image, check=False).returncode != 0:
                _podman("build", "-t", image, "-f", str(LAB_DIR / dockerfile), str(LAB_DIR))
        _podman(
            "run",
            "-d",
            "--name",
            f"{PREFIX}targets",
            "--network",
            NETWORK,
            *[a for alias in _TARGET_ALIASES for a in ("--network-alias", alias)],
            f"localhost/{PREFIX}targets:lab",
        )
        for name in ("squid", "dante"):
            args = ["run", "-d", "--name", f"{PREFIX}{name}", "--network", NETWORK]
            if name == "squid":
                args += [
                    "-v",
                    f"{certs}:/certs:ro",
                    "-e",
                    f"LAB_PROXY_USER={PROXY_USER}",
                    "-e",
                    f"LAB_PROXY_PASSWORD={PROXY_PASSWORD}",
                ]
            for port in _CONTAINERS[name][1]:
                args += ["-p", f"127.0.0.1::{port}"]
            _podman(*args, f"localhost/{PREFIX}{name}:lab")

        lab = cls(ca_file=pki.ca_file, workdir=workdir)
        names = {
            ("squid", 3128): "http-basic",
            ("squid", 3129): "https-basic",
            ("squid", 3130): "http",
            ("dante", 1080): "socks5",
            ("dante", 1081): "socks5-auth",
        }
        for (container, port), alias in names.items():
            out = _podman("port", f"{PREFIX}{container}", f"{port}/tcp").stdout.strip()
            lab.ports[alias] = int(out.splitlines()[0].rsplit(":", 1)[1])
        lab.ports["socks4"] = lab.ports["socks5"]  # dante answers both versions
        lab.ports["http-ntlm"] = lab.ports["http-basic"]  # squid offers Basic and NTLM
        try:
            lab.wait_ready()
        except BaseException:
            cls.down(quiet=True)
            raise
        return lab

    def wait_ready(self, timeout: float = 90.0) -> None:
        """Block until the targets answer *through* the SOCKS proxy."""
        import socket

        from core.proxy import ProxyConfig, create_proxy_socket

        cfg = ProxyConfig("socks5", self.host, self.ports["socks5"])
        deadline = time.monotonic() + timeout
        last = ""
        while time.monotonic() < deadline:
            for target, port in (("ssh.lab", 22), ("redis.lab", 6379), ("http.lab", 80)):
                try:
                    from unittest import mock

                    with mock.patch("core.proxy._assert_proxy_host_not_private"):
                        sock = create_proxy_socket(cfg, target, port, timeout=3)
                    sock.close()
                except (OSError, socket.error, ValueError) as exc:
                    last = f"{target}:{port}: {exc}"
                    break
            else:
                return
            time.sleep(1)
        raise LabError(f"lab did not become ready in {timeout:.0f}s ({last})")

    @staticmethod
    def down(quiet: bool = False) -> None:
        names = [f"{PREFIX}{n}" for n in _CONTAINERS]
        _podman("rm", "-f", "-t", "0", *names, check=False)
        _podman("network", "rm", "-f", NETWORK, check=False)
        if not quiet:
            print("lab removed")

    def close(self) -> None:
        self.down(quiet=True)
        if self.workdir:
            shutil.rmtree(self.workdir, ignore_errors=True)


def main(argv: list[str]) -> int:
    cmd = argv[1] if len(argv) > 1 else "up"
    if cmd == "down":
        ProxyLab.down()
        return 0
    if cmd == "up":
        lab = ProxyLab.up(rebuild="--rebuild" in argv)
        for name, port in sorted(lab.ports.items()):
            print(f"{name:12} 127.0.0.1:{port}")
        print(f"CA file      {lab.ca_file}")
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
