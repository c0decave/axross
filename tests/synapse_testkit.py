"""A throw-away Synapse homeserver on 127.0.0.1 for the Matrix tests.

Synapse is not a dependency of axross (AGPL; test-only): the tests that
need it run when ``AXROSS_TEST_SYNAPSE`` names a Python that can import
``synapse`` (a venv of its own: ``pip install matrix-synapse``) and are
skipped otherwise.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import socket
import subprocess
import time
import urllib.request

SHARED_SECRET = "axross-test-registration"


def synapse_python() -> str | None:
    path = os.environ.get("AXROSS_TEST_SYNAPSE", "")
    return path if path and os.path.exists(path) else None


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Synapse:
    def __init__(self, python: str, workdir) -> None:
        self.python = python
        self.dir = str(workdir)
        self.port = _free_port()
        self.url = f"http://127.0.0.1:{self.port}"
        self.proc: subprocess.Popen | None = None

    def start(self) -> "Synapse":
        cfg = os.path.join(self.dir, "homeserver.yaml")
        env = dict(os.environ, SYNAPSE_NO_TLS="1")
        subprocess.run([self.python, "-m", "synapse.app.homeserver", "--server-name", "localhost",
                        "--config-path", cfg, "--data-directory", self.dir, "--generate-config",
                        "--report-stats=no"], check=True, capture_output=True, cwd=self.dir, env=env, timeout=120)
        import yaml

        with open(cfg, encoding="utf-8") as f:
            config = yaml.safe_load(f)
        unlimited = {"per_second": 1000, "burst_count": 1000}
        config.update({
            # one plain listener on loopback
            "listeners": [{"port": self.port, "tls": False, "type": "http", "x_forwarded": False,
                           "bind_addresses": ["127.0.0.1"],
                           "resources": [{"names": ["client", "federation"], "compress": False}]}],
            "registration_shared_secret": SHARED_SECRET,
            "enable_registration": False,
            "suppress_key_server_warning": True,
            "trusted_key_servers": [],
            "report_stats": False,
            # no limits that would slow the tests
            "rc_message": unlimited, "rc_registration": unlimited, "rc_key_requests": unlimited,
            "rc_room_creation": unlimited, "rc_3pid_validation": unlimited,
            "rc_login": {"address": unlimited, "account": unlimited, "failed_attempts": unlimited},
            "rc_joins": {"local": unlimited, "remote": unlimited},
            "rc_invites": {"per_room": unlimited, "per_user": unlimited, "per_issuer": unlimited},
        })
        with open(cfg, "w", encoding="utf-8") as f:
            yaml.safe_dump(config, f)
        self.log = open(os.path.join(self.dir, "synapse.out"), "wb")
        self.proc = subprocess.Popen([self.python, "-m", "synapse.app.homeserver", "--config-path", cfg],
                                     cwd=self.dir, stdout=self.log, stderr=subprocess.STDOUT, env=env)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if self.proc.poll() is not None:
                raise RuntimeError("Synapse exited:\n" + open(os.path.join(self.dir, "synapse.out")).read()[-3000:])
            try:
                urllib.request.urlopen(self.url + "/_matrix/client/versions", timeout=2).read()
                return self
            except OSError:
                time.sleep(0.3)
        raise RuntimeError("Synapse did not start")

    def register(self, user: str, password: str) -> str:
        base = self.url + "/_synapse/admin/v1/register"
        nonce = json.loads(urllib.request.urlopen(base, timeout=10).read())["nonce"]
        mac = hmac.new(SHARED_SECRET.encode(), b"\x00".join(
            [nonce.encode(), user.encode(), password.encode(), b"notadmin"]), hashlib.sha1).hexdigest()
        body = json.dumps({"nonce": nonce, "username": user, "password": password, "admin": False,
                           "mac": mac}).encode()
        req = urllib.request.Request(base, data=body, headers={"Content-Type": "application/json"})
        return json.loads(urllib.request.urlopen(req, timeout=30).read())["user_id"]

    def stop(self) -> None:
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(15)
            except subprocess.TimeoutExpired:
                self.proc.kill()
        if getattr(self, "log", None):
            self.log.close()
