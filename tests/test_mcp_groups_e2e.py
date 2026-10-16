"""End to end: the real ``axross --mcp-server --mcp-tools all --mcp-write
--mcp-root <tmp> --mcp-allow-exec`` as a subprocess, over stdio and over
HTTP on loopback.

Each run drives initialize -> tools/list -> one call per capability group
-> tasks/start of a long pack + tasks/cancel, and checks what landed on
disk. The child gets a home of its own (profiles.json with a RamFS
profile) and no keyring: no D-Bus session, null keyring backend.
"""

from __future__ import annotations

import base64
import json
import os
import queue
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import zipfile
from pathlib import Path

import pytest

from core import mcp_groups as G
from core.profiles import ConnectionProfile
from tests import metadata_testkit as K

REPO = Path(__file__).resolve().parents[1]
TIMEOUT = 60.0


def _child_env(home: Path) -> dict:
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith("AXROSS_") and k not in ("DBUS_SESSION_BUS_ADDRESS", "SSH_AUTH_SOCK")
    }
    runtime = home / "run"
    runtime.mkdir(mode=0o700, exist_ok=True)
    env.update(
        HOME=str(home),
        XDG_CONFIG_HOME=str(home / ".config"),
        XDG_DATA_HOME=str(home / ".local" / "share"),
        XDG_CACHE_HOME=str(home / ".cache"),
        XDG_STATE_HOME=str(home / ".local" / "state"),
        XDG_RUNTIME_DIR=str(runtime),
        PYTHON_KEYRING_BACKEND="keyring.backends.null.Keyring",
        QT_QPA_PLATFORM="offscreen",
    )
    return env


@pytest.fixture
def world(tmp_path):
    home = tmp_path / "home"
    config = home / ".config" / "axross"
    config.mkdir(parents=True)
    ram = ConnectionProfile(name="ram", protocol="ramfs").to_dict()
    (config / "profiles.json").write_text(json.dumps({"ram": ram}))
    root = tmp_path / "root"
    root.mkdir()
    K.write(root / "photo.jpg", K.jpeg_bytes())
    (root / "a.txt").write_text("twin\n")
    (root / "b.txt").write_text("twin\n")
    (root / "big").mkdir()
    (root / "big" / "random.bin").write_bytes(os.urandom(48 * 1024 * 1024))
    return home, root


class _Stdio:
    def __init__(self, home: Path, root: Path) -> None:
        self.proc = subprocess.Popen(
            [sys.executable, str(REPO / "main.py"), "--mcp-server", "--mcp-tools", "all",
             "--mcp-write", "--mcp-root", str(root), "--mcp-allow-exec"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, env=_child_env(home), cwd=REPO,
        )
        self.lines: queue.Queue = queue.Queue()
        threading.Thread(target=self._pump, daemon=True).start()
        self._id = 0

    def _pump(self) -> None:
        for line in self.proc.stdout:
            self.lines.put(line)
        self.lines.put(None)

    def rpc(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        msg = {"jsonrpc": "2.0", "id": self._id, "method": method, "params": params or {}}
        self.proc.stdin.write(json.dumps(msg) + "\n")
        self.proc.stdin.flush()
        deadline = time.monotonic() + TIMEOUT
        while time.monotonic() < deadline:
            line = self.lines.get(timeout=TIMEOUT)
            assert line is not None, self.proc.stderr.read()
            frame = json.loads(line)
            if frame.get("id") == self._id:
                return frame
        raise AssertionError(f"no answer to {method}")

    def close(self) -> int:
        self.proc.stdin.close()
        try:
            return self.proc.wait(timeout=TIMEOUT)
        finally:
            self.proc.stdout.close()
            self.proc.stderr.close()


class _Http:
    def __init__(self, home: Path, root: Path) -> None:
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            self.port = s.getsockname()[1]
        self.proc = subprocess.Popen(
            [sys.executable, str(REPO / "main.py"), "--mcp-server", "--mcp-http",
             f"127.0.0.1:{self.port}", "--mcp-tools", "all", "--mcp-write", "--mcp-root", str(root),
             "--mcp-allow-exec"],
            stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=_child_env(home), cwd=REPO,
        )
        self.session = None
        self._id = 0
        deadline = time.monotonic() + TIMEOUT
        while True:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/health", timeout=2).read()
                break
            except OSError:
                assert self.proc.poll() is None, self.proc.stderr.read()
                assert time.monotonic() < deadline, "HTTP server never came up"
                time.sleep(0.1)

    def rpc(self, method: str, params: dict | None = None) -> dict:
        self._id += 1
        body = json.dumps({"jsonrpc": "2.0", "id": self._id, "method": method,
                           "params": params or {}}).encode()
        req = urllib.request.Request(
            f"http://127.0.0.1:{self.port}/messages", data=body, method="POST",
            headers={"Content-Type": "application/json"},
        )
        if self.session:
            req.add_header("Mcp-Session-Id", self.session)
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            if method == "initialize":
                self.session = resp.headers["Mcp-Session-Id"]
            return json.loads(resp.read())

    def close(self) -> int:
        self.proc.terminate()
        try:
            return self.proc.wait(timeout=TIMEOUT)
        finally:
            self.proc.stdout.close()
            self.proc.stderr.close()


def _call(client, name: str, args: dict) -> dict:
    frame = client.rpc("tools/call", {"name": name, "arguments": args})
    assert "result" in frame, f"{name}: {frame.get('error')}"
    return json.loads(frame["result"]["content"][0]["text"])


def _drive(client, root: Path) -> None:
    init = client.rpc("initialize", {"protocolVersion": "2024-11-05"})
    assert init["result"]["serverInfo"]["name"] == "axross-mcp"
    names = {t["name"] for t in client.rpc("tools/list")["result"]["tools"]}
    expected = {
        "metadata_read", "metadata_remove", "duplicates_scan", "duplicates_dedupe", "pack",
        "archive_extract", "encrypt", "decrypt", "index_build", "file_type", "transfer_copy",
        "remote_open", "list_backends", "extensions_list", "write_file", "remote_exec",
        "remote_script", "exec_backends", "agent_run",
    }
    assert expected <= names
    assert {"script_run"}.isdisjoint(names)  # not requested

    # metadata
    meta = _call(client, "metadata_read", {"path": str(root / "photo.jpg")})
    assert meta["files"][0]["removable_count"] > 0
    # duplicates
    _call(client, "duplicates_scan", {"path": str(root)})
    groups = _call(client, "duplicates_groups", {})["groups"]
    assert any({os.path.basename(c["path"]) for c in g["copies"]} == {"a.txt", "b.txt"} for g in groups)
    # packer + archive
    packed = _call(client, "pack", {"folder": str(root), "names": ["a.txt", "photo.jpg"], "archive_name": "e2e"})
    with zipfile.ZipFile(packed["path"]) as zf:
        assert sorted(zf.namelist()) == ["a.txt", "photo.jpg"]
    listed = _call(client, "archive_list", {"path": packed["path"]})
    assert listed["total"] == 2
    extracted = _call(client, "archive_extract", {"path": packed["path"]})
    assert (Path(extracted["path"]) / "a.txt").read_text() == "twin\n"
    # crypto
    enc = _call(client, "encrypt", {"path": str(root / "a.txt"), "passphrase": "pp"})
    dec = _call(client, "decrypt", {"path": enc["path"], "passphrase": "pp"})
    assert Path(dec["path"]).read_text() == "twin\n"
    # index -> search
    _call(client, "index_build", {"path": str(root)})
    hits = {h["path"] for h in _call(client, "search", {"needle": "photo"})}
    assert hits == {str(root / "photo.jpg"), str(Path(extracted["path"]) / "photo.jpg")}
    # filetype
    assert _call(client, "file_type", {"path": str(root / "photo.jpg")})["mime"] == "image/jpeg"
    # remote + transfer
    assert [p["name"] for p in _call(client, "remote_profiles", {})["profiles"]] == ["ram"]
    bid = _call(client, "remote_open", {"profile": "ram"})["backend"]
    assert bid in {b["id"] for b in _call(client, "list_backends", {})}
    copied = _call(client, "transfer_copy", {"src": str(root / "b.txt"), "dst_backend": bid, "dst": "/b.txt"})
    assert copied["copied"] == 1
    back = _call(client, "read_file", {"backend": bid, "path": "/b.txt"})
    assert base64.b64decode(back["content_b64"]) == b"twin\n"
    # exec: no backend here has a remote shell (the lab run covers real
    # ones), so the group answers with an empty list and a clear refusal.
    assert _call(client, "exec_backends", {}) == {"backends": []}
    refused = client.rpc("tools/call", {"name": "remote_exec", "arguments": {"backend": bid, "command": "id"}})
    assert "no remote shell" in refused["error"]["message"]
    # agent: the child has no LLM profile, so the hand-off says how to get one
    refused = client.rpc("tools/call", {"name": "agent_run", "arguments": {"task": "summarise"}})
    assert "LLM profile" in refused["error"]["message"]
    # extensions
    exts = _call(client, "extensions_list", {})
    assert exts["runnable_over_mcp"] is False and exts["extensions"]

    # A long job under tasks/start, cancelled while it runs.
    started = client.rpc("tasks/start", {"name": "pack", "arguments": {
        "folder": str(root / "big"), "names": ["random.bin"], "archive_name": "slow",
        "format": "tar.xz", "level": "best"}})
    task_id = started["result"]["task_id"]
    assert client.rpc("tasks/cancel", {"task_id": task_id})["result"]["ok"] is True
    deadline = time.monotonic() + TIMEOUT
    while True:
        status = client.rpc("tasks/status", {"task_id": task_id})["result"]
        if status["status"] != "running":
            break
        assert time.monotonic() < deadline, "the cancelled task never stopped"
        time.sleep(0.05)
    assert status["status"] == "cancelled", status
    assert not list((root / "big").glob("slow*")) and not list((root / "big").glob(".axross-pack-*"))


def test_happy_stdio_server_serves_every_group(world):
    home, root = world
    client = _Stdio(home, root)
    try:
        _drive(client, root)
    finally:
        rc = client.close()
    assert rc == 0


def test_happy_http_server_serves_every_group(world):
    home, root = world
    client = _Http(home, root)
    try:
        _drive(client, root)
    finally:
        client.close()


def test_sad_stdio_without_write_offers_no_mutating_group_tool(world):
    home, root = world
    proc = subprocess.run(
        [sys.executable, str(REPO / "main.py"), "--mcp-server", "--mcp-tools", "all",
         "--mcp-root", str(root)],
        input=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n",
        capture_output=True, text=True, timeout=TIMEOUT, env=_child_env(home), cwd=REPO,
    )
    assert proc.returncode == 0, proc.stderr
    tools = json.loads(proc.stdout.splitlines()[0])["result"]["tools"]
    names = {t["name"] for t in tools}
    assert "metadata_read" in names and "pack" not in names and "transfer_copy" not in names


def test_edge_the_child_environment_reaches_no_keyring(world):
    home, _ = world
    probe = (
        "from core import credentials as c; c._ensure_non_interactive_keyring(); "
        "print(c._keyring_usable)"
    )
    proc = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, timeout=TIMEOUT,
        env=_child_env(home), cwd=REPO,
    )
    assert proc.stdout.strip() == "False", proc.stderr


def test_edge_every_group_is_exercised_by_the_driver():
    import inspect

    source = inspect.getsource(_drive)
    for group in G.GROUPS:
        tools = {
            t.name for t in __import__("core.mcp_server", fromlist=["_build_tools"])._build_tools(
                __import__("core.local_fs", fromlist=["LocalFS"]).LocalFS(), allow_write=True,
                root=tempfile.gettempdir(), tool_groups=frozenset({group}), allow_exec=True,
            ) if t.group == group
        }
        assert any(f'"{name}"' in source for name in tools), group
