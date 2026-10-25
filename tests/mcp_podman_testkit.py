"""A stand-in for ``podman`` in the MCP install tests (tests/test_mcp_install.py,
tests/test_mcp_catalog_dialog.py): a Python program on PATH that keeps its
state in a JSON file, logs every call, and for ``podman run`` of a server
acts as a small MCP server that reports the environment file it was given.

``fake_podman(tmp_path, monkeypatch, **state)`` installs it and returns a
:class:`FakePodman` to read the log and change the state."""

from __future__ import annotations

import json
import os
import stat
import sys
import textwrap
from pathlib import Path

SCRIPT = textwrap.dedent('''
    import fcntl, hashlib, json, os, sys, time
    STATE = __STATE__

    def load():
        with open(STATE) as f:
            return json.load(f)

    def save(state):
        tmp = STATE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, STATE)

    def locked(update):
        with open(STATE + ".lock", "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            state = load()
            out = update(state)
            save(state)
            return out

    argv = sys.argv[1:]
    locked(lambda s: s["log"].append(argv))
    state = load()
    cmd = argv[0] if argv else ""

    def find(state, ref):
        for img in state["images"].values():
            if ref in (img["Id"], img["Id"][:12]) or ref in img["Names"] \\
                    or ref in img["RepoDigests"]:
                return img
        return None

    def fail(kind):
        msg = state["fail"].get(kind)
        if msg:
            sys.stderr.write(msg + "\\n")
            sys.exit(125)

    if cmd == "info":
        print("true" if state.get("rootless", True) else "false")
    elif cmd == "images":
        print(json.dumps(list(state["images"].values())))
    elif cmd == "image" and argv[1] == "inspect":
        img = find(state, argv[-1])
        if img is None:
            sys.stderr.write(f"Error: {argv[-1]}: image not known\\n")
            sys.exit(125)
        print(json.dumps([img]))
    elif cmd == "pull":
        ref = argv[-1]
        hang = state["hang"].get("pull")
        if hang:
            time.sleep(hang)
        fail("pull")
        for n in (1, 2):
            sys.stderr.write(f"Copying blob {n} of 2\\n")
            sys.stderr.flush()
        name, _, digest = ref.partition("@")
        if not digest:
            digest = "sha256:" + hashlib.sha256(ref.encode()).hexdigest()
            name = name.rsplit(":", 1)[0] if ":" in name.rsplit("/", 1)[-1] else name
        ident = hashlib.sha256(("img" + name + digest).encode()).hexdigest()
        def add(s):
            s["images"][ident] = {"Id": ident, "Names": [ref], "Digest": digest,
                                  "RepoDigests": [f"{name}@{digest}"], "RepoTags": []}
        locked(add)
        print(ident)
    elif cmd == "rmi":
        fail("rmi")
        ref = argv[-1]
        img = find(state, ref)
        if img is None:
            sys.stderr.write(f"Error: {ref}: image not known\\n")
            sys.exit(1)
        locked(lambda s: s["images"].pop(img["Id"]))
        print("Deleted: " + img["Id"])
    elif cmd == "commit":
        target = argv[-1]
        fail("commit")
        ident = hashlib.sha256(("commit" + target).encode()).hexdigest()
        def add(s):
            s["images"][ident] = {"Id": ident, "Names": [target], "Digest": "",
                                  "RepoDigests": [], "RepoTags": [target]}
        locked(add)
        print(ident)
    elif cmd == "rm":
        pass
    elif cmd == "run" and any(a.startswith("--name=axross-mcp-install-") for a in argv):
        sys.stderr.write("added 3 packages\\n")
        fail("build")
        print("some output")
        if state.get("entry_line"):
            print(state["entry_line"])
    elif cmd == "run":
        envfile = ""
        for a in argv:
            if a.startswith("--env-file="):
                with open(a.split("=", 1)[1]) as f:
                    envfile = f.read()
        secret_in_env = any("s3cr3t" in v for v in os.environ.values())
        locked(lambda s: s["envfiles"].append(envfile))
        mode = state.get("server_mode", "normal")
        if mode == "stuck":
            import signal
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        def send(m):
            sys.stdout.write(json.dumps(m) + "\\n"); sys.stdout.flush()
        for line in sys.stdin:
            m = json.loads(line)
            if "id" not in m:
                continue
            meth, i = m.get("method"), m["id"]
            if meth == "initialize":
                send({"jsonrpc": "2.0", "id": i, "result": {"protocolVersion": "2024-11-05",
                      "capabilities": {"tools": {}},
                      "serverInfo": {"name": "fake-podman", "version": "1"}}})
            elif meth == "tools/list":
                send({"jsonrpc": "2.0", "id": i, "result": {"tools": [
                    {"name": "env", "inputSchema": {"type": "object"},
                     "annotations": {"readOnlyHint": True}}]}})
            elif meth == "tools/call":
                text = json.dumps({"envfile": envfile, "secret_in_env": secret_in_env})
                send({"jsonrpc": "2.0", "id": i,
                      "result": {"content": [{"type": "text", "text": text}]}})
        while mode == "stuck":
            time.sleep(1)
    else:
        sys.stderr.write("fake podman: unknown command " + " ".join(argv) + "\\n")
        sys.exit(2)
''')


class FakePodman:
    def __init__(self, folder: Path) -> None:
        self.folder = folder
        self.state_file = folder / "state.json"

    @property
    def state(self) -> dict:
        return json.loads(self.state_file.read_text())

    def update(self, **changes) -> None:
        state = self.state
        for key, value in changes.items():
            if isinstance(value, dict) and isinstance(state.get(key), dict):
                state[key].update(value)
            else:
                state[key] = value
        self.state_file.write_text(json.dumps(state))

    def log(self) -> list[list[str]]:
        return self.state["log"]

    def calls(self, command: str) -> list[list[str]]:
        return [argv for argv in self.log() if argv and argv[0] == command]

    def add_image(self, ident: str, names: list[str], digests: list[str] = ()) -> None:
        state = self.state
        state["images"][ident] = {"Id": ident, "Names": list(names), "Digest": "",
                                  "RepoDigests": list(digests), "RepoTags": []}
        self.state_file.write_text(json.dumps(state))


def fake_podman(tmp_path: Path, monkeypatch, **state) -> FakePodman:
    folder = tmp_path / "fakepodman"
    folder.mkdir()
    program = folder / "podman"
    # The state's path is written into the program: a container server's
    # podman gets only named variables of the environment (core.mcp_client).
    program.write_text(f"#!{sys.executable}\n"
                       + SCRIPT.replace("__STATE__", repr(str(folder / "state.json"))))
    program.chmod(program.stat().st_mode | stat.S_IXUSR)
    initial = {"images": {}, "log": [], "fail": {}, "hang": {}, "envfiles": [],
               "entry_line": "", "rootless": True}
    initial.update(state)
    (folder / "state.json").write_text(json.dumps(initial))
    monkeypatch.setenv("PATH", f"{folder}{os.pathsep}{os.environ.get('PATH', '')}")
    return FakePodman(folder)
