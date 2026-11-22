"""Fuzz: axross's own MCP server against a hostile client.

Three layers, each held to "answer or refuse, never die":

* the JSON-RPC dispatcher (``mcp_server._handle_request``) with
  structurally mutated requests - wrong types for id / method / params /
  _meta / arguments / requestId, absurd numbers, traversal paths;
* the stdio transport (``mcp_server.serve``) with byte-mutated request
  lines - it must answer every line and keep reading;
* the HTTP transport (``mcp_http``) with byte-mutated raw HTTP requests
  and a slow-loris client - every connection gets an answer or is closed,
  no handler thread dies with an exception, and the server stays up.

The tools run read-only against a temporary directory.
"""

from __future__ import annotations

import io
import json
import os
import random
import shutil
import socket
import sys
import tempfile
import threading
import time
import zlib
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from fuzz_testkit import iterations, mutants, run_bounded  # noqa: E402

from core import mcp_http  # noqa: E402
from core import mcp_server as M  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


@pytest.fixture(scope="module")
def root():
    tmp = Path(tempfile.mkdtemp()).resolve()
    (tmp / "a.txt").write_text("hello\n")
    (tmp / "sub").mkdir()
    (tmp / "sub" / "b.bin").write_bytes(b"\x00\xff" * 100)
    try:
        yield str(tmp)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


# -- dispatcher ---------------------------------------------------------------

_METHODS = [
    "initialize",
    "ping",
    "notifications/initialized",
    "notifications/cancelled",
    "tools/list",
    "tools/call",
    "logging/setLevel",
    "resources/list",
    "resources/read",
    "resources/templates/list",
    "tasks/start",
    "tasks/status",
    "tasks/cancel",
    "tasks/list",
    "completion/complete",
    "nope",
]
_PARAM_KEYS = [
    "name",
    "arguments",
    "_meta",
    "protocolVersion",
    "requestId",
    "level",
    "uri",
    "taskId",
    "cursor",
]
_ARG_KEYS = [
    "path",
    "pattern",
    "max_depth",
    "offset",
    "length",
    "encoding",
    "limit",
    "backend",
    "query",
    "recursive",
    "max_results",
    "algorithm",
    "version_id",
]


def _weird(root: str) -> list:
    return [
        None,
        True,
        0,
        -1,
        2**70,
        1.5,
        float("nan"),
        "",
        "\x00",
        "../../..",
        "/",
        root,
        root + "/a.txt",
        root + "/../../etc/passwd",
        "axross://" + root + "/a.txt",
        "\ud800",
        "x" * 5000,
        [],
        [1],
        {},
        {"a": {"b": [None]}},
    ]


def _random_request(rng: random.Random, names: list[str], weird: list) -> dict:
    req: dict = {"jsonrpc": rng.choice(["2.0", "2.0", "1.0", None])}
    req["method"] = rng.choice(_METHODS + weird[:8])
    if rng.random() < 0.85:
        params: object = {
            k: rng.choice(weird + names) for k in rng.sample(_PARAM_KEYS, rng.randint(0, 4))
        }
        if rng.random() < 0.6:
            params["name"] = rng.choice(names)
            args = {k: rng.choice(weird) for k in rng.sample(_ARG_KEYS, rng.randint(0, 4))}
            params["arguments"] = rng.choice([args, args, args, [], "x", None])
    else:
        params = rng.choice([None, [], "x", 1, [{}]])
    req["params"] = params
    if rng.random() < 0.9:
        req["id"] = rng.choice([1, "a", None, 1.5, True, [], {}, 2**70])
    return req


def test_sad_dispatcher_answers_every_mutated_request(root):
    tools = M._build_tools(LocalFS(), allow_write=False, root=root)
    names = [t.name for t in tools]
    resources = M._build_resources(LocalFS(), root=root)
    cancels, tasks, fwd = M._CancelRegistry(), M._TaskRegistry(), M._LogForwarder()
    weird = _weird(root)
    rng = random.Random(0x6D6370)
    for n in range(iterations(1500)):
        req = _random_request(rng, names, weird)

        def call(req=req):
            return M._handle_request(
                req,
                tools,
                cancels=cancels,
                resources=resources,
                log_forwarder=fwd,
                tasks=tasks,
                session_id="fuzz",
            )

        resp, exc = run_bounded(call, timeout=30.0)
        assert exc is None, f"request {n} {req!r:.300} raised {exc!r}"
        if resp is None:
            continue
        assert resp.get("jsonrpc") == "2.0"
        assert ("result" in resp) != ("error" in resp), resp
        json.dumps(resp)  # the transport must be able to send it


# Argument names of the capability-group tools (--mcp-tools all).
_GROUP_ARG_KEYS = [
    "path",
    "recursive",
    "max_files",
    "format",
    "out",
    "max_bytes",
    "use_file_command",
    "mismatches_only",
    "algorithm",
    "rehash",
    "scan_id",
    "max_groups",
    "dry_run",
    "prune",
    "folder",
    "names",
    "archive_name",
    "level",
    "password",
    "encrypt_names",
    "max_entries",
    "dest_dir",
    "passphrase",
    "src",
    "dst",
    "src_backend",
    "dst_backend",
    "overwrite",
    "resumable",
    "max_file_bytes",
    "profile",
    "backend",
    "ext_id",
    # 0.15.184: paging, the trash, the LLM profiles
    "offset",
    "max_scans",
    "max_results",
    "trash_id",
    "llm_profile",
]


def test_sad_group_tools_answer_every_malformed_call(tmp_path, monkeypatch):
    # Every tool of every group, mutating ones included, against arguments
    # of the wrong type, out of range, traversal paths and unknown keys:
    # each call is answered (result or JSON-RPC error), none kills the
    # dispatcher, and nothing is written outside the root.
    from core import credentials
    from core import mcp_groups as G

    monkeypatch.setattr(credentials, "_keyring_checked", True)
    monkeypatch.setattr(credentials, "_keyring_usable", False)
    from core import llm_profiles

    # agent_run finds no LLM profile: no fuzzed call reaches a model.
    monkeypatch.setattr(llm_profiles, "SETTINGS_FILE", tmp_path / "no-llm.json")
    outside = tmp_path  # a private parent: only this test writes here
    (tmp_path / "root" / "sub").mkdir(parents=True)
    (tmp_path / "root" / "a.txt").write_text("hello\n")
    (tmp_path / "root" / "sub" / "b.bin").write_bytes(b"\x00\xff" * 100)
    (tmp_path / "secret.txt").write_text("outside the root\n")
    root = str(tmp_path / "root")
    before = {p: p.stat().st_mtime_ns for p in tmp_path.iterdir()}
    tools = M._build_tools(
        LocalFS(), allow_write=True, root=root, tool_groups=frozenset(G.GROUPS)
    )
    names = [t.name for t in tools if t.group in G.GROUPS]
    weird = _weird(root) + [["a", "../x"], {"x": 1}, "profile:nope", "local", 0.0, -(2**31)]
    # Well-formed calls, one field of which is then mutated, so most
    # calls get past the schema and into the handlers.
    base = {
        "metadata_read": {"path": root},
        "metadata_export": {"path": root, "format": "csv"},
        "metadata_export_file": {"path": root, "out": root + "/m.json"},
        "metadata_remove": {"path": root + "/a.txt"},
        "duplicates_scan": {"path": root},
        "duplicates_scans": {"max_scans": 2, "offset": 1},
        "duplicates_groups": {"path": root, "max_groups": 2, "offset": 1},
        "duplicates_dedupe": {"path": root},
        "trash_list": {"max_results": 2, "offset": 0},
        "trash_restore": {"trash_id": "nope", "dst": root + "/back.txt"},
        "llm_profiles": {},
        "pack_formats": {},
        "pack": {"folder": root, "names": ["a.txt"], "archive_name": "fz"},
        "archive_list": {"path": root + "/a.txt"},
        "archive_extract": {"path": root + "/a.txt"},
        "encrypt": {"path": root + "/a.txt", "passphrase": "p"},
        "decrypt": {"path": root + "/a.txt", "passphrase": "p"},
        "index_build": {"path": root},
        "file_type": {"path": root + "/a.txt"},
        "file_type_scan": {"path": root},
        "transfer_copy": {"src": root + "/a.txt", "dst": root + "/sub/c.txt"},
        "transfer_move": {"src": root + "/sub/c.txt", "dst": root + "/c.txt"},
        "remote_profiles": {},
        "remote_open": {"profile": "nope"},
        "remote_close": {"backend": "profile:nope"},
        "list_backends": {},
        "extensions_list": {},
        "extensions_info": {"ext_id": "bundled:nope"},
        "agent_run": {"task": "summarise a.txt", "groups": ["filetype"], "llm_profile": "x"},
        # adb: no phone here, so each answers that the backend is none
        # (test_sad_adb_tools_answer_every_malformed_call drives a fake one).
        **{name: {"backend": "profile:phone", **args} for name, args in _ADB_BASE.items()},
    }
    assert set(names) <= set(base), sorted(set(names) - set(base))
    shaped = {
        str: [w for w in weird if isinstance(w, str)]
        + [root + "/sub", root + "/sub/b.bin", root + "/../" + os.path.basename(root) + "/a.txt"],
        list: [[], ["../x"], ["a.txt", "a.txt"], ["\x00"], ["x" * 300], ["sub"], [".."]],
    }
    rng = random.Random(0x67727073)
    cancels, tasks = M._CancelRegistry(), M._TaskRegistry()
    for n in range(iterations(600)):
        name = rng.choice(names)
        if rng.random() < 0.6:
            args = dict(base[name])
            key = rng.choice(list(args) or _GROUP_ARG_KEYS) if rng.random() < 0.7 else (
                rng.choice(_GROUP_ARG_KEYS)
            )
            if key in args and rng.random() < 0.15:
                del args[key]
            elif key in args and rng.random() < 0.8:
                # Same type, hostile value: gets past the schema's type check.
                args[key] = rng.choice(shaped.get(type(args[key]), weird))
            else:
                args[key] = rng.choice(weird)
        else:
            args = {k: rng.choice(weird) for k in rng.sample(_GROUP_ARG_KEYS, rng.randint(0, 5))}
        req = {
            "jsonrpc": "2.0",
            "id": n,
            "method": rng.choice(["tools/call", "tools/call", "tasks/start"]),
            "params": {"name": name, "arguments": args},
        }

        def call(req=req):
            return M._handle_request(req, tools, cancels=cancels, tasks=tasks, session_id="fz")

        resp, exc = run_bounded(call, timeout=30.0)
        assert exc is None, f"call {n} {req!r:.300} raised {exc!r}"
        assert resp is not None and resp.get("jsonrpc") == "2.0"
        assert ("result" in resp) != ("error" in resp), resp
        json.dumps(resp)
    deadline = time.monotonic() + 30
    while any(t.status == "running" for t in tasks.list_scope("fz")):
        assert time.monotonic() < deadline, "a fuzzed task never finished"
        time.sleep(0.05)
    after = {p: p.stat().st_mtime_ns for p in outside.iterdir()}
    assert set(after) == set(before), "a group tool wrote outside the root"
    secret = outside / "secret.txt"
    assert after[secret] == before[secret] and secret.read_text() == "outside the root\n"


# -- the file and write tools, with every mode and page -----------------------------

#: Argument names of the file and write tools (0.15.184's modes and pages too).
_FILE_ARG_KEYS = sorted({
    "path", "pattern", "max_depth", "max_entries", "max_matches", "offset", "include",
    "encoding", "max_bytes", "algorithm", "max_files", "max_file_bytes", "version_id",
    "content", "content_b64", "write_mode", "src", "dst", "overwrite", "recursive",
    "target", "link_path", "kind", "mode", "ext", "min_size", "max_size", "max_results",
    "path_b64", "src_b64", "dst_b64", "edge"})


class _VersionedFS(LocalFS):
    """The local disk with one older version of every file: restore_file_version
    and read_file_version reach their streaming code."""

    def list_versions(self, path):
        from models.file_version import FileVersion

        return [FileVersion(version_id="v1", size=3, is_current=False)]

    def open_version_read(self, path, version_id):
        if version_id != "v1":
            raise OSError(f"no version {version_id!r}")
        return io.BytesIO(b"old")


def test_sad_file_tools_answer_every_malformed_call(tmp_path):
    # The always-on and write tools - write_file's create / append /
    # at_offset, restore_file_version, create_link's kinds, the offsets of
    # walk_tree and search_content - against well-formed calls with one
    # field made hostile: each call is answered, a failure is a refusal or
    # an I/O error (never a TypeError, KeyError ... out of a handler), and
    # nothing outside the root changes.
    (tmp_path / "root" / "sub").mkdir(parents=True)
    (tmp_path / "root" / "a.txt").write_text("hello\n")
    (tmp_path / "root" / "sub" / "b.bin").write_bytes(b"\x00\xff" * 100)
    (tmp_path / "secret.txt").write_text("outside the root\n")
    root = str(tmp_path / "root")
    before = {p: p.stat().st_mtime_ns for p in tmp_path.iterdir()}
    tools = M._build_tools(_VersionedFS(), allow_write=True, root=root)
    names = sorted(t.name for t in tools)
    base = {
        "list_dir": {"path": root}, "stat": {"path": root + "/a.txt"},
        "read_file": {"path": root + "/a.txt", "offset": 1, "encoding": "text"},
        "checksum": {"path": root + "/a.txt"}, "search": {"pattern": "a", "offset": 1},
        "walk": {"path": root, "max_entries": 2, "offset": 1},
        "recursive_checksum": {"path": root, "max_files": 2},
        "preview": {"path": root + "/a.txt"},
        "grep": {"pattern": "h", "path": root, "max_matches": 1, "offset": 1},
        "list_versions": {"path": root + "/a.txt"},
        "open_version_read": {"path": root + "/a.txt", "version_id": "v1"},
        "write_file": {"path": root + "/w.txt", "content": "x", "write_mode": "replace"},
        "write_file:create": {"path": root + "/n.txt", "content": "x", "write_mode": "create"},
        "write_file:append": {"path": root + "/a.txt", "content": "x", "write_mode": "append"},
        "write_file:at_offset": {"path": root + "/a.txt", "content_b64": "eA==",
                                 "write_mode": "at_offset", "offset": 2},
        "restore_version": {"path": root + "/a.txt", "version_id": "v1"},
        "mkdir": {"path": root + "/d"}, "remove": {"path": root + "/w.txt"},
        "rename": {"src": root + "/n.txt", "dst": root + "/m.txt"},
        "copy": {"src": root + "/a.txt", "dst": root + "/c.txt"},
        "bulk_copy": {"src": root + "/sub", "dst": root + "/sub2"},
        "symlink": {"target": "a.txt", "link_path": root + "/s"},
        "symlink:hard": {"target": root + "/a.txt", "link_path": root + "/h", "kind": "hard"},
        "chmod": {"path": root + "/a.txt", "mode": "640"},
    }
    calls = sorted(base)
    assert set(names) <= {c.split(":")[0] for c in calls}, sorted(set(names) - set(base))
    weird = _weird(root) + ["create", "append", "at_offset", "hard", "symbolic", "v9",
                            root + "/../" + os.path.basename(root) + "/a.txt", 10**12,
                            MAX := M.MAX_WALK_OFFSET, MAX + 1]
    allowed = {"ValueError", "OSError", "PermissionError", "FileNotFoundError",
               "FileExistsError", "IsADirectoryError", "NotADirectoryError", "TimeoutError",
               "PreviewNotAvailable", "PreviewTooLarge", "PreviewDecodeFailed", "CancelledError",
               "UnicodeEncodeError", "OverflowError", "ValidationError", "RemoteNameError"}
    rng = random.Random(0x66696C65)
    cancels = M._CancelRegistry()
    seen: set = set()
    for n in range(iterations(900)):
        call = calls[n % len(calls)] if n < len(calls) * 3 else rng.choice(calls)
        name, args = call.split(":")[0], dict(base[call])
        if n >= len(calls) and rng.random() < 0.8:
            key = rng.choice(list(args) if rng.random() < 0.6 else _FILE_ARG_KEYS)
            if key in args and rng.random() < 0.15:
                del args[key]
            else:
                args[key] = rng.choice(weird)
        req = {"jsonrpc": "2.0", "id": n, "method": "tools/call",
               "params": {"name": name, "arguments": args}}
        resp, exc = run_bounded(lambda req=req: M._handle_request(
            req, tools, cancels=cancels, protocol=M.ProtocolState("2025-11-25"),
            session_id="ff"), timeout=30.0)
        assert exc is None, f"call {n} {req!r:.300} raised {exc!r}"
        assert resp is not None and ("result" in resp) != ("error" in resp), resp
        json.dumps(resp)
        result = resp.get("result") or {}
        if result.get("isError"):
            kind = (result.get("_meta") or {}).get("type")
            seen.add(kind)
            assert kind in allowed, f"call {n} {req!r:.300}: {result['content'][0]['text'][:300]}"
    # A fuzzed set_permissions may have closed a folder to its owner: open
    # the root again, so the comparison below and pytest's clean-up see it.
    for folder, dirs, _files in os.walk(root):
        for d in dirs:
            try:
                os.chmod(os.path.join(folder, d), 0o700, follow_symlinks=False)
            except (OSError, NotImplementedError):
                pass
    after = {p: p.stat().st_mtime_ns for p in tmp_path.iterdir()}
    assert set(after) == set(before), "a file tool wrote outside the root"
    assert (tmp_path / "secret.txt").read_text() == "outside the root\n"


# -- the adb group against a phone that answers garbage --------------------------

#: A well-formed call of each adb tool (the backend added where it is used).
_ADB_BASE = {
    "get_device_info": {}, "list_device_properties": {"filter": "ro.*"},
    "get_battery_status": {}, "list_apps": {"kind": "user", "match": "notes"},
    "get_app_info": {"package": "org.x"}, "list_running_apps": {},
    "get_logcat": {"max_lines": 5, "tag": "Notes"}, "take_screenshot": {},
    "list_sms": {"box": "inbox", "max_results": 3}, "start_app": {"package": "org.x"},
    "stop_app": {"package": "org.x"}, "install_app": {"path": "a.apk"},
    "uninstall_app": {"package": "org.x"}, "export_app": {"package": "org.x"},
    "grant_permission": {"package": "org.x", "permission": "android.permission.CAMERA"},
    "revoke_permission": {"package": "org.x", "permission": "android.permission.CAMERA"},
    "reboot_device": {"mode": "recovery"}, "write_sms": {"address": "Bank", "body": "a\nb"},
    "compose_sms": {"number": "+4915112345678", "text": "x"},
    "send_at_command": {"command": "AT+CSQ", "timeout": 1},
}
_ADB_ARG_KEYS = sorted({k for args in _ADB_BASE.values() for k in args}
                       | {"activity", "replace", "keep_data", "out", "offset", "max_body", "read",
                          "date_ms", "device", "min_priority", "buffer", "state", "max_results",
                          "grant_permissions", "allow_downgrade", "allow_test_only", "backend"})


def _device_garbage(rng: random.Random) -> list:
    """What a hostile or broken phone might answer to any command."""
    from tests.test_adb_device import parcel

    digits = "0123456789\u0661\u0662\u00b2\uff11"
    return [
        "", "\n", "\x00\xff", "Error: x", "Exception occurred\njava.lang.SecurityException: no",
        "package:", "package:org.x versionCode:\u00b2 uid:-1 installer=", "package:" + "a." * 200,
        "[ro.x]: [", "[ro.x]: [y]\n[ro.a]: [b\n", "Row: 0 _id=", "Row: 0 _id=\u0661",
        "Row: 0 _id=1, thread_id=, date=x, date_sent=-5, read=1, type=\u00b2, address=, body=",
        "Row: 0 _id=1, thread_id=1, date=99999999999999999999, date_sent=0, read=1, type=9, "
        "address=a, body=b, body=c", "No result found.", parcel("x" * 70), parcel("", code=7),
        "Result: Parcel(\n  0x00000000: ffffffff ffffffff '....')", "AXDEV /dev/smd11",
        "AXDEV /dev/../etc", "AXAT_DONE", "AXAT_NOACCESS", "Success", "Failure [", "Failure [X: y]",
        "PID USER RSS NAME\nx y z w\n-1 a b org.x", "USER PID\n", "  level: \u00b2\n  scale: 0",
        "  level: 5\n  scale: 0\n  temperature: -\u0661", "Packages:\n  Package [org.x] (1):\n"
        "    versionCode=\u00b2 minSdk= targetSdk=\n    flags=[\n    requested permissions:\n",
        "  topResumedActivity=ActivityRecord{x u0 org.x/", "\u202e" * 50 + "\U000e0041" * 50,
        "x" * 300_000, "".join(rng.choice(digits + "abc:=[], \n") for _ in range(400)),
    ]


def test_sad_adb_tools_answer_every_malformed_call(tmp_path, monkeypatch):
    # Every adb tool, against malformed arguments and against a phone whose
    # every answer is garbage: each call is answered, a failure is a
    # refusal or an I/O error - never a TypeError, KeyError, IndexError or
    # the like out of a parser - and nothing is written outside the root.
    from core import mcp_groups as G
    from tests.fake_android import tiny_png
    from tests.test_adb_device import AdbSession, FakeShell, _profile

    root = tmp_path / "root"
    root.mkdir()
    (root / "a.apk").write_bytes(b"PK\x03\x04apk")
    (tmp_path / "secret.txt").write_text("outside the root\n")
    before = {p: p.stat().st_mtime_ns for p in tmp_path.iterdir()}
    rng = random.Random(0x616462)
    garbage = _device_garbage(rng)

    class Shell(FakeShell):
        def exec(self, command, *, timeout, stdout_cap):
            out = rng.choice(garbage)
            return type("R", (), {"returncode": rng.choice([0, 0, 1, 127]),
                                  "stdout": out.encode("utf-8", "surrogatepass")[:stdout_cap],
                                  "truncated_stdout": False})()

        def pull_stream(self, remote_path, sink, max_bytes):
            sink.write(rng.choice([b"", b"PK\x03\x04", tiny_png(), b"\x89PNG\r\n\x1a\nIHDR"]))

    registry = G.RemoteRegistry()
    registry.attach("profile:phone", AdbSession(Shell([])), _profile())
    tools = M._build_tools(LocalFS(), allow_write=True, root=str(root),
                           tool_groups=frozenset({"remote", "adb"}), remote_registry=registry)
    names = sorted(t.name for t in tools if t.group == "adb")
    assert set(names) == set(_ADB_BASE), sorted(set(names) ^ set(_ADB_BASE))
    weird = _weird(str(root)) + ["com.x;id", "AT;ATD1", "/dev/smd11", "\u0661", "a" * 300]
    allowed = {"ValueError", "DeviceRefused", "OSError", "PermissionError", "TimeoutError",
               "InterruptedError", "FileNotFoundError", "IsADirectoryError", "NotADirectoryError",
               "FileExistsError", "ConnectionResetError"}
    seen_types = set()
    outcomes: list[str] = []
    cancels = M._CancelRegistry()
    for n in range(iterations(800)):
        name = names[n % len(names)] if n < len(names) * 3 else rng.choice(names)
        args = {"backend": "profile:phone", **_ADB_BASE[name]}
        if rng.random() < 0.7:
            key = rng.choice(list(args) if rng.random() < 0.7 else _ADB_ARG_KEYS)
            if key != "backend" or rng.random() < 0.1:
                args[key] = rng.choice(weird)
        req = {"jsonrpc": "2.0", "id": n, "method": "tools/call",
               "params": {"name": name, "arguments": args}}
        resp, exc = run_bounded(lambda req=req: M._handle_request(req, tools, cancels=cancels,
                                                                  session_id=""), timeout=30.0)
        assert exc is None, f"call {n} {req!r:.300} raised {exc!r}"
        assert resp is not None and ("result" in resp) != ("error" in resp), resp
        json.dumps(resp)
        result = resp.get("result") or {}
        outcomes.append("error" if "error" in resp else "refused" if result.get("isError") else "ok")
        if result.get("isError"):
            kind = (result.get("_meta") or {}).get("type")
            seen_types.add(kind)
            assert kind in allowed, f"call {n} {req!r:.300}: {result['content'][0]['text'][:300]}"
    # The garbage reaches the parsers: some calls even succeed on it.
    assert outcomes.count("ok") > 20 and outcomes.count("refused") > 20, (
        outcomes.count("ok"), outcomes.count("refused"), outcomes.count("error"))
    assert "DeviceRefused" in seen_types or "ValueError" in seen_types
    after = {p: p.stat().st_mtime_ns for p in tmp_path.iterdir()}
    assert set(after) == set(before), "an adb tool wrote outside the root"
    assert (tmp_path / "secret.txt").read_text() == "outside the root\n"


# -- stdio transport ----------------------------------------------------------

_LINES = [
    b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26"}}',
    b'{"jsonrpc":"2.0","id":2,"method":"tools/list"}',
    b'{"jsonrpc":"2.0","id":"x","method":"tools/call","params":'
    b'{"name":"list_dir","arguments":{"path":"ROOT"},"_meta":{"progressToken":1}}}',
    b'{"jsonrpc":"2.0","id":4,"method":"tools/call","params":'
    b'{"name":"read_file","arguments":{"path":"ROOT/a.txt","length":3}}}',
    b'{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":4}}',
    b'{"jsonrpc":"2.0","id":6,"method":"resources/read","params":{"uri":"axross://ROOT/a.txt"}}',
]
_SENTINEL = b'{"jsonrpc":"2.0","id":"sentinel","method":"ping"}'


def _stdio_corpus(root: str) -> list[bytes]:
    return [line.replace(b"ROOT", root.encode()) for line in _LINES]


def test_happy_stdio_corpus(root):
    data = b"\n".join(_stdio_corpus(root) + [_SENTINEL]) + b"\n"
    out = io.StringIO()
    stdin = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")
    cfg = M.ServerConfig(backend=LocalFS(), root=root, stdin=stdin, stdout=out)
    assert M.serve(cfg) == 0
    answers = [json.loads(x) for x in out.getvalue().splitlines()]
    assert all("result" in a for a in answers if a.get("id") is not None), answers
    # Tool calls and resources/read run on workers (round 2 of the MCP
    # review): the ping can be answered before them; the server read on to
    # the end and answered it.
    assert "sentinel" in [a.get("id") for a in answers]


def test_sad_stdio_survives_mutated_lines(root):
    lines = list(mutants(_stdio_corpus(root), seed=0x5354, per_entry=iterations(100)))
    data = b"\n".join(lines + [_SENTINEL]) + b"\n"
    out = io.StringIO()
    stdin = io.TextIOWrapper(io.BytesIO(data), encoding="utf-8")
    cfg = M.ServerConfig(
        backend=LocalFS(), root=root, stdin=stdin, stdout=out, rate_limit_enabled=False
    )
    rc, exc = run_bounded(lambda: M.serve(cfg), timeout=120.0)
    assert exc is None, f"serve() died: {exc!r}"
    assert rc == 0
    answers = [json.loads(x) for x in out.getvalue().splitlines() if x.strip()]
    assert answers and "sentinel" in [a.get("id") for a in answers], answers[-3:]


# -- HTTP transport -----------------------------------------------------------


@pytest.fixture
def http_server(root):
    config = mcp_http.HTTPServerConfig(
        backend=LocalFS(),
        host="127.0.0.1",
        port=0,
        root=root,
        rate_limit_enabled=False,
        http_ip_rate_enabled=False,
        auth_token=_HTTP_TOKEN,
    )
    server = mcp_http.build_server(config)
    crashes: list[str] = []

    def record(request, client_address):  # replaces the stderr traceback
        import traceback

        crashes.append(traceback.format_exc())

    server.handle_error = record
    server.RequestHandlerClass.timeout = 2.0
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1], crashes
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _exchange(port: int, raw: bytes, timeout: float = 10.0) -> bytes:
    with socket.create_connection(("127.0.0.1", port), timeout=timeout) as s:
        try:
            s.sendall(raw)
            s.shutdown(socket.SHUT_WR)
        except OSError:
            pass  # the server may answer and close before reading it all
        data = b""
        try:
            while chunk := s.recv(65536):
                data += chunk
        except ConnectionResetError:
            pass
    # An interim 100 Continue is how the server asks a half-closed client
    # (this one shuts its sending side) whether it is still there; a
    # client skips it (round 4/5 of the MCP review).
    while data.startswith(b"HTTP/1.1 100 "):
        data = data.split(b"\r\n\r\n", 1)[1]
    return data


# A plain-HTTP server demands a bearer token; the fuzz requests carry it
# so that their bodies and headers reach the parser behind the check.
_HTTP_TOKEN = "fuzz-test-token-0123456789abcdef"


def _http(method: str, path: str, body: bytes = b"", headers: bytes = b"") -> bytes:
    return (
        f"{method} {path} HTTP/1.1\r\nHost: 127.0.0.1\r\n".encode()
        + f"Authorization: Bearer {_HTTP_TOKEN}\r\n".encode()
        + headers
        + (b"Content-Type: application/json\r\nContent-Length: %d\r\n" % len(body) if body else b"")
        + b"\r\n"
        + body
    )


def _http_corpus(root: str) -> list[bytes]:
    init = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
    return [
        _http("POST", "/messages", init),
        _http("GET", "/health"),
        _http("GET", "/messages", headers=b"Accept: text/event-stream\r\nMcp-Session-Id: x\r\n"),
        _http("DELETE", "/messages", headers=b"Mcp-Session-Id: abc\r\n"),
        _http("POST", "/messages", _stdio_corpus(root)[1], headers=b"Mcp-Session-Id: abc\r\n"),
    ]


def _health_ok(port: int) -> bool:
    return _exchange(port, _http("GET", "/health")).startswith(b"HTTP/1.0 200 ")


def test_happy_http_corpus(http_server, root):
    port, crashes = http_server
    for raw in _http_corpus(root):
        assert _exchange(port, raw).startswith(b"HTTP/1.0 "), raw[:60]
    assert not crashes


def test_sad_http_survives_mutated_requests(http_server, root):
    port, crashes = http_server
    corpus = _http_corpus(root)
    for n, raw in enumerate(mutants(corpus, seed=0x48545450, per_entry=iterations(150))):
        answer, exc = run_bounded(lambda raw=raw: _exchange(port, raw), timeout=15.0)
        assert exc is None or isinstance(exc, OSError), f"mutant {n}: {exc!r}"
        request_line = raw.split(b"\n", 1)[0]
        if answer and b" HTTP/" in request_line:
            # (a request line without a version is HTTP/0.9: the stdlib
            # answers it with a bare body, as the protocol says)
            assert answer.startswith(b"HTTP/"), f"mutant {n} {raw[:80]!r}: {answer[:80]!r}"
    time.sleep(0.2)  # let the last handler thread finish
    assert not crashes, crashes[0]
    assert _health_ok(port)


@pytest.mark.parametrize("line, status", [
    (b"POST /messages HTTP/1.", b"400"),
    (b"POST0/messages HTTP/1.1", b"400"),
    (b"POST /messages HTTP/2.0", b"505"),
    (b"POST /messages", b"400"),
])
def test_sad_a_request_line_the_stdlib_cannot_parse_gets_a_status_line(
        http_server, line, status):
    """Python 3.11 left request_version at HTTP/0.9 for a request line it
    could not parse and sent the error as a bare HTML body: a client that
    spoke HTTP/1.x read no status line. Only "GET <path>" is HTTP/0.9."""
    port, crashes = http_server
    answer = _exchange(port, line + b"\r\nHost: 127.0.0.1\r\n\r\n")
    assert answer.startswith(b"HTTP/1.0 " + status + b" "), answer[:80]
    assert not _exchange(port, b"GET /health\r\n").startswith(b"HTTP/")
    assert not crashes


def test_sad_http_mutated_bodies_in_a_live_session(http_server, root):
    port, crashes = http_server
    init = b'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
    answer = _exchange(port, _http("POST", "/messages", init))
    head = answer.split(b"\r\n\r\n", 1)[0].decode("latin-1")
    sid = next(
        line.split(":", 1)[1].strip()
        for line in head.split("\r\n")
        if line.lower().startswith("mcp-session-id:")
    )
    hdr = f"Mcp-Session-Id: {sid}\r\n".encode()
    seed = zlib.crc32(b"session-bodies")
    for n, body in enumerate(mutants(_stdio_corpus(root), seed=seed, per_entry=iterations(60))):
        if not body:
            continue
        raw = _http("POST", "/messages", body, headers=hdr)
        answer, exc = run_bounded(lambda raw=raw: _exchange(port, raw), timeout=40.0)
        assert exc is None, f"body {n} {body[:80]!r}: {exc!r}"
        assert answer.startswith(b"HTTP/1.0 "), f"body {n} {body[:80]!r}: {answer[:80]!r}"
    time.sleep(0.2)
    assert not crashes, crashes[0]
    assert _health_ok(port)


def test_edge_http_slow_loris_does_not_block_others(http_server):
    port, crashes = http_server
    slow = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        slow.sendall(b"POST /messages HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Le")
        assert _health_ok(port)  # served while the slow client hangs
        started = time.monotonic()
        rest = b""
        try:
            while chunk := slow.recv(4096):
                rest += chunk
        except OSError:
            pass
        # The server drops it after its connection timeout (2 s here).
        assert time.monotonic() - started < 8.0
    finally:
        slow.close()
    assert not crashes
