"""Measure axross's non-GUI services: counts first, CPU time second.

Usage: python scripts/services_bench.py [--only NAME[,NAME]] [--json OUT] [--tree DIR]

Scenarios (each prints CPU milliseconds and the counts that explain them):

* ``tags_toggle``    - FilePaneWidget.toggle_tag on 3000 selected files
                       (on, then off again): tags.json writes and CPU.
* ``visit_record``   - core.visit_history.record_visit with a full history
                       (200 hosts x 20 operations, ~0.5 MB): reads and
                       writes of the file and CPU per call - what every
                       mutating scripting call on a profile's backend pays.
* ``mcp_grep``       - the MCP / agent ``grep`` tool over 5000 small files
                       below a root five folders deep: realpath() calls
                       and CPU.
* ``mcp_search``     - the MCP / agent ``search`` tool answering 5000 index
                       rows: realpath() calls and CPU.
* ``mcp_call``       - one MCP / agent ``stat`` call (the tool's own work is
                       a stat): CPU per call and how often a tool schema is
                       checked against its metaschema.
* ``profiles_keyring`` - keyring lookups of 30 saved profiles for
                       ProfileManager(), axross.list_profiles() and
                       axross.get_profile(name) - a D-Bus round trip each
                       with the Secret Service.

Everything runs in a temporary HOME (no real settings, history, tags or
keyring are read or written). ``--tree`` imports axross from another
checkout (an old version extracted with ``git archive``) for an A/B; the
script checks that the modules really come from there. Compare minima of
alternating runs: CPU time still moves with the host's load, the counts
do not.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


def _check_origin(module, tree: str) -> None:
    if not Path(module.__file__).resolve().is_relative_to(Path(tree).resolve()):
        raise SystemExit(f"{module.__name__} came from {module.__file__}, not from {tree}")


def _cpu_ms(fn) -> float:
    started = time.process_time()
    fn()
    return (time.process_time() - started) * 1000


# -- scenarios --------------------------------------------------------------------------------


def bench_tags_toggle(args, work: Path, record) -> None:
    import types

    from core import tags as T

    _check_origin(T, args.tree)
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from ui.file_pane import FilePaneWidget

    _check_origin(sys.modules["ui.file_pane"], args.tree)
    path = work / "tags.json"
    with mock.patch.object(T, "tags_file", lambda: path):
        T.reset_cache()
        store = T.store()
        paths = [f"/srv/case/evidence/file{i:05d}.bin" for i in range(args.tags)]
        pane = types.SimpleNamespace(
            selected_items=lambda: list(paths), _backend=types.SimpleNamespace(name="Local"),
            profile_name="", _tags_changed=lambda: None)
        writes = [0]
        save = T.TagStore._save

        def counted(self):
            writes[0] += 1
            save(self)

        with mock.patch.object(T.TagStore, "_save", counted):
            record("tags_toggle_on_cpu_ms", _cpu_ms(lambda: FilePaneWidget.toggle_tag(pane, "Important")))
            record("tags_toggle_on_writes", writes[0])
            assert len(store.items_with("Important")) == len(paths)
            writes[0] = 0
            record("tags_toggle_off_cpu_ms", _cpu_ms(lambda: FilePaneWidget.toggle_tag(pane, "Important")))
            record("tags_toggle_off_writes", writes[0])
            assert store.items_with("Important") == []
        T.reset_cache()


def bench_visit_record(args, work: Path, record) -> None:
    from core import visit_history as V

    _check_origin(V, args.tree)
    history = work / "visit_history.json"
    with mock.patch.object(V, "CONFIG_DIR", work), mock.patch.object(V, "HISTORY_FILE", history):
        payload = [{
            "protocol": "sftp", "host": f"host{h}.example", "username": "alice",
            "last_path": f"/var/log/app{h}", "last_seen": 1_700_000_000.0 + h, "visit_count": 20,
            "recent_ops": [{"ts": 1_700_000_000.0 + h, "verb": "copy",
                            "desc": f"copy /srv/data/file{k}.txt"} for k in range(20)],
        } for h in range(200)]
        history.write_text(json.dumps(payload, indent=2))
        reads = [0]
        read_text = Path.read_text

        def counted_read(self, *a, **kw):
            if self.name == "visit_history.json":
                reads[0] += 1
            return read_text(self, *a, **kw)

        replaced = [0]
        replace = os.replace

        def counted_replace(src, dst, *a, **kw):
            if str(dst).endswith("visit_history.json"):
                replaced[0] += 1
            return replace(src, dst, *a, **kw)

        calls = args.visits
        with mock.patch.object(Path, "read_text", counted_read), \
                mock.patch("os.replace", counted_replace):
            cost = _cpu_ms(lambda: [V.record_visit("sftp", "host7.example", "alice",
                                                   path=f"/srv/f{i}", verb="copy",
                                                   desc=f"copy f{i}") for i in range(calls)])
        record("visit_record_cpu_ms_per_call", cost / calls)
        record("visit_record_reads_per_call", reads[0] / calls)
        record("visit_record_writes_per_call", replaced[0] / calls)
        record("visit_file_kb", history.stat().st_size / 1024)


def _mcp_tools(args, root: str):
    from core.backend_registry import init_registry

    init_registry()
    from core import mcp_server as M
    from core.local_fs import LocalFS

    _check_origin(M, args.tree)
    return M, M._build_tools(LocalFS(), allow_write=False, root=root)


def _counting_realpath():
    import os.path as op

    count = [0]
    realpath = op.realpath

    def counted(path, *a, **kw):
        count[0] += 1
        return realpath(path, *a, **kw)

    return count, mock.patch("os.path.realpath", counted)


def bench_mcp_grep(args, work: Path, record) -> None:
    root = work / "a" / "b" / "c" / "d" / "root"
    big = root / "big"
    big.mkdir(parents=True)
    for i in range(args.files):
        (big / f"f{i:05d}.txt").write_text("hello world line\n" * 20)
    M, tools = _mcp_tools(args, str(root))

    def call():
        response = M._handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "grep", "arguments": {"path": str(big), "pattern": "nomatch",
                                                       "max_depth": 1}}},
            tools, cancels=M._CancelRegistry())
        assert "error" not in response, response
        assert json.loads(response["result"]["content"][0]["text"])["files_scanned"] == args.files

    call()  # warm the page cache and the imports
    count, patch = _counting_realpath()
    with patch:
        record("mcp_grep_cpu_ms", _cpu_ms(call))
    record("mcp_grep_realpath_calls", count[0])


def bench_mcp_search(args, work: Path, record) -> None:
    root = work / "a" / "b" / "c" / "d" / "root"
    root.mkdir(parents=True)
    M, tools = _mcp_tools(args, str(root))
    from core import metadata_index as MX

    from datetime import datetime

    now = datetime.now()
    rows = [MX.MetaEntry(backend_id="x", path=f"{root}/dir{i % 50}/file{i:05d}.log",
                         name=f"file{i:05d}.log", size=i, is_dir=False, extension=".log",
                         modified=None, indexed_at=now)
            for i in range(args.files)]

    def call():
        response = M._handle_request(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
             "params": {"name": "search", "arguments": {"needle": "file"}}},
            tools, cancels=M._CancelRegistry())
        assert "error" not in response, response
        assert len(json.loads(response["result"]["content"][0]["text"])) == args.files

    with mock.patch.object(MX, "search_all", lambda **kw: list(rows)):
        call()
        count, patch = _counting_realpath()
        with patch:
            record("mcp_search_cpu_ms", _cpu_ms(call))
    record("mcp_search_realpath_calls", count[0])


def bench_mcp_call(args, work: Path, record) -> None:
    M, tools = _mcp_tools(args, str(work))
    jsonschema = M.jsonschema
    request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
               "params": {"name": "stat", "arguments": {"path": str(work)}}}
    for _ in range(5):
        assert "error" not in M._handle_request(request, tools, cancels=M._CancelRegistry())
    checks = [0]
    cls = jsonschema.validators.Draft202012Validator
    check = cls.check_schema.__func__

    def counted(klass, schema, *a, **kw):
        checks[0] += 1
        return check(klass, schema, *a, **kw)

    calls = args.calls
    with mock.patch.object(cls, "check_schema", classmethod(counted)):
        cost = _cpu_ms(lambda: [M._handle_request(request, tools, cancels=M._CancelRegistry())
                                for _ in range(calls)])
    record("mcp_call_cpu_ms_per_call", cost / calls)
    record("mcp_call_schema_checks", checks[0])


def bench_profiles_keyring(args, work: Path, record) -> None:
    from core import credentials as CR
    from core import profiles as P
    from core import scripting

    _check_origin(P, args.tree)
    file = work / "profiles.json"
    data = {f"host{i:02d}": P.ConnectionProfile(name=f"host{i:02d}", protocol="sftp",
                                                host=f"10.0.0.{i}").to_dict()
            for i in range(args.profiles)}
    file.write_text(json.dumps(data, indent=2))
    lookups = [0]

    def get_password(_entry):
        lookups[0] += 1
        return None

    with mock.patch.object(P, "CONFIG_DIR", work), mock.patch.object(P, "PROFILES_FILE", file), \
            mock.patch.object(CR, "get_password", get_password):
        manager = P.ProfileManager()
        record("profiles_manager_lookups", lookups[0])
        lookups[0] = 0
        names = scripting.list_profiles()
        record("profiles_list_names_lookups", lookups[0])
        lookups[0] = 0
        assert scripting.get_profile(names[3]) is not None
        record("profiles_get_one_lookups", lookups[0])
        lookups[0] = 0
        assert len(manager.all_profiles()) == args.profiles
        record("profiles_all_profiles_lookups", lookups[0])


SCENARIOS = {
    "tags_toggle": bench_tags_toggle,
    "visit_record": bench_visit_record,
    "mcp_grep": bench_mcp_grep,
    "mcp_search": bench_mcp_search,
    "mcp_call": bench_mcp_call,
    "profiles_keyring": bench_profiles_keyring,
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--only", default="", help="comma-separated scenario names")
    parser.add_argument("--tags", type=int, default=3000, help="selected files to tag")
    parser.add_argument("--visits", type=int, default=50, help="record_visit calls")
    parser.add_argument("--files", type=int, default=5000, help="files / rows of the MCP tools")
    parser.add_argument("--calls", type=int, default=200, help="MCP tool calls")
    parser.add_argument("--profiles", type=int, default=30, help="saved profiles")
    parser.add_argument("--json", help="write the results to this file as well")
    parser.add_argument("--tree", default=str(ROOT), help="the axross checkout to measure")
    args = parser.parse_args(argv)
    wanted = [n for n in args.only.split(",") if n] or list(SCENARIOS)
    unknown = sorted(set(wanted) - set(SCENARIOS))
    if unknown:
        parser.error(f"unknown scenario(s): {', '.join(unknown)}")
    home = tempfile.mkdtemp(prefix="services-bench-home-")
    os.environ.update({
        "HOME": home, "XDG_CONFIG_HOME": f"{home}/.config", "XDG_DATA_HOME": f"{home}/.local",
        "XDG_CACHE_HOME": f"{home}/.cache", "XDG_STATE_HOME": f"{home}/.state",
        "PYTHON_KEYRING_BACKEND": "keyring.backends.null.Keyring",
        "AXROSS_OPERATION_JOURNAL": "0",
    })
    sys.path.insert(0, str(Path(args.tree).resolve()))
    results: dict = {}

    def record(name: str, value: float) -> None:
        results[name] = round(value, 3)
        print(f"{name:34s} {value:12.3f}", flush=True)

    try:
        for name in wanted:
            work = Path(tempfile.mkdtemp(prefix=f"services-bench-{name}-"))
            try:
                SCENARIOS[name](args, work, record)
            finally:
                shutil.rmtree(work, ignore_errors=True)
    finally:
        shutil.rmtree(home, ignore_errors=True)
    if args.json:
        Path(args.json).write_text(json.dumps(results, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
