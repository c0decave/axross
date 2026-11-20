"""Tool definitions a client (and a directory's quality score, Glama's TDQS)
can judge without reading the code.

Measured before: 54 parameters of 23 tools had no description; list_dir,
stat and search were one-line descriptions without their result; search
(offline index) and walk (live tree) did not point at each other; and
initialize sent no instructions."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import mcp_groups as G  # noqa: E402
from core import mcp_server as M  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402


def _all_tools(tmp_path):
    return M._build_tools(LocalFS(), allow_write=True, root=str(tmp_path), allow_scripts=True,
                          tool_groups=frozenset(G.GROUPS), allow_exec=True)


def test_sad_every_parameter_of_every_tool_is_described(tmp_path):
    missing = {
        tool.name: [name for name, spec in (tool.schema or {}).get("properties", {}).items()
                    if not str(spec.get("description", "")).strip()]
        for tool in _all_tools(tmp_path)
    }
    assert {k: v for k, v in missing.items() if v} == {}


@pytest.mark.parametrize("name", ["list_dir", "stat", "search", "mkdir", "remove", "rename",
                                  "copy", "script_delete"])
def test_sad_a_tool_says_what_it_returns(tmp_path, name):
    tool = next(t for t in _all_tools(tmp_path) if t.name == name)
    assert "Returns" in tool.description, tool.description


def test_sad_search_and_walk_point_at_each_other(tmp_path):
    tools = {t.name: t.description for t in _all_tools(tmp_path)}
    assert "walk" in tools["search"] and "index" in tools["search"]
    assert "search" in tools["walk"] and "list_dir" in tools["walk"]
    assert "walk" in tools["list_dir"]


def _initialize(version):
    tools = M._build_tools(LocalFS(), allow_write=False, root=None)
    return M._handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                              "params": {"protocolVersion": version}}, tools,
                             protocol=M.ProtocolState())["result"]


@pytest.mark.parametrize("version", ["2025-11-25", "2025-06-18"])
def test_happy_initialize_sends_short_factual_instructions(version):
    text = _initialize(version)["instructions"]
    assert text == M.SERVER_INSTRUCTIONS and len(text) < 2500
    # Facts about the tools, never requests to the model a client could
    # mistake for injected instructions.
    assert not re.search(r"\b(you|your|must|should|always|never|ignore|do not)\b", text, re.I)
    for tool in ("list_dir", "walk", "stat", "read_file", "grep", "search", "list_backends"):
        assert tool in text


def test_edge_a_2024_session_gets_no_instructions():
    assert "instructions" not in _initialize("2024-11-05")


# -- the definitions' shape, as a grader (Glama's TDQS) reads it --------------------
#
# Measured before: no description said when to use the tool or which sibling to
# take instead, none named the flag a gated tool needs, defaults lived in prose
# only, copy was marked destructive although it never replaces anything, and
# grep's default path ('/') was refused under every --mcp-root but '/'.

#: The labelled lines every description has, in this order (Requires: only
#: where a flag or a prerequisite applies).
LABELS = ("Use when:", "Instead:", "Requires:", "Behavior:", "Returns:")
REQUIRED_LABELS = ("Use when:", "Instead:", "Behavior:", "Returns:")
#: The flag each gated kind of tool names on its Requires: line.
GATE_FLAGS = {"write": "--mcp-write", "scripts": "--mcp-allow-scripts", "exec": "--mcp-allow-exec"}
#: Tools that change or remove what exists: destructiveHint must say so.
DESTRUCTIVE = {"write_file", "remove", "rename", "chmod", "bulk_copy", "script_write",
               "script_delete", "script_run", "duplicates_dedupe", "transfer_copy",
               "transfer_move", "remote_exec", "remote_script"}
#: Tools that only add new entries under free names: never destructive.
ADDITIVE = {"mkdir", "copy", "symlink", "hardlink", "metadata_export_file", "metadata_remove",
            "pack", "archive_extract", "encrypt", "decrypt"}


def _lines(tool) -> dict:
    out = {}
    for line in tool.description.split("\n")[1:]:
        label = next((lab for lab in LABELS if line.startswith(lab)), None)
        assert label is not None, f"{tool.name}: unlabelled line {line!r}"
        assert label not in out, f"{tool.name}: {label} twice"
        out[label] = line[len(label):].strip()
    return out


def _gate(tool) -> str | None:
    if tool.group in ("scripts", "exec"):
        return tool.group
    return "write" if tool.write else None


def test_sad_every_tool_has_a_title_and_all_five_annotations(tmp_path):
    for tool in _all_tools(tmp_path):
        assert tool.title and len(tool.title) <= 40, tool.name
        assert tool.annotations["title"] == tool.title, tool.name
        assert set(tool.annotations) == {"title", "readOnlyHint", "destructiveHint",
                                         "idempotentHint", "openWorldHint"}, tool.name


def test_sad_destructive_tools_are_marked_destructive_and_additive_ones_not(tmp_path):
    hints = {t.name: t.annotations for t in _all_tools(tmp_path)}
    assert DESTRUCTIVE | ADDITIVE <= set(hints)
    for name in DESTRUCTIVE:
        assert hints[name]["destructiveHint"] is True, name
        assert hints[name]["readOnlyHint"] is False, name
    for name in ADDITIVE:
        assert hints[name]["destructiveHint"] is False, name
        assert hints[name]["readOnlyHint"] is False, name
    # The rest only read (an index row or a connection is no change of data).
    for name, hint in hints.items():
        if name not in DESTRUCTIVE:
            assert hint["destructiveHint"] is False, name


@pytest.mark.parametrize("version", ["2025-06-18", "2025-11-25"])
def test_happy_tools_list_carries_title_and_annotations(tmp_path, version):
    tools = _all_tools(tmp_path)
    M._handle_request({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                       "params": {"protocolVersion": version}}, tools,
                      protocol=(state := M.ProtocolState()))
    listing = M._handle_request({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, tools,
                                protocol=state)["result"]["tools"]
    assert len(listing) == len(tools)
    for entry in listing:
        assert entry["title"] == entry["annotations"]["title"], entry["name"]
        assert isinstance(entry["annotations"]["readOnlyHint"], bool)


def _summary_and_lines_faults(tool, names) -> list[str]:
    faults = []
    summary = tool.description.split("\n")[0]
    if not summary.endswith(".") or len(summary) > 200 or summary.startswith(LABELS):
        faults.append(f"summary: {summary!r}")
    lines = _lines(tool)
    if not set(REQUIRED_LABELS) <= set(lines):
        faults.append(f"labels: {sorted(lines)}")
    if list(lines) != [lab for lab in LABELS if lab in lines]:
        faults.append("label order")
    if not all(lines.values()):
        faults.append("empty line")
    # Instead: names at least one real sibling tool.
    words = set(re.findall(r"[a-z][a-z0-9_]+", lines.get("Instead:", "")))
    if not words & (names - {tool.name}):
        faults.append("Instead: names no other tool")
    if len(tool.description) > 900:
        faults.append(f"{len(tool.description)} characters")
    return faults


def test_sad_every_description_is_a_summary_then_labelled_lines(tmp_path):
    tools = _all_tools(tmp_path)
    names = {t.name for t in tools}
    faults = {t.name: f for t in tools if (f := _summary_and_lines_faults(t, names))}
    assert faults == {}


def test_sad_a_gated_tool_names_its_flag(tmp_path):
    for tool in _all_tools(tmp_path):
        gate = _gate(tool)
        if gate is None:
            continue
        assert GATE_FLAGS[gate] in _lines(tool).get("Requires:", ""), tool.name


def test_sad_the_behavior_line_agrees_with_the_annotations(tmp_path):
    for tool in _all_tools(tmp_path):
        behavior = _lines(tool)["Behavior:"]
        assert behavior.startswith("read-only") == tool.annotations["readOnlyHint"], tool.name
        assert ("destructive" in behavior) == tool.annotations["destructiveHint"], tool.name


#: Home folders, commit ids, internal notes, module names, reST markup.
_INTERNAL = re.compile(r"~/|/home/|/root/|\b(?=[0-9a-f]*[a-f])[0-9a-f]{7,40}\b|\bTODO\b|"
                       r"\bV1\b|\bcore\.[a-z_]+|``")


def test_sad_a_description_holds_no_internal_notes_or_odd_characters(tmp_path):
    faults = []
    for tool in _all_tools(tmp_path):
        texts = [tool.description, tool.title] + [
            str(spec.get("description", "")) for _, spec in _props(tool)]
        for text in texts:
            if not all(ch == "\n" or " " <= ch <= "~" for ch in text) or _INTERNAL.search(text):
                faults.append((tool.name, text))
    assert faults == []


def test_sad_a_deadline_is_stated_where_the_tool_has_no_timeout_argument(tmp_path):
    for tool in _all_tools(tmp_path):
        props = tool.schema.get("properties", {})
        behavior = _lines(tool)["Behavior:"]
        if {"timeout", "timeout_s"} & set(props):
            assert "Time limit:" not in behavior, tool.name
        else:
            assert f"Time limit: {M._duration_text(tool.timeout_seconds)}." in behavior, tool.name


def _props(tool):
    return tool.schema.get("properties", {}).items()


def _schema_faults(tool) -> list[str]:
    faults = []
    required = set(tool.schema.get("required", []))
    if not required <= set(tool.schema.get("properties", {})):
        faults.append("required names a missing property")
    for name, spec in _props(tool):
        text = spec.get("description", "")
        kinds = {spec.get("type")} | {alt.get("type") for alt in spec.get("oneOf", [])}
        if kinds & {"integer", "number"} and not (
                {"minimum", "exclusiveMinimum"} & set(spec) or spec.get("oneOf")):
            faults.append(f"{name}: no minimum")
        if spec.get("type") == "boolean" and "default" not in spec:
            faults.append(f"{name}: no default")
        if (name not in required and kinds & {"integer", "number"} and "default" not in spec
                and not re.search(r"[Dd]efault|[Oo]mit", text)):
            faults.append(f"{name}: what omitting it means")
        if "enum" in spec and "default" not in spec and name not in required \
                and not re.search(r"[Dd]efault|[Oo]mit", text):
            faults.append(f"{name}: what omitting it means")
        if "default" in spec:
            default = spec["default"]
            if "enum" in spec and default not in spec["enum"]:
                faults.append(f"{name}: default outside the enum")
            if isinstance(default, (int, float)) and not isinstance(default, bool) and not (
                    spec.get("minimum", default) <= default <= spec.get("maximum", default)):
                faults.append(f"{name}: default outside the bounds")
    return faults


def test_sad_every_schema_states_its_bounds_and_defaults(tmp_path):
    faults = {t.name: f for t in _all_tools(tmp_path) if (f := _schema_faults(t))}
    assert faults == {}


def test_sad_path_arguments_say_how_a_path_is_written(tmp_path):
    faults = []
    for tool in _all_tools(tmp_path):
        for name, spec in _props(tool):
            if name in M.PATH_ARGUMENTS and spec.get("type") == "string" and name != "target":
                if "MCP root" not in spec["description"] or spec.get("minLength") != 1:
                    faults.append(f"{tool.name}.{name}")
    assert faults == []


def _call(tools, name, args):
    reply = M._handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                               "params": {"name": name, "arguments": args}}, tools,
                              protocol=M.ProtocolState("2025-11-25"))
    return reply["result"]


@pytest.mark.parametrize("name, args", [
    ("list_dir", {"path": "."}),
    ("walk", {"path": "."}),
    ("read_file", {"path": "a/f.txt"}),
    ("read_file", {"path": "a/f.txt", "encoding": "text"}),
    ("checksum", {"path": "a/f.txt"}),
    ("recursive_checksum", {"path": "."}),
    ("grep", {"pattern": "hello"}),
    ("search", {}),
    ("file_type_scan", {"path": "."}),
    ("metadata_read", {"path": "."}),
    ("archive_list", {"path": "z.zip"}),
])
def test_happy_the_schema_defaults_are_the_handlers_defaults(tmp_path, name, args):
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "a" / "f.txt").write_text("hello\nworld\n")
    import zipfile

    with zipfile.ZipFile(tmp_path / "z.zip", "w") as zf:
        zf.writestr("m.txt", "member")
    tools = _all_tools(tmp_path)
    tool = next(t for t in tools if t.name == name)
    explicit = dict(args)
    for key, spec in _props(tool):
        if "default" in spec:
            explicit.setdefault(key, spec["default"])
    assert explicit != args or not any("default" in s for _, s in _props(tool))
    plain, filled = _call(tools, name, args), _call(tools, name, explicit)
    assert not plain.get("isError"), plain
    assert plain == filled


def test_happy_walk_max_depth_0_lists_the_path_itself_like_1(tmp_path):
    # The schema says 1 is the least; a caller's former 0 still works, as 1.
    (tmp_path / "a" / "b").mkdir(parents=True)
    tools = _all_tools(tmp_path)
    walk = next(t for t in tools if t.name == "walk")
    assert walk.schema["properties"]["max_depth"]["minimum"] == 1
    zero = _call(tools, "walk", {"path": ".", "max_depth": 0})
    one = _call(tools, "walk", {"path": ".", "max_depth": 1})
    four = _call(tools, "walk", {"path": "."})
    assert zero == one != four
    assert '"a/b"' not in zero["content"][0]["text"] and "a/b" in four["content"][0]["text"]


def test_happy_grep_without_a_path_searches_the_mcp_root(tmp_path):
    (tmp_path / "f.txt").write_text("needle\n")
    result = _call(_all_tools(tmp_path), "grep", {"pattern": "needle"})
    assert not result.get("isError"), result
    assert '"line_no": 1' in result["content"][0]["text"]


def test_sad_remote_exec_cannot_ask_for_more_time_than_its_call_has(tmp_path):
    tool = next(t for t in _all_tools(tmp_path) if t.name == "remote_exec")
    assert tool.schema["properties"]["timeout"]["maximum"] < tool.timeout_seconds



# -- the second round: what a blind grader found ------------------------------------
#
# Measured before: 31 tools kept a path argument in required although its
# *_b64 twin may replace it; max_depth meant two different depths with two
# minimums; remove, copy, symlink, hardlink and remote_close said a repeat
# fails while rename and bulk_copy (the same) were marked not idempotent;
# preview and the archive tools took a backend they could only fail on; the
# paranoid mode, protected places and secret files were never defined;
# agent_run, which sends file contents to an LLM server, was marked
# read-only; remote_exec took no backend although the default runs nothing.

from core import mcp_terms as TERMS  # noqa: E402


def test_sad_the_idempotency_hint_is_what_the_text_says(tmp_path):
    faults = []
    for tool in _all_tools(tmp_path):
        behavior = _lines(tool)["Behavior:"]
        hint = tool.annotations["idempotentHint"]
        if tool.annotations["readOnlyHint"]:
            if not hint:
                faults.append(f"{tool.name}: read-only but not idempotent")
            continue
        says_yes = TERMS.IDEMPOTENT in behavior  # the one wording
        says_no = "Not idempotent:" in behavior
        if says_yes == says_no or says_yes != hint:
            faults.append(f"{tool.name}: hint {hint}, text {behavior!r}")
    assert faults == []


def test_sad_agent_run_is_not_read_only_and_says_where_the_data_goes(tmp_path):
    tool = next(t for t in _all_tools(tmp_path) if t.name == "agent_run")
    assert tool.annotations["readOnlyHint"] is False
    assert tool.annotations["openWorldHint"] is True
    assert "sends file contents to the configured LLM" in _lines(tool)["Behavior:"]


def test_sad_a_b64_alternative_is_not_held_in_required(tmp_path):
    faults = []
    for tool in _all_tools(tmp_path):
        props = tool.schema.get("properties", {})
        required = tool.schema.get("required", [])
        assert not {"anyOf", "oneOf", "allOf"} & set(tool.schema), tool.name  # clients refuse
        for name in props:
            if f"{name}_b64" in props and name in required:
                faults.append(f"{tool.name}.{name}")
        for name in tool.twin_required:
            if "Required unless" not in props[name]["description"]:
                faults.append(f"{tool.name}.{name}: does not say it is required")
    assert faults == []


@pytest.mark.parametrize("name, args, twins", [
    ("list_dir", {}, {"path": "."}),
    ("read_file", {}, {"path": "f.txt"}),
    ("copy", {}, {"src": "f.txt", "dst": "g.txt"}),
])
def test_happy_the_b64_form_alone_is_a_whole_call(tmp_path, name, args, twins):
    import base64

    (tmp_path / "f.txt").write_text("hi\n")
    tools = _all_tools(tmp_path)
    tool = next(t for t in tools if t.name == name)
    encoded = {f"{k}_b64": base64.b64encode(v.encode()).decode() for k, v in twins.items()}
    if M.jsonschema is not None:
        M.jsonschema.validate(encoded, tool.schema)  # a client validating sends it
    result = _call(tools, name, {**args, **encoded})
    assert not result.get("isError"), result
    refused = _call(tools, name, args)  # neither form: the server says what is missing
    assert refused.get("isError") and "is a required property" in refused["content"][0]["text"]


def _depth_faults(tool) -> list[str]:
    spec = tool.schema.get("properties", {}).get("max_depth")
    if spec is None:
        return []
    start = "src" if "src" in tool.schema["properties"] else "path"
    if tool.name in M._LEVEL_DEPTH_TOOLS:
        ok = spec["description"].startswith(TERMS.levels_text(start)) and spec["minimum"] == 1
    else:
        ok = spec["description"] == TERMS.descend_text(start) and spec["minimum"] == 0
    return [] if ok else [f"{tool.name}: {spec}"]


def test_sad_max_depth_is_one_of_two_stated_counts(tmp_path):
    tools = _all_tools(tmp_path)
    assert {t.name for t in tools if "max_depth" in t.schema.get("properties", {})} == {
        "walk", "grep", "recursive_checksum", "bulk_copy", "file_type_scan", "transfer_copy"}
    assert [f for t in tools for f in _depth_faults(t)] == []


def test_edge_both_counts_reach_the_same_tree(tmp_path):
    # walk's N+1 is file_type_scan's N: both see the same files.
    (tmp_path / "a" / "b").mkdir(parents=True)
    (tmp_path / "top.txt").write_text("t")
    (tmp_path / "a" / "mid.txt").write_text("m")
    (tmp_path / "a" / "b" / "low.txt").write_text("l")
    tools = _all_tools(tmp_path)
    import json

    walked = json.loads(_call(tools, "walk", {"path": ".", "max_depth": 2})["content"][0]["text"])
    scanned = json.loads(_call(tools, "file_type_scan", {"path": ".", "max_depth": 1})
                         ["content"][0]["text"])
    files = {e["name"] for e in walked["entries"] if not e["is_dir"]}
    assert files == {e["name"] for e in scanned["entries"]} == {"top.txt", "mid.txt"}


@pytest.mark.parametrize("name", ["preview", "archive_list", "archive_extract"])
def test_sad_a_local_only_tool_takes_no_backend(tmp_path, name):
    tool = next((t for t in _all_tools(tmp_path) if t.name == name), None)
    if tool is None:
        pytest.skip(f"{name} is not served here")
    assert "backend" not in tool.schema["properties"]
    assert "local disk" in tool.description


def test_sad_remote_commands_need_a_named_backend(tmp_path):
    for tool in _all_tools(tmp_path):
        if tool.name in ("remote_exec", "remote_script"):
            assert "backend" in tool.schema["required"], tool.name


def test_sad_the_shared_rules_are_stated_once_in_the_instructions(tmp_path):
    # Round 2 repeated each definition in every tool that used it (47 KB of
    # descriptions); the rules live in the initialize instructions now, and
    # a tool carries the short tag only.
    for rule in TERMS.RULES:
        assert rule in M.SERVER_INSTRUCTIONS
    faults = []
    for tool in _all_tools(tmp_path):
        text = tool.description + " ".join(
            str(spec.get("description", "")) for _, spec in _props(tool))
        for rule in TERMS.RULES:
            if rule[:60] in text:
                faults.append(f"{tool.name}: repeats {rule[:30]!r}")
        for word in ("--mcp-allow-secret-reads", "AXROSS_SECURITY_MODE", "protected places"):
            if word in text:
                faults.append(f"{tool.name}: {word}")
        if "paranoid" in tool.description and TERMS.PARANOID_TAG not in tool.description:
            faults.append(f"{tool.name}: paranoid without its tag")
    assert faults == []


def test_sad_descriptions_are_short_and_share_no_boilerplate(tmp_path):
    tools = _all_tools(tmp_path)
    lengths = [len(t.description) for t in tools]
    assert sum(lengths) / len(lengths) <= 600 and max(lengths) <= 900, (
        sum(lengths) / len(lengths), max(lengths))
    seen: dict[str, set] = {}
    for tool in tools:
        for line in tool.description.split("\n"):
            if line.startswith("Requires:"):
                continue  # the operator condition, one short phrase by design
            for sentence in re.split(r"(?<=[.;])\s+", line):
                if len(sentence) > 45 and not sentence.startswith("Time limit:"):
                    seen.setdefault(sentence, set()).add(tool.name)
    repeated = {s: sorted(n) for s, n in seen.items() if len(n) > 3}
    assert repeated == {}
    # The per-argument phrases that do repeat are one short wording each.
    for tool in tools:
        for name, spec in _props(tool):
            props = tool.schema["properties"]
            if name == "backend" or (name.endswith("_b64") and name[:-4] in props):
                assert len(spec["description"]) <= 80, (tool.name, name)
            assert spec.get("description", "").count("Required unless") <= 1, (tool.name, name)


def test_sad_a_tool_that_reaches_remote_backends_says_open_world(tmp_path):
    for tool in _all_tools(tmp_path):  # the remote group is on: backends reach hosts
        props = tool.schema.get("properties", {})
        if {"backend", "src_backend", "dst_backend"} & set(props):
            assert tool.annotations["openWorldHint"] is True, tool.name
    local = M._build_tools(LocalFS(), allow_write=True, root=str(tmp_path))
    assert all(t.annotations["openWorldHint"] is False for t in local)  # no backend at all
    hints = {t.name: t.annotations for t in _all_tools(tmp_path)}
    assert hints["remote_open"] == {**hints["remote_close"], "title": hints["remote_open"]["title"]}


def test_sad_every_schema_refuses_unknown_arguments(tmp_path):
    assert [t.name for t in _all_tools(tmp_path)
            if t.schema.get("additionalProperties") is not False] == []


def _validate(result, schema):
    import json

    if M.jsonschema is None:
        pytest.skip("jsonschema not installed")
    structured = result.get("structuredContent")
    assert structured is not None
    M.jsonschema.validate(structured, schema)
    text = json.loads(result["content"][0]["text"])
    # The text is the same data: the object itself, or the array it wraps.
    assert text == structured or (isinstance(text, list) and text in structured.values())


#: Calls that succeed on a bare local root, per tool with an outputSchema.
_HAPPY = [
    ("stat", {"path": "f.txt"}), ("read_file", {"path": "f.txt"}),
    ("checksum", {"path": "f.txt"}), ("walk", {"path": "."}),
    ("recursive_checksum", {"path": "."}), ("grep", {"pattern": "hi"}),
    ("write_file", {"path": "w.txt", "content": "x"}), ("mkdir", {"path": "d1"}),
    ("copy", {"src": "f.txt", "dst": "c.txt"}), ("rename", {"src": "c.txt", "dst": "r.txt"}),
    ("hardlink", {"target": "f.txt", "link_path": "h.txt"}),
    ("symlink", {"target": "f.txt", "link_path": "s.txt"}),
    ("chmod", {"path": "w.txt", "mode": "600"}), ("remove", {"path": "r.txt"}),
    ("bulk_copy", {"src": "sub", "dst": "sub2"}),
    ("script_write", {"name": "q", "source": "print(1)"}), ("script_list", {}),
    ("script_read", {"name": "q"}), ("script_run", {"name": "q"}),
    ("script_delete", {"name": "q"}),
    ("encrypt", {"path": "f.txt", "passphrase": "pw"}),
    ("transfer_copy", {"src": "sub", "dst": "sub3"}),
    ("exec_backends", {}),
    ("decrypt", {"path": "f.txt.axenc", "passphrase": "pw"}),
    ("transfer_move", {"src": "w.txt", "dst": "moved/w.txt"}),
    ("metadata_read", {"path": "."}), ("metadata_export", {"path": "."}),
    ("metadata_export_file", {"path": ".", "out": "meta.json"}),
    ("metadata_remove", {"path": "."}),
    ("pack_formats", {}), ("pack", {"folder": ".", "names": ["sub"], "archive_name": "z"}),
    ("archive_list", {"path": "z.zip"}), ("archive_extract", {"path": "z.zip"}),
    ("duplicates_scan", {}), ("duplicates_scans", {}), ("duplicates_groups", {}),
    ("duplicates_dedupe", {}), ("index_build", {}),
    ("file_type_scan", {"path": "."}), ("remote_profiles", {}), ("extensions_list", {}),
    ("list_dir", {"path": "."}), ("search", {}), ("list_versions", {"path": "f.txt"}),
    ("list_backends", {}), ("file_type", {"path": "f.txt"}),
    ("script_api_schema", {"names": []}),
]
#: Tools with an outputSchema that need a remote host or a version history.
_NOT_HERE = {"open_version_read", "remote_open", "remote_close", "remote_exec", "remote_script",
             "agent_run", "extensions_info"}


def test_happy_real_results_match_every_output_schema(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    root = tmp_path / "root"
    (root / "sub").mkdir(parents=True)
    (root / "f.txt").write_text("hi\n")
    (root / "sub" / "g.txt").write_text("hi\n")
    tools = {t.name: t for t in _all_tools(root)}
    with_schema = {n for n, t in tools.items() if t.output_schema is not None}
    assert with_schema - _NOT_HERE == {n for n, _ in _HAPPY}
    for name, args in _HAPPY:
        result = M._handle_request({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                                    "params": {"name": name, "arguments": args}},
                                   list(tools.values()), protocol=M.ProtocolState("2025-11-25"))
        result = result["result"]
        assert not result.get("isError"), (name, result)
        _validate(result, tools[name].output_schema)


def test_happy_an_encrypted_archive_opens_with_its_password(tmp_path):
    tools = _all_tools(tmp_path)
    formats = _call(tools, "pack_formats", {})["content"][0]["text"]
    if '"format": "7z"' not in formats or '"available": true' not in formats.split(
            '"format": "7z"')[1].split("}")[0]:
        pytest.skip("7z is not available")
    (tmp_path / "in.txt").write_text("secret words\n")
    packed = _call(tools, "pack", {"folder": ".", "names": ["in.txt"], "archive_name": "x",
                                   "format": "7z", "password": "pw"})
    assert not packed.get("isError"), packed
    locked = _call(tools, "archive_list", {"path": "x.7z"})
    assert locked.get("isError") and "password" in locked["content"][0]["text"]
    assert not _call(tools, "archive_list", {"path": "x.7z", "password": "pw"}).get("isError")
    done = _call(tools, "archive_extract", {"path": "x.7z", "password": "pw"})
    assert not done.get("isError"), done
    assert (tmp_path / "x" / "in.txt").read_text() == "secret words\n"


def test_sad_file_type_has_time_for_its_own_15_s_limit(tmp_path):
    from core import file_type

    tool = next(t for t in _all_tools(tmp_path) if t.name == "file_type")
    assert tool.timeout_seconds > file_type.DEFAULT_TIMEOUT


def test_edge_the_script_api_sizes_stated_hold():
    from core import scripting

    import json

    whole = len(json.dumps(scripting.api_schema()))
    index = len(json.dumps(scripting.api_schema(names=[])))
    assert 100_000 < whole < 400_000 and 10_000 < index < 60_000, (whole, index)


# -- round three: small capabilities the definitions promised ---------------------

def _json_call(tools, name, args):
    import json

    result = _call(tools, name, args)
    assert not result.get("isError"), result
    return json.loads(result["content"][0]["text"])


def test_happy_stat_reads_the_mode_chmod_replaces(tmp_path):
    (tmp_path / "f.txt").write_text("x")
    tools = _all_tools(tmp_path)
    _json_call(tools, "chmod", {"path": "f.txt", "mode": "640"})
    assert _json_call(tools, "stat", {"path": "f.txt"})["mode"] == "0640"


def test_happy_grep_include_narrows_by_file_name(tmp_path):
    (tmp_path / "a.py").write_text("needle\n")
    (tmp_path / "b.txt").write_text("needle\n")
    tools = _all_tools(tmp_path)
    hits = _json_call(tools, "grep", {"pattern": "needle", "include": "*.py"})["matches"]
    assert [h["path"].rsplit("/", 1)[1] for h in hits] == ["a.py"]
    assert len(_json_call(tools, "grep", {"pattern": "needle"})["matches"]) == 2


def test_happy_search_pages_with_offset(tmp_path, monkeypatch):
    from core import metadata_index as MX

    class Row:
        def __init__(self, n):
            self.backend_id, self.path, self.name = "x", str(tmp_path / f"f{n}"), f"f{n}"
            self.size, self.is_dir, self.modified = n, False, None

    monkeypatch.setattr(MX, "search_all", lambda **kw: [Row(n) for n in range(5)])
    tools = _all_tools(tmp_path)
    first = _json_call(tools, "search", {"limit": 2})
    second = _json_call(tools, "search", {"limit": 2, "offset": 2})
    last = _json_call(tools, "search", {"limit": 2, "offset": 4})
    assert [r["name"] for r in first + second + last] == [f"f{n}" for n in range(5)]


def test_happy_script_write_counts_bytes(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    out = _json_call(_all_tools(tmp_path), "script_write", {"name": "u", "source": "s = 'é'\n"})
    assert out["size"] == len("s = 'é'\n".encode())


def test_sad_preview_refuses_an_edge_outside_its_range_as_its_schema_says(tmp_path):
    tool = next((t for t in _all_tools(tmp_path) if t.name == "preview"), None)
    if tool is None:
        pytest.skip("no image decoder")
    spec = tool.schema["properties"]["edge"]
    assert (spec["minimum"], spec["maximum"]) == (16, 2048) and "clamp" not in spec["description"]
    result = _call(_all_tools(tmp_path), "preview", {"path": "x.png", "edge": 5000})
    assert result.get("isError") and ("edge" in result["content"][0]["text"]
                                      or "maximum" in result["content"][0]["text"])


# -- round four: one meaning of truncated/complete, links, paging ------------------

def _deep_tree(root):
    (root / "a" / "b" / "c").mkdir(parents=True)
    (root / "top.txt").write_text("needle\n")
    (root / "a" / "b" / "c" / "deep.txt").write_text("needle\n")


@pytest.mark.parametrize("name, args", [
    ("walk", {"path": ".", "max_depth": 1}),
    ("grep", {"pattern": "needle", "max_depth": 1}),
    ("recursive_checksum", {"path": ".", "max_depth": 1}),
    ("file_type_scan", {"path": ".", "max_depth": 0}),
])
def test_sad_a_folder_left_at_max_depth_is_no_complete_answer(tmp_path, name, args):
    _deep_tree(tmp_path)
    tools = _all_tools(tmp_path)
    cut = _json_call(tools, name, args)
    assert cut["truncated"] is True and cut["complete"] is False
    whole = _json_call(tools, name, {**args, "max_depth": 10})
    assert whole["truncated"] is False and whole["complete"] is True


def test_happy_index_and_duplicate_scans_say_complete(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    root = tmp_path / "root"
    root.mkdir()
    (root / "x.txt").write_text("x")
    tools = _all_tools(root)
    for name in ("index_build", "duplicates_scan"):
        out = _json_call(tools, name, {})
        assert out["truncated"] is False and out["complete"] is True, (name, out)


def test_happy_list_dir_walk_and_stat_show_a_symlink(tmp_path):
    import os

    (tmp_path / "d").mkdir()
    (tmp_path / "f.txt").write_text("x")
    os.symlink("d", tmp_path / "ld")
    os.symlink("f.txt", tmp_path / "lf")
    tools = _all_tools(tmp_path)
    listed = {e["name"]: e for e in _json_call(tools, "list_dir", {"path": "."})}
    assert listed["ld"]["is_link"] and not listed["ld"]["is_dir"]
    assert not listed["d"]["is_link"] and listed["d"]["is_dir"]
    walked = {e["name"]: e for e in _json_call(tools, "walk", {"path": "."})["entries"]}
    assert walked["lf"]["is_link"] and not walked["f.txt"]["is_link"]
    assert _json_call(tools, "stat", {"path": "lf"})["is_link"] is True
    assert _json_call(tools, "stat", {"path": "f.txt"})["is_link"] is False


def test_happy_search_narrows_to_a_folder_and_tells_an_empty_index(tmp_path, monkeypatch):
    from core import metadata_index as MX

    class Row:
        def __init__(self, path):
            self.backend_id, self.path, self.name = "x", str(path), path.name
            self.size, self.is_dir, self.modified = 1, False, None

    rows = [Row(tmp_path / "docs" / "a"), Row(tmp_path / "docsx" / "b"), Row(tmp_path / "c")]
    monkeypatch.setattr(MX, "search_all", lambda **kw: rows[:kw.get("limit", 9)])
    tools = _all_tools(tmp_path)
    names = [r["name"] for r in _json_call(tools, "search", {"path": "docs"})]
    assert names == ["a"]
    reply = _call(tools, "search", {"needle": "zzz", "path": "nowhere"})
    assert reply["structuredContent"] == {"entries": [], "indexed": True, "truncated": False}
    monkeypatch.setattr(MX, "search_all", lambda **kw: [])
    assert _call(tools, "search", {})["structuredContent"] == {
        "entries": [], "indexed": False, "truncated": False}


def test_happy_duplicate_groups_page_with_offset(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    root = tmp_path / "root"
    root.mkdir()
    for n in range(3):
        for copy in ("a", "b"):
            (root / f"{copy}{n}.txt").write_text(f"content {n}")
    tools = _all_tools(root)
    _json_call(tools, "duplicates_scan", {})
    pages = [_json_call(tools, "duplicates_groups", {"max_groups": 2, "offset": o})
             for o in (0, 2)]
    assert [len(p["groups"]) for p in pages] == [2, 1]
    assert pages[0]["truncated"] is True and pages[1]["truncated"] is False


def test_sad_an_unknown_llm_profile_names_the_known_ones(tmp_path, monkeypatch):
    from core import llm_profiles as LP

    class Profile:
        name = "local-llama"

    monkeypatch.setattr(LP.LLMSettings, "load", classmethod(
        lambda cls, path=None: cls(profiles=[Profile()], active="")))
    result = _call(_all_tools(tmp_path), "agent_run", {"task": "x", "profile": "nope"})
    assert result.get("isError") and "'local-llama'" in result["content"][0]["text"]


def test_happy_remote_timeouts_are_numbers_like_script_run(tmp_path):
    tools = {t.name: t for t in _all_tools(tmp_path)}
    kinds = {tools["script_run"].schema["properties"]["timeout_s"]["type"]}
    for name in ("remote_exec", "remote_script"):
        kinds.add(tools[name].schema["properties"]["timeout"]["type"])
    assert kinds == {"number"}


def test_sad_agent_run_says_which_tools_each_group_gives(tmp_path):
    tools = _all_tools(tmp_path)
    for group, names in G.AGENT_GROUP_TOOLS.items():
        served = {t.name for t in tools if t.group == group and not t.write}
        if group == "remote":
            served.add("list_backends")
        assert set(names) == served, group
    text = next(t for t in tools if t.name == "agent_run").schema["properties"]["groups"]
    assert all(name in text["description"] for names in G.AGENT_GROUP_TOOLS.values()
               for name in names)


def test_sad_every_optional_group_tool_names_its_flags(tmp_path):
    for tool in _all_tools(tmp_path):
        # list_backends: there whenever a tool takes backend, no flag of its own.
        if tool.group in G.GROUPS and tool.group != "exec" and tool.name != "list_backends":
            assert f"--mcp-tools {tool.group}" in _lines(tool).get("Requires:", ""), tool.name


def test_sad_a_read_only_tool_points_at_no_write_tool_instead(tmp_path):
    tools = {t.name: t for t in _all_tools(tmp_path)}
    gated = {n for n, t in tools.items() if t.write}
    for tool in tools.values():
        if tool.annotations["readOnlyHint"]:
            line = _lines(tool)["Instead:"]
            for name in set(re.findall(r"[a-z][a-z0-9_]+", line)) & gated:
                assert f"{name} (needs --mcp-write)" in line, (tool.name, name)


def test_happy_extensions_info_matches_its_output_schema(tmp_path):
    tools = _all_tools(tmp_path)
    listed = _json_call(tools, "extensions_list", {})["extensions"]
    if not listed:
        pytest.skip("no extension installed")
    tool = next(t for t in tools if t.name == "extensions_info")
    _validate(_call(tools, "extensions_info", {"ext_id": listed[0]["id"]}), tool.output_schema)


@pytest.mark.parametrize("name, args", [
    ("remove", {"path": "f.txt"}),
    ("rename", {"src": "f.txt", "dst": "g.txt"}),
    ("copy", {"src": "f.txt", "dst": "g.txt"}),
    ("symlink", {"target": "f.txt", "link_path": "s"}),
    ("hardlink", {"target": "f.txt", "link_path": "h"}),
    ("transfer_move", {"src": "f.txt", "dst": "m/f.txt"}),
])
def test_happy_a_repeat_fails_with_the_error_its_description_names(tmp_path, name, args):
    (tmp_path / "f.txt").write_text("x")
    tools = _all_tools(tmp_path)
    tool = next(t for t in tools if t.name == name)
    named = re.search(r"it fails with '([^']+)'", tool.description).group(1)
    assert not _call(tools, name, args).get("isError")
    again = _call(tools, name, args)
    assert again.get("isError"), again
    assert named.lower() in again["content"][0]["text"].lower(), (named, again)



# -- round five ---------------------------------------------------------------------

def test_sad_no_undefined_terms_and_the_instructions_name_every_flag(tmp_path):
    for flag in ("--mcp-write", "--mcp-allow-scripts", "--mcp-allow-exec", "--mcp-tools"):
        assert flag in M.SERVER_INSTRUCTIONS
    for tool in _all_tools(tmp_path):
        assert "write mode" not in tool.description, tool.name


def test_sad_whenever_a_tool_takes_backend_list_backends_is_there(tmp_path):
    from core.ram_fs import RamFsSession as RamFS

    configs = [
        _all_tools(tmp_path),
        M._build_tools(LocalFS(), allow_write=False, root=str(tmp_path),
                       backends={"ram": RamFS()}),
        M._build_tools(LocalFS(), allow_write=False, root=str(tmp_path)),
    ]
    for tools in configs:
        takes = [t.name for t in tools if "backend" in t.schema.get("properties", {})]
        names = {t.name for t in tools}
        assert not takes or "list_backends" in names
        lb = next((t for t in tools if t.name == "list_backends"), None)
        if lb is not None:
            assert "Requires:" not in lb.description  # no flag of its own


def test_happy_script_delete_says_whether_there_was_a_script(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    tools = _all_tools(tmp_path)
    _json_call(tools, "script_write", {"name": "s", "source": "x = 1\n"})
    assert _json_call(tools, "script_delete", {"name": "s"})["deleted"] is True
    assert _json_call(tools, "script_delete", {"name": "s"})["deleted"] is False


def test_happy_search_says_when_more_pages_follow(tmp_path, monkeypatch):
    from core import metadata_index as MX

    class Row:
        def __init__(self, n):
            self.backend_id, self.path, self.name = "x", str(tmp_path / f"f{n}"), f"f{n}"
            self.size, self.is_dir, self.modified = n, False, None

    monkeypatch.setattr(MX, "search_all", lambda **kw: [Row(n) for n in range(5)])
    tools = _all_tools(tmp_path)
    assert _call(tools, "search", {"limit": 2})["structuredContent"]["truncated"] is True
    last = _call(tools, "search", {"limit": 2, "offset": 4})["structuredContent"]
    assert last["truncated"] is False and len(last["entries"]) == 1


def test_happy_walk_and_the_index_tools_give_iso_times(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "config"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "data"))
    root = tmp_path / "root"
    root.mkdir()
    (root / "a.txt").write_text("same")
    (root / "b.txt").write_text("same")
    import zipfile

    with zipfile.ZipFile(root / "z.zip", "w") as zf:
        zf.writestr("m.txt", "member")
    tools = _all_tools(root)
    walked = _json_call(tools, "walk", {"path": "."})["entries"]
    assert all(e["modified"] for e in walked)
    _json_call(tools, "duplicates_scan", {})
    copies = _json_call(tools, "duplicates_groups", {})["groups"][0]["copies"]
    assert all(c["modified"] and "T" in c["modified"] for c in copies)
    members = _json_call(tools, "archive_list", {"path": "z.zip"})["entries"]
    assert members[0]["modified"] and "T" in members[0]["modified"]
