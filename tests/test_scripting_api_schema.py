"""``axross.api_schema()``: the scripting API described for a machine.

An LLM that writes scripts for ``script_run`` had ``axross.help()`` (one
line per function, for humans) and ``axross.docs()`` (Markdown). The
schema is JSON: every public function with its parameters and types,
return type, first docstring paragraph, topic group, and whether it can
change state or needs a human. It is built from the live objects
(inspect), so it cannot drift from the code; the MCP tool
``script_api_schema`` serves it next to ``script_run``.
"""

from __future__ import annotations

import ast
import inspect
import json
import textwrap

import pytest

from core import mcp_server as M
from core import scripting as axross
from core.local_fs import LocalFS


@pytest.fixture(scope="module")
def schema() -> dict:
    return axross.api_schema()


def _entries(schema: dict) -> dict:
    return {f["name"]: f for f in schema["functions"]}


def _public_functions() -> dict:
    """Public functions reachable on the module, found without __all__."""
    return {
        name: value
        for name, value in vars(axross).items()
        if not name.startswith("_") and inspect.isfunction(value)
    }


# -- happy --------------------------------------------------------------------------


def test_happy_the_schema_is_json_and_versioned(schema) -> None:
    assert json.loads(json.dumps(schema)) == schema
    assert schema["schema_version"] == 2 and schema["module"] == "axross"


def test_happy_every_public_function_is_in_the_schema(schema) -> None:
    # Fails when a function is added without __all__, or __all__ without it.
    assert set(_public_functions()) == set(_entries(schema))


def test_happy_every_public_class_is_in_the_schema(schema) -> None:
    classes = {n for n in axross.__all__ if inspect.isclass(getattr(axross, n))}
    assert classes == {c["name"] for c in schema["classes"]}
    by_name = {c["name"]: c for c in schema["classes"]}
    assert {"name": "host", "annotation": "str"} in [
        {k: f[k] for k in ("name", "annotation")} for f in by_name["PingResult"]["fields"]
    ]
    assert "PermissionError" in by_name["NonInteractiveError"]["bases"]


def test_happy_a_function_entry_carries_types_doc_and_traits(schema) -> None:
    copy = _entries(schema)["copy"]
    params = {p["name"]: p for p in copy["parameters"]}
    assert params["src_backend"] == {
        "name": "src_backend", "kind": "positional_or_keyword",
        "annotation": "FileBackend", "required": True,
    }
    assert params["overwrite"]["kind"] == "keyword_only"
    assert params["overwrite"]["default"] is False and params["overwrite"]["required"] is False
    assert copy["returns"] == "int"
    assert copy["summary"].startswith("Copy bytes from one backend to another.")
    assert copy["signature"].startswith("copy(src_backend: FileBackend")
    assert copy["mutates"] is True and copy["prompts"] is True
    assert copy["group"] == "File I/O"


def test_happy_reads_and_prompts_are_told_apart(schema) -> None:
    entries = _entries(schema)
    assert entries["read_bytes"]["mutates"] is False and entries["read_bytes"]["prompts"] is False
    assert entries["confirm"]["prompts"] is True and entries["confirm"]["mutates"] is False
    assert entries["remove"]["mutates"] is True
    assert entries["snmp_set"]["mutates"] is True and entries["snmp_get"]["mutates"] is False


def test_happy_the_backend_protocol_and_its_lifecycle_are_described(schema) -> None:
    methods = {m["name"]: m for m in schema["backend_protocol"]}
    assert {"list_dir", "open_read", "stat", "close", "__enter__", "__exit__"} <= set(methods)
    assert methods["list_dir"]["returns"] == "list[FileItem]"
    # Defaults keep their quotes; ``self`` is not an argument a caller passes.
    assert methods["checksum"]["signature"] == (
        "checksum(path: str, algorithm: str = 'sha256') -> str"
    )


# -- sad ----------------------------------------------------------------------------


def test_sad_every_public_function_declares_its_traits(schema) -> None:
    undeclared = sorted(
        f["name"] for f in schema["functions"] if f["mutates"] is None or f["prompts"] is None
    )
    assert undeclared == []


def test_sad_an_unmarked_function_is_reported_as_unknown_not_as_safe() -> None:
    def helper(x: int) -> int:
        """Do a thing."""
        return x

    entry = axross._function_entry("helper", helper)
    assert entry["mutates"] is None and entry["prompts"] is None


def _called_names(fn) -> set[str]:
    tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
    return {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }


def test_sad_everything_behind_the_production_gate_is_declared_mutating_and_prompting(
    schema,
) -> None:
    # Derived from the code: a function that enters _mutation_gate, or calls
    # a public function that does, can write and can need a human.
    own = {n: f for n, f in _public_functions().items() if f.__module__ == axross.__name__}
    gated: set[str] = set()
    changed = True
    while changed:
        changed = False
        for name, fn in own.items():
            if name not in gated and ({"_mutation_gate"} | gated) & _called_names(fn):
                gated.add(name)
                changed = True
    assert {"copy", "write_bytes", "write_text", "remove", "dedupe"} <= gated
    entries = _entries(schema)
    wrong = sorted(n for n in gated if not (entries[n]["mutates"] and entries[n]["prompts"]))
    assert wrong == []


# -- edge ---------------------------------------------------------------------------


def test_edge_defaults_that_are_not_json_are_given_as_repr() -> None:
    def helper(a: object = object, b: tuple = (1, 2), c: float = 1.5) -> None:
        """Doc."""

    params = {p["name"]: p for p in axross._function_entry("helper", helper)["parameters"]}
    assert params["a"]["default_repr"] == repr(object) and "default" not in params["a"]
    assert params["b"]["default_repr"] == "(1, 2)"
    assert params["c"]["default"] == 1.5


def test_edge_var_arguments_are_kinds_not_required(schema) -> None:
    params = {p["name"]: p for p in _entries(schema)["query"]["parameters"]}
    assert params["args"]["kind"] == "var_positional" and params["args"]["required"] is False
    assert params["kwargs"]["kind"] == "var_keyword"


def test_edge_the_schema_names_itself(schema) -> None:
    entry = _entries(schema)["api_schema"]
    assert entry["mutates"] is False and entry["returns"] == "dict"


# -- schema 2: what a model writing a script needs beyond the signature ---------------


def test_happy_a_function_entry_carries_the_whole_docstring_and_its_examples(schema) -> None:
    entries = _entries(schema)
    remove = entries["remove"]
    # The first paragraph alone hid the confirm=True rule of remove().
    assert remove["doc"] == inspect.getdoc(axross.remove)
    assert "confirm=True" in remove["doc"] and "confirm=True" not in remove["summary"]
    dedupe = entries["dedupe"]
    assert len(dedupe["examples"]) == 1
    assert dedupe["examples"][0].startswith('plan = axross.dedupe(folder="/home/me/Photos")')
    # Two literal blocks, both kept, dedented.
    query = entries["query"]["examples"]
    assert query == [
        'rows = axross.query(b, "SELECT * FROM users WHERE id = ?", (1,))',
        'rows = axross.query(b, "orders", {"status": "open"}, limit=50)',
    ]


def test_happy_raises_lists_what_the_axross_layer_raises_itself(schema) -> None:
    entries = _entries(schema)
    assert entries["open"]["raises"] == ["KeyError"]
    assert entries["remove"]["raises"] == ["PermissionError"]
    # Through the same-module guard _refuse_existing_target_unless_overwrite.
    assert "FileExistsError" in entries["write_bytes"]["raises"]
    # write_text -> write_bytes -> the guard: followed through public calls too.
    assert "FileExistsError" in entries["write_text"]["raises"]
    assert entries["exec"]["raises"] == ["TypeError"]


def test_happy_the_session_methods_say_what_they_change_and_take(schema) -> None:
    methods = {m["name"]: m for m in schema["backend_protocol"]}
    assert methods["remove"]["mutates"] is True and methods["list_dir"]["mutates"] is False
    assert methods["open_write"]["mutates"] is True and methods["stat"]["mutates"] is False
    assert [p["name"] for p in methods["remove"]["parameters"]] == ["path", "recursive"]
    assert methods["remove"]["parameters"][1]["default"] is False
    assert methods["checksum"]["doc"].startswith("Return a hex-encoded checksum")
    # copy/symlink/hardlink exist only on some sessions; the defaulted ones
    # tell what a session without support answers.
    assert methods["copy"]["optional"] is True and methods["list_dir"]["optional"] is False
    assert methods["checksum"]["fallback"] and "fallback" not in methods["list_dir"]
    assert methods["readlink"]["fallback"]
    attributes = {m["name"]: m for m in schema["backend_protocol"] if m["kind"] == "attribute"}
    assert set(attributes) == {"supports_symlinks", "supports_hardlinks"}
    assert attributes["supports_symlinks"]["default"] is False


def test_happy_the_types_a_script_gets_back_are_described(schema) -> None:
    types = {t["name"]: t for t in schema["types"]}
    item = types["FileItem"]
    assert item["module"] == "models.file_item"
    fields = {f["name"]: f["annotation"] for f in item["fields"]}
    assert fields["name"] == "str" and fields["is_dir"] == "bool" and fields["size"] == "int"
    assert "permissions_str" in {p["name"] for p in item["properties"]}
    assert "check" in {m["name"] for m in types["ExecResult"]["methods"]}
    assert "FileVersion" in types  # list_versions() -> list[FileVersion]


def test_happy_rules_and_errors_are_given_for_a_machine(schema) -> None:
    ids = [r["id"] for r in schema["rules"]]
    assert len(ids) == len(set(ids)) and all(r["text"] for r in schema["rules"])
    assert {"sessions", "paths", "helpers-before-session-methods", "no-human"} <= set(ids)
    errors = {e["name"]: e for e in schema["errors"]}
    assert {"OSError", "FileExistsError", "PermissionError", "NonInteractiveError"} <= set(errors)
    assert errors["NonInteractiveError"]["base"] == "PermissionError"


def test_happy_groups_cover_every_public_name_once(schema) -> None:
    listed = [n for g in schema["groups"] for n in g["functions"] + g["classes"]]
    assert sorted(listed) == sorted(axross.__all__)
    assert schema["groups"][0]["name"] == "Open / connect"


def test_sad_every_session_method_declares_whether_it_mutates(schema) -> None:
    undeclared = [m["name"] for m in schema["backend_protocol"] if m["mutates"] is None]
    assert undeclared == []


def test_sad_every_described_member_has_a_summary(schema) -> None:
    empty = [m["name"] for m in schema["backend_protocol"] if not m["summary"]]
    empty += [f["name"] for f in schema["functions"] if not f["summary"]]
    assert empty == []


def test_sad_every_return_type_is_described_or_builtin(schema) -> None:
    # A type a function or session method returns must be in classes or
    # types - a model cannot use what it cannot see.
    described = {c["name"] for c in schema["classes"]} | {t["name"] for t in schema["types"]}
    named: set[str] = set()
    for entry in schema["functions"] + schema["backend_protocol"]:
        for text in [entry.get("returns") or ""] + [
            p.get("annotation", "") for p in entry.get("parameters", [])
        ]:
            named |= axross._annotation_names(text)
    unknown = {n for n in named if n[:1].isupper()} - described - axross._NOT_DESCRIBED_TYPES
    assert unknown == set()


def test_sad_errors_name_real_exception_classes(schema) -> None:
    import builtins

    for error in schema["errors"]:
        cls = getattr(builtins, error["name"], None) or getattr(axross, error["name"], None)
        assert isinstance(cls, type) and issubclass(cls, BaseException), error["name"]
        assert error["base"] == cls.__mro__[1].__name__, error["name"]


def test_sad_an_undeclared_session_method_is_reported_as_unknown() -> None:
    assert axross._session_method_mutates("frobnicate") is None


def test_sad_the_legend_explains_every_field_used(schema) -> None:
    legend = schema["legend"]
    for section in ("functions", "backend_protocol", "types"):
        used = {k for entry in schema[section] for k in entry}
        assert used <= set(legend[section]), (section, used - set(legend[section]))


def test_edge_examples_come_from_literal_blocks_only() -> None:
    doc = (
        "Do a thing.\n\nNo block here: a colon :: in the middle.\n\n"
        "Example::\n\n    x = 1\n        y = 2\n\nAfter the block.\n\nTrailing::"
    )
    assert axross._docstring_examples(doc) == ["x = 1\n    y = 2"]
    assert axross._docstring_examples("") == []


def test_edge_raises_ignores_reraise_and_variables() -> None:
    def helper(flag: bool) -> None:
        """Doc."""
        try:
            if flag:
                raise ValueError("bad")
        except ValueError as exc:
            err = exc
            raise err from None
        raise

    assert axross._raised_exceptions(helper) == ["ValueError"]


def test_happy_names_select_functions_and_the_types_they_need(schema) -> None:
    part = axross.api_schema(names=["write_bytes", "PingResult", "ExecResult"])
    assert [f["name"] for f in part["functions"]] == ["write_bytes"]
    assert [c["name"] for c in part["classes"]] == ["PingResult"]
    types = {t["name"] for t in part["types"]}
    # FileItem through the session methods; ExecResult because it was named.
    assert {"FileItem", "ExecResult"} <= types and "AttackReport" not in types
    # The index and the conventions always come along.
    for key in ("legend", "rules", "errors", "groups", "backend_protocol"):
        assert part[key] == schema[key], key


def test_sad_an_unknown_name_is_refused() -> None:
    with pytest.raises(ValueError, match="nope"):
        axross.api_schema(names=["write_bytes", "nope"])
    with pytest.raises(ValueError):
        axross.api_schema(names="write_bytes")  # a string is not a list of names


def test_edge_no_names_gives_the_index_only(schema) -> None:
    index = axross.api_schema(names=[])
    assert index["functions"] == [] and index["classes"] == []
    assert {t["name"] for t in index["types"]} >= {"FileItem", "FileVersion"}
    assert index["groups"] == schema["groups"]
    assert len(json.dumps(index)) < len(json.dumps(schema)) / 4


def test_happy_the_mcp_tool_passes_names_through(schema) -> None:
    tool = _tools(allow_scripts=True)["script_api_schema"]
    assert tool.handler({"names": ["copy"]}, M._ToolContext()) == axross.api_schema(names=["copy"])
    assert tool.schema["properties"]["names"]["type"] == "array"


def test_edge_type_names_are_unique_and_stable(schema) -> None:
    names = [t["name"] for t in schema["types"]] + [c["name"] for c in schema["classes"]]
    assert len(names) == len(set(names))
    assert axross.api_schema() == schema
    assert " at 0x" not in json.dumps(schema)


# -- the MCP tool -------------------------------------------------------------------


def _tools(**kw) -> dict:
    return {t.name: t for t in M._build_tools(LocalFS(), allow_write=False, **kw)}


def test_happy_the_mcp_tool_serves_the_same_schema(schema) -> None:
    tool = _tools(allow_scripts=True)["script_api_schema"]
    assert tool.group == "scripts" and tool.write is False
    assert tool.handler({}, M._ToolContext()) == schema


def test_sad_without_scripts_there_is_no_schema_tool() -> None:
    assert "script_api_schema" not in _tools(allow_scripts=False)


# -- the checked-in human reference ---------------------------------------------------


def test_edge_the_checked_in_reference_is_the_generator_output() -> None:
    # docs/SCRIPTING_REFERENCE.md says it is generated from axross.docs();
    # it had drifted by hand. Regenerate with:
    #   python -c "import core.scripting as s, sys; sys.stdout.write(s.docs())" \
    #       > docs/SCRIPTING_REFERENCE.md
    from pathlib import Path

    reference = Path(__file__).resolve().parents[1] / "docs" / "SCRIPTING_REFERENCE.md"
    assert reference.read_text(encoding="utf-8") == axross.docs()
