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
    assert schema["schema_version"] == 1 and schema["module"] == "axross"


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
