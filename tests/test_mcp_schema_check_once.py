"""A tool's input schema is checked against its metaschema once, not per call.

Every ``tools/call`` (the MCP server over stdio and HTTP, and every tool
call of the Agent dock, which dispatches through the same function) ran
``jsonschema.validate(args, tool.schema)``. That first validates the SCHEMA
against the JSON Schema 2020-12 metaschema - ``$ref``/``$dynamicRef``
resolution through the vocabularies - and only then the arguments: 4.2 ms
of CPU for a ``stat`` call whose own work takes 0.1 ms (measured).

Now a validator is built once per schema text (the metaschema check runs
then) and reused; the arguments are checked as ``jsonschema.validate``
checks them, so every answer - accepted, or refused with its message and
path - is the former one.
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import mcp_server as M  # noqa: E402
from core.local_fs import LocalFS  # noqa: E402

jsonschema = M.jsonschema


def _call(tools, name, arguments, req_id=1, method="tools/call"):
    return M._handle_request(
        {"jsonrpc": "2.0", "id": req_id, "method": method,
         "params": {"name": name, "arguments": arguments}},
        tools, cancels=M._CancelRegistry(), tasks=M._TaskRegistry())


def _reference_error(args, schema):
    """The refusal the former jsonschema.validate call produced, or None."""
    try:
        jsonschema.validate(args, schema)
    except jsonschema.ValidationError as exc:
        return exc.message, list(exc.absolute_path)
    return None


@unittest.skipIf(jsonschema is None, "jsonschema not installed")
class SchemaCheckedOnceTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = self.tmp.name
        Path(self.root, "a.txt").write_text("hello\n")
        self.tools = M._build_tools(LocalFS(), allow_write=True, root=self.root)
        getattr(M, "_SCHEMA_VALIDATORS", {}).clear()  # (absent before the change)
        self.checks = []
        original = jsonschema.validators.Draft202012Validator.check_schema.__func__

        def counted(cls, schema, *a, **kw):
            self.checks.append(schema)
            return original(cls, schema, *a, **kw)

        patcher = mock.patch.object(jsonschema.validators.Draft202012Validator,
                                    "check_schema", classmethod(counted))
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_happy_fifty_calls_check_the_schema_once(self) -> None:
        for i in range(50):
            response = _call(self.tools, "stat", {"path": self.root}, req_id=i + 1)
            self.assertNotIn("error", response)
        self.assertEqual(len(self.checks), 1)
        _call(self.tools, "list_dir", {"path": self.root})
        self.assertEqual(len(self.checks), 2)  # another schema: its own check

    def test_sad_refusals_are_the_former_ones(self) -> None:
        cases = [
            ("read_file", {}),
            ("list_dir", {"path": 42}),
            ("read_file", {"path": "a.txt", "max_bytes": -1}),
            ("read_file", {"path": "a.txt", "encoding": "rot13"}),
            ("stat", {"path": "a.txt", "nonsense": True}),
            ("grep", {"path": self.root}),
            ("write_file", {"path": "b.txt"}),
            ("walk", {"path": self.root, "max_depth": "deep"}),
        ]
        checked = 0
        for name, args in cases:
            tool = next(t for t in self.tools if t.name == name)
            expected = _reference_error(args, tool.schema)
            for _attempt in range(2):  # a fresh validator, then the kept one
                response = _call(self.tools, name, args)
                with self.subTest(name=name, args=args):
                    if expected is None:  # the schema lets it through (the handler decides)
                        self.assertNotIn("failed schema",
                                         response.get("error", {}).get("message", ""))
                        continue
                    checked += 1
                    error = response["error"]
                    self.assertEqual(error["code"], M.ERR_INVALID_PARAMS)
                    self.assertEqual(error["message"],
                                     f"tool {name!r} arguments failed schema: {expected[0]}")
                    self.assertEqual(error["data"], {"type": "ValidationError",
                                                     "path": expected[1]})
        self.assertGreaterEqual(checked, 12)

    def test_sad_tasks_start_refuses_like_tools_call(self) -> None:
        tool = next(t for t in self.tools if t.name == "read_file")
        message, path = _reference_error({}, tool.schema)
        self.checks.clear()  # the reference's own check
        response = _call(self.tools, "read_file", {}, method="tasks/start")
        self.assertEqual(response["error"]["message"],
                         f"tool 'read_file' arguments failed schema: {message}")
        self.assertEqual(response["error"]["data"]["path"], path)
        _call(self.tools, "read_file", {}, method="tasks/start")
        _call(self.tools, "read_file", {})
        self.assertEqual(len(self.checks), 1)

    def test_sad_an_invalid_schema_is_refused_on_every_call(self) -> None:
        broken = M._Tool(name="broken", description="", schema={"type": 12},
                         handler=lambda args, ctx: {"ok": True})
        tools = [*self.tools, broken]
        for _ in range(2):
            with self.assertRaises(jsonschema.SchemaError):
                _call(tools, "broken", {})
        self.assertEqual(len(self.checks), 2)  # never kept

    def test_edge_a_schema_changed_in_place_is_checked_again(self) -> None:
        tool = next(t for t in self.tools if t.name == "stat")
        self.assertNotIn("error", _call(self.tools, "stat", {"path": self.root}))
        tool.schema["required"] = ["path", "must_have"]
        tool.schema["properties"]["must_have"] = {"type": "string"}
        response = _call(self.tools, "stat", {"path": self.root})
        self.assertEqual(response["error"]["code"], M.ERR_INVALID_PARAMS)
        self.assertIn("must_have", response["error"]["message"])
        self.assertEqual(len(self.checks), 2)

    def test_edge_the_kept_validator_does_not_follow_later_edits_of_its_dict(self) -> None:
        """Two tools with equal schemas share a validator; editing one dict
        afterwards does not change what the other one accepts."""
        stat = next(t for t in self.tools if t.name == "stat")
        twin = M._Tool(name="twin", description="", schema=__import__("copy").deepcopy(stat.schema),
                       handler=lambda args, ctx: {"ok": True})
        tools = [*self.tools, twin]
        self.assertNotIn("error", _call(tools, "twin", {"path": self.root}))
        self.assertNotIn("error", _call(tools, "stat", {"path": self.root}))
        self.assertEqual(len(self.checks), 1)
        twin.schema["properties"]["path"]["type"] = "integer"
        self.assertNotIn("error", _call(tools, "stat", {"path": self.root}))
        self.assertEqual(_call(tools, "twin", {"path": self.root})["error"]["code"],
                         M.ERR_INVALID_PARAMS)

    def test_edge_the_kept_validators_are_bounded(self) -> None:
        with mock.patch.object(M, "_SCHEMA_VALIDATORS_MAX", 4):
            for i in range(10):
                tool = M._Tool(name=f"t{i}", description="",
                               schema={"type": "object", "properties": {f"p{i}": {"type": "string"}}},
                               handler=lambda args, ctx: {"ok": True})
                self.assertNotIn("error", _call([tool], tool.name, {}))
            self.assertLessEqual(len(M._SCHEMA_VALIDATORS), 4)


if __name__ == "__main__":
    unittest.main()
