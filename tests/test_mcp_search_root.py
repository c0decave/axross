"""MCP ``search`` must not reveal indexed paths outside the configured root."""
from __future__ import annotations

import os
import tempfile
import unittest
from unittest import mock

from core import mcp_server as M
from core import metadata_index as MX
from core.local_fs import LocalFS


class SearchRootScopeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.mkdtemp()
        self.root = os.path.join(self.tmp, "root")
        os.mkdir(self.root)
        self.db = os.path.join(self.tmp, "idx.sqlite")
        for path in (
            os.path.join(self.root, "inside.txt"),
            os.path.join(self.tmp, "outside-secret.txt"),
            os.path.join(self.tmp, "rootkit", "evil.txt"),
        ):
            MX.upsert(self.db, "local", path, name=os.path.basename(path), size=1, is_dir=False)

    def _tool(self):
        backend = LocalFS()
        tools = M._build_tools(
            backend, allow_write=False, backend_id="local", root=self.root
        )
        return next(t for t in tools if t.name == "search")

    def _run(self, needle: str):
        real = MX.search_all
        with mock.patch.object(
            MX, "search_all", lambda **kw: real(**{**kw, "db_path": self.db})
        ):
            return self._tool().handler({"needle": needle}, M._ToolContext())

    def test_inside_root_is_returned(self) -> None:
        names = {r["name"] for r in self._run("inside")}
        self.assertEqual(names, {"inside.txt"})

    def test_outside_root_is_dropped(self) -> None:
        self.assertEqual(self._run("outside-secret"), [])

    def test_sibling_with_root_as_prefix_is_dropped(self) -> None:
        self.assertEqual(self._run("evil"), [])


if __name__ == "__main__":
    unittest.main()
