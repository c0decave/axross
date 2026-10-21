"""subTest parameters reach an xdist worker's report as plain values
(tests/conftest.py): an enum or exception label failed tests only under
``pytest -n`` with "DumpError: can't serialize"."""

from __future__ import annotations

import enum
import unittest


class _Color(enum.Enum):
    RED = 1


class SubTestParamsTest(unittest.TestCase):
    def test_happy_an_enum_label_becomes_its_repr(self) -> None:
        with self.subTest(color=_Color.RED):
            self.assertEqual(self._subtest.params["color"], repr(_Color.RED))

    def test_sad_an_exception_label_becomes_its_repr(self) -> None:
        err = PermissionError("Permission denied")
        with self.subTest(error=err):
            self.assertEqual(self._subtest.params["error"], repr(err))

    def test_edge_plain_values_stay_as_they_are(self) -> None:
        for value in ("s", 3, 2.5, True, None):
            with self.subTest(value=value):
                self.assertIs(self._subtest.params["value"], value)

    def test_edge_a_message_still_passes_through(self) -> None:
        with self.subTest("named", n=1):
            self.assertEqual(self._subtest._message, "named")
