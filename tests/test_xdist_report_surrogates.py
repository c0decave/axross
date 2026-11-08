"""A report carrying a non-UTF-8 name can be sent to the xdist controller.

A worker died with UnicodeEncodeError while sending the report of a test
that logged a surrogate-escaped file name ("caf\\udce9"); every test still
scheduled on that worker was dropped without a failure. tests/conftest.py
now makes serialised reports encodable.
"""

from __future__ import annotations

import json
import logging

import pytest


def test_sad_a_logged_surrogate_name_still_serialises(pytestconfig):
    from _pytest.reports import TestReport

    report = TestReport("t.py::x", ("t.py", 1, "x"), {}, "passed", None, "call",
                        sections=[("Captured log call", "INFO saved /data/caf\udce9")])
    data = pytestconfig.hook.pytest_report_to_serializable(config=pytestconfig, report=report)
    json.dumps(data, ensure_ascii=False).encode("utf-8")  # would raise on a surrogate
    assert data["sections"][0][1] == "INFO saved /data/caf\\udce9"


def test_edge_plain_reports_are_left_as_they_are(pytestconfig):
    from _pytest.reports import TestReport

    report = TestReport("t.py::y", ("t.py", 1, "y"), {}, "passed", None, "call",
                        sections=[("Captured log call", "INFO café")])
    data = pytestconfig.hook.pytest_report_to_serializable(config=pytestconfig, report=report)
    assert data["sections"] == [["Captured log call", "INFO café"]] or \
        data["sections"] == [("Captured log call", "INFO café")]


def test_happy_this_test_logs_a_surrogate_and_passes_under_xdist(caplog):
    caplog.set_level(logging.INFO)
    logging.getLogger("axross.test").info("saved /data/caf\udce9")
    assert True
