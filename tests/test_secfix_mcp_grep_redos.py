"""The MCP grep tool stops a catastrophically backtracking pattern (final
security review of 0.15.177, finding 5).

Before: a shape check (``_REDOS_NESTED_QUANTIFIER``) refused ``(a+)+`` but
passed ``(?:(a)+)+$``, ``(a|a)+$`` and ``(a+){2,}$``; each ran 10-20 s on a
27-character line inside one ``re.search`` that neither the tool timeout nor
a cancel could interrupt (one call per client thread, CPU-bound with the GIL
held). Now the lines are matched in a child process (core.regex_worker) that
is killed once one file takes longer than GREP_REGEX_SECONDS_PER_FILE, or
when the call is cancelled.
"""

from __future__ import annotations

import threading
import time

import pytest

from core import mcp_server as M
from core import regex_worker as RW
from tests import mcp_group_testkit as T

LINE = "a" * 26 + "!"


@pytest.fixture
def tree(tmp_path):
    (tmp_path / "a.txt").write_text(f"{LINE}\nhello world\nfoo\n")
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "b.txt").write_text("say hello\n")
    return tmp_path


@pytest.fixture
def short_bound(monkeypatch):
    monkeypatch.setattr(M, "GREP_REGEX_SECONDS_PER_FILE", 1.0, raising=False)


@pytest.mark.parametrize("pattern", [r"(?:(a)+)+$", r"(a|a)+$", r"(a+){2,}$"])
def test_sad_a_catastrophic_pattern_is_stopped_at_the_bound(tree, short_bound, pattern):
    tools = T.build(tree, ())
    started = time.monotonic()
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "grep", {"pattern": pattern, "path": str(tree)})
    elapsed = time.monotonic() - started
    assert err.value.code == -32602 and "ReDoS" in err.value.message
    assert elapsed < 4.0, f"grep ran {elapsed:.1f} s"


def test_edge_a_cancel_stops_the_matching_child(tree):
    tools = T.build(tree, ())
    cancel = threading.Event()
    threading.Timer(0.5, cancel.set).start()
    started = time.monotonic()
    with pytest.raises(M.CancelledError):
        T.run_handler(tools, "grep", {"pattern": r"(a|a)+$", "path": str(tree)}, cancel=cancel)
    assert time.monotonic() - started < 3.0


def test_happy_grep_still_finds_what_it_found(tree):
    tools = T.build(tree, ())
    out = T.call(tools, "grep", {"pattern": "hel+o", "path": str(tree)})
    got = sorted((m["path"].rsplit("/", 1)[-1], m["line_no"], m["line"]) for m in out["matches"])
    assert got == [("a.txt", 2, "hello world"), ("b.txt", 1, "say hello")]
    assert out["files_scanned"] == 2 and out["complete"]


def test_happy_max_matches_still_bounds_the_answer(tree):
    (tree / "many.txt").write_text("x\n" * 50)
    tools = T.build(tree, ())
    out = T.call(tools, "grep", {"pattern": "x", "path": str(tree), "max_matches": 7})
    assert len(out["matches"]) == 7 and out["truncated"]


def test_sad_a_bad_pattern_is_still_an_argument_error(tree):
    tools = T.build(tree, ())
    with pytest.raises(T.RpcError) as err:
        T.call(tools, "grep", {"pattern": "(", "path": str(tree)})
    assert err.value.code == -32602 and "bad regex" in err.value.message


def test_happy_the_matcher_child_answers_line_numbers_and_ends():
    with RW.RegexMatcher(r"b\d") as matcher:
        assert matcher.matching_lines("a\nb1\nc\nb2\nb3", 2) == [2, 4]
        assert matcher.matching_lines("", 5) == []
        proc = matcher._proc
    assert proc.poll() is not None


def test_sad_the_matcher_refuses_a_bad_pattern():
    with pytest.raises(ValueError):
        RW.RegexMatcher("(")


def test_edge_a_timed_out_matcher_kills_its_child():
    matcher = RW.RegexMatcher(r"(a|a)+$", seconds_per_text=0.5)
    with pytest.raises(RW.RegexTimeout):
        matcher.matching_lines(LINE, 1)
    assert matcher._proc.poll() is not None
    matcher.close()
