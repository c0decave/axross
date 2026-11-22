"""The Markdown tests and elapsed time (tests/markdown_timing.py): a test that passes or fails by elapsed time
only carries the marker ``timing`` (the standalone's CI runs it in a job that does not block - a shared
runner about twice as slow failed 133 of them in 0.17.0's CI without a bug); a test that asserts its content
and a duration asserts the duration through ``budget()`` (or a helper that does: the heartbeat's
assert_responsive, within_turn, _quick, until_within) - its content blocks a release, the duration is a
warning in the blocking job (``-m "not timing"``) and fails in the timing job (``-m "timing or budgets"``).

The scan here reads every test:
- **a duration asserted with a plain assert** - a clock in the assertion (``time.monotonic() - began < 2``),
  an ordering of a time measured in the test (a name bound to a clock's reading or a measuring helper's
  result: ``assert longest < 0.25``), a float ordered in a test that reads a clock, a wait asserted with a
  timeout of at most 30 s (``assert until(..., 5)``) - is allowed only in a TIMING test;
- **a TIMING test** asserts nothing but durations and waits for its page (a test that asserts what is shown,
  exported or refused is split: its content asserted, its duration a budget), and no security, safety or
  hostile test is one (0.17.2 left a symlinked .env's secret, the safe links of an export and an image bomb
  out of the release gate);
- **BUDGETS** is every other test that calls a budget.
The helpers that measure a time are found as before: a call of the heartbeat or a turn meter, of
time.process_time, thread_time or perf_counter, of a helper that measures a time itself (a clock minus a
moment) or calls one. A helper that only waits for a page to be ready waits long enough (READY_SECONDS).
"""

from __future__ import annotations

import ast
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from tests import markdown_timing as MT  # noqa: E402

#: What measures elapsed time, by name (a call of it, or of an attribute of that name).
SEEDS = {"Heartbeat", "assert_responsive", "gap_budget", "within_turn", "turn_for", "_Turns", "Turns",
         "_longest_turn", "_quick", "measure_again", "gaps_since", "thread_time", "process_time",
         "perf_counter", "Frozen"}
#: What judges a duration as a budget (tests/markdown_timing.py's budget(): a warning under -m "not timing")
#: - a test calling one of them (or a helper that does) has a timing part: the marker budgets.
BUDGETED = {"budget", "until_within", "assert_responsive", "within_turn", "_quick", "_ops_turns"}
#: The clocks an elapsed time is read from (a moment subtracted from one of them is a measured time).
CLOCKS = ("monotonic", "time", "perf_counter", "process_time", "thread_time")
#: The waits whose timeout, asserted, is a budget.
WAITS = ("until", "wait_until", "_until")
#: The longest timeout or deadline that still counts as a budget (a readiness wait is longer).
SHORT = 30
#: Words of a test's name that say it checks security: such a test always blocks (never TIMING).
GUARDED_WORDS = ("safety", "safe", "secure", "security", "hostile", "secret", "attack", "bomb")


def _modules() -> dict[str, ast.Module]:
    files = sorted((ROOT / "tests").glob("test_markdown*.py")) + [ROOT / "tests" / "test_open_as_markdown.py"]
    return {p.stem: ast.parse(p.read_text(encoding="utf-8")) for p in files if p.is_file()}


def _names(node) -> set[str]:
    found = set()
    for sub in ast.walk(node):
        if isinstance(sub, ast.Name):
            found.add(sub.id)
        elif isinstance(sub, ast.Attribute):
            found.add(sub.attr)
    return found


def _short(value) -> bool:
    return isinstance(value, ast.Constant) and isinstance(value.value, (int, float)) and value.value <= SHORT


def _wait_call(node) -> ast.Call | None:
    """The wait asserted by the assert *node* (``assert until(...)``), or None."""
    for call in ast.walk(node.test):
        if isinstance(call, ast.Call) and getattr(call.func, "id", getattr(call.func, "attr", "")) in WAITS:
            return call
    return None


def _short_wait(node) -> bool:
    """An assert of a wait with a timeout of at most SHORT s: its speed is asserted."""
    call = _wait_call(node)
    return call is not None and any(_short(arg) for arg in [*call.args[1:], *(k.value for k in call.keywords)])


def _clock(node) -> bool:
    return isinstance(node, ast.Call) and getattr(node.func, "attr", getattr(node.func, "id", "")) in CLOCKS


def _measures(node) -> bool:
    """A clock minus a moment (``time.monotonic() - began``, ``now - self.last`` with ``now`` a clock's) - an
    elapsed time; a clock minus a number (``time.time() - 7200``) is a moment, no measure."""
    read = {target.id for sub in ast.walk(node) if isinstance(sub, ast.Assign) and _clock(sub.value)
            for target in sub.targets if isinstance(target, ast.Name)}
    return any(isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Sub)
               and (_clock(sub.left) or (isinstance(sub.left, ast.Name) and sub.left.id in read))
               and not isinstance(sub.right, ast.Constant)
               for sub in ast.walk(node))


def _deadline(node) -> bool:
    for sub in ast.walk(node):
        if isinstance(sub, ast.BinOp) and isinstance(sub.op, ast.Add) and isinstance(sub.left, ast.Call) \
                and getattr(sub.left.func, "attr", "") == "monotonic" and _short(sub.right):
            return True
    return False


def _timed(test, measuring: set[str]) -> set[str]:
    """The names *test* binds to a time it measured: a clock's reading, a measuring helper's result, an
    expression of such names."""
    timed: set[str] = set()
    grew = True
    while grew:
        grew = False
        for sub in ast.walk(test):
            value = getattr(sub, "value", None) if isinstance(sub, (ast.Assign, ast.AugAssign, ast.AnnAssign)) \
                else None
            if value is None:
                continue
            if not (any(_clock(call) for call in ast.walk(value)) or _names(value) & (measuring | timed)):
                continue
            for target in (sub.targets if isinstance(sub, ast.Assign) else [sub.target]):
                for name in ast.walk(target):
                    if isinstance(name, ast.Name) and name.id not in timed:
                        timed.add(name.id)
                        grew = True
    return timed


def duration_asserted(node, test, measuring: set[str], timed: set[str] | None = None) -> bool:
    """Whether the assert *node* of *test* asserts a duration with a plain assert: a clock in it, an ordering of
    a time *test* measured, a float ordered in a test that reads a clock, a short wait."""
    if _short_wait(node):
        return True
    if any(_clock(call) for call in ast.walk(node.test)):
        return True
    timed = _timed(test, measuring) if timed is None else timed
    reads_clock = any(_clock(call) for call in ast.walk(test))
    for compare in ast.walk(node.test):
        if not isinstance(compare, ast.Compare) or not any(
                isinstance(op, (ast.Lt, ast.LtE, ast.Gt, ast.GtE)) for op in compare.ops):
            continue
        if _names(compare) & (timed | {"turn_for", "gap_budget", "machine_factor"}):
            return True
        if reads_clock and any(isinstance(c, ast.Constant) and isinstance(c.value, float)
                               for c in [compare.left, *compare.comparators]):
            return True
    return False


def _readiness(node) -> bool:
    """An assert of a wait for the page (a long timeout, or the wait's own): no budget."""
    return _wait_call(node) is not None and not _short_wait(node)


def _tests(modules) -> list[tuple[str, ast.FunctionDef]]:
    return [(module, node) for module, tree in modules.items() for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")]


def scan() -> tuple[set[str], set[str], int]:
    """(the tests that measure elapsed time, the helpers that do, how many tests there are)."""
    modules = _modules()
    helpers = set(SEEDS)
    for tree in modules.values():  # (a helper that waits a few seconds and goes on, or measures: a budget too)
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("test_") \
                    and (_deadline(node) or _measures(node)):
                helpers.add(node.name)
    grew = True
    while grew:  # (helpers calling helpers, across the modules: they import each other's)
        grew = False
        for tree in modules.values():
            for node in tree.body:
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("test_") \
                        and node.name not in helpers and _names(node) & helpers:
                    helpers.add(node.name)
                    grew = True
    found, count = set(), 0
    tests = _tests(modules)
    for module, node in tests:
        count += 1
        if _names(node) & helpers or _deadline(node) or _measures(node) \
                or any(isinstance(sub, ast.Assert) and _short_wait(sub) for sub in ast.walk(node)):
            found.add(f"{module}::{node.name}")
    return found, helpers, count


def raw_durations() -> dict[str, list[int]]:
    """module::test (or module::helper) -> the lines where it asserts a duration with a plain assert."""
    modules = _modules()
    _found, helpers, _count = scan()
    raw: dict[str, list[int]] = {}
    for module, tree in modules.items():
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            timed = _timed(node, helpers)
            lines = [sub.lineno for sub in ast.walk(node)
                     if isinstance(sub, ast.Assert) and duration_asserted(sub, node, helpers, timed)]
            if lines:
                raw.setdefault(f"{module}::{node.name}", []).extend(lines)
    return {name: sorted(set(lines)) for name, lines in raw.items()}


def budgeted() -> set[str]:
    """The tests that call a budget (BUDGETED) or a helper that does - across the modules."""
    modules = _modules()
    names = set(BUDGETED)
    grew = True
    while grew:
        grew = False
        for tree in modules.values():
            for node in tree.body:  # (the modules' own helpers: a method's generic name - stop - no helper)
                if isinstance(node, (ast.FunctionDef, ast.ClassDef)) and not node.name.startswith("test_") \
                        and node.name not in names and _names(node) & names:
                    names.add(node.name)
                    grew = True
    return {f"{module}::{node.name}" for module, node in _tests(modules)
            if _names(node) & names and module != "test_markdown_timing_marks"}  # (budget() itself tested here)


def test_sad_no_test_asserts_a_duration_but_through_a_budget_or_in_the_timing_set():
    """A duration asserted with a plain assert fails a blocking test on a slow runner without a bug: in a test
    of TIMING (or BY_HAND) only - every other test asserts it through budget() (a helper that measures one
    too). The scan sees the tests: none lost to a rename."""
    found, _helpers, count = scan()
    listed = MT.TIMING | set(MT.BY_HAND)
    raw = {name: lines for name, lines in raw_durations().items() if name not in listed}
    assert not raw, ("a duration asserted with a plain assert - TB.budget(...) or TB.until_within(...) it (tests/markdown_timing.py), "
                     "or list the test in TIMING if it asserts nothing else:\n"
                     + "\n".join(f"{name}: lines {lines}" for name, lines in sorted(raw.items())))
    assert count > 700 and len(found) > 100


def test_sad_a_timing_test_asserts_nothing_but_durations():
    """0.17.2's timing set held about 180 tests, out of the release gate - a symlinked README showing a
    .env's secret, an export's unsafe links, an image bomb drawn, the rate limit of the theme on a held clock
    among them: tests that pass or fail by their content. A TIMING test asserts durations and waits for its
    page only, and no test named for security or safety is one."""
    modules = _modules()
    _found, helpers, _count = scan()
    tests = {f"{module}::{node.name}": node for module, node in _tests(modules)}
    listed = MT.TIMING | set(MT.BY_HAND)
    guarded = sorted(name for name in listed | MT.BUDGETS
                     if name in listed and any(word in name.split("::", 1)[1] for word in GUARDED_WORDS))
    assert not guarded, f"security tests block - split them (content asserted, the duration a budget): {guarded}"
    content = {}
    for name in sorted(MT.TIMING):
        node = tests.get(name)
        if node is None:
            continue
        timed = _timed(node, helpers)
        lines = [sub.lineno for sub in ast.walk(node) if isinstance(sub, ast.Assert)
                 and not duration_asserted(sub, node, helpers, timed) and not _readiness(sub)]
        if lines:
            content[name] = lines
    assert not content, ("a TIMING test asserts its content - split it (that assert blocks, the duration "
                         "TB.budget) and take it out of TIMING:\n"
                         + "\n".join(f"{name}: lines {lines}" for name, lines in content.items()))


def test_sad_the_tests_with_a_budget_carry_the_marker_budgets():
    """The timing job (``-m "timing or budgets"``) runs every duration strictly: BUDGETS is every test that
    calls a budget but TIMING's."""
    listed = MT.TIMING | set(MT.BY_HAND)
    wanted = budgeted() - listed
    missing, stale = sorted(wanted - MT.BUDGETS), sorted(MT.BUDGETS - wanted)
    if not (ROOT / "ui").is_dir():  # (an export carries some of axross's test modules)
        stale = [name for name in stale if name.split("::", 1)[0] in _modules()]
    assert not missing and not stale, ("tests/markdown_timing.py BUDGETS: add", missing, "drop", stale)


def test_sad_a_budget_is_a_warning_in_the_blocking_job_and_fails_elsewhere(monkeypatch):
    import warnings

    monkeypatch.setattr(MT, "SOFT", False)
    with pytest.raises(AssertionError, match="0.4 s"):
        MT.budget(0.4 < 0.1, "0.4 s")
    assert MT.budget(True, "never said")
    monkeypatch.setattr(MT, "SOFT", True)
    with warnings.catch_warnings(record=True) as said:
        warnings.simplefilter("always")
        assert MT.budget(False, "0.4 s, at most 0.1 s") is False
    assert [type(w.message) for w in said] == [MT.TimingBudgetWarning] and "0.4 s" in str(said[0].message)
    calls = []

    def wait(condition, seconds):
        calls.append(seconds)
        return condition()

    with warnings.catch_warnings(record=True):
        warnings.simplefilter("always")
        assert MT.until_within(wait, lambda: True, 5) is True
        assert MT.until_within(wait, lambda: False, 5) is False
    assert calls == [MT.READY_SECONDS, MT.READY_SECONDS]  # (the condition waited for as long as a page)


def test_sad_the_blocking_job_runs_the_security_tests_and_makes_budgets_warnings(tmp_path):
    """Under ``-m "not timing"`` the formerly timing security tests are collected (they block), and a
    budget missed there is a warning (SOFT set by the conftest)."""
    pytest.importorskip("PyQt6.QtWidgets")
    wanted = {"test_markdown_image_safety.py": ["test_safety_a_use_bomb_is_refused_at_once"],
              "test_markdown_reader_bugs15.py": ["test_hostile_a_folders_readme_is_checked_as_a_link"],
              "test_markdown_reader_bugs3.py": ["test_sad_qts_own_parser_exports_only_checked_images_and_safe_links"],
              "test_markdown_reader_features.py": ["test_sad_hostile_math_is_bounded_and_escaped"]}
    targets = [f"tests/{name}" for name in wanted if (ROOT / "tests" / name).is_file()]
    out = subprocess.run([sys.executable, "-m", "pytest", "-q", "--collect-only", "-p", "no:cacheprovider",
                          "-m", "not timing", *targets], cwd=ROOT, capture_output=True, text=True, timeout=300,
                         env=dict(os.environ, QT_QPA_PLATFORM="offscreen"))
    collected = out.stdout
    for name, tests in wanted.items():
        if (ROOT / "tests" / name).is_file():
            for test in tests:
                assert f"{name}::{test}" in collected, (test, collected[-2000:])
    probe = tmp_path / "test_soft_probe.py"
    probe.write_text("from tests import markdown_timing as MT\n\n"
                     "def test_probe():\n    assert MT.SOFT\n    MT.budget(False, 'over')\n", encoding="utf-8")
    ran = subprocess.run([sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "-p", "tests.conftest",
                          "-m", "not timing", "--rootdir", str(tmp_path), str(probe)],
                         cwd=ROOT, capture_output=True, text=True, timeout=300,
                         env=dict(os.environ, QT_QPA_PLATFORM="offscreen", PYTHONPATH=str(ROOT)))
    assert ran.returncode == 0 and "TimingBudgetWarning" in ran.stdout, ran.stdout[-2000:] + ran.stderr[-2000:]


def test_sad_every_listed_test_is_there():
    modules = _modules()
    tests = {f"{module}::{node.name}" for module, tree in modules.items() for node in ast.walk(tree)
             if isinstance(node, ast.FunctionDef) and node.name.startswith("test_")}
    listed = MT.TIMING | set(MT.BY_HAND)
    if not (ROOT / "ui").is_dir():  # (an export carries some of axross's test modules: the others' names wait)
        listed = {name for name in listed if name.split("::", 1)[0] in modules}
    gone = sorted(listed - tests)
    assert not gone, gone
    assert all(why.strip() for why in MT.BY_HAND.values())
    assert not set(MT.BY_HAND) & MT.TIMING  # (the scan finds it: no reason by hand needed)


def test_happy_the_readiness_helpers_wait_for_the_page_not_a_budget():
    """view_of, dialog_of, _dialog, jumped: a wait of 10 s that went on with a half-made page made
    typography tests fail on a slow runner - they wait up to READY_SECONDS and go on when ready."""
    _found, helpers, _count = scan()
    assert not {"view_of", "dialog_of", "_dialog", "jumped"} & helpers


def test_happy_the_conftest_marks_them_and_not_timing_leaves_them_out(tmp_path):
    pytest.importorskip("PyQt6.QtWidgets")
    target = "tests/test_markdown_reader_bugs25.py"

    def collected(expression: str) -> list[str]:
        out = subprocess.run([sys.executable, "-m", "pytest", "-q", "--collect-only", "-p", "no:cacheprovider",
                              "-m", expression, target], cwd=ROOT, capture_output=True, text=True, timeout=300,
                             env=dict(os.environ, QT_QPA_PLATFORM="offscreen"))
        return [line for line in out.stdout.splitlines() if "::" in line]

    timing, rest = collected("timing"), collected("not timing")
    assert timing and rest and not set(timing) & set(rest)
    listed = {name.split("::", 1)[1] for name in MT.TIMING if name.startswith("test_markdown_reader_bugs25::")}
    assert {line.split("::", 1)[1].split("[", 1)[0] for line in timing} == listed
