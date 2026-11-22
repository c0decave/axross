"""Every regular expression of the Markdown reader, timed on adversarial texts of doubling length.

Review 24 found two patterns that held the window for seconds although the audit before (bugs24's: each
pattern on runs of 1,500 and 6,000 characters) passed them: the outline's heading pattern, quadratic in a
run of spaces after "# " (H1), and the fence pattern of Qt's own parser, quadratic in fences never closed
(H2) - neither met a run where it begins: after a block's marker, on many lines. And a third the sweep
found (tests/test_markdown_freeze_sweep.py): the space run pattern, which tried each space of a run just
too short to match again (2 MB of words 999 spaces apart: 1.1 s).

Here each pattern (every ``re`` call of core/markdown_*.py and ui/markdown_*.py, compiled or not, as it is
used: searched, or matched at one place) meets texts made for it:

- **units:** the punctuation, spaces and words the stress tests use - and the pattern's own literals;
- **where a run begins:** bare, after a word, before one, after each block marker (``# ``, ``> ``,
  ``- ``, ``1. ``, ``| ``, a fence, an indent) and inside a word's pair (``a`` ... ``b``);
- **how it repeats:** one run; a line of the unit repeated on many lines; runs just short of each of the
  pattern's own counts (``{1001,}``: runs of 1,000) between letters;

each at 2,000, 4,000, 8,000 and 16,000 characters. Twice the text may take about twice as long (the
growth's exponent over the doublings at most LINEAR), and no text more than PER_CHARACTER a character: a
pattern that is linear only with a huge factor (the space runs') fails too.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

pytest.importorskip("PyQt6.QtWidgets", reason="PyQt6 not installed")
pytest.importorskip("markdown_it")

#: The modules whose patterns are audited.
AUDITED = ("core.markdown_cli", "core.markdown_doc", "core.markdown_term", "ui.markdown_app", "ui.markdown_html",
           "ui.markdown_safe", "ui.markdown_view", "ui.markdown_viewer")

_SCRIPT = r'''
import ast, importlib, json, math, os, re, sys, time
try:
    import re._parser as sre_parse
    from re._constants import LITERAL, NOT_LITERAL, IN, MAX_REPEAT, MIN_REPEAT, POSSESSIVE_REPEAT, SUBPATTERN, \
        BRANCH, ATOMIC_GROUP, ASSERT, ASSERT_NOT, RANGE, NEGATE, CATEGORY, AT, AT_END
except ImportError:  # (before Python 3.11)
    import sre_parse
    from sre_constants import LITERAL, NOT_LITERAL, IN, MAX_REPEAT, MIN_REPEAT, SUBPATTERN, BRANCH, ASSERT, \
        ASSERT_NOT, RANGE, NEGATE, CATEGORY, AT, AT_END
    POSSESSIVE_REPEAT = ATOMIC_GROUP = None
sys.path.insert(0, sys.argv[1])
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
MODULES = sys.argv[2].split(",")
SIZES = [int(size) for size in sys.argv[3].split(",")]
LINEAR, PER_CHARACTER, FLOOR = float(sys.argv[4]), float(sys.argv[5]), float(sys.argv[6])
SEARCHING = {"sub", "subn", "search", "finditer", "findall", "split"}
CALLS = SEARCHING | {"compile", "match", "fullmatch"}
UNITS = ["`", "[", "]", "*", "_", "|", "\\", " ", "\t", "(", ")", "<", ">", "!", "#", "-", "=", "~", "$", ":",
         "&", "\"", "^", "{", "}", "\xa0", "a", "1", ".", "/", "@", "'", "+", ",", ";", "?", "%",
         "[a", "](", "<a", "<!--", "&#", "[^", "`a", "*a", "_a", "a ", "\\`", "http://", "www.", "a.", "a@",
         "\\begin{", "\\frac{", "a^", "a_", "{a", "<a:", "py", "a b", "\u200b", "\u3000"]
PREFIXES = ["", "x ", "# ", "> ", "- ", "1. ", "| ", "```", "```py", "    ", "a", "*", "[", "`", "<", "$", "![",
            "[a](", "> - "]
LINE_UNITS = ["```py", "~~~x", "```", "# a", "> a", "- a", "| a |", "|-|", "---", "===", "+++", "    a", "[a]: b",
              "<div>", "$$", "\\[", "[^a]: b", "a  ", "a\\", "*", "1. a", ": a", "<!--", "-->"]
sources = {name: open(importlib.import_module(name).__file__, encoding="utf-8").read() for name in MODULES}
trees = {}
for name, source in sources.items():
    trees[name] = tree = ast.parse(source)
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            child.parent = parent


def uses_of(target):
    uses = set()
    for tree in trees.values():
        for node in ast.walk(tree):
            named = (isinstance(node, ast.Name) and node.id == target) or \
                (isinstance(node, ast.Attribute) and node.attr == target)
            if not named or isinstance(getattr(node, "ctx", None), ast.Store):
                continue
            parent = getattr(node, "parent", None)
            if isinstance(parent, ast.Attribute) and parent.value is node:
                if parent.attr in CALLS:
                    uses.add(parent.attr)
            elif isinstance(parent, ast.Compare):
                continue
            else:
                uses.add("search")  # (handed on: what is done with it unknown - searched, as the worst)
    return uses


patterns = []
for name in MODULES:
    module = importlib.import_module(name)
    source, tree = sources[name], trees[name]
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr in CALLS
                and isinstance(node.func.value, ast.Name) and node.func.value.id == "re" and node.args):
            continue
        flags = None
        if node.func.attr == "compile" and len(node.args) > 1:
            flags = node.args[1]
        elif node.func.attr in ("sub", "subn") and len(node.args) > 4:
            flags = node.args[4]
        elif node.func.attr in ("search", "match", "fullmatch", "findall", "finditer") and len(node.args) > 2:
            flags = node.args[2]
        for keyword in node.keywords:
            if keyword.arg == "flags":
                flags = keyword.value
        try:
            pattern = eval("(" + ast.get_source_segment(source, node.args[0]) + ")", vars(module), {"re": re})
            flag = eval("(" + ast.get_source_segment(source, flags) + ")", vars(module), {"re": re}) if flags else 0
            compiled = re.compile(pattern, flag)
        except Exception:  # (made of a function's own values: its call is checked by the pages' tests)
            continue
        if isinstance(compiled.pattern, bytes):
            continue
        uses = set()
        if node.func.attr != "compile":
            uses.add(node.func.attr)
        else:
            parent = getattr(node, "parent", None)
            if isinstance(parent, ast.Attribute):
                uses.add(parent.attr)
            elif isinstance(parent, (ast.Assign, ast.AnnAssign)):
                targets = parent.targets if isinstance(parent, ast.Assign) else [parent.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        uses |= uses_of(target.id)
            if not uses:
                uses.add("search")
        patterns.append((f"{name}:{node.lineno}", compiled, sorted(uses)))


def ends_with_dollar(compiled) -> bool:
    """Whether the pattern ends in "$" outside MULTILINE (as the repository's guard, test_validation_regex_
    full_match, reads it): it matches before a last newline too ("http\\n" was a scheme) - "\\Z" is the
    text's end. One that ends in "\\s*$" takes the newline itself."""
    pattern = compiled.pattern
    if compiled.flags & re.MULTILINE or not pattern.endswith("$") or pattern.endswith("\\$"):
        return False
    return not re.search(r"\\s[*+]\$$", pattern)


def own_parts(compiled):
    """(the pattern's literal strings, its counts of {m,...} at least 3) - read from its parse."""
    literals, counts = set(), set()

    def walk(items):
        run = ""
        for op, av in items:
            if op is LITERAL:
                run += chr(av)
                continue
            if run:
                literals.add(run[:12])
                run = ""
            if op is IN:
                for kind, value in av:
                    if kind is LITERAL:
                        literals.add(chr(value))
                    elif kind is RANGE:
                        literals.add(chr(value[0]))
            elif op in (MAX_REPEAT, MIN_REPEAT, POSSESSIVE_REPEAT):
                low, _high, inner = av
                if 3 <= low <= 20000:
                    counts.add(low)
                walk(inner)
            elif op is SUBPATTERN:
                walk(av[-1])
            elif op is ATOMIC_GROUP:
                walk(av)
            elif op is BRANCH:
                for branch in av[1]:
                    walk(branch)
            elif op in (ASSERT, ASSERT_NOT):
                walk(av[1])
        if run:
            literals.add(run[:12])

    try:
        walk(sre_parse.parse(compiled.pattern, compiled.flags))
    except Exception:
        pass
    return sorted(literal for literal in literals if literal.strip("\n")), sorted(counts)


#: The prefixes a pattern that is searched for meets (one matched at a place meets all of PREFIXES): a
#: search tries every place anyway - the run after a word, a heading's mark, a link, a nested line.
SEARCH_PREFIXES = ["", "x ", "# ", "[a](", "> - "]


def texts(unit_list, counts, size, lines=True, prefixes=None):
    """(shape, text of about *size* characters) - every shape of every unit (and of the lines when *lines*)."""
    for unit in unit_list:
        body = unit * max(1, size // len(unit))
        for prefix in prefixes or PREFIXES:
            yield f"{prefix!r}+{unit!r}*n", prefix + body
            yield f"{prefix!r}+a+{unit!r}*n+b", prefix + "a" + body + "b"
        yield f"{unit!r}*n+x", body + "x"
    for line in (LINE_UNITS if lines else []) + [unit for unit in unit_list if len(unit) > 1]:
        yield f"({line!r}+nl)*n", (line + "\n") * max(1, size // (len(line) + 1))
    for count in counts:
        for unit in (" ", "\t", "`", "~", "*", "-", "=", "#", "a", "|", ">"):
            run = "a" + unit * (count - 1)
            yield f"(a+{unit!r}*{count - 1})*n", run * max(1, size // len(run))
            line = unit * (count - 1) + "\n"
            yield f"(a+{unit!r}*{count - 1}+nl)*n", line * max(1, size // len(line))


#: (the texts of the shared units, made once for every pattern: {(size, searched): {shape: text}})
SHARED = {}


def shared(size, searched):
    if (size, searched) not in SHARED:
        SHARED[size, searched] = dict(texts(UNITS, [], size, prefixes=SEARCH_PREFIXES if searched else None))
    return SHARED[size, searched]


def timed(call, text):
    best = 99.0
    for _ in range(3):
        began = time.perf_counter()
        call(text)
        best = min(best, time.perf_counter() - began)
        if best > 0.05:
            break
    return best


def once(call, text):
    began = time.perf_counter()
    call(text)
    return time.perf_counter() - began


flagged = []
checked = 0
began_all = time.perf_counter()
done_patterns = set()
for where, compiled, uses in patterns:
    if (compiled.pattern, compiled.flags, tuple(uses)) in done_patterns:  # (the same pattern, used alike: once)
        continue
    done_patterns.add((compiled.pattern, compiled.flags, tuple(uses)))
    began_one = time.perf_counter()
    calls = []
    if set(uses) & SEARCHING:
        # (all of it searched in C - subn: a match object made in Python for each of a text's characters, "\\s*"
        # on any text, was that much Python, not the pattern's growth)
        calls.append(("finditer", lambda text: compiled.subn("", text)))
    if "match" in uses:
        calls.append(("match", lambda text: compiled.match(text)))
    if "fullmatch" in uses:
        calls.append(("fullmatch", lambda text: compiled.fullmatch(text)))
    if ends_with_dollar(compiled) and set(uses) & {"match", "search", "fullmatch"}:
        flagged.append((where, compiled.pattern[:90], "/".join(uses), "a $ outside MULTILINE: \\Z is the end",
                        [], 0, ""))
    literals, counts = own_parts(compiled)
    own = [literal for literal in literals if literal not in UNITS]
    made = {}

    def of_size(size, searched):
        if (size, searched) not in made:
            prefixes = SEARCH_PREFIXES if searched else None
            made[size, searched] = {**shared(size, searched),
                                    **dict(texts(own, counts, size, lines=False, prefixes=prefixes))}
        return made[size, searched]

    for how, call in calls:
        searched = how == "finditer"
        of = lambda size: of_size(size, searched)  # noqa: E731
        for shape, text in of(SIZES[0]).items():
            checked += 1
            # (linear from here it stays under the floor: no closer look - from the second size, or the largest
            # for runs just short of a count: a pattern's engine gives up on a text shorter than its count at
            # once)
            look = SIZES[-1] if shape.startswith("(a+") else SIZES[1]
            if once(call, of(look)[shape]) * (SIZES[-1] / look) < FLOOR:
                continue
            times = [timed(call, text)]
            for size in SIZES[1:]:
                times.append(timed(call, of(size)[shape]))
                if times[-1] > 1.0:
                    break
            sizes = SIZES[:len(times)]
            # (the growth's exponent: from the first size whose time is over a millisecond - noise below)
            points = [(math.log(n), math.log(max(t, 1e-7))) for n, t in zip(sizes, times) if t > 0.001]
            exponent = 0.0
            if len(points) >= 2:
                exponent = (points[-1][1] - points[0][1]) / (points[-1][0] - points[0][0])
            per = times[-1] / sizes[-1]
            if (exponent > LINEAR and times[-1] > FLOOR) or per > PER_CHARACTER:
                flagged.append((where, compiled.pattern[:90], how, shape, [round(t, 4) for t in times],
                                round(exponent, 2), f"{per * 1e6:.2f} us a character"))
    if time.perf_counter() - began_one > 5:
        print(f"{where}: {time.perf_counter() - began_one:.1f} s", file=sys.stderr, flush=True)
print(f"all: {time.perf_counter() - began_all:.1f} s", file=sys.stderr)
print(json.dumps({"patterns": len(patterns), "checked": checked, "flagged": flagged}))
'''

#: The texts' sizes (characters): each twice the one before.
SIZES = (2_000, 4_000, 8_000, 16_000)
#: The growth's exponent over the doublings at most (1: linear; 2: quadratic) - above it a pattern fails
#: when its largest text took over FLOOR.
LINEAR = 1.35
#: The most a pattern may take a character of its largest text (seconds): 0.2 µs - 0.4 s for 2 MB in one
#: call. (The space runs' pattern took 0.42 µs a character on runs of 1,000.)
PER_CHARACTER = 0.2e-6
#: Times below this (seconds) are noise: never judged by their growth alone.
FLOOR = 0.004


def _audit(tmp_path) -> dict:
    script = tmp_path / "audit.py"
    script.write_text(_SCRIPT, encoding="utf-8")
    result = subprocess.run([sys.executable, str(script), str(ROOT), ",".join(AUDITED),
                             ",".join(map(str, SIZES)), str(LINEAR), str(PER_CHARACTER), str(FLOOR)],
                            capture_output=True, text=True, timeout=1800, cwd=tmp_path, env=dict(os.environ))
    assert result.returncode == 0, result.stderr[-3000:]
    return json.loads(result.stdout.strip().splitlines()[-1])


def test_sad_every_regular_expression_grows_linearly_on_texts_made_for_it(tmp_path):
    """Before: the outline's heading pattern on "# a" and a run of spaces (H1: exponent 2), the fence
    pattern on "```py" lines (H2: 2), the space runs' on runs of 1,000 between words (30 µs a character) -
    none of them flagged by the audit before."""
    report = _audit(tmp_path)
    assert report["patterns"] > 250, report["patterns"]  # (all of them looked at: none lost to a rename)
    flagged = report["flagged"]
    if flagged:  # (measured again, alone: a machine's moment is not a pattern's growth)
        again = _audit(tmp_path)["flagged"]
        flagged = [found for found in flagged if any(found[:4] == other[:4] for other in again)]
    assert not flagged, "\n".join(map(str, flagged))


def test_sad_the_audit_flags_the_patterns_review_24_found(tmp_path):
    """The audit itself: 0.16.10's heading, fence and space run patterns, put in a module of their own, are
    flagged - each by the shape that froze the window; and a scheme pattern that ends in "$" (0.16.10's
    SCHEME_RE: "http\\n://" was a link), and the long line pattern on lines just short of it (found by the
    sweep)."""
    import re

    folder = tmp_path / "old"
    folder.mkdir()
    (folder / "old_patterns.py").write_text(
        "import re\n"
        "_ATX = re.compile(r\"^ {0,3}(#{1,6})(?:[ \\t]+(.*?))?(?:[ \\t]+#+)?[ \\t]*\\Z\")\n"
        "def heading(line):\n    return _ATX.match(line)\n"
        "_FENCE_BLOCK = re.compile(r\"^(?P<lead>[ \\t>]*?)(?P<fence>`{3,}|~{3,})[ \\t]*(?P<lang>[\\w+#.-]+)[^\\n]*\\n\"\n"
        "                          r\"(?P<body>(?:.*\\n)*?)(?P=lead)(?P=fence)[`~]*[ \\t]*$\", re.MULTILINE)\n"
        "def fences(text):\n    return list(_FENCE_BLOCK.finditer(text))\n"
        "_SPACE_RUN = re.compile(\"[ \\t]{1001,}\")\n"
        "def spaces(text):\n    return _SPACE_RUN.sub('', text)\n"
        "_SCHEME = re.compile(r\"(?:^|[^a-z])([a-z]+)$\")\n"
        "def scheme(text):\n    return _SCHEME.search(text)\n"
        "_LONG_LINE = re.compile(r\"[^\\n]{2001}\")\n"
        "def long_line(text):\n    return _LONG_LINE.search(text)\n", encoding="utf-8")
    script = tmp_path / "audit.py"
    script.write_text(_SCRIPT, encoding="utf-8")
    result = subprocess.run([sys.executable, str(script), str(folder), "old_patterns", ",".join(map(str, SIZES)),
                             str(LINEAR), str(PER_CHARACTER), str(FLOOR)], capture_output=True, text=True,
                            timeout=1800, cwd=tmp_path, env=dict(os.environ))
    assert result.returncode == 0, result.stderr[-3000:]
    flagged = json.loads(result.stdout.strip().splitlines()[-1])["flagged"]
    lines = {found[0].split(":")[1] for found in flagged}
    assert {"2", "5", "9", "12", "15"} <= lines, flagged
    assert re  # (the module's own import)
