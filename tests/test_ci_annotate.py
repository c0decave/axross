"""scripts/ci_annotate.py: text as GitHub error annotations, in pieces."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

import ci_annotate as CA  # noqa: E402


def _data(command: str) -> str:
    return command.split("::", 2)[2].replace("%0A", "\n").replace("%25", "%")


def test_happy_a_short_text_is_one_annotation():
    lines = CA.commands("build", "one\ntwo 100%\n")
    assert lines == ["::error title=build (1/1)::one%0Atwo 100%25%0A"]


def test_happy_a_long_text_keeps_its_end_and_cuts_at_line_ends():
    text = "".join(f"line {n:05d}\n" for n in range(5000))
    lines = CA.commands("log", text, count=3)
    assert len(lines) == 3
    joined = "".join(_data(line) for line in lines)
    assert joined.endswith("line 04999\n") and joined.startswith("line ")
    assert all(_data(line).endswith("\n") for line in lines)
    assert all(len(_data(line)) <= CA.PIECE for line in lines)


def test_happy_head_keeps_the_start_of_a_diff():
    text = "".join(f"+row {n}\n" for n in range(5000))
    first = _data(CA.commands("diff", text, count=2, head=True)[0])
    assert first.startswith("+row 0\n")


def test_sad_never_more_than_github_keeps_per_step():
    text = "x" * (CA.PIECE * 30)
    assert len(CA.commands("t", text, count=50)) == CA.MAX_PIECES


def test_edge_colour_codes_and_carriage_returns_go_and_the_title_is_escaped():
    line = CA.commands("a: b, c", "\x1b[31mred\x1b[0m\r\n")[0]
    assert line.startswith("::error title=a%3A b%2C c (1/1)::")
    assert _data(line) == "red\n"


def test_edge_empty_input_prints_nothing(capsys, monkeypatch):
    import io

    monkeypatch.setattr(sys, "stdin", io.StringIO("  \n"))
    assert CA.main(["t"]) == 0
    assert capsys.readouterr().out == ""
