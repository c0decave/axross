"""Appending a journal event does only the work that changes the result.

Measured before (per event, tmpfs): ``mkdir(parents=True, exist_ok=True)``
on every event 14 µs, a text-mode ``fdopen`` per line, and ``redact``
walking ABC ``isinstance`` checks for every plain str / dict (25 µs).
Trashing 1 000 files writes ~4 000 events.

The reference functions below are verbatim copies of the code before the
change; the A/B tests hold byte-identical journal lines and identical
redaction results.
"""

from __future__ import annotations

import collections
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from core import operation_journal as OJ  # noqa: E402
from core import redaction as R  # noqa: E402


# --- verbatim reference (before the change) --------------------------------
def _old_redact(value):
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        try:
            return R.redact_text(value.decode("utf-8", errors="replace"))
        except Exception:
            return "<bytes>"
    if isinstance(value, str):
        return R.redact_text(value)
    if isinstance(value, Mapping):
        out = {}
        for key, item in value.items():
            out[key] = "<redacted>" if R._is_sensitive_key(key) else _old_redact(item)
        return out
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes, bytearray)):
        return [_old_redact(item) for item in value]
    return R.redact_text(str(value))


def _old_append_line(event, path: Path) -> None:
    payload = _old_redact(asdict(event))
    line = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    with os.fdopen(fd, "a", encoding="utf-8") as handle:
        handle.write(line + "\n")


# --- corpus ------------------------------------------------------------------
@dataclass
class _Inner:
    password: str
    n: int


class _StrSub(str):
    pass


class _DictSub(dict):
    pass


def _values():
    return [
        None, True, 0, -3, 1.5, float("inf"), "", "plain", "a b", "token=x",
        "Ünïcödé — ✓", b"bytes token=1", b"\xff\xfe", bytearray(b"ba"), _StrSub("sub"),
        ("t", 1), ["l", {"secret": 1}], {"password": "x", "k": [1, "pwd=2"]},
        _DictSub(token="t", ok="v"), collections.OrderedDict(b=1, a="s p"),
        collections.UserDict({"api_key": "k"}), range(3), {1, 2}, _Inner("p", 1),
        {"nested": {"deeper": {"sig": "s", "list": [b"x", None]}}},
        {7: "int key", None: "none key", ("a",): "tuple key"},
    ]


def _events():
    # The mixed-key dict is left out: json.dumps(sort_keys=True) cannot
    # order its keys, old and new alike.
    for i, v in enumerate(_values()[:-1]):
        yield OJ.JournalEvent(
            operation_id=f"id{i}",
            phase="start",
            operation="trash",
            timestamp="2026-10-14T00:00:00+00:00",
            source=f"/src/{i} x",
            dest="https://u:p@h/x?sig=1",
            error="password=hunter2" if i % 2 else "",
            details={"v": v, "password": "pw", "i": i},
        )


class RedactFastPathTest(unittest.TestCase):
    def test_happy_redact_equals_the_old_function(self) -> None:
        for v in _values():
            with self.subTest(v=repr(v)[:40]):
                new, old = R.redact(v), _old_redact(v)
                self.assertEqual(new, old)
                self.assertIs(type(new), type(old))

    def test_happy_dict_key_order_is_kept(self) -> None:
        self.assertEqual(list(R.redact({"b": 1, "a": 2, "token": 3})), ["b", "a", "token"])


class AppendTest(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def test_happy_lines_are_byte_identical_to_the_old_code(self) -> None:
        new, old = self.tmp / "new" / "j.jsonl", self.tmp / "old" / "j.jsonl"
        for ev in _events():
            OJ.append_event(ev, journal_path=new)
            _old_append_line(ev, old)
        self.assertEqual(new.read_bytes(), old.read_bytes())

    def test_happy_an_existing_directory_is_not_created_again(self) -> None:
        path = self.tmp / "j.jsonl"
        ev = next(_events())
        OJ.append_event(ev, journal_path=path)
        with mock.patch.object(Path, "mkdir", side_effect=AssertionError("mkdir per event")):
            OJ.append_event(ev, journal_path=path)
        self.assertEqual(len(path.read_text().splitlines()), 2)

    def test_sad_a_missing_or_deleted_directory_is_created(self) -> None:
        path = self.tmp / "a" / "b" / "j.jsonl"
        ev = next(_events())
        OJ.append_event(ev, journal_path=path)
        shutil.rmtree(self.tmp / "a")
        OJ.append_event(ev, journal_path=path)
        self.assertEqual(len(path.read_text().splitlines()), 1)

    def test_sad_a_file_in_place_of_the_directory_raises(self) -> None:
        (self.tmp / "blocker").write_text("x")
        with self.assertRaises(OSError):
            OJ.append_event(next(_events()), journal_path=self.tmp / "blocker" / "j.jsonl")

    def test_edge_mode_is_tightened_to_0600_on_an_existing_file(self) -> None:
        path = self.tmp / "j.jsonl"
        path.write_text("")
        path.chmod(0o644)
        OJ.append_event(next(_events()), journal_path=path)
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_edge_large_line_is_written_whole(self) -> None:
        path = self.tmp / "j.jsonl"
        ev = OJ.JournalEvent(operation_id="x", phase="p", operation="o", details={"k": "v" * 300_000})
        OJ.append_event(ev, journal_path=path)
        self.assertEqual(json.loads(path.read_text())["details"]["k"], "v" * 300_000)


if __name__ == "__main__":
    unittest.main()
