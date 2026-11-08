"""The operation journal keeps its file open and builds event lines directly.

Measured before (worker profile, 1 000 local 4 KiB files): append_event was
38 % of the worker's time - a dataclasses.asdict deep copy and redaction
per event, then open, chmod, write and close of the journal file, and an
INFO log line; three events per file. Now the file descriptor stays open
(checked by one stat per event to still be the journal), the line is built
field by field, and an event that went as planned logs at DEBUG.

What must not change: every event is in the file when append_event
returns (an interrupted move is found in the journal after a crash at any
point), the lines are byte-identical, a journal deleted or replaced while
open gets the next events, and its mode stays 0600.
"""

from __future__ import annotations

import json
import logging
import os
import random
import stat
import subprocess
import sys
import textwrap
from dataclasses import asdict
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from core import operation_journal as OJ  # noqa: E402


def _event(i: int = 0, **kw) -> OJ.JournalEvent:
    base = dict(operation_id=f"op{i}", phase="worker_start", operation="move",
                source=f"/src/f{i}.bin", dest=f"/dst/f{i}.bin", bytes_total=4096,
                details={"direction": "UPLOAD", "source_backend": "Local"})
    base.update(kw)
    return OJ.JournalEvent(**base)


def _lines(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


@pytest.fixture(autouse=True)
def _fresh_file():
    OJ._FILE.close()
    yield
    OJ._FILE.close()


# -- happy ---------------------------------------------------------------------------------


def test_happy_every_event_is_in_the_file_when_append_returns(tmp_path):
    path = tmp_path / "j.jsonl"
    for i in range(5):
        OJ.append_event(_event(i), journal_path=path)
        # Read by another handle: nothing waits in this process for a flush.
        assert [e["operation_id"] for e in _lines(path)] == [f"op{k}" for k in range(i + 1)]


def test_happy_the_descriptor_is_kept_between_events(tmp_path, monkeypatch):
    path = tmp_path / "j.jsonl"
    OJ.append_event(_event(0), journal_path=path)
    opened = []
    real_open = os.open
    monkeypatch.setattr(os, "open", lambda *a, **k: opened.append(a[0]) or real_open(*a, **k))
    for i in range(1, 20):
        OJ.append_event(_event(i), journal_path=path)
    assert opened == []
    assert len(_lines(path)) == 20


def test_happy_an_interrupted_move_is_in_the_journal_after_the_process_dies(tmp_path):
    """The process is killed right after the worker_start of a move (no
    exit handlers, no flush): the start and worker_start are both there,
    with no finish - what tells the user the move did not complete."""
    path = tmp_path / "j.jsonl"
    code = textwrap.dedent(
        f"""
        import os, sys
        sys.path.insert(0, {str(ROOT)!r})
        from core import operation_journal as OJ
        op = OJ.start_operation("move", source="/a/x", dest="/b/x",
                                details={{"direction": "UPLOAD"}})
        OJ.record_phase(op, "worker_start", "move", source="/a/x", dest="/b/x")
        os.kill(os.getpid(), 9)
        """
    )
    env = {**os.environ, "AXROSS_OPERATION_JOURNAL": str(path)}
    env.pop("PYTEST_CURRENT_TEST", None)
    proc = subprocess.run([sys.executable, "-c", code], env=env, timeout=60)
    assert proc.returncode == -9
    events = OJ.read_recent(10, journal_path=path)
    assert [e["phase"] for e in events] == ["start", "worker_start"]
    assert events[0]["operation_id"] == events[1]["operation_id"]
    from core.undo import undoable

    assert undoable(events) == []  # unfinished: nothing claims it was done


def test_happy_payload_equals_the_asdict_redaction_it_replaces():
    """The field-by-field line equals redaction of asdict(event), as the
    old code built it, over random plain and secret-looking values."""
    rnd = random.Random(7)
    strs = ["", "plain", "a b", "token=x", "password=hunter2", "https://u:p@h/x?sig=1",
            "/a/b c", "2026-10-14T00:00:00+00:00", "2026-10-14T00:00:00.5Z", "Basic abc",
            "Authorization: Bearer abc", "x:y", "Ünïcödé"]
    values = strs + [0, 3, -1, 1.5, True, None]
    keys = ["direction", "password", "path", "temp", "batch", "x", "token", "trash_root"]
    for _ in range(2000):
        details = rnd.choice([None, {}, {k: rnd.choice(values)
                                         for k in rnd.sample(keys, rnd.randint(0, 5))}])
        if details and rnd.random() < 0.3:
            details["nested"] = {"secret": "s", "list": [rnd.choice(values), {"path": "/p q"}]}
        event = OJ.JournalEvent(
            operation_id=rnd.choice(strs), phase=rnd.choice(strs), operation="transfer",
            timestamp=rnd.choice(strs), status=rnd.choice(["", "done", "error"]),
            source=rnd.choice(strs), dest=rnd.choice(strs), backend=rnd.choice(strs),
            bytes_total=rnd.choice([0, 5]), bytes_done=rnd.choice([0, True]),
            error=rnd.choice(strs), details=details,
        )
        batch = rnd.choice(["", "b1"])
        old = event
        if batch and not (event.details or {}).get("batch"):
            old = OJ.JournalEvent(**{**asdict(event),
                                     "details": {**(event.details or {}), "batch": batch}})
        want = json.dumps(OJ._redact_event(asdict(old)), sort_keys=True)
        assert json.dumps(OJ._event_payload(event, batch), sort_keys=True) == want


def test_happy_a_planned_event_logs_at_debug_an_error_at_warning(tmp_path, caplog):
    path = tmp_path / "j.jsonl"
    with caplog.at_level(logging.DEBUG, logger="core.operation_journal"):
        OJ.append_event(_event(1, status="active"), journal_path=path)
        OJ.append_event(_event(2, phase="finish", status="error", error="boom"),
                        journal_path=path)
    levels = [(r.levelno, "operation_id='op1'" in r.getMessage()) for r in caplog.records
              if r.name == "core.operation_journal"]
    assert levels == [(logging.DEBUG, True), (logging.WARNING, False)]


# -- sad -----------------------------------------------------------------------------------


def test_sad_a_journal_replaced_while_open_gets_the_next_events(tmp_path):
    path = tmp_path / "j.jsonl"
    OJ.append_event(_event(0), journal_path=path)
    other = tmp_path / "new.jsonl"
    other.write_text("")
    os.replace(other, path)  # a rotation, a restore from backup
    OJ.append_event(_event(1), journal_path=path)
    assert [e["operation_id"] for e in _lines(path)] == ["op1"]


def test_sad_a_journal_deleted_while_open_is_created_again(tmp_path):
    path = tmp_path / "j.jsonl"
    OJ.append_event(_event(0), journal_path=path)
    path.unlink()
    OJ.append_event(_event(1), journal_path=path)
    assert [e["operation_id"] for e in _lines(path)] == ["op1"]
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_sad_a_failed_write_reopens_for_the_next_event(tmp_path, monkeypatch):
    path = tmp_path / "j.jsonl"
    OJ.append_event(_event(0), journal_path=path)
    real_write = os.write
    monkeypatch.setattr(os, "write", lambda fd, data: (_ for _ in ()).throw(OSError(5, "EIO")))
    with pytest.raises(OSError):
        OJ.append_event(_event(1), journal_path=path)
    assert OJ._FILE.fd == -1
    monkeypatch.setattr(os, "write", real_write)
    OJ.append_event(_event(2), journal_path=path)
    assert [e["operation_id"] for e in _lines(path)] == ["op0", "op2"]


# -- edge ----------------------------------------------------------------------------------


def test_edge_a_mode_widened_while_open_is_tightened_again(tmp_path):
    path = tmp_path / "j.jsonl"
    OJ.append_event(_event(0), journal_path=path)
    path.chmod(0o644)
    OJ.append_event(_event(1), journal_path=path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600


def test_edge_two_journals_alternating_each_get_their_events(tmp_path):
    a, b = tmp_path / "a.jsonl", tmp_path / "b.jsonl"
    for i in range(4):
        OJ.append_event(_event(i), journal_path=a if i % 2 == 0 else b)
    assert [e["operation_id"] for e in _lines(a)] == ["op0", "op2"]
    assert [e["operation_id"] for e in _lines(b)] == ["op1", "op3"]


def test_edge_details_none_stays_null(tmp_path):
    path = tmp_path / "j.jsonl"
    OJ.append_event(OJ.JournalEvent(operation_id="x", phase="p", operation="o", details=None),
                    journal_path=path)
    assert _lines(path)[0]["details"] is None
