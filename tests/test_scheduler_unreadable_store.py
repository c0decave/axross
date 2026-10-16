"""An unreadable job store is set aside, never overwritten by the next save.

Measured before: ``JobStore.load`` degraded a file it could not parse to
"no jobs" (so the app still starts), and the next ``save`` -- adding one
job in the scheduler dialog -- replaced the file with that one job. Every
schedule the user had configured was gone.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.scheduler import Job, JobStore  # noqa: E402


def _job(job_id="j1") -> Job:
    return Job(job_id=job_id, name="nightly", kind="script", target="m.py", interval_s=3600)


def _aside(tmp_path: Path) -> list[Path]:
    return sorted(p for p in tmp_path.iterdir() if p.name.startswith("jobs.json.unreadable-"))


def test_happy_a_valid_store_round_trips_without_a_side_copy(tmp_path):
    store = JobStore(tmp_path / "jobs.json")
    store.save([_job()])
    assert [j.job_id for j in store.load()] == ["j1"]
    assert _aside(tmp_path) == []


def test_sad_a_truncated_store_survives_the_next_save(tmp_path):
    path = tmp_path / "jobs.json"
    broken = '[{"job_id": "keep-me", "name": "mirror", "kind": "script", "tar'
    path.write_text(broken, encoding="utf-8")
    store = JobStore(path)
    assert store.load() == []
    store.save([_job("new")])
    assert [p.read_text(encoding="utf-8") for p in _aside(tmp_path)] == [broken]
    assert [j.job_id for j in store.load()] == ["new"]


def test_sad_a_non_list_store_is_set_aside(tmp_path):
    path = tmp_path / "jobs.json"
    path.write_text('{"jobs": []}', encoding="utf-8")
    assert JobStore(path).load() == []
    assert len(_aside(tmp_path)) == 1


def test_edge_a_missing_store_sets_nothing_aside(tmp_path):
    assert JobStore(tmp_path / "jobs.json").load() == []
    assert _aside(tmp_path) == []


def test_edge_a_malformed_row_alone_does_not_set_the_file_aside(tmp_path):
    """A readable list with one bad row keeps loading the good rows."""
    store = JobStore(tmp_path / "jobs.json")
    store.save([_job("good")])
    raw = (tmp_path / "jobs.json").read_text(encoding="utf-8")
    (tmp_path / "jobs.json").write_text(raw.replace("[", '[{"bad": 1},', 1), encoding="utf-8")
    assert [j.job_id for j in store.load()] == ["good"]
    assert _aside(tmp_path) == []
