"""Setting an unreadable job store aside never moves another writer's file.

Measured before: ``JobStore.load`` read a broken jobs.json, then renamed
whatever was at the path at that moment - outside the store lock. When a
second axross had meanwhile set the broken file aside itself and saved its
jobs, the first one renamed that fresh, valid store away: every job was
gone from jobs.json (and the second process's save looked lost).

Now the set-aside happens under the store lock and only when the file is
still the one that could not be read; the load then reads the new file.
A malformed row a save would drop is kept in a copy first.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import scheduler  # noqa: E402
from core.scheduler import Job, JobStore  # noqa: E402


def _job(job_id="j1") -> Job:
    return Job(job_id=job_id, name="nightly", kind="script", target="m.py", interval_s=3600)


def _aside(tmp_path: Path) -> list[Path]:
    return sorted(p for p in tmp_path.iterdir() if p.name.startswith("jobs.json.unreadable-"))


def test_sad_a_store_replaced_after_the_failed_read_is_not_set_aside(tmp_path, monkeypatch):
    path = tmp_path / "jobs.json"
    path.write_text("[{broken", encoding="utf-8")
    other = JobStore(path)
    real_loads = json.loads
    calls = {"n": 0}

    def loads_then_other_writer(text, *args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            # The other process: sets the broken file aside, saves its jobs.
            path.rename(tmp_path / "jobs.json.unreadable-other")
            other.save([_job("theirs")])
        return real_loads(text, *args, **kwargs)

    monkeypatch.setattr(scheduler.json, "loads", loads_then_other_writer)
    jobs = JobStore(path).load()
    monkeypatch.setattr(scheduler.json, "loads", real_loads)

    assert path.exists(), "the other writer's store was renamed away"
    assert [j.job_id for j in JobStore(path).load()] == ["theirs"]
    assert [j.job_id for j in jobs] == ["theirs"]
    assert [p.name for p in _aside(tmp_path)] == ["jobs.json.unreadable-other"]


def test_happy_a_store_still_broken_is_set_aside_once(tmp_path):
    path = tmp_path / "jobs.json"
    path.write_text("[{broken", encoding="utf-8")
    assert JobStore(path).load() == []
    kept = _aside(tmp_path)
    assert [p.read_text(encoding="utf-8") for p in kept] == ["[{broken"]
    assert not path.exists()


def test_sad_a_malformed_row_is_kept_in_a_copy_before_a_save_drops_it(tmp_path):
    path = tmp_path / "jobs.json"
    good = {"job_id": "good", "name": "n", "kind": "script", "target": "t", "interval_s": 3600}
    raw = json.dumps([good, {"job_id": "bad", "interval_s": "soon"}])
    path.write_text(raw, encoding="utf-8")
    store = JobStore(path)
    store.update(lambda jobs: jobs + [_job("new")])
    assert [j.job_id for j in store.load()] == ["good", "new"]
    assert [p.read_text(encoding="utf-8") for p in _aside(tmp_path)] == [raw]
    # The file no longer holds the row: no second copy.
    store.update(lambda jobs: jobs)
    assert len(_aside(tmp_path)) == 1
