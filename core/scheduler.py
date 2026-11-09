"""Recurring jobs — deciding what is due, and remembering what happened.

axross has scripts, profiles and a transfer engine, but nothing ran any
of it on a timer: "mirror this nightly" meant an external cron entry
that knows none of the app's connections or credentials.

Everything here is deliberately free of execution. Deciding WHEN a job
is due is arithmetic over stored state, and keeping it pure is what
makes "did it skip a run?" a question with a testable answer instead of
one you wait a day to observe. The GUI owns the timer and the actual
running; this module owns the decision.

Three rules earn their place:

* **A running job is not started again.** Two concurrent runs of a
  mirror put two writers on one destination.
* **A missed window does not queue up.** A laptop closed over the
  weekend must not wake to forty-eight backlogged hourly runs; it runs
  once and carries on.
* **A failed run still moves the clock, and repeated failure disables
  the job.** Otherwise a permanently failing job retries as fast as the
  tick allows, hammering a host that has already said no.
"""

from __future__ import annotations

import json
import logging
import os
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta
from pathlib import Path

from core.secure_storage import locked_store_update, write_secret_file

log = logging.getLogger(__name__)

#: Consecutive failures after which a job disables itself. A schedule
#: that fails every time is not a schedule, it is a retry loop.
MAX_CONSECUTIVE_FAILURES = 10
#: The shortest interval the Scheduled Jobs window offers and accepts.
MIN_INTERVAL_S = 300

#: Wall-clock limit of one scheduled script run. Generous on purpose (a
#: nightly mirror may take hours); it exists so a hung script ends as a
#: recorded failure instead of blocking its job forever ("a running job is
#: not started again").
SCRIPT_TIMEOUT_S = 24 * 3600

#: Characters of stdout (and of stderr) a scheduled run may produce before
#: it is stopped. Nobody watches the output; only its tail reaches the
#: job's detail on failure.
SCRIPT_OUTPUT_CHARS = 1_000_000


@dataclass(frozen=True)
class Job:
    """One recurring task."""

    job_id: str
    name: str
    #: ``"script"`` or ``"sync"`` — what the runner should do.
    kind: str
    #: Script name, or an opaque identifier the runner understands.
    target: str
    interval_s: int
    enabled: bool = True
    last_run_at: datetime | None = None
    last_ok: bool | None = None
    last_detail: str = ""
    consecutive_failures: int = 0
    #: Whether a run is in flight *in this process*. Never persisted.
    running: bool = False
    details: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.interval_s <= 0:
            # A zero or negative interval makes the job due on every
            # tick — a tight loop wearing the disk, not a schedule.
            raise ValueError(f"interval_s must be positive, got {self.interval_s}")


def next_run_at(job: Job, *, now: datetime) -> datetime | None:
    """When ``job`` should next run, or ``None`` if it should not.

    A job that has never run is due immediately: the user just created
    it and would otherwise watch nothing happen for a full interval.
    """
    if not job.enabled:
        return None
    if job.last_run_at is None:
        return now
    try:
        return job.last_run_at + timedelta(seconds=job.interval_s)
    except OverflowError:
        # Past the calendar (a hand-edited interval of 10**15 s, or a last
        # run near datetime.max): never due, rather than an exception on
        # every tick and in the Scheduler window.
        return None


def due_jobs(jobs: list[Job], *, now: datetime) -> list[Job]:
    """Every job that should start right now.

    A job already in flight is excluded, and an overdue job appears
    exactly once no matter how long the outage was — the schedule is a
    cadence, not a queue.
    """
    due: list[Job] = []
    for job in jobs:
        if job.running:
            continue
        when = next_run_at(job, now=now)
        if when is not None and when <= now:
            due.append(job)
    return due


def planned_start(job: Job, *, now: datetime) -> datetime:
    """The time a run started at *now* stands for, recorded as its
    ``last_run_at``: the slot it was due at, so "every 1 h" stays on the
    hour instead of drifting by each run's length (and the tick's delay).
    A slot missed by a whole interval or more (the machine was off) is
    not caught up on: the run counts from *now*."""
    when = next_run_at(job, now=now)
    if when is None or when > now:
        return now
    try:
        late = now - when >= timedelta(seconds=job.interval_s)
    except OverflowError:
        late = False
    return now if late else when


def reenabled(job: Job) -> Job:
    """*job* switched on by the user: its failure count starts over (one
    more transient failure must not disable it again at once), and the
    "disabled after N consecutive failures" note leaves its detail."""
    detail = job.last_detail
    marker = detail.rfind(" — disabled after ")
    if marker >= 0 and detail.endswith(" consecutive failures"):
        detail = detail[:marker]
    elif detail.startswith("disabled after ") and detail.endswith(" consecutive failures"):
        detail = ""
    return replace(job, enabled=True, consecutive_failures=0, last_detail=detail)


def record_result(job: Job, *, ok: bool, at: datetime, detail: str = "") -> Job:
    """Return ``job`` updated with the outcome of a run.

    The clock moves on failure too. Leaving it untouched would make a
    failing job due again on the very next tick, turning a nightly
    mirror into a hot loop against a host that is already unhappy.
    """
    failures = 0 if ok else job.consecutive_failures + 1
    enabled = job.enabled
    if not ok and failures >= MAX_CONSECUTIVE_FAILURES:
        enabled = False
        detail = f"{detail} — disabled after {failures} consecutive failures".strip(" —")
        log.warning("scheduler: disabling %s after %d failures", job.name, failures)

    return replace(
        job,
        last_run_at=at,
        last_ok=ok,
        last_detail=detail,
        consecutive_failures=failures,
        enabled=enabled,
        running=False,
    )


class JobStore:
    """JSON-backed job list.

    Lives in the user's state directory and is written by a running
    app, so every read path degrades to "no jobs" rather than raising:
    a truncated write must not stop the application from starting.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)

    def load(self, *, strict: bool = False) -> list[Job]:
        """The stored jobs; [] when there are none or the file cannot be
        read. *strict* (before a save): a file that exists but cannot be
        read (permissions, I/O) is an OSError - saving over it would
        replace every job with the few the caller knows."""
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            return []
        except (ValueError, RecursionError) as exc:
            log.warning("scheduler: ignoring unreadable job store %s: %s", self.path, exc)
            self._set_aside()
            return []
        except OSError as exc:
            if strict:
                raise
            log.warning("scheduler: ignoring unreadable job store %s: %s", self.path, exc)
            return []
        if not isinstance(raw, list):
            log.warning("scheduler: job store %s is not a list; ignoring", self.path)
            self._set_aside()
            return []

        jobs: list[Job] = []
        for row in raw:
            if not isinstance(row, dict):
                continue
            try:
                jobs.append(
                    Job(
                        job_id=str(row["job_id"]),
                        name=str(row["name"]),
                        kind=str(row["kind"]),
                        target=str(row["target"]),
                        interval_s=int(row["interval_s"]),
                        # Only a JSON true switches a job on: a hand-edited
                        # "false" is truthy and would run a job the user
                        # switched off. A missing key keeps the old default.
                        enabled=row.get("enabled", True) is True,
                        last_run_at=_parse_dt(row.get("last_run_at")),
                        last_ok=row.get("last_ok"),
                        last_detail=str(row.get("last_detail", "")),
                        consecutive_failures=int(row.get("consecutive_failures", 0)),
                        # `running` describes THIS process. Persisting it
                        # would leave a job permanently "running" after a
                        # crash, and it would never start again.
                        running=False,
                        details=row.get("details") or {},
                    )
                )
            except (KeyError, TypeError, ValueError, OverflowError) as exc:
                # OverflowError: int() of a hand-edited Infinity.
                log.warning("scheduler: dropping malformed job row: %s", exc)
        return jobs

    def _set_aside(self) -> None:
        """Move an unparseable store out of the way of the next save.

        Loading degrades to "no jobs" so the app still starts; without
        this, the next save would replace every configured job with
        whatever the user added after the failed load.
        """
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        aside = self.path.with_name(f"{self.path.name}.unreadable-{stamp}-{uuid.uuid4().hex[:8]}")
        try:
            os.rename(self.path, aside)
        except OSError as exc:
            log.error("scheduler: could not set %s aside: %s", self.path, exc)
            return
        log.warning("scheduler: unreadable job store kept as %s", aside)

    def update(self, change: Callable[[list[Job]], list[Job]]) -> list[Job]:
        """Load, apply ``change`` and save, under a file lock, and return
        the saved jobs. Every writer of the store (the main window
        recording a run, the Scheduler dialog) goes through here, so none
        writes back a list that is older than the file."""
        with locked_store_update(self.path):
            jobs = change(self.load(strict=True))
            self.save(jobs)
            return jobs

    def save(self, jobs: list[Job]) -> None:
        payload = [
            {
                "job_id": j.job_id,
                "name": j.name,
                "kind": j.kind,
                "target": j.target,
                "interval_s": j.interval_s,
                "enabled": j.enabled,
                "last_run_at": j.last_run_at.isoformat() if j.last_run_at else None,
                "last_ok": j.last_ok,
                "last_detail": j.last_detail,
                "consecutive_failures": j.consecutive_failures,
                "details": j.details,
            }
            for j in jobs
        ]
        # Write-then-rename (a crash mid-write must not leave the user
        # with a half-written schedule), 0o600 like every other store.
        write_secret_file(str(self.path), json.dumps(payload, indent=2))


class RunCancelled(RuntimeError):
    """A run stopped because the application closed during it: no failure
    of the job (it counted towards disabling it, and "failed" stood in
    the Scheduler)."""


def run_job(job: Job, *, runner, on_finished) -> None:
    """Execute one job and report the outcome through ``on_finished``.

    Kept here, and free of Qt, so the try/except that turns a raising
    job into a recorded failure is testable without a running
    application. A scheduled job that throws must not take down
    whatever invoked the tick.

    The caller is responsible for running this off the GUI thread — the
    first wiring called the script straight from the timer slot, which
    froze the window for as long as the job took, which is the one thing
    a background schedule must never do.

    ``on_finished(job, ok, detail)``: *ok* is None for a run stopped
    because the application closed (:class:`RunCancelled`) - not run,
    rather than failed.
    """
    try:
        detail = runner(job)
    except RunCancelled as exc:
        log.info("scheduler: job %s stopped: %s", job.name, exc)
        on_finished(job, None, str(exc))
        return
    except BaseException as exc:  # noqa: BLE001 — a bad job must not escape
        # BaseException, not Exception: this is the top of a worker
        # thread, and a SystemExit leaving it took the whole app down.
        log.warning("scheduler: job %s failed: %r", job.name, exc)
        on_finished(job, False, str(exc) or type(exc).__name__)
        return
    on_finished(job, True, str(detail) if detail else "")


def script_target(target: str) -> str:
    """The saved-script name a script job runs. A trailing ``.py`` is
    dropped (scripts are listed and run by name, but the file on disk is
    ``<name>.py``); raises ``ValueError`` for a name scripts refuse."""
    from core import scripting

    name = target.strip()
    if name.endswith(".py"):
        name = name[: -len(".py")]
    return scripting._validate_script_name(name)  # noqa: SLF001


def run_script_job(
    job: Job,
    *,
    cancel_event=None,
    timeout_s: float = SCRIPT_TIMEOUT_S,
) -> str:
    """Run a job: a script job runs its saved script in a child process,
    as the Scripts dock and the MCP ``script_run`` tool do
    (:func:`core.script_runner.run_bounded`). Whatever the script does -
    ``sys.exit()``, a crash, an endless loop - stays in the child. Returns
    the success detail; raises with the failure detail.

    The child is not interactive: a prompt or a production-profile
    countdown refuses instead of waiting for someone who is not there.
    """
    if job.kind != "script":
        raise ValueError(f"unknown job kind {job.kind!r}")
    from core import script_runner, scripting
    from core.security_mode import current_policy, require
    from core.ui_helpers import ENV_NONINTERACTIVE

    require("saved script execution", current_policy().allow_scripts)
    name = script_target(job.target)
    try:
        scripting.load_script(name)  # a missing script fails here, before a child starts
    except FileNotFoundError:
        # Not "[Errno 2] No such file or directory: '/home/…/scripts/x.py'".
        raise RuntimeError(
            f"the saved script {name!r} does not exist (any more): save it in the Scripts "
            "dock under that name, or remove this job") from None
    run = script_runner.run_bounded(
        name,
        timeout_s=timeout_s,
        max_output_chars=SCRIPT_OUTPUT_CHARS,
        cancel_event=cancel_event,
        env_overrides={ENV_NONINTERACTIVE: "1"},
    )
    if run.cancelled:
        raise RunCancelled("cancelled: the application closed during the run")
    if run.timed_out:
        raise RuntimeError(f"timed out after {timeout_s:g} s")
    if run.output_exceeded:
        raise RuntimeError(
            f"{run.output_exceeded} exceeded {SCRIPT_OUTPUT_CHARS} characters; "
            "the script was stopped"
        )
    if run.error_type:
        raise RuntimeError(f"{run.error_type}: {run.error or ''}".rstrip(": "))
    if run.exit != 0:
        last = run.stderr.strip().splitlines()[-1:] if run.stderr.strip() else []
        raise RuntimeError(f"exited with status {run.exit}" + (f": {last[0]}" if last else ""))
    return f"ran {name}"


def _parse_dt(value) -> datetime | None:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        # axross keeps naive local times (datetime.now()); a hand-edited
        # "...Z" compared with them raised TypeError on every tick.
        try:
            parsed = parsed.astimezone().replace(tzinfo=None)
        except (OverflowError, ValueError):
            return None
    return parsed


__all__ = [
    "MAX_CONSECUTIVE_FAILURES",
    "MIN_INTERVAL_S",
    "Job",
    "JobStore",
    "RunCancelled",
    "due_jobs",
    "next_run_at",
    "planned_start",
    "record_result",
    "reenabled",
    "run_job",
    "run_script_job",
    "script_target",
]
