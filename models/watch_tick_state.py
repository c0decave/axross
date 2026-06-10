"""Tick accounting for polling filesystem watchers."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(slots=True)
class WatchTickState:
    """Tracks started/completed poll ticks.

    ``started`` advances before a snapshot is taken; ``completed`` advances
    after the snapshot is diffed. Callers must hold the surrounding watcher
    condition lock while mutating or reading this state.

    Invariant: ``0 <= completed <= started`` at all times. Two exception
    types signal distinct failure classes so callers can react differently:

    * ``RuntimeError`` from :meth:`mark_completed` when no started tick is
      in flight (``completed == started``). The caller's call order is
      wrong; the state itself is still valid.
    * ``ValueError`` from :meth:`_ensure_valid` when the invariant is
      already broken (negative counters or ``completed > started``). The
      state is corrupt; recovery requires reconstruction, not retry.
    """

    started: int = 0
    completed: int = 0

    def mark_started(self) -> None:
        self._ensure_valid()
        self.started += 1

    def mark_completed(self) -> None:
        self._ensure_valid()
        if self.completed >= self.started:
            raise RuntimeError("watch tick completed before it started")
        self.completed += 1

    def target_after(self, ticks: int) -> int:
        """Return the completed-tick count needed for a future wait.

        In-flight ticks are intentionally excluded because their snapshot may
        already have captured stale state before the caller made a mutation.
        """

        self._ensure_valid()
        if ticks < 1:
            return self.completed
        return max(self.started, self.completed) + ticks

    def completed_at_least(self, target: int) -> bool:
        self._ensure_valid()
        return self.completed >= target

    def _ensure_valid(self) -> None:
        if self.started < 0 or self.completed < 0:
            raise ValueError("watch tick counters cannot be negative")
        if self.completed > self.started:
            raise ValueError("watch tick completed count exceeds started count")
