import pytest

from models.watch_tick_state import WatchTickState


def test_target_after_idle_tick_waits_for_next_completed_tick() -> None:
    state = WatchTickState()

    assert state.target_after(1) == 1

    state.mark_started()
    state.mark_completed()

    assert state.completed_at_least(1)
    assert state.target_after(1) == 2


def test_target_after_excludes_already_inflight_tick() -> None:
    state = WatchTickState()

    state.mark_started()
    target = state.target_after(1)

    assert target == 2
    state.mark_completed()
    assert not state.completed_at_least(target)

    state.mark_started()
    state.mark_completed()
    assert state.completed_at_least(target)


def test_target_after_nonpositive_ticks_uses_current_completion_boundary() -> None:
    state = WatchTickState()

    assert state.target_after(0) == 0

    state.mark_started()
    assert state.target_after(-1) == 0

    state.mark_completed()
    assert state.target_after(0) == 1


def test_mark_completed_before_started_fails_closed() -> None:
    state = WatchTickState()

    with pytest.raises(RuntimeError, match="completed before it started"):
        state.mark_completed()


@pytest.mark.parametrize(
    ("started", "completed"),
    [
        (-1, 0),
        (0, -1),
        (1, 2),
    ],
)
def test_invalid_counter_state_fails_closed(started: int, completed: int) -> None:
    state = WatchTickState(started=started, completed=completed)

    with pytest.raises(ValueError):
        state.target_after(1)
