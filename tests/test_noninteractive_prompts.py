"""Confirmations fail closed when no human can answer them.

``axross.confirm()`` fell back to ``input()`` without Qt and returned
``default_yes`` on EOF, so a script run with closed stdin (an MCP
``script_run`` child, the Scripts dock, cron, ``--script`` from a pipe)
silently approved every ``confirm(..., default_yes=True)``. The headless
production tarpit printed a countdown nobody could interrupt and then
went ahead.

Now a run is interactive only when a human can be asked: no
``AXROSS_NONINTERACTIVE``, and either a Qt application on its GUI thread
(dialogs) or a terminal on stdin. Otherwise ``confirm()`` raises
``NonInteractiveError`` unless the script passed ``assume_yes=True``,
and the headless tarpit raises unless ``AXROSS_TARPIT_DISABLE=1``.
A human at a terminal or in the GUI sees no change.
"""

from __future__ import annotations

import threading
from unittest import mock

import pytest

from core import safety_tarpit
from core import scripting as axross
from core import ui_helpers as U


@pytest.fixture
def unattended(monkeypatch):
    """No Qt, no terminal, no override: nobody can answer."""
    monkeypatch.delenv(U.ENV_NONINTERACTIVE, raising=False)
    monkeypatch.setattr(U, "_qt_is_running", lambda: False)
    monkeypatch.setattr(U, "_stdin_is_terminal", lambda: False)


@pytest.fixture
def at_terminal(monkeypatch):
    """A human at a terminal, no Qt."""
    monkeypatch.delenv(U.ENV_NONINTERACTIVE, raising=False)
    monkeypatch.setattr(U, "_qt_is_running", lambda: False)
    monkeypatch.setattr(U, "_stdin_is_terminal", lambda: True)


def _no_input(*_a, **_kw):
    raise AssertionError("input() must not be called without a human")


# -- confirm ------------------------------------------------------------------------


def test_happy_a_human_at_a_terminal_is_still_asked(at_terminal) -> None:
    with mock.patch("builtins.input", return_value="y") as asked:
        assert U.confirm("Delete?") is True
    asked.assert_called_once()
    with mock.patch("builtins.input", side_effect=EOFError):
        # Ctrl-D at the prompt still answers the default, as before.
        assert U.confirm("Delete?", default_yes=True) is True


def test_happy_assume_yes_answers_yes_without_a_human(unattended) -> None:
    with mock.patch("builtins.input", side_effect=_no_input):
        assert U.confirm("Delete 47 files?", assume_yes=True) is True


def test_happy_a_human_is_asked_even_with_assume_yes(at_terminal) -> None:
    # assume_yes only stands in for a missing human; it never outvotes one.
    with mock.patch("builtins.input", return_value="n"):
        assert U.confirm("Delete?", assume_yes=True) is False


@pytest.mark.parametrize("default_yes", [True, False])
def test_sad_without_a_human_confirm_raises_instead_of_answering(unattended, default_yes) -> None:
    with mock.patch("builtins.input", side_effect=_no_input):
        with pytest.raises(U.NonInteractiveError) as caught:
            U.confirm("Delete 47 files?", default_yes=default_yes)
    message = str(caught.value)
    assert "Delete 47 files?" in message and "assume_yes=True" in message


def test_sad_the_env_override_wins_over_a_terminal_and_qt(monkeypatch) -> None:
    monkeypatch.setenv(U.ENV_NONINTERACTIVE, "1")
    monkeypatch.setattr(U, "_qt_is_running", lambda: True)
    monkeypatch.setattr(U, "_stdin_is_terminal", lambda: True)
    assert U.is_interactive() is False
    with pytest.raises(U.NonInteractiveError, match=U.ENV_NONINTERACTIVE):
        U.confirm("Delete?")


def test_edge_non_interactive_error_is_a_permission_error() -> None:
    assert issubclass(U.NonInteractiveError, PermissionError)


@pytest.mark.parametrize("value", ["", "0", "false", "no", "off"])
def test_edge_a_falsy_override_does_not_force_non_interactive(monkeypatch, value) -> None:
    monkeypatch.setenv(U.ENV_NONINTERACTIVE, value)
    monkeypatch.setattr(U, "_qt_is_running", lambda: False)
    monkeypatch.setattr(U, "_stdin_is_terminal", lambda: True)
    assert U.is_interactive() is True


def test_edge_qt_off_its_gui_thread_cannot_ask(monkeypatch) -> None:
    # A scheduled job runs scripts on a worker thread of the GUI process;
    # a dialog cannot be shown from there.
    monkeypatch.delenv(U.ENV_NONINTERACTIVE, raising=False)
    monkeypatch.setattr(U, "_qt_is_running", lambda: True)
    monkeypatch.setattr(U, "_stdin_is_terminal", lambda: False)
    assert U.is_interactive() is True  # this test runs on the main thread
    seen: list[bool] = []
    worker = threading.Thread(target=lambda: seen.append(U.is_interactive()))
    worker.start()
    worker.join()
    assert seen == [False]


def test_edge_a_closed_stdin_is_not_a_terminal(monkeypatch) -> None:
    monkeypatch.setattr("sys.stdin", None)
    assert U._stdin_is_terminal() is False


def test_edge_the_scripting_surface_forwards_assume_yes(unattended) -> None:
    assert axross.confirm("go?", assume_yes=True) is True
    with pytest.raises(axross.NonInteractiveError):
        axross.confirm("go?", default_yes=True)
    assert axross.is_interactive() is False


# -- production tarpit -----------------------------------------------------------


def _prod_profile():
    from core.profiles import ConnectionProfile

    return ConnectionProfile(name="prod", protocol="sftp", host="prod.internal", production=True)


@pytest.fixture
def tarpit(monkeypatch):
    safety_tarpit.reset_all()
    monkeypatch.delenv(safety_tarpit.ENV_DISABLE, raising=False)
    yield
    safety_tarpit.reset_all()


def test_sad_the_headless_tarpit_refuses_without_a_human(unattended, tarpit) -> None:
    ran: list[str] = []
    with pytest.raises(U.NonInteractiveError, match=safety_tarpit.ENV_DISABLE):
        with safety_tarpit.production_gate(_prod_profile(), "rm /etc", session_id="t1"):
            ran.append("op")
    assert ran == []
    # Refusing is not paying the toll: the next op is refused again.
    with pytest.raises(U.NonInteractiveError):
        with safety_tarpit.production_gate(_prod_profile(), "rm /etc", session_id="t1"):
            ran.append("op")
    assert ran == []


def test_happy_the_headless_tarpit_counts_down_for_a_human(at_terminal, tarpit) -> None:
    ran: list[str] = []
    with mock.patch.object(safety_tarpit.time, "sleep"):
        with safety_tarpit.production_gate(
            _prod_profile(), "rm /tmp/x", session_id="t2", countdown_s=0.01
        ):
            ran.append("op")
    assert ran == ["op"]


def test_edge_the_operator_opt_out_lets_unattended_runs_through(
    unattended, tarpit, monkeypatch
) -> None:
    monkeypatch.setenv(safety_tarpit.ENV_DISABLE, "1")
    ran: list[str] = []
    with safety_tarpit.production_gate(_prod_profile(), "rm /tmp/x", session_id="t3"):
        ran.append("op")
    assert ran == ["op"]


def test_sad_a_scripting_write_to_production_fails_closed(unattended, tarpit) -> None:
    ram = axross.ramfs()
    ram._axross_profile = _prod_profile()
    ram._axross_profile_key = "prod-session"
    with pytest.raises(axross.NonInteractiveError):
        axross.write_bytes(ram, "/danger.txt", b"payload")
    assert not ram.exists("/danger.txt")
