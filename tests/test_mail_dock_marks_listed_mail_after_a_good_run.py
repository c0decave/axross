"""Mail dock: a run that ends without error marks the mails it listed seen.

Round 2 made a mail count as handled only once the agent read, analysed
or answered it, so a run that fails after ``mail_list_new`` keeps it new.
But a mail the agent listed and chose to leave alone (no need to open
it) then came back in every run: each one woke the model again for
nothing. Now a run that ends with an answer marks everything it listed;
a failed, cancelled or cut-off run still marks only what it read.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))

from test_mail_dock import INJECT, _runner, call  # noqa: E402
from test_mail_dock import _no_proxy, fake, mailbox  # noqa: E402,F401

from core import mail_dock as MD  # noqa: E402


# -- happy -------------------------------------------------------------------


def test_happy_a_listed_mail_left_unopened_is_not_listed_again(tmp_path, mailbox, fake):
    server = fake(call("mail_list_new"), {"content": "Nothing urgent."})
    runner = _runner(tmp_path, mailbox, server)
    assert runner.run_once() == "Nothing urgent."
    asked = len(server.requests)
    # Nothing new: the next run does not wake the model.
    assert runner.run_once() == ""
    assert len(server.requests) == asked


def test_happy_a_mail_that_arrives_later_is_still_new(tmp_path, mailbox, fake):
    server = fake(call("mail_list_new"), {"content": "ok"}, call("mail_list_new"), {"content": "2"})
    runner = _runner(tmp_path, mailbox, server)
    runner.run_once()
    with mailbox.open_write("/INBOX/2.eml") as f:
        f.write(INJECT)
    assert runner.run_once() == "2"
    listing = [m["content"] for m in server.requests[-1]["messages"] if m.get("role") == "tool"][0]
    assert "urgent" in listing and "Lunch?" not in listing


# -- sad ---------------------------------------------------------------------


def test_sad_a_failed_run_still_marks_nothing_it_did_not_read(tmp_path, mailbox, fake):
    server = fake(call("mail_list_new"), 500, call("mail_list_new"), {"content": "again"})
    runner = _runner(tmp_path, mailbox, server)
    with pytest.raises(Exception, match="500"):
        runner.run_once()
    assert runner.run_once() == "again"


def test_sad_a_cut_off_run_marks_nothing_it_did_not_read(tmp_path, mailbox, fake):
    # max_steps: the agent never answered.
    server = fake(*[call("mail_list_new", cid=f"c{i}") for i in range(40)])
    runner = _runner(tmp_path, mailbox, server)
    assert runner.run_once() == ""          # 20 steps, no answer
    still_new = MD.Mailbox(mailbox, "INBOX", runner.state_dir / "seen.json").new(mark=False)
    assert [m["name"] for m in still_new] == ["1.eml"]


# -- edge --------------------------------------------------------------------


def test_edge_the_runners_own_look_marks_nothing(tmp_path, mailbox, fake):
    # The agent answers without listing: the runner's check for new mail
    # is no listing of the agent's.
    server = fake({"content": "did not look"}, call("mail_list_new"), {"content": "looked"})
    runner = _runner(tmp_path, mailbox, server)
    assert runner.run_once() == "did not look"
    assert runner.run_once() == "looked"
