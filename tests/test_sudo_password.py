"""The sudo password is remembered while axross runs.

Operator: *„per default sudo merken, disable in settings erlauben. sodass man
nicht immer wieder das PW eingeben muss bei pkexec, polikit..."*

* Remembering is on by default and can be switched off (Tools > Remember
  sudo Password, ``remember_sudo_password`` in settings.json). Switching it
  off forgets the password at once. Paranoid mode never remembers.
* The password lives only in memory, never on disk, never on argv: it is
  checked with ``sudo -S -v`` before use; a wrong one is forgotten and asked
  again (three tries).
* polkit (pkexec, udisksctl) cannot be remembered by axross - its agent asks
  and axross never sees the password. With remembering on, the mount tries
  udisksctl without any prompt first (``--no-user-interaction``), then sudo
  (asked once), and only then pkexec and an interactive udisksctl.
* sudo, pkexec and udisksctl are taken only from root-owned system folders,
  so a planted ``sudo`` early in ``$PATH`` never receives the password.
"""

from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core import loop_mount as LM  # noqa: E402
from core import open_limits as OL  # noqa: E402
from core import security_mode as SM  # noqa: E402
from core import sudo_password as SP  # noqa: E402
from tests.test_loop_mount import IMG, Runner, fake_system, tools  # noqa: E402


@pytest.fixture(autouse=True)
def settings(tmp_path, monkeypatch):
    monkeypatch.setattr(OL, "SETTINGS_PATH", tmp_path / "settings.json")
    monkeypatch.setattr(SM, "_CURRENT", SM.policy_from_name("normal"))
    SP.forget()
    LM.reset_for_tests()
    yield tmp_path / "settings.json"
    SP.forget()
    LM.reset_for_tests()


class Asker:
    """The password callback: answers from a list and records each call."""

    def __init__(self, *answers):
        self.answers = list(answers)
        self.calls = []

    def __call__(self, retry=False):
        self.calls.append(retry)
        return self.answers.pop(0) if self.answers else None


VALIDATE = ["sudo", "-S", "-p", "", "-v"]
NO_TICKET = (["sudo", "-n", "-v"], 1, "", "sudo: a password is required\n")


def sudo_mount(run, asker, tmp_path, which=tools("sudo")):
    return LM.mount_partition(IMG, offset=0, size=4096, runner=run, which=which,
                              mount_root=str(tmp_path / "mnt"), password=asker)


# -- the setting ---------------------------------------------------------------------------


def test_happy_remembering_is_on_by_default_and_can_be_switched_off(settings):
    assert SP.remember_enabled()
    SP.remember("pw")
    assert SP.remembered() == "pw"
    SP.set_remember(False)
    assert not SP.remember_enabled() and SP.remembered() is None
    assert OL.read_setting(SP.SETTING) is False
    SP.remember("pw")  # switched off: nothing is kept
    assert SP.remembered() is None
    SP.set_remember(True)
    assert SP.remember_enabled() and SP.remembered() is None
    assert "pw" not in settings.read_text()


@pytest.mark.parametrize("bad", ["no", 0, None, [], {"x": 1}])
def test_sad_a_hand_edited_setting_reads_as_the_default(bad):
    OL.write_setting(SP.SETTING, bad)
    assert SP.remember_enabled() is True
    with pytest.raises(TypeError):
        SP.set_remember(bad)


def test_edge_paranoid_mode_never_remembers(monkeypatch):
    SP.remember("pw")
    monkeypatch.setattr(SM, "_CURRENT", SM.policy_from_name("paranoid"))
    assert not SP.remember_enabled() and SP.remembered() is None
    SP.remember("other")
    monkeypatch.setattr(SM, "_CURRENT", SM.policy_from_name("normal"))
    assert SP.remembered() is None  # paranoid dropped it, nothing came back


def test_edge_an_empty_password_is_not_remembered():
    SP.remember("")
    assert SP.remembered() is None


# -- sudo with a remembered password ---------------------------------------------------------


def test_happy_the_second_mount_does_not_ask_again(tmp_path):
    run = Runner([
        NO_TICKET, (VALIDATE, 0, "", ""), (["sudo", "-S"], 0, "/dev/loop4\n", ""),
        NO_TICKET, (VALIDATE, 0, "", ""), (["sudo", "-S"], 0, "/dev/loop5\n", ""),
    ])
    asker = Asker("s3cret")
    first = sudo_mount(run, asker, tmp_path)
    second = sudo_mount(run, asker, tmp_path)
    assert asker.calls == [False]  # asked once
    assert first.device == "/dev/loop4" and second.device == "/dev/loop5"
    for argv, stdin in run.calls:
        assert "s3cret" not in " ".join(argv)
        assert stdin in (None, "s3cret\n")
    assert SP.remembered() == "s3cret"


def test_happy_a_valid_sudo_ticket_needs_no_password(tmp_path):
    run = Runner([(["sudo", "-n", "-v"], 0, "", ""), (["sudo", "-n"], 0, "/dev/loop2\n", "")])
    asker = Asker("never")
    m = sudo_mount(run, asker, tmp_path)
    assert asker.calls == [] and m.method == "sudo"
    argv, stdin = run.calls[-1]
    assert argv[:4] == ["sudo", "-n", "/bin/sh", "-c"] and stdin is None


def test_happy_unmount_uses_the_remembered_password(tmp_path, monkeypatch):
    SP.remember("s3cret")
    point = tmp_path / "disk-1"
    point.mkdir()
    fake_system(tmp_path, monkeypatch, "/dev/loop3", IMG, str(point))
    m = LM.Mount(IMG, "/dev/loop3", str(point), "sudo", True)
    run = Runner([NO_TICKET, (VALIDATE, 0, "", ""), (["sudo", "-S"], 0, "", "")])
    asker = Asker()
    LM.unmount(m, runner=run, password=asker, which=tools("sudo"))
    assert asker.calls == [] and not point.exists()
    assert run.calls[-1][1] == "s3cret\n"


def test_sad_a_wrong_password_is_asked_again_and_the_right_one_kept(tmp_path):
    run = Runner([
        NO_TICKET,
        (VALIDATE, 1, "", "sudo: 1 incorrect password attempt\n"),
        (VALIDATE, 0, "", ""),
        (["sudo", "-S"], 0, "/dev/loop4\n", ""),
    ])
    asker = Asker("wrong", "right")
    sudo_mount(run, asker, tmp_path)
    assert asker.calls == [False, True]  # the second question says it is a retry
    assert SP.remembered() == "right"


def test_sad_three_wrong_passwords_give_up_and_keep_nothing(tmp_path):
    bad = (VALIDATE, 1, "", "sudo: 1 incorrect password attempt\n")
    run = Runner([NO_TICKET, bad, bad, bad])
    asker = Asker("a", "b", "c", "d")
    with pytest.raises(LM.MountError, match="not accepted"):
        sudo_mount(run, asker, tmp_path)
    assert len(asker.calls) == 3 and SP.remembered() is None
    assert not any(c[0][:2] == ["sudo", "-S"] and "/bin/sh" in c[0] for c in run.calls)


def test_sad_a_remembered_password_that_stopped_working_is_asked_anew(tmp_path):
    SP.remember("old")
    run = Runner([
        NO_TICKET,
        (VALIDATE, 1, "", "sudo: 1 incorrect password attempt\n"),
        (VALIDATE, 0, "", ""),
        (["sudo", "-S"], 0, "/dev/loop4\n", ""),
    ])
    asker = Asker("new")
    sudo_mount(run, asker, tmp_path)
    assert asker.calls == [False]  # the stale one was the user's last answer, not theirs now
    assert run.calls[1][1] == "old\n" and SP.remembered() == "new"


def test_sad_switched_off_asks_every_time_and_keeps_nothing(tmp_path):
    SP.set_remember(False)
    run = Runner([
        NO_TICKET, (VALIDATE, 0, "", ""), (["sudo", "-S"], 0, "/dev/loop4\n", ""),
        NO_TICKET, (VALIDATE, 0, "", ""), (["sudo", "-S"], 0, "/dev/loop5\n", ""),
    ])
    asker = Asker("pw", "pw")
    sudo_mount(run, asker, tmp_path)
    sudo_mount(run, asker, tmp_path)
    assert asker.calls == [False, False] and SP.remembered() is None


def test_edge_cancelling_the_question_mounts_nothing(tmp_path):
    run = Runner([NO_TICKET])
    with pytest.raises(LM.MountError, match="no password given"):
        sudo_mount(run, Asker(None), tmp_path)
    assert SP.remembered() is None


# -- the order of the methods ------------------------------------------------------------------


def test_happy_remembering_tries_udisks_without_a_prompt_then_sudo_before_pkexec(tmp_path):
    run = Runner([
        (["udisksctl", "loop-setup"], 1, "",
         "GDBus.Error:org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain: Not authorized\n"),
        NO_TICKET, (VALIDATE, 0, "", ""), (["sudo", "-S"], 0, "/dev/loop6\n", ""),
    ])
    m = sudo_mount(run, Asker("pw"), tmp_path, which=tools("udisksctl", "pkexec", "sudo"))
    assert m.method == "sudo"
    assert "--no-user-interaction" in run.calls[0][0]
    assert not any(c[0][0] == "pkexec" for c in run.calls)


def test_happy_udisks_without_a_prompt_mounts_when_polkit_allows_it(tmp_path):
    run = Runner([
        (["udisksctl", "loop-setup"], 0, "Mapped file x as /dev/loop1.\n", ""),
        (["udisksctl", "mount"], 0, "Mounted /dev/loop1 at /run/media/u/x.\n", ""),
    ])
    asker = Asker("never")
    m = sudo_mount(run, asker, tmp_path, which=tools("udisksctl", "pkexec", "sudo"))
    assert m.method == "udisksctl" and asker.calls == []
    assert all("--no-user-interaction" in c[0] for c in run.calls)


def test_sad_switched_off_keeps_the_decided_chain(tmp_path):
    SP.set_remember(False)
    run = Runner([
        (["udisksctl", "loop-setup"], 1, "", "Not authorized"),
        (["pkexec"], 0, "/dev/loop9\n", ""),
    ])
    asker = Asker("never")
    m = sudo_mount(run, asker, tmp_path, which=tools("udisksctl", "pkexec", "sudo"))
    assert m.method == "pkexec" and asker.calls == []
    assert "--no-user-interaction" not in run.calls[0][0]


def test_edge_udisks_is_asked_interactively_last_when_nothing_else_works(tmp_path):
    run = Runner([
        (["udisksctl", "loop-setup", "--no-user-interaction"], 1, "",
         "Error: org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain: Not authorized"),
        (["udisksctl", "loop-setup"], 0, "Mapped file x as /dev/loop1.\n", ""),
        (["udisksctl", "mount"], 0, "Mounted /dev/loop1 at /run/media/u/x.\n", ""),
    ])
    m = sudo_mount(run, Asker(), tmp_path, which=tools("udisksctl"))
    assert m.method == "udisksctl"
    assert "--no-user-interaction" not in run.calls[1][0]  # polkit may ask now


def test_edge_a_udisks_failure_that_is_no_permission_is_not_repeated(tmp_path):
    run = Runner([
        (["udisksctl", "loop-setup"], 0, "Mapped file x as /dev/loop1.\n", ""),
        (["udisksctl", "mount"], 1, "", "wrong fs type"),
        (["udisksctl", "loop-delete"], 0, "", ""),
    ])
    with pytest.raises(LM.MountError, match="wrong fs type"):
        sudo_mount(run, Asker(), tmp_path, which=tools("udisksctl"))
    assert [c[0][1] for c in run.calls].count("loop-setup") == 1


def test_edge_a_udisks_mount_unmounts_without_a_prompt_or_falls_back_to_sudo(tmp_path, monkeypatch):
    SP.remember("pw")
    fake_system(tmp_path, monkeypatch, "/dev/loop7", IMG, "/run/media/u/ROOT")
    m = LM.Mount(IMG, "/dev/loop7", "/run/media/u/ROOT", "udisksctl", True)
    run = Runner([
        (["udisksctl", "unmount"], 1, "", "org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain"),
        NO_TICKET, (VALIDATE, 0, "", ""), (["sudo", "-S"], 0, "", ""),
    ])
    LM.unmount(m, runner=run, password=Asker(), which=tools("udisksctl", "sudo"))
    assert "--no-user-interaction" in run.calls[0][0]
    assert run.calls[-1][0][4:] == ["/bin/sh", "-c", LM.UNMOUNT_SCRIPT, "axross-unmount",
                                    "/run/media/u/ROOT", "/dev/loop7"]
    assert m not in LM.active_mounts()


# -- where the tools come from -----------------------------------------------------------------


def test_sad_a_planted_sudo_early_in_path_is_not_used(tmp_path, monkeypatch):
    planted = tmp_path / "bin" / "sudo"
    planted.parent.mkdir()
    planted.write_text("#!/bin/sh\necho stolen\n")
    planted.chmod(planted.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("PATH", f"{planted.parent}{os.pathsep}{os.environ.get('PATH', '')}")
    found = LM._which("sudo")
    assert found != str(planted)
    assert found is None or os.stat(found).st_uid == 0


def test_happy_the_resolved_absolute_path_is_run(tmp_path):
    run = Runner([(["pkexec"], 0, "/dev/loop3\n", "")])
    SP.set_remember(False)
    LM.mount_partition(IMG, offset=0, size=10, runner=run, which=tools("pkexec"),
                       mount_root=str(tmp_path))
    assert run.raw_calls[0][0] == "/usr/bin/pkexec"


def test_edge_a_loop_device_that_cannot_be_freed_is_logged(tmp_path, caplog):
    run = Runner([
        (["udisksctl", "loop-setup"], 0, "Mapped file x as /dev/loop1.\n", ""),
        (["udisksctl", "mount"], 1, "", "wrong fs type"),
        (["udisksctl", "loop-delete"], 1, "", "Not authorized"),
    ])
    with caplog.at_level("WARNING", logger="core.loop_mount"):
        with pytest.raises(LM.MountError, match="wrong fs type"):
            sudo_mount(run, Asker(), tmp_path, which=tools("udisksctl"))
    assert any("/dev/loop1 stays attached" in r.getMessage() for r in caplog.records)


def test_sad_a_cancelled_unmount_lets_polkit_ask_nothing(tmp_path, monkeypatch):
    """The dialog closed while sudo asked for the password: no polkit
    prompt follows (bughunt 2026-10-22)."""
    fake_system(tmp_path, monkeypatch, "/dev/loop7", IMG, "/run/media/u/ROOT")
    m = LM.Mount(IMG, "/dev/loop7", "/run/media/u/ROOT", "udisksctl", True)
    gone = {"closed": False}

    def closed_while_asking(retry=False):
        gone["closed"] = True
        return None

    run = Runner([
        (["udisksctl", "unmount"], 1, "", "org.freedesktop.UDisks2.Error.NotAuthorizedCanObtain"),
        NO_TICKET,
    ])
    with pytest.raises(LM.MountError, match="cancelled"):
        LM.unmount(m, runner=run, password=closed_while_asking,
                   which=tools("udisksctl", "sudo"), cancelled=lambda: gone["closed"])
    assert [c[0][0] for c in run.calls] == ["udisksctl", "sudo"]
